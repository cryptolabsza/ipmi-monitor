#!/usr/bin/env python3
"""
IPMI/BMC Event Monitor
A Flask-based dashboard for monitoring IPMI SEL logs across all servers

GitHub: https://github.com/jjziets/ipmi-monitor
License: MIT
"""

from flask import Flask, render_template, render_template_string, jsonify, request, Response, session, redirect, url_for, make_response, stream_with_context
from functools import wraps
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from prometheus_client import Gauge, Counter, generate_latest, CONTENT_TYPE_LATEST, CollectorRegistry
import subprocess
import threading
import time
import json
import os
import re
from pathlib import Path
import hmac
import ipaddress
import requests
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
from werkzeug.security import generate_password_hash, check_password_hash

# CryptoLabs Alert System integration (v1.1.0+)
# Provides hooks for push notifications to CryptoLabs app, email, and web browser
try:
    from . import alerts as _alerts_module
    _ALERTS_AVAILABLE = True
except ImportError:
    _alerts_module = None
    _ALERTS_AVAILABLE = False

# Suppress SSL warnings for self-signed BMC certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
# Use proper paths - check for user config first, then fall back to system paths
def get_data_dir():
    """Get data directory - user config or system path."""
    if os.environ.get('DATA_DIR'):
        return os.environ['DATA_DIR']
    # Running as root or via sudo
    if os.geteuid() == 0:
        return '/var/lib/ipmi-monitor'
    # Running as regular user
    return os.path.expanduser('~/.config/ipmi-monitor')

DATA_DIR = get_data_dir()
os.makedirs(DATA_DIR, exist_ok=True)

# =============================================================================
# RATE LIMITING & BRUTE-FORCE PROTECTION
# =============================================================================
# In-memory rate limiting (cleared on restart - consider Redis for production clusters)
_login_attempts = {}  # {ip: {'attempts': int, 'first_attempt': datetime, 'locked_until': datetime}}
_login_attempts_lock = threading.Lock()

# Rate limit configuration
RATE_LIMIT_WINDOW_SECONDS = int(os.environ.get('RATE_LIMIT_WINDOW_SECONDS', '300'))  # 5 minutes
RATE_LIMIT_MAX_ATTEMPTS = int(os.environ.get('RATE_LIMIT_MAX_ATTEMPTS', '5'))  # 5 attempts
RATE_LIMIT_LOCKOUT_SECONDS = int(os.environ.get('RATE_LIMIT_LOCKOUT_SECONDS', '900'))  # 15 minute lockout

def get_client_ip():
    """Get client IP, respecting X-Forwarded-For for proxied requests"""
    # Check for forwarded IP (behind nginx/proxy)
    from flask import request as flask_request
    forwarded_for = flask_request.headers.get('X-Forwarded-For', '')
    if forwarded_for:
        # X-Forwarded-For can be comma-separated list, take the first
        return forwarded_for.split(',')[0].strip()
    return flask_request.remote_addr or '0.0.0.0'

def is_rate_limited(client_ip):
    """Check if a client IP is rate limited. Returns (is_limited, seconds_remaining)"""
    now = datetime.utcnow()
    with _login_attempts_lock:
        if client_ip not in _login_attempts:
            return False, 0
        
        record = _login_attempts[client_ip]
        
        # Check if currently locked out
        if record.get('locked_until') and now < record['locked_until']:
            remaining = int((record['locked_until'] - now).total_seconds())
            return True, remaining
        
        # Check if window has expired - reset counter
        window_start = now - timedelta(seconds=RATE_LIMIT_WINDOW_SECONDS)
        if record['first_attempt'] < window_start:
            _login_attempts[client_ip] = {'attempts': 0, 'first_attempt': now, 'locked_until': None}
            return False, 0
        
        return False, 0

def record_failed_login(client_ip, username=None):
    """Record a failed login attempt. Returns True if now locked out."""
    now = datetime.utcnow()
    with _login_attempts_lock:
        if client_ip not in _login_attempts:
            _login_attempts[client_ip] = {'attempts': 0, 'first_attempt': now, 'locked_until': None}
        
        record = _login_attempts[client_ip]
        
        # Reset if window expired
        window_start = now - timedelta(seconds=RATE_LIMIT_WINDOW_SECONDS)
        if record['first_attempt'] < window_start:
            record['attempts'] = 0
            record['first_attempt'] = now
            record['locked_until'] = None
        
        record['attempts'] += 1
        
        # Check if should lock out
        if record['attempts'] >= RATE_LIMIT_MAX_ATTEMPTS:
            record['locked_until'] = now + timedelta(seconds=RATE_LIMIT_LOCKOUT_SECONDS)
            # Log security event (deferred to avoid circular import)
            _log_security_event_deferred('LOGIN_LOCKOUT', client_ip, username, 
                f"Account locked after {record['attempts']} failed attempts")
            return True
        
        return False

def record_successful_login(client_ip):
    """Clear failed login attempts on successful login"""
    with _login_attempts_lock:
        if client_ip in _login_attempts:
            del _login_attempts[client_ip]

def _log_security_event_deferred(event_type, client_ip, username=None, details=None):
    """Deferred logging to avoid issues during module initialization"""
    # Queue for later logging once app is fully initialized
    if not hasattr(app, '_security_log_queue'):
        app._security_log_queue = []
    app._security_log_queue.append((event_type, client_ip, username, details))

def log_security_event(event_type, client_ip, username=None, details=None):
    """Log security-related events for audit trail"""
    timestamp = datetime.utcnow().isoformat()
    log_entry = {
        'timestamp': timestamp,
        'event': event_type,
        'ip': client_ip,
        'username': username,
        'details': details
    }
    # Log to application logger (will appear in Docker logs)
    import logging
    security_logger = logging.getLogger('security')
    if not security_logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter('[SECURITY] %(message)s'))
        security_logger.addHandler(handler)
        security_logger.setLevel(logging.INFO)
    
    security_logger.info(json.dumps(log_entry))
    
    # Also log to file
    try:
        audit_file = os.path.join(DATA_DIR, 'security_audit.log')
        with open(audit_file, 'a') as f:
            f.write(json.dumps(log_entry) + '\n')
    except Exception:
        pass  # Don't fail if audit file can't be written

# =============================================================================
# SECURE COMMAND EXECUTION HELPERS
# =============================================================================
# NOTE: The following functions provide more secure alternatives to direct
# password exposure in process listings. However, they require client-side
# configuration that may not always be possible.
#
# SECURITY CONSIDERATIONS:
# 1. ipmitool -P <pass> exposes passwords in `ps` output
#    BETTER: Use ipmitool -E with IPMI_PASSWORD environment variable
#    
# 2. sshpass -p <pass> exposes passwords in `ps` output  
#    BETTER: Use sshpass -e with SSHPASS environment variable, or SSH keys
#
# 3. Redfish with verify=False trusts self-signed BMC certs
#    This is acceptable on private networks but NEVER expose the UI publicly

def run_ipmitool_secure(bmc_ip, ipmi_user, ipmi_pass, *args, timeout=30):
    """
    Run ipmitool with password via environment variable (more secure).
    Falls back to -P if -E fails (some older ipmitool versions).
    
    SECURITY: Using -E prevents password exposure in process listings.
    The password is passed via IPMI_PASSWORD environment variable.
    """
    # Build command with -E (password from environment)
    cmd = ['ipmitool', '-I', 'lanplus', '-H', bmc_ip, '-U', ipmi_user, '-E'] + list(args)
    env = os.environ.copy()
    env['IPMI_PASSWORD'] = ipmi_pass
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
        if result.returncode == 0:
            return result
        # Some systems don't support -E, fall back to -P with warning
        if 'IPMI_PASSWORD' in result.stderr or 'password' in result.stderr.lower():
            app.logger.debug(f"ipmitool -E not supported for {bmc_ip}, falling back to -P")
    except subprocess.TimeoutExpired:
        raise
    except Exception as e:
        app.logger.debug(f"ipmitool -E failed for {bmc_ip}: {e}, falling back to -P")
    
    # Fallback to -P (less secure but more compatible)
    # NOTE: This exposes password in process listings
    cmd_fallback = ['ipmitool', '-I', 'lanplus', '-H', bmc_ip, '-U', ipmi_user, '-P', ipmi_pass] + list(args)
    return subprocess.run(cmd_fallback, capture_output=True, text=True, timeout=timeout)

def run_ssh_secure(server_ip, ssh_user, ssh_pass=None, ssh_key=None, command='', timeout=30):
    """
    Run SSH command with secure credential handling.
    
    Priority:
    1. SSH key file (most secure)
    2. sshpass -e with SSHPASS env var (more secure than -p)
    3. sshpass -p (fallback, exposes password in ps)
    
    SECURITY: Using SSH keys or sshpass -e prevents password exposure.
    """
    ssh_opts = ['-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null',
                '-o', 'ConnectTimeout=10', '-o', 'BatchMode=yes']
    
    key_file_path = None
    env = os.environ.copy()
    
    try:
        if ssh_key:
            # Write key to temp file
            import tempfile
            fd, key_file_path = tempfile.mkstemp(prefix='ssh_key_', suffix='.pem')
            os.write(fd, ssh_key.encode() if isinstance(ssh_key, str) else ssh_key)
            os.close(fd)
            os.chmod(key_file_path, 0o600)
            cmd = ['ssh', '-i', key_file_path] + ssh_opts + [f'{ssh_user}@{server_ip}', command]
        elif ssh_pass:
            # Try sshpass with environment variable first (more secure)
            env['SSHPASS'] = ssh_pass
            cmd = ['sshpass', '-e', 'ssh'] + ssh_opts + [f'{ssh_user}@{server_ip}', command]
        else:
            # No password - try with default SSH key
            cmd = ['ssh'] + ssh_opts + [f'{ssh_user}@{server_ip}', command]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
        return result
        
    finally:
        if key_file_path:
            try:
                os.unlink(key_file_path)
            except:
                pass
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DATA_DIR}/ipmi_events.db'
app.config['DATA_DIR'] = DATA_DIR
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# SQLite connection pool settings for multi-threaded access
# Use NullPool to avoid connection pool exhaustion with parallel workers
from sqlalchemy.pool import NullPool
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'poolclass': NullPool,  # Each thread gets its own connection, closes when done
    'connect_args': {'check_same_thread': False, 'timeout': 60}  # Allow multi-threaded access, longer timeout
}

# Security Configuration
SECRET_KEY = os.environ.get('SECRET_KEY')
if not SECRET_KEY or SECRET_KEY == 'ipmi-monitor-secret-key-change-me':
    import secrets
    SECRET_KEY = secrets.token_hex(32)
    app.logger.warning("⚠️  SECRET_KEY not set! Using random key (sessions won't persist across restarts)")

app.config['SECRET_KEY'] = SECRET_KEY
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('SESSION_COOKIE_SECURE', 'false').lower() == 'true'
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent XSS access to cookies
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF protection
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)  # Session timeout

# =============================================================================
# REVERSE PROXY / SUBPATH SUPPORT
# =============================================================================
# Support running behind a reverse proxy at a subpath like /ipmi/
# Handles X-Forwarded-Proto (HTTPS), X-Forwarded-For, and X-Script-Name headers
from werkzeug.middleware.proxy_fix import ProxyFix

# Apply ProxyFix first to handle X-Forwarded-* headers (HTTPS, client IP, etc.)
# x_for=1, x_proto=1, x_host=1 means trust 1 proxy for these headers
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# Environment variable for subpath (optional override)
APPLICATION_ROOT = os.environ.get('APPLICATION_ROOT', os.environ.get('SCRIPT_NAME', ''))
if APPLICATION_ROOT:
    app.config['APPLICATION_ROOT'] = APPLICATION_ROOT

class ScriptNameMiddleware:
    """
    Middleware to handle X-Script-Name header for subpath routing.
    Sets SCRIPT_NAME so Flask generates correct URLs with the subpath prefix.
    """
    def __init__(self, app):
        self.app = app
    
    def __call__(self, environ, start_response):
        # Check for X-Script-Name header (set by nginx proxy_set_header)
        script_name = environ.get('HTTP_X_SCRIPT_NAME', '')
        if script_name:
            environ['SCRIPT_NAME'] = script_name
            # Don't strip PATH_INFO - nginx proxy_pass already handles that
        # Fallback to environment variable
        elif APPLICATION_ROOT:
            environ['SCRIPT_NAME'] = APPLICATION_ROOT
        
        return self.app(environ, start_response)

# Apply script name middleware (after ProxyFix)
app.wsgi_app = ScriptNameMiddleware(app.wsgi_app)

@app.context_processor
def inject_base_path():
    """Inject base path and fleet home URL into all templates."""
    # Get base path from SCRIPT_NAME (set by middleware) or config
    base_path = request.environ.get('SCRIPT_NAME', '') or app.config.get('APPLICATION_ROOT', '')
    
    # Fleet home URL - links back to the Fleet Management dashboard (cryptolabs-proxy landing page)
    # Priority: 1) FLEET_HOME_URL env var  2) "/" when behind proxy  3) empty (hide button)
    fleet_home_url = os.environ.get('FLEET_HOME_URL', '')
    if not fleet_home_url and base_path:
        # Running behind proxy at a subpath (e.g. /ipmi/) - fleet home is the proxy root
        fleet_home_url = '/'
    
    return {
        'base_path': base_path,
        'api_base': base_path,  # Alias for clarity in JS
        'fleet_home_url': fleet_home_url,
    }

db = SQLAlchemy(app)

# Branding - customize for your organization
APP_NAME = os.environ.get('APP_NAME', 'IPMI Monitor')

# =============================================================================
# VERSION INFORMATION
# =============================================================================
from ipmi_monitor import __version__
APP_VERSION = __version__  # Use version from package

def get_build_info():
    """
    Get build information including git commit and timestamp.
    Priority:
    1. Environment variables (Docker builds)
    2. build_info.json file (pip package builds)
    3. Live git info (development)
    4. Fallback to unknown
    """
    import subprocess
    from pathlib import Path
    
    # Try environment variables first (Docker builds)
    git_branch = os.environ.get('GIT_BRANCH')
    git_commit = os.environ.get('GIT_COMMIT')
    build_time = os.environ.get('BUILD_TIME')
    
    if git_commit and git_commit != 'unknown':
        return {
            'version': APP_VERSION,
            'git_branch': git_branch or 'unknown',
            'git_commit': git_commit[:7],
            'git_commit_full': git_commit,
            'build_time': build_time or 'unknown',
        }
    
    # Try build_info.json file (pip package builds)
    try:
        build_info_path = Path(__file__).parent / 'build_info.json'
        if build_info_path.exists():
            import json
            with open(build_info_path) as f:
                info = json.load(f)
                return {
                    'version': APP_VERSION,
                    'git_branch': info.get('git_branch', 'unknown'),
                    'git_commit': info.get('git_commit', 'unknown')[:7],
                    'git_commit_full': info.get('git_commit', 'unknown'),
                    'build_time': info.get('build_time', 'unknown'),
                }
    except Exception:
        pass
    
    # Try live git info (development mode)
    try:
        git_commit = subprocess.check_output(
            ['git', 'rev-parse', 'HEAD'], 
            stderr=subprocess.DEVNULL,
            cwd=Path(__file__).parent
        ).decode().strip()
        git_branch = subprocess.check_output(
            ['git', 'rev-parse', '--abbrev-ref', 'HEAD'],
            stderr=subprocess.DEVNULL,
            cwd=Path(__file__).parent
        ).decode().strip()
        return {
            'version': APP_VERSION,
            'git_branch': git_branch,
            'git_commit': git_commit[:7],
            'git_commit_full': git_commit,
            'build_time': datetime.now().strftime('%Y-%m-%d %H:%M UTC'),
        }
    except Exception:
        pass
    
    # Fallback
    return {
        'version': APP_VERSION,
        'git_branch': 'unknown',
        'git_commit': 'dev',
        'git_commit_full': 'unknown',
        'build_time': 'unknown',
    }

def get_version_string():
    """
    Get formatted version string.
    Always includes commit hash and build time when available.
    Examples:
      - Production: v0.7.0 (main@8d7150c, 2025-12-07 05:47 UTC)
      - Development: v0.7.0-dev (dev@8d7150c, 2025-12-07 05:47 UTC)
      - Local dev: v0.7.0-dev (local@abc1234, 2025-12-07 05:47 UTC)
    """
    info = get_build_info()
    branch = info['git_branch']
    commit = info['git_commit']
    build_time = info['build_time']
    
    # Add -dev suffix when running from develop/dev branch or local development
    is_dev = branch in ['develop', 'dev', 'unknown'] or commit in ['dev', 'unknown']
    version_suffix = '-dev' if is_dev else ''
    
    # Always try to show commit and time
    if commit not in ('dev', 'unknown') and build_time != 'unknown':
        return f"v{info['version']}{version_suffix} ({branch}@{commit}, {build_time})"
    elif commit not in ('dev', 'unknown'):
        return f"v{info['version']}{version_suffix} ({branch}@{commit})"
    elif build_time != 'unknown':
        return f"v{info['version']}{version_suffix} ({branch}, {build_time})"
    else:
        # Final fallback: show current time as build time for local dev
        from datetime import datetime
        now = datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')
        return f"v{info['version']}{version_suffix} (local, {now})"

def check_for_updates():
    """
    Check GitHub for newer releases.
    Returns dict with update_available, latest_version, current_version.
    """
    try:
        # Check GitHub API for latest release
        response = requests.get(
            'https://api.github.com/repos/cryptolabsza/ipmi-monitor/releases/latest',
            timeout=5,
            headers={'Accept': 'application/vnd.github.v3+json'}
        )
        if response.status_code == 200:
            data = response.json()
            latest_tag = data.get('tag_name', '').lstrip('v')
            latest_commit = data.get('target_commitish', '')
            published_at = data.get('published_at', '')
            
            # Also check main branch for latest commit
            commits_response = requests.get(
                'https://api.github.com/repos/cryptolabsza/ipmi-monitor/commits/main',
                timeout=5,
                headers={'Accept': 'application/vnd.github.v3+json'}
            )
            latest_main_commit = ''
            latest_main_date = ''
            if commits_response.status_code == 200:
                commit_data = commits_response.json()
                latest_main_commit = commit_data.get('sha', '')[:7]
                latest_main_date = commit_data.get('commit', {}).get('committer', {}).get('date', '')
            
            current_info = get_build_info()
            current_commit = current_info['git_commit_full'][:7] if current_info['git_commit_full'] != 'unknown' else ''
            
            # Check if update available
            update_available = False
            if latest_main_commit and current_commit and latest_main_commit != current_commit:
                update_available = True
            
            return {
                'update_available': update_available,
                'current_version': APP_VERSION,
                'current_commit': current_commit,
                'latest_release': latest_tag,
                'latest_release_date': published_at,
                'latest_main_commit': latest_main_commit,
                'latest_main_date': latest_main_date,
                'release_notes_url': data.get('html_url', ''),
                'docker_pull': 'docker pull ghcr.io/cryptolabsza/ipmi-monitor:latest'
            }
    except Exception as e:
        app.logger.debug(f"Update check failed: {e}")
    
    return {
        'update_available': False,
        'error': 'Could not check for updates'
    }

# Configure logging to work with gunicorn
import logging
import sys
if not app.debug:
    # In production, log to stdout for Docker/gunicorn
    gunicorn_logger = logging.getLogger('gunicorn.error')
    app.logger.handlers = gunicorn_logger.handlers
    app.logger.setLevel(gunicorn_logger.level)
    
    # Also add a stream handler for background threads
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.INFO)
    formatter = logging.Formatter('[%(asctime)s] %(levelname)s: %(message)s')
    handler.setFormatter(formatter)
    app.logger.addHandler(handler)

# Configuration
IPMI_USER = os.environ.get('IPMI_USER', 'admin')
IPMI_PASS = os.environ.get('IPMI_PASS', '')
IPMI_PASS_NVIDIA = os.environ.get('IPMI_PASS_NVIDIA', '')  # NVIDIA BMCs need 16 chars

# Warn if passwords not set
if not IPMI_PASS:
    app.logger.warning("⚠️  IPMI_PASS not set! IPMI commands will fail. Set via environment variable.")
if not IPMI_PASS_NVIDIA:
    app.logger.warning("⚠️  IPMI_PASS_NVIDIA not set! NVIDIA BMC commands will fail.")
POLL_INTERVAL = int(os.environ.get('POLL_INTERVAL', 300))  # 5 minutes for SEL events
SENSOR_POLL_MULTIPLIER = int(os.environ.get('SENSOR_POLL_MULTIPLIER', 1))  # Collect sensors every N collection cycles (1 = every cycle)

# Admin authentication - defaults can be overridden by env vars or database
DEFAULT_ADMIN_USER = os.environ.get('ADMIN_USER', 'admin')
DEFAULT_ADMIN_PASS = os.environ.get('ADMIN_PASS', 'admin')  # Default: admin/admin

# Server config file paths (checked on startup)
def get_config_dir():
    """Get config directory - same as data dir for simplicity."""
    if os.environ.get('CONFIG_DIR'):
        return os.environ['CONFIG_DIR']
    return DATA_DIR  # Use same directory as data

CONFIG_DIR = get_config_dir()
SERVERS_CONFIG_FILE = os.environ.get('SERVERS_CONFIG_FILE', '')  # Override specific file

# Setup complete flag
SETUP_COMPLETE_FILE = os.path.join(DATA_DIR, '.setup_complete')

# =============================================================================
# SSE (Server-Sent Events) for Real-Time Updates
# =============================================================================

import queue
_sse_subscribers = []  # List of (queue, client_id)
_sse_lock = threading.Lock()

def broadcast_status_update(event_type: str, data: dict):
    """Broadcast a status update to all connected SSE clients"""
    import json
    message = f"event: {event_type}\ndata: {json.dumps(data)}\n\n"
    with _sse_lock:
        for q, client_id in _sse_subscribers:
            try:
                q.put_nowait(message)
            except queue.Full:
                pass  # Skip if queue is full

def sse_stream(client_id: str):
    """Generator function for SSE stream"""
    q = queue.Queue(maxsize=100)
    with _sse_lock:
        _sse_subscribers.append((q, client_id))
    try:
        # Send initial keepalive
        yield ": keepalive\n\n"
        while True:
            try:
                message = q.get(timeout=30)  # 30s heartbeat
                yield message
            except queue.Empty:
                # Send keepalive comment
                yield ": keepalive\n\n"
    finally:
        with _sse_lock:
            _sse_subscribers[:] = [(sq, sid) for sq, sid in _sse_subscribers if sq != q]

# =============================================================================
# GPU ERROR HANDLING - User-friendly descriptions (hide technical Xid codes)
# =============================================================================

# Map Xid codes to user-friendly descriptions (clients don't need to know Xid numbers)
GPU_ERROR_DESCRIPTIONS = {
    # Memory errors
    31: 'GPU Memory Error',
    48: 'GPU Memory Error (ECC)',
    63: 'GPU Memory Degradation',
    64: 'GPU Memory Degradation (Critical)',
    92: 'GPU Memory Warning',
    94: 'GPU Memory Error (Contained)',
    95: 'GPU Memory Error (Critical)',
    
    # GPU unresponsive
    43: 'GPU Not Responding',
    45: 'GPU Process Terminated',
    61: 'GPU Firmware Error',
    62: 'GPU Firmware Error',
    74: 'GPU Exception',
    79: 'GPU Disconnected',
    119: 'GPU System Error',
    
    # Recovery required
    154: 'GPU Requires Recovery',
}

# Recovery actions with user-friendly names
RECOVERY_ACTIONS = {
    'gpu_reset': 'GPU Reset',
    'node_reboot': 'Server Reboot Required',
    'power_cycle': 'Power Cycle Required',
    'clock_limit': 'GPU Clock Limited',
    'workload_killed': 'Workload Terminated',
    'maintenance': 'Maintenance Required',
}

def get_gpu_error_description(xid_code, recovery_action=None):
    """Get user-friendly description for GPU error (hides Xid code from clients)"""
    base_desc = GPU_ERROR_DESCRIPTIONS.get(xid_code, 'GPU Error Detected')
    if recovery_action:
        action_desc = RECOVERY_ACTIONS.get(recovery_action, recovery_action)
        return f"{base_desc} - {action_desc}"
    return base_desc

def get_user(username):
    """Get user by username"""
    try:
        return User.query.filter_by(username=username, enabled=True).first()
    except Exception:
        return None

def verify_user_password(username, password):
    """Verify user credentials, returns user object if valid"""
    try:
        user = User.query.filter_by(username=username, enabled=True).first()
        if user and user.verify_password(password):
            return user
        # Fallback to defaults for first-time setup
        if not User.query.first() and username == DEFAULT_ADMIN_USER and password == DEFAULT_ADMIN_PASS:
            return 'default_admin'
    except Exception:
        pass
    return None

def allow_anonymous_read():
    """Check if anonymous read access is enabled"""
    try:
        # SECURITY: Default to FALSE for safer deployments
        # Admins can enable anonymous read via Settings if needed
        setting = SystemSettings.get('allow_anonymous_read', 'false')
        return setting.lower() == 'true'
    except Exception:
        return False  # Default to DENY (safer)

def is_api_request():
    """Check if this is an API request that expects JSON"""
    return (request.is_json or 
            request.path.startswith('/api/') or
            request.headers.get('Accept', '').startswith('application/json') or
            request.headers.get('X-Requested-With') == 'XMLHttpRequest')

# =============================================================================
# PROXY AUTHENTICATION (Unified Fleet Auth)
# =============================================================================
# When running behind cryptolabs-proxy with unified authentication,
# the proxy forwards authentication headers that we can trust.

PROXY_AUTH_HEADER_USER = 'X-Fleet-Auth-User'
PROXY_AUTH_HEADER_ROLE = 'X-Fleet-Auth-Role'
PROXY_AUTH_HEADER_TOKEN = 'X-Fleet-Auth-Token'
PROXY_AUTH_HEADER_FLAG = 'X-Fleet-Authenticated'

def is_proxy_authenticated():
    """
    Check if request came through an authenticated proxy.
    
    When running behind cryptolabs-proxy with unified auth,
    the proxy forwards authentication headers that we can trust.
    Returns True and sets up session if authenticated via proxy.
    """
    # Check if the proxy auth flag is set
    auth_flag = request.headers.get(PROXY_AUTH_HEADER_FLAG)
    if auth_flag == 'true':
        username = request.headers.get(PROXY_AUTH_HEADER_USER)
        proxy_role = request.headers.get(PROXY_AUTH_HEADER_ROLE, 'readonly')
        
        # Debug logging for proxy auth
        app.logger.debug(f"[PROXY_AUTH] Flag: {auth_flag}, User: {username}, Role: {proxy_role}")
        
        if username:
            # Valid roles: admin, readwrite, readonly
            ipmi_role = proxy_role if proxy_role in ['admin', 'readwrite', 'readonly'] else 'readonly'
            
            # Always update session with current proxy auth info
            # This ensures username, role, and auth_via are always current
            session['logged_in'] = True
            session['username'] = username
            session['user_role'] = ipmi_role
            session['auth_via'] = 'fleet_proxy'
            app.logger.info(f"[PROXY_AUTH] Authenticated: {username} (role: {ipmi_role})")
            return True
        else:
            app.logger.warning(f"[PROXY_AUTH] Flag set but username is empty/None")
    return False

def check_auth_with_proxy():
    """Check if user is authenticated (via session or proxy)."""
    # First check for proxy authentication
    if is_proxy_authenticated():
        return True
    # Then check session
    return session.get('logged_in', False)

def is_running_behind_proxy():
    """Check if we're running behind the fleet proxy."""
    return request.headers.get(PROXY_AUTH_HEADER_FLAG) == 'true'

def admin_required(f):
    """Decorator to require admin login for a route"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check proxy auth first
        if is_proxy_authenticated():
            if session.get('user_role') == 'admin':
                return f(*args, **kwargs)
        
        if not session.get('logged_in') or session.get('user_role') != 'admin':
            if is_api_request():
                return jsonify({'error': 'Admin authentication required'}), 401
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def view_required(f):
    """Decorator for read-only endpoints - allows anonymous if enabled, otherwise requires login"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check proxy auth first
        if is_proxy_authenticated():
            return f(*args, **kwargs)
        
        if session.get('logged_in'):
            return f(*args, **kwargs)
        # Check if anonymous access is allowed
        if allow_anonymous_read():
            return f(*args, **kwargs)
        if is_api_request():
            return jsonify({'error': 'Authentication required'}), 401
        return redirect(url_for('login', next=request.url))
    return decorated_function

def login_required(f):
    """Decorator to require any logged-in user (admin, readwrite, or readonly) - no anonymous"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check proxy auth first
        if is_proxy_authenticated():
            return f(*args, **kwargs)
        
        if not session.get('logged_in'):
            if is_api_request():
                return jsonify({'error': 'Authentication required'}), 401
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def write_required(f):
    """Decorator for write operations - requires admin or readwrite role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check proxy auth first
        if is_proxy_authenticated():
            role = session.get('user_role', 'readonly')
            if role in ['admin', 'readwrite']:
                return f(*args, **kwargs)
        
        if not session.get('logged_in'):
            if is_api_request():
                return jsonify({'error': 'Authentication required'}), 401
            return redirect(url_for('login', next=request.url))
        
        role = session.get('user_role', 'readonly')
        if role not in ['admin', 'readwrite']:
            if is_api_request():
                return jsonify({'error': 'Write access required. Your role: ' + role}), 403
            return render_template('login.html', error='Write access required'), 403
        return f(*args, **kwargs)
    return decorated_function

def is_admin():
    """Check if current user is admin"""
    return session.get('logged_in') and session.get('user_role') == 'admin'

def is_readwrite():
    """Check if current user has write access (admin or readwrite)"""
    return session.get('logged_in') and session.get('user_role') in ['admin', 'readwrite']

def is_logged_in():
    """Check if user is logged in (any role)"""
    return session.get('logged_in', False)

def can_view():
    """Check if current user/visitor can view data (logged in OR anonymous allowed)"""
    if session.get('logged_in'):
        return True
    return allow_anonymous_read()

def get_user_role():
    """Get current user's role or 'anonymous' if not logged in"""
    if session.get('logged_in'):
        return session.get('user_role', 'readonly')
    return 'anonymous'

def needs_password_change():
    """Check if current user needs to change default password"""
    try:
        username = session.get('username')
        if username:
            user = User.query.filter_by(username=username).first()
            if user:
                return not user.password_changed
        # First-time setup
        if not User.query.first():
            return True
        return False
    except Exception:
        return False

# NVIDIA BMCs (require 16-char password) - loaded from server config or env
# Can be set via NVIDIA_BMCS env var as comma-separated IPs, e.g.: "192.168.1.98,192.168.1.99"
NVIDIA_BMCS = set(os.environ.get('NVIDIA_BMCS', '').split(',')) if os.environ.get('NVIDIA_BMCS') else set()

# ============== Redfish Client ==============

class RedfishClient:
    """Redfish REST API client for BMC communication"""
    
    def __init__(self, host, username, password, timeout=30):
        self.host = host
        self.base_url = f"https://{host}"
        self.username = username
        self.password = password
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = False  # BMCs use self-signed certs
        self.session.auth = (username, password)
        self.session.headers.update({
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        })
        self._service_root = None
        self._managers_uri = None
        self._systems_uri = None
        self._chassis_uri = None
    
    def _get(self, uri, timeout=None):
        """Make GET request to Redfish endpoint"""
        try:
            url = f"{self.base_url}{uri}"
            resp = self.session.get(url, timeout=timeout or self.timeout)
            resp.raise_for_status()
            return resp.json()
        except requests.exceptions.RequestException as e:
            app.logger.debug(f"Redfish GET {uri} failed for {self.host}: {e}")
            return None
    
    def is_available(self):
        """Check if Redfish is available on this BMC"""
        try:
            resp = self.session.get(
                f"{self.base_url}/redfish/v1/", 
                timeout=5
            )
            return resp.status_code == 200
        except Exception:
            return False
    
    def get_service_root(self):
        """Get Redfish service root"""
        if not self._service_root:
            self._service_root = self._get("/redfish/v1/")
        return self._service_root
    
    def get_managers_uri(self):
        """Get Managers collection URI"""
        if not self._managers_uri:
            root = self.get_service_root()
            if root and 'Managers' in root:
                self._managers_uri = root['Managers'].get('@odata.id')
        return self._managers_uri
    
    def get_systems_uri(self):
        """Get Systems collection URI"""
        if not self._systems_uri:
            root = self.get_service_root()
            if root and 'Systems' in root:
                self._systems_uri = root['Systems'].get('@odata.id')
        return self._systems_uri
    
    def get_chassis_uri(self):
        """Get Chassis collection URI"""
        if not self._chassis_uri:
            root = self.get_service_root()
            if root and 'Chassis' in root:
                self._chassis_uri = root['Chassis'].get('@odata.id')
        return self._chassis_uri
    
    def get_power_status(self):
        """Get server power state via Redfish"""
        try:
            systems_uri = self.get_systems_uri()
            if not systems_uri:
                return None
            
            systems = self._get(systems_uri)
            if not systems or 'Members' not in systems or not systems['Members']:
                return None
            
            # Get first system
            system_uri = systems['Members'][0].get('@odata.id')
            system = self._get(system_uri)
            
            if system and 'PowerState' in system:
                state = system['PowerState']
                return f"Chassis Power is {'on' if state == 'On' else 'off'}"
            return None
        except Exception as e:
            app.logger.debug(f"Redfish power status failed for {self.host}: {e}")
            return None
    
    def get_sel_entries(self):
        """Get System Event Log entries via Redfish - checks multiple paths for vendor compatibility"""
        events = []
        try:
            # Try multiple LogServices paths (vendor-specific)
            log_services_paths = []
            
            # Path 1: Under Managers (Dell, HPE, Supermicro)
            managers_uri = self.get_managers_uri()
            if managers_uri:
                managers = self._get(managers_uri)
                if managers and 'Members' in managers and managers['Members']:
                    manager_uri = managers['Members'][0].get('@odata.id')
                    manager = self._get(manager_uri)
                    if manager and 'LogServices' in manager:
                        log_services_paths.append(manager['LogServices'].get('@odata.id'))
            
            # Path 2: Under Systems (Lenovo, some others)
            systems_uri = self.get_systems_uri()
            if systems_uri:
                systems = self._get(systems_uri)
                if systems and 'Members' in systems and systems['Members']:
                    system_uri = systems['Members'][0].get('@odata.id')
                    system = self._get(system_uri)
                    if system and 'LogServices' in system:
                        log_services_paths.append(system['LogServices'].get('@odata.id'))
            
            # Try each LogServices path
            for log_services_uri in log_services_paths:
                if not log_services_uri:
                    continue
                    
                log_services = self._get(log_services_uri)
                if not log_services or 'Members' not in log_services:
                    continue
                
                # Look for SEL or PlatformLog service
                for member in log_services['Members']:
                    log_uri = member.get('@odata.id', '')
                    log_name = log_uri.upper()
                    if 'SEL' in log_name or 'PLATFORMLOG' in log_name:
                        log_service = self._get(log_uri)
                        if log_service and 'Entries' in log_service:
                            entries_uri = log_service['Entries'].get('@odata.id')
                            entries_resp = self._get(entries_uri, timeout=120)
                            if entries_resp and 'Members' in entries_resp:
                                for entry in entries_resp['Members']:
                                    event = self._parse_log_entry(entry)
                                    if event:
                                        events.append(event)
                                if events:
                                    return events  # Found events, return
            
            return events
        except Exception as e:
            app.logger.error(f"Redfish SEL collection failed for {self.host}: {e}")
            return events
    
    def _parse_log_entry(self, entry):
        """Parse Redfish log entry into our event format"""
        try:
            event_id = entry.get('Id', entry.get('EntryCode', ''))
            message = entry.get('Message', entry.get('MessageId', ''))
            created = entry.get('Created', entry.get('EventTimestamp', ''))
            severity = entry.get('Severity', 'OK')
            sensor_type = entry.get('SensorType', entry.get('EntryType', 'System'))
            
            # Ensure sensor_type is a string (some Redfish implementations return lists)
            if isinstance(sensor_type, list):
                sensor_type = json.dumps(sensor_type) if sensor_type else 'Unknown'
            elif not isinstance(sensor_type, str):
                sensor_type = str(sensor_type) if sensor_type else 'Unknown'
            
            # Parse timestamp
            if created:
                try:
                    # Handle various Redfish date formats
                    if 'T' in created:
                        created = created.replace('Z', '+00:00')
                        if '.' in created:
                            event_date = datetime.fromisoformat(created.split('.')[0])
                        else:
                            event_date = datetime.fromisoformat(created.split('+')[0])
                    else:
                        event_date = datetime.utcnow()
                except Exception:
                    event_date = datetime.utcnow()
            else:
                event_date = datetime.utcnow()
            
            # Map severity
            severity_map = {
                'Critical': 'critical',
                'Warning': 'warning',
                'OK': 'info',
                'Informational': 'info'
            }
            mapped_severity = severity_map.get(severity, 'info')
            
            return {
                'sel_id': str(event_id),
                'event_date': event_date,
                'sensor_type': sensor_type,
                'event_description': message,
                'severity': mapped_severity,
                'raw_entry': json.dumps(entry)
            }
        except Exception as e:
            app.logger.debug(f"Failed to parse Redfish log entry: {e}")
            return None
    
    def get_thermal(self):
        """Get thermal (temperature/fan) readings via Redfish"""
        sensors = []
        try:
            chassis_uri = self.get_chassis_uri()
            if not chassis_uri:
                return sensors
            
            chassis_coll = self._get(chassis_uri)
            if not chassis_coll or 'Members' not in chassis_coll or not chassis_coll['Members']:
                return sensors
            
            # Get first chassis
            chassis_member_uri = chassis_coll['Members'][0].get('@odata.id')
            chassis = self._get(chassis_member_uri)
            
            if not chassis or 'Thermal' not in chassis:
                # Try direct path
                thermal = self._get(f"{chassis_member_uri}/Thermal")
            else:
                thermal_uri = chassis['Thermal'].get('@odata.id')
                thermal = self._get(thermal_uri)
            
            if not thermal:
                return sensors
            
            # Parse temperatures
            for temp in thermal.get('Temperatures', []):
                if temp.get('ReadingCelsius') is not None:
                    sensors.append({
                        'sensor_name': temp.get('Name', temp.get('MemberId', 'Unknown')),
                        'sensor_type': 'temperature',
                        'value': temp.get('ReadingCelsius'),
                        'unit': 'degrees C',
                        'status': temp.get('Status', {}).get('Health', 'OK'),
                        'upper_critical': temp.get('UpperThresholdCritical'),
                        'upper_warning': temp.get('UpperThresholdNonCritical'),
                        'lower_warning': temp.get('LowerThresholdNonCritical'),
                        'lower_critical': temp.get('LowerThresholdCritical')
                    })
            
            # Parse fans
            for fan in thermal.get('Fans', []):
                reading = fan.get('Reading') or fan.get('ReadingRPM')
                if reading is not None:
                    sensors.append({
                        'sensor_name': fan.get('Name', fan.get('MemberId', 'Unknown')),
                        'sensor_type': 'fan',
                        'value': reading,
                        'unit': fan.get('ReadingUnits', 'RPM'),
                        'status': fan.get('Status', {}).get('Health', 'OK'),
                        'lower_critical': fan.get('LowerThresholdCritical')
                    })
            
            return sensors
        except Exception as e:
            app.logger.debug(f"Redfish thermal failed for {self.host}: {e}")
            return sensors
    
    def get_power(self):
        """Get power readings via Redfish"""
        power_data = {
            'current_watts': None,
            'min_watts': None,
            'max_watts': None,
            'avg_watts': None
        }
        voltages = []
        
        try:
            chassis_uri = self.get_chassis_uri()
            if not chassis_uri:
                return power_data, voltages
            
            chassis_coll = self._get(chassis_uri)
            if not chassis_coll or 'Members' not in chassis_coll or not chassis_coll['Members']:
                return power_data, voltages
            
            chassis_member_uri = chassis_coll['Members'][0].get('@odata.id')
            chassis = self._get(chassis_member_uri)
            
            if not chassis or 'Power' not in chassis:
                power = self._get(f"{chassis_member_uri}/Power")
            else:
                power_uri = chassis['Power'].get('@odata.id')
                power = self._get(power_uri)
            
            if not power:
                return power_data, voltages
            
            # Parse power consumption
            for ctrl in power.get('PowerControl', []):
                if ctrl.get('PowerConsumedWatts') is not None:
                    power_data['current_watts'] = ctrl.get('PowerConsumedWatts')
                metrics = ctrl.get('PowerMetrics', {})
                if metrics:
                    power_data['min_watts'] = metrics.get('MinConsumedWatts')
                    power_data['max_watts'] = metrics.get('MaxConsumedWatts')
                    power_data['avg_watts'] = metrics.get('AverageConsumedWatts')
                break
            
            # Parse voltages
            for volt in power.get('Voltages', []):
                if volt.get('ReadingVolts') is not None:
                    voltages.append({
                        'sensor_name': volt.get('Name', volt.get('MemberId', 'Unknown')),
                        'sensor_type': 'voltage',
                        'value': volt.get('ReadingVolts'),
                        'unit': 'Volts',
                        'status': volt.get('Status', {}).get('Health', 'OK'),
                        'upper_critical': volt.get('UpperThresholdCritical'),
                        'upper_warning': volt.get('UpperThresholdNonCritical'),
                        'lower_warning': volt.get('LowerThresholdNonCritical'),
                        'lower_critical': volt.get('LowerThresholdCritical')
                    })
            
            return power_data, voltages
        except Exception as e:
            app.logger.debug(f"Redfish power failed for {self.host}: {e}")
            return power_data, voltages
    
    def clear_sel(self):
        """Clear SEL via Redfish"""
        try:
            managers_uri = self.get_managers_uri()
            if not managers_uri:
                return False
            
            managers = self._get(managers_uri)
            if not managers or 'Members' not in managers:
                return False
            
            manager_uri = managers['Members'][0].get('@odata.id')
            manager = self._get(manager_uri)
            
            if not manager or 'LogServices' not in manager:
                return False
            
            log_services_uri = manager['LogServices'].get('@odata.id')
            log_services = self._get(log_services_uri)
            
            for member in log_services.get('Members', []):
                log_uri = member.get('@odata.id', '')
                if 'SEL' in log_uri.upper() or 'LOG' in log_uri.upper():
                    log_service = self._get(log_uri)
                    if log_service:
                        # Try ClearLog action
                        actions = log_service.get('Actions', {})
                        clear_action = actions.get('#LogService.ClearLog', {})
                        clear_target = clear_action.get('target')
                        
                        if clear_target:
                            resp = self.session.post(
                                f"{self.base_url}{clear_target}",
                                json={},
                                timeout=30
                            )
                            return resp.status_code in [200, 202, 204]
                    break
            
            return False
        except Exception as e:
            app.logger.error(f"Redfish clear SEL failed for {self.host}: {e}")
            return False
    
    def get_system_info(self):
        """Get system info (Manufacturer, Model, BIOS) directly from /redfish/v1/Systems/1"""
        try:
            systems_uri = self.get_systems_uri()
            if not systems_uri:
                return None
            
            systems = self._get(systems_uri)
            if not systems or 'Members' not in systems or not systems['Members']:
                return None
            
            system_uri = systems['Members'][0].get('@odata.id')
            system = self._get(system_uri)
            
            if system:
                return {
                    'Manufacturer': system.get('Manufacturer'),
                    'Model': system.get('Model'),
                    'SerialNumber': system.get('SerialNumber'),
                    'SKU': system.get('SKU'),
                    'BiosVersion': system.get('BiosVersion'),
                    'MemorySummary': system.get('MemorySummary', {}),
                    'ProcessorSummary': system.get('ProcessorSummary', {}),
                }
            return None
        except Exception as e:
            app.logger.debug(f"Redfish system info failed for {self.host}: {e}")
            return None
    
    def get_bmc_info(self):
        """Get BMC/Manager info (firmware version, MAC) via Redfish"""
        try:
            managers_uri = self.get_managers_uri()
            if not managers_uri:
                return None
            
            managers = self._get(managers_uri)
            if not managers or 'Members' not in managers or not managers['Members']:
                return None
            
            manager_uri = managers['Members'][0].get('@odata.id')
            manager = self._get(manager_uri)
            
            if manager:
                # Try to get MAC from EthernetInterfaces
                mac = None
                eth_uri = manager.get('EthernetInterfaces', {}).get('@odata.id')
                if eth_uri:
                    eth_list = self._get(eth_uri)
                    if eth_list and 'Members' in eth_list and eth_list['Members']:
                        eth_member = self._get(eth_list['Members'][0].get('@odata.id'))
                        if eth_member:
                            mac = eth_member.get('MACAddress') or eth_member.get('PermanentMACAddress')
                
                return {
                    'FirmwareVersion': manager.get('FirmwareVersion'),
                    'Model': manager.get('Model'),
                    'MAC': mac,
                }
            return None
        except Exception as e:
            app.logger.debug(f"Redfish BMC info failed for {self.host}: {e}")
            return None
    
    def get_processors(self):
        """Get processor (CPU) information via Redfish"""
        processors = []
        try:
            systems_uri = self.get_systems_uri()
            if not systems_uri:
                return processors
            
            systems = self._get(systems_uri)
            if not systems or 'Members' not in systems or not systems['Members']:
                return processors
            
            system_uri = systems['Members'][0].get('@odata.id')
            system = self._get(system_uri)
            
            if not system:
                return processors
            
            # Try direct access to first processor (faster)
            first_proc = self._get(f"{system_uri}/Processors/1")
            if first_proc and first_proc.get('Model'):
                processors.append({
                    'Id': first_proc.get('Id', '1'),
                    'Model': first_proc.get('Model', ''),
                    'Manufacturer': first_proc.get('Manufacturer', ''),
                    'TotalCores': first_proc.get('TotalCores'),
                    'TotalThreads': first_proc.get('TotalThreads'),
                    'MaxSpeedMHz': first_proc.get('MaxSpeedMHz'),
                    'ProcessorType': first_proc.get('ProcessorType'),
                    'Status': first_proc.get('Status', {}).get('Health', 'OK')
                })
                # Check for second processor
                second_proc = self._get(f"{system_uri}/Processors/2")
                if second_proc and second_proc.get('Model'):
                    processors.append({
                        'Id': second_proc.get('Id', '2'),
                        'Model': second_proc.get('Model', ''),
                        'Manufacturer': second_proc.get('Manufacturer', ''),
                        'TotalCores': second_proc.get('TotalCores'),
                        'TotalThreads': second_proc.get('TotalThreads'),
                        'MaxSpeedMHz': second_proc.get('MaxSpeedMHz'),
                        'ProcessorType': second_proc.get('ProcessorType'),
                        'Status': second_proc.get('Status', {}).get('Health', 'OK')
                    })
                return processors
            
            # Fallback: Get Processors collection
            if 'Processors' in system:
                proc_uri = system['Processors'].get('@odata.id')
                proc_coll = self._get(proc_uri)
                
                if proc_coll and 'Members' in proc_coll:
                    for member in proc_coll['Members']:
                        proc = self._get(member.get('@odata.id'))
                        if proc:
                            processors.append({
                                'Id': proc.get('Id'),
                                'Model': proc.get('Model', ''),
                                'Manufacturer': proc.get('Manufacturer', ''),
                                'TotalCores': proc.get('TotalCores'),
                                'TotalThreads': proc.get('TotalThreads'),
                                'MaxSpeedMHz': proc.get('MaxSpeedMHz'),
                                'ProcessorType': proc.get('ProcessorType'),
                                'Status': proc.get('Status', {}).get('Health', 'OK')
                            })
            
            return processors
        except Exception as e:
            app.logger.debug(f"Redfish processors failed for {self.host}: {e}")
            return processors
    
    def get_memory(self):
        """Get memory (DIMM) information via Redfish - Enhanced for multi-vendor support"""
        memory = []
        try:
            systems_uri = self.get_systems_uri()
            if not systems_uri:
                return memory
            
            systems = self._get(systems_uri)
            if not systems or 'Members' not in systems or not systems['Members']:
                return memory
            
            system_uri = systems['Members'][0].get('@odata.id')
            system = self._get(system_uri)
            
            if not system:
                return memory
            
            # Also collect MemorySummary from system for totals
            memory_summary = system.get('MemorySummary', {})
            
            # Get Memory collection
            if 'Memory' in system:
                mem_uri = system['Memory'].get('@odata.id')
                mem_coll = self._get(mem_uri)
                
                if mem_coll and 'Members' in mem_coll:
                    for member in mem_coll['Members']:
                        dimm = self._get(member.get('@odata.id'))
                        if dimm and dimm.get('CapacityMiB', 0) > 0:  # Skip empty slots
                            # Extract status details - varies by vendor
                            status = dimm.get('Status', {})
                            health = status.get('Health', status.get('State', 'OK'))
                            
                            # Comprehensive DIMM info for all manufacturers
                            dimm_info = {
                                # Basic identification
                                'Id': dimm.get('Id'),
                                'Name': dimm.get('Name', ''),
                                'DeviceLocator': dimm.get('DeviceLocator', ''),  # Physical slot: "DIMM_A1"
                                'SocketLocator': dimm.get('SocketLocator', ''),  # Dell, Supermicro
                                'BankLocator': dimm.get('BankLocator', ''),      # Bank grouping
                                
                                # Capacity and configuration
                                'CapacityMiB': dimm.get('CapacityMiB', 0),
                                'DataWidthBits': dimm.get('DataWidthBits'),      # 64-bit typically
                                'BusWidthBits': dimm.get('BusWidthBits'),        # 72 for ECC
                                'RankCount': dimm.get('RankCount'),              # 1, 2, 4, 8 rank
                                
                                # Speed and timing
                                'OperatingSpeedMhz': dimm.get('OperatingSpeedMhz'),
                                'AllowedSpeedsMHz': dimm.get('AllowedSpeedsMHz', []),  # HPE specific
                                'ConfiguredSpeedMhz': dimm.get('ConfiguredSpeedMhz'),  # Lenovo, Dell
                                
                                # Memory type details
                                'MemoryType': dimm.get('MemoryDeviceType', dimm.get('MemoryType', '')),
                                'MemoryMedia': dimm.get('MemoryMedia', []),      # DRAM, Intel Optane, etc.
                                'BaseModuleType': dimm.get('BaseModuleType', ''), # RDIMM, LRDIMM, UDIMM
                                
                                # Manufacturer info
                                'Manufacturer': dimm.get('Manufacturer', ''),
                                'PartNumber': dimm.get('PartNumber', '').strip(),
                                'SerialNumber': dimm.get('SerialNumber', '').strip(),
                                'ModuleManufacturerID': dimm.get('ModuleManufacturerID', {}),  # JEDEC
                                'ModuleProductID': dimm.get('ModuleProductID', {}),
                                
                                # ECC and error info
                                'ErrorCorrection': dimm.get('ErrorCorrection', ''),  # NoECC, SingleBitECC, MultiBitECC
                                'VolatileRegionSizeLimitMiB': dimm.get('VolatileRegionSizeLimitMiB'),
                                
                                # Voltage (Intel, Supermicro)
                                'OperatingMemoryModes': dimm.get('OperatingMemoryModes', []),
                                'VoltageVolt': dimm.get('VoltageVolt'),
                                
                                # Status and health
                                'Status': health,
                                'State': status.get('State', 'Enabled'),
                                
                                # Vendor-specific OEM data
                                'Oem': self._extract_oem_memory(dimm.get('Oem', {})),
                            }
                            
                            # Clean up None values to save space
                            dimm_info = {k: v for k, v in dimm_info.items() if v is not None and v != '' and v != []}
                            memory.append(dimm_info)
            
            return memory
        except Exception as e:
            app.logger.debug(f"Redfish memory failed for {self.host}: {e}")
            return memory
    
    def _extract_oem_memory(self, oem_data):
        """Extract useful OEM-specific memory data from various manufacturers"""
        if not oem_data:
            return None
        
        extracted = {}
        
        # Dell iDRAC
        if 'Dell' in oem_data:
            dell = oem_data.get('Dell', {}).get('DellMemory', {})
            if dell:
                extracted['DellMemoryType'] = dell.get('MemoryType')
                extracted['DellRemainingRatedWriteEndurance'] = dell.get('RemainingRatedWriteEndurance')
                extracted['DellLastSystemInventoryTime'] = dell.get('LastSystemInventoryTime')
        
        # HPE iLO
        if 'Hpe' in oem_data:
            hpe = oem_data.get('Hpe', {})
            if hpe:
                extracted['HpeDIMMStatus'] = hpe.get('DIMMStatus')
                extracted['HpeMinimumVoltageVoltsX10'] = hpe.get('MinimumVoltageVoltsX10')
                extracted['HpePredictedMediaLifeLeftPercent'] = hpe.get('PredictedMediaLifeLeftPercent')
        
        # Lenovo XCC
        if 'Lenovo' in oem_data:
            lenovo = oem_data.get('Lenovo', {})
            if lenovo:
                extracted['LenovoMemoryType'] = lenovo.get('MemoryType')
                extracted['LenovoThrottled'] = lenovo.get('Throttled')
        
        # Supermicro
        if 'Supermicro' in oem_data:
            sm = oem_data.get('Supermicro', {})
            if sm:
                extracted['SMCMemoryHealth'] = sm.get('Health')
        
        return extracted if extracted else None
    
    def get_storage(self):
        """Get storage (drives) information via Redfish"""
        drives = []
        try:
            systems_uri = self.get_systems_uri()
            if not systems_uri:
                return drives
            
            systems = self._get(systems_uri)
            if not systems or 'Members' not in systems or not systems['Members']:
                return drives
            
            system_uri = systems['Members'][0].get('@odata.id')
            system = self._get(system_uri)
            
            if not system:
                return drives
            
            # Get Storage collection
            if 'Storage' in system:
                storage_uri = system['Storage'].get('@odata.id')
                storage_coll = self._get(storage_uri)
                
                if storage_coll and 'Members' in storage_coll:
                    for member in storage_coll['Members']:
                        controller = self._get(member.get('@odata.id'))
                        if controller and 'Drives' in controller:
                            # Get drives from this controller
                            for drive_ref in controller.get('Drives', []):
                                drive = self._get(drive_ref.get('@odata.id'))
                                if drive:
                                    drives.append({
                                        'Id': drive.get('Id'),
                                        'Name': drive.get('Name', ''),
                                        'Model': drive.get('Model', ''),
                                        'Manufacturer': drive.get('Manufacturer', ''),
                                        'SerialNumber': drive.get('SerialNumber', ''),
                                        'CapacityBytes': drive.get('CapacityBytes'),
                                        'MediaType': drive.get('MediaType', ''),  # HDD, SSD, etc.
                                        'Protocol': drive.get('Protocol', ''),  # SATA, SAS, NVMe
                                        'Status': drive.get('Status', {}).get('Health', 'OK')
                                    })
            
            # Also try SimpleStorage (older Redfish)
            if 'SimpleStorage' in system and not drives:
                simple_uri = system['SimpleStorage'].get('@odata.id')
                simple_coll = self._get(simple_uri)
                
                if simple_coll and 'Members' in simple_coll:
                    for member in simple_coll['Members']:
                        controller = self._get(member.get('@odata.id'))
                        if controller and 'Devices' in controller:
                            for device in controller.get('Devices', []):
                                drives.append({
                                    'Name': device.get('Name', ''),
                                    'Model': device.get('Model', ''),
                                    'Manufacturer': device.get('Manufacturer', ''),
                                    'CapacityBytes': device.get('CapacityBytes'),
                                    'Status': device.get('Status', {}).get('Health', 'OK')
                                })
            
            return drives
        except Exception as e:
            app.logger.debug(f"Redfish storage failed for {self.host}: {e}")
            return drives
    
    def get_gpus(self):
        """Get GPU/accelerator information via Redfish
        
        Works with:
        - NVIDIA DGX systems (GPUs as Chassis members or Processors)
        - Standard Redfish ProcessorType=GPU
        - PCIe device enumeration
        """
        gpus = []
        try:
            # Method 1: Check Processors for GPU type (some systems list GPUs here)
            systems_uri = self.get_systems_uri()
            if systems_uri:
                systems = self._get(systems_uri)
                if systems and 'Members' in systems and systems['Members']:
                    system_uri = systems['Members'][0].get('@odata.id')
                    system = self._get(system_uri)
                    
                    if system and 'Processors' in system:
                        proc_uri = system['Processors'].get('@odata.id')
                        proc_coll = self._get(proc_uri)
                        
                        if proc_coll and 'Members' in proc_coll:
                            for member in proc_coll['Members']:
                                proc = self._get(member.get('@odata.id'))
                                if proc:
                                    proc_type = proc.get('ProcessorType', '')
                                    # GPU, Accelerator, or contains GPU/NVIDIA in model
                                    model = proc.get('Model', '')
                                    if proc_type in ('GPU', 'Accelerator') or 'GPU' in model.upper() or 'NVIDIA' in model.upper():
                                        gpus.append({
                                            'name': proc.get('Model', proc.get('Name', 'Unknown GPU')),
                                            'manufacturer': proc.get('Manufacturer', 'NVIDIA'),
                                            'id': proc.get('Id', ''),
                                            'socket': proc.get('Socket', ''),
                                            'status': proc.get('Status', {}).get('Health', 'OK'),
                                            'state': proc.get('Status', {}).get('State', 'Enabled'),
                                        })
            
            # Method 2: DGX-specific - Check Chassis for GPU members (GPU0-GPU7)
            if not gpus:
                chassis_resp = self._get('/redfish/v1/Chassis')
                if chassis_resp and 'Members' in chassis_resp:
                    for member in chassis_resp['Members']:
                        member_id = member.get('@odata.id', '')
                        # Look for GPU chassis members (DGX exposes GPUs this way)
                        if '/GPU' in member_id or 'gpu' in member_id.lower():
                            gpu_chassis = self._get(member_id)
                            if gpu_chassis:
                                gpus.append({
                                    'name': gpu_chassis.get('Model', gpu_chassis.get('Name', 'GPU')),
                                    'manufacturer': gpu_chassis.get('Manufacturer', 'NVIDIA'),
                                    'id': gpu_chassis.get('Id', ''),
                                    'serial': gpu_chassis.get('SerialNumber', ''),
                                    'part_number': gpu_chassis.get('PartNumber', ''),
                                    'status': gpu_chassis.get('Status', {}).get('Health', 'OK'),
                                    'state': gpu_chassis.get('Status', {}).get('State', 'Enabled'),
                                })
            
            # Method 3: PCIeDevices under System - look for NVIDIA/GPU devices
            if not gpus and systems_uri:
                systems = self._get(systems_uri)
                if systems and 'Members' in systems and systems['Members']:
                    system_uri = systems['Members'][0].get('@odata.id')
                    system = self._get(system_uri)
                    
                    if system and 'PCIeDevices' in system:
                        pcie_uri = system['PCIeDevices'].get('@odata.id') if isinstance(system['PCIeDevices'], dict) else None
                        if pcie_uri:
                            pcie_coll = self._get(pcie_uri)
                            if pcie_coll and 'Members' in pcie_coll:
                                for member in pcie_coll['Members']:
                                    device = self._get(member.get('@odata.id'))
                                    if device:
                                        dev_type = device.get('DeviceType', '')
                                        manufacturer = device.get('Manufacturer', '').upper()
                                        name = device.get('Name', '').upper()
                                        
                                        if 'GPU' in dev_type or 'NVIDIA' in manufacturer or 'GPU' in name or 'H100' in name or 'A100' in name:
                                            gpus.append({
                                                'name': device.get('Name', 'GPU'),
                                                'manufacturer': device.get('Manufacturer', 'NVIDIA'),
                                                'id': device.get('Id', ''),
                                                'serial': device.get('SerialNumber', ''),
                                                'part_number': device.get('PartNumber', ''),
                                                'firmware': device.get('FirmwareVersion', ''),
                                                'pci_slot': device.get('Slot', {}).get('Location', {}).get('PartLocation', {}).get('ServiceLabel', ''),
                                                'status': device.get('Status', {}).get('Health', 'OK'),
                                            })
            
            # Method 4: PCIeDevices under Chassis (Lenovo, Dell, HPE)
            if not gpus:
                chassis_resp = self._get('/redfish/v1/Chassis')
                if chassis_resp and 'Members' in chassis_resp:
                    for chassis_member in chassis_resp['Members']:
                        chassis_uri = chassis_member.get('@odata.id', '')
                        # Try PCIeDevices under each chassis
                        pcie_uri = f"{chassis_uri}/PCIeDevices"
                        pcie_coll = self._get(pcie_uri)
                        if pcie_coll and 'Members' in pcie_coll:
                            for member in pcie_coll['Members']:
                                device = self._get(member.get('@odata.id'))
                                if device:
                                    name = (device.get('Name', '') or device.get('Model', '')).upper()
                                    if 'GPU' in name or 'NVIDIA' in name or 'H100' in name or 'A100' in name or 'A10' in name:
                                        gpus.append({
                                            'name': device.get('Name', device.get('Model', 'GPU')),
                                            'manufacturer': device.get('Manufacturer', 'NVIDIA'),
                                            'model': device.get('Model', ''),
                                            'id': device.get('Id', ''),
                                            'serial': device.get('SerialNumber', ''),
                                            'part_number': device.get('PartNumber', device.get('SKU', '')),
                                            'firmware': device.get('FirmwareVersion', ''),
                                            'pci_slot': device.get('Slot', {}).get('Location', {}).get('PartLocation', {}).get('ServiceLabel', ''),
                                            'status': device.get('Status', {}).get('Health', 'OK'),
                                        })
            
            if gpus:
                app.logger.info(f"Redfish GPUs for {self.host}: {len(gpus)} found")
            
            return gpus
        except Exception as e:
            app.logger.debug(f"Redfish GPU collection failed for {self.host}: {e}")
            return gpus
    
    def get_pcie_devices(self):
        """Get all PCIe devices (NICs, storage controllers, GPUs, etc.)"""
        devices = []
        try:
            # Method 1: PCIeDevices as list of URIs under System (Lenovo, some HPE)
            systems_uri = self.get_systems_uri()
            if systems_uri:
                systems = self._get(systems_uri)
                if systems and 'Members' in systems and systems['Members']:
                    system_uri = systems['Members'][0].get('@odata.id')
                    system = self._get(system_uri)
                    if system and 'PCIeDevices' in system:
                        pcie_refs = system['PCIeDevices']
                        # Lenovo: PCIeDevices is a list of device URIs directly
                        if isinstance(pcie_refs, list):
                            for ref in pcie_refs:
                                device = self._get(ref.get('@odata.id'))
                                if device and device.get('Name'):
                                    devices.append(self._parse_pcie_device(device))
                        # Other vendors: PCIeDevices has @odata.id to collection
                        elif isinstance(pcie_refs, dict) and '@odata.id' in pcie_refs:
                            pcie_coll = self._get(pcie_refs['@odata.id'])
                            if pcie_coll and 'Members' in pcie_coll:
                                for member in pcie_coll['Members']:
                                    device = self._get(member.get('@odata.id'))
                                    if device and device.get('Name'):
                                        devices.append(self._parse_pcie_device(device))
            
            # Method 2: Try Chassis PCIeDevices (some vendors)
            if not devices:
                chassis_resp = self._get('/redfish/v1/Chassis')
                if chassis_resp and 'Members' in chassis_resp:
                    for chassis in chassis_resp['Members']:
                        pcie_uri = f"{chassis['@odata.id']}/PCIeDevices"
                        pcie_coll = self._get(pcie_uri)
                        if pcie_coll and 'Members' in pcie_coll:
                            for member in pcie_coll['Members']:
                                device = self._get(member.get('@odata.id'))
                                if device and device.get('Name'):
                                    devices.append(self._parse_pcie_device(device))
            
            if devices:
                app.logger.info(f"Redfish PCIe for {self.host}: {len(devices)} devices")
            return devices
        except Exception as e:
            app.logger.debug(f"Redfish PCIe collection failed for {self.host}: {e}")
            return devices
    
    def _parse_pcie_device(self, device):
        """Parse a PCIe device response into a standardized dict"""
        slot_info = device.get('Slot', {}).get('Location', {}).get('Info', '')
        pcie_iface = device.get('PCIeInterface', {})
        return {
            'Id': device.get('Id', ''),
            'Name': device.get('Name', ''),
            'DeviceType': device.get('DeviceType', ''),
            'Manufacturer': device.get('Manufacturer', ''),
            'Model': device.get('Model', ''),
            'SerialNumber': device.get('SerialNumber', ''),
            'PartNumber': device.get('PartNumber', ''),
            'FirmwareVersion': device.get('FirmwareVersion', ''),
            'SlotInfo': slot_info,
            'PCIeType': pcie_iface.get('PCIeType', ''),
            'Lanes': pcie_iface.get('LanesInUse', ''),
            'Status': device.get('Status', {}).get('Health', 'OK'),
        }
    
    def get_network_interfaces(self):
        """Get system network interfaces (NICs)"""
        nics = []
        try:
            systems_uri = self.get_systems_uri()
            if systems_uri:
                systems = self._get(systems_uri)
                if systems and 'Members' in systems and systems['Members']:
                    system_uri = systems['Members'][0].get('@odata.id')
                    system = self._get(system_uri)
                    if system and 'EthernetInterfaces' in system:
                        eth_uri = system['EthernetInterfaces'].get('@odata.id')
                        eth_coll = self._get(eth_uri)
                        if eth_coll and 'Members' in eth_coll:
                            for member in eth_coll['Members']:
                                nic = self._get(member.get('@odata.id'))
                                if nic:
                                    nics.append({
                                        'Id': nic.get('Id', ''),
                                        'Name': nic.get('Name', ''),
                                        'MACAddress': nic.get('MACAddress', ''),
                                        'SpeedMbps': nic.get('SpeedMbps'),
                                        'LinkStatus': nic.get('LinkStatus', ''),
                                        'IPv4': [a.get('Address') for a in nic.get('IPv4Addresses', []) if a.get('Address')],
                                        'Status': nic.get('Status', {}).get('Health', 'OK'),
                                    })
            return nics
        except Exception as e:
            app.logger.debug(f"Redfish NIC collection failed for {self.host}: {e}")
            return nics


def check_redfish_available(bmc_ip):
    """Quick check if BMC supports Redfish"""
    try:
        resp = requests.get(
            f"https://{bmc_ip}/redfish/v1/",
            verify=False,
            timeout=5
        )
        return resp.status_code == 200
    except Exception:
        return False


# Redfish availability cache
_redfish_cache = {}
_redfish_cache_lock = threading.Lock()

# Prometheus Metrics
PROM_REGISTRY = CollectorRegistry()

# Server metrics
prom_server_reachable = Gauge(
    'ipmi_server_reachable', 
    'Whether the BMC is reachable (1=yes, 0=no)',
    ['bmc_ip', 'server_name'],
    registry=PROM_REGISTRY
)
prom_server_power_on = Gauge(
    'ipmi_server_power_on',
    'Whether the server power is on (1=yes, 0=no)',
    ['bmc_ip', 'server_name'],
    registry=PROM_REGISTRY
)

# Event metrics
prom_events_total = Gauge(
    'ipmi_events_total',
    'Total number of IPMI events collected',
    ['bmc_ip', 'server_name'],
    registry=PROM_REGISTRY
)
prom_events_critical_24h = Gauge(
    'ipmi_events_critical_24h',
    'Number of critical events in last 24 hours',
    ['bmc_ip', 'server_name'],
    registry=PROM_REGISTRY
)
prom_events_warning_24h = Gauge(
    'ipmi_events_warning_24h',
    'Number of warning events in last 24 hours',
    ['bmc_ip', 'server_name'],
    registry=PROM_REGISTRY
)

# Aggregate metrics
prom_total_servers = Gauge(
    'ipmi_total_servers',
    'Total number of monitored servers',
    registry=PROM_REGISTRY
)
prom_reachable_servers = Gauge(
    'ipmi_reachable_servers',
    'Number of reachable servers',
    registry=PROM_REGISTRY
)
prom_total_critical_24h = Gauge(
    'ipmi_total_critical_events_24h',
    'Total critical events across all servers in 24h',
    registry=PROM_REGISTRY
)
prom_total_warning_24h = Gauge(
    'ipmi_total_warning_events_24h',
    'Total warning events across all servers in 24h',
    registry=PROM_REGISTRY
)
prom_collection_timestamp = Gauge(
    'ipmi_last_collection_timestamp',
    'Unix timestamp of last successful collection',
    registry=PROM_REGISTRY
)

# Alert metrics
prom_alerts_total = Gauge(
    'ipmi_alerts_total',
    'Total number of fired alerts',
    registry=PROM_REGISTRY
)
prom_alerts_unacknowledged = Gauge(
    'ipmi_alerts_unacknowledged',
    'Number of unacknowledged alerts',
    registry=PROM_REGISTRY
)
prom_alerts_critical_24h = Gauge(
    'ipmi_alerts_critical_24h',
    'Critical alerts in last 24 hours',
    registry=PROM_REGISTRY
)
prom_alerts_warning_24h = Gauge(
    'ipmi_alerts_warning_24h',
    'Warning alerts in last 24 hours',
    registry=PROM_REGISTRY
)

# Sensor metrics
prom_temperature = Gauge(
    'ipmi_temperature_celsius',
    'Temperature sensor reading in Celsius',
    ['bmc_ip', 'server_name', 'sensor_name'],
    registry=PROM_REGISTRY
)
prom_fan_speed = Gauge(
    'ipmi_fan_speed_rpm',
    'Fan speed in RPM',
    ['bmc_ip', 'server_name', 'sensor_name'],
    registry=PROM_REGISTRY
)
prom_voltage = Gauge(
    'ipmi_voltage_volts',
    'Voltage sensor reading in Volts',
    ['bmc_ip', 'server_name', 'sensor_name'],
    registry=PROM_REGISTRY
)
prom_power_watts = Gauge(
    'ipmi_power_watts',
    'Power consumption in Watts',
    ['bmc_ip', 'server_name'],
    registry=PROM_REGISTRY
)

# Default server inventory - empty by default, add servers via UI or INI import
# Example format: {'192.168.1.100': 'server-01', '192.168.1.101': 'server-02'}
DEFAULT_SERVERS = {}

def get_servers(include_deprecated=False):
    """Get servers from database, fallback to defaults
    
    Args:
        include_deprecated: If True, include deprecated servers (for reports/history)
    """
    with app.app_context():
        try:
            if include_deprecated:
                # Get all servers except explicitly disabled
                servers = Server.query.filter_by(enabled=True).all()
            else:
                # Only active servers (not deprecated, not in maintenance)
                servers = Server.query.filter(
                    Server.enabled == True,
                    db.or_(Server.status == 'active', Server.status.is_(None))  # None for backwards compat
                ).all()
            if servers:
                return {s.bmc_ip: s.server_name for s in servers}
        except Exception as e:
            app.logger.warning(f"Failed to get servers from database, using defaults: {e}")
    return DEFAULT_SERVERS

# Legacy compatibility - will be replaced by get_servers() calls
SERVERS = DEFAULT_SERVERS

# Database Models
class Server(db.Model):
    """Server inventory - managed dynamically"""
    id = db.Column(db.Integer, primary_key=True)
    bmc_ip = db.Column(db.String(45), nullable=False, unique=True)  # IPv6 support
    server_name = db.Column(db.String(50), nullable=False)
    server_ip = db.Column(db.String(45))  # OS IP (usually .1) - IPv6 support
    public_ip = db.Column(db.String(45))  # External/public IP (optional, for reference)
    enabled = db.Column(db.Boolean, default=True)
    use_nvidia_password = db.Column(db.Boolean, default=False)  # Needs 16-char password
    protocol = db.Column(db.String(20), default='auto')  # 'auto', 'ipmi', 'redfish'
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Lifecycle management
    # status: 'active', 'deprecated', 'maintenance'
    status = db.Column(db.String(20), default='active')
    deprecated_at = db.Column(db.DateTime, nullable=True)
    deprecated_reason = db.Column(db.Text, nullable=True)
    
    def is_active(self):
        """Check if server should be collected from"""
        return self.enabled and self.status == 'active'
    
    def deprecate(self, reason=None):
        """Mark server as deprecated - stops collection but keeps data"""
        self.status = 'deprecated'
        self.enabled = False
        self.deprecated_at = datetime.utcnow()
        self.deprecated_reason = reason
    
    def restore(self):
        """Restore a deprecated server to active"""
        self.status = 'active'
        self.enabled = True
        self.deprecated_at = None
        self.deprecated_reason = None

class IPMIEvent(db.Model):
    """IPMI SEL Event"""
    id = db.Column(db.Integer, primary_key=True)
    bmc_ip = db.Column(db.String(20), nullable=False, index=True)
    server_name = db.Column(db.String(50), nullable=False, index=True)
    sel_id = db.Column(db.String(10), nullable=False)
    event_date = db.Column(db.DateTime, nullable=False, index=True)
    sensor_type = db.Column(db.String(50), nullable=False, index=True)
    sensor_id = db.Column(db.String(20))
    sensor_number = db.Column(db.String(10))  # For identifying specific DIMM/sensor
    event_description = db.Column(db.String(200), nullable=False)
    event_direction = db.Column(db.String(20))  # Asserted/Deasserted
    event_data = db.Column(db.String(50))  # Raw event data bytes for ECC details
    severity = db.Column(db.String(20), nullable=False, index=True)  # critical, warning, info
    raw_entry = db.Column(db.Text)
    collected_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    __table_args__ = (
        db.UniqueConstraint('bmc_ip', 'sel_id', name='unique_event'),
    )

class ServerStatus(db.Model):
    """Server health status"""
    id = db.Column(db.Integer, primary_key=True)
    bmc_ip = db.Column(db.String(20), nullable=False, unique=True)
    server_name = db.Column(db.String(50), nullable=False)
    power_status = db.Column(db.String(20))
    last_check = db.Column(db.DateTime)
    is_reachable = db.Column(db.Boolean, default=True)
    consecutive_failures = db.Column(db.Integer, default=0)  # Track consecutive check failures
    last_failure_time = db.Column(db.DateTime)  # When first failure in current streak occurred
    total_events = db.Column(db.Integer, default=0)
    total_events_24h = db.Column(db.Integer, default=0)
    critical_events_24h = db.Column(db.Integer, default=0)
    warning_events_24h = db.Column(db.Integer, default=0)
    info_events_24h = db.Column(db.Integer, default=0)
    critical_events_total = db.Column(db.Integer, default=0)
    warning_events_total = db.Column(db.Integer, default=0)
    info_events_total = db.Column(db.Integer, default=0)

class ServerUptime(db.Model):
    """Track server uptime to detect unexpected reboots"""
    id = db.Column(db.Integer, primary_key=True)
    bmc_ip = db.Column(db.String(45), nullable=False, unique=True, index=True)
    server_name = db.Column(db.String(50), nullable=False)
    last_uptime_seconds = db.Column(db.Integer)  # Last known uptime in seconds
    last_boot_time = db.Column(db.DateTime)  # Calculated boot time
    last_check = db.Column(db.DateTime, default=datetime.utcnow)
    reboot_count = db.Column(db.Integer, default=0)  # Total reboots detected
    unexpected_reboot_count = db.Column(db.Integer, default=0)  # Reboots not initiated by us

class MaintenanceTask(db.Model):
    """AI-generated maintenance tasks based on patterns"""
    id = db.Column(db.Integer, primary_key=True)
    bmc_ip = db.Column(db.String(45), nullable=False, index=True)
    server_name = db.Column(db.String(50), nullable=False)
    task_type = db.Column(db.String(50), nullable=False)  # 'gpu_replacement', 'memory_check', 'general'
    description = db.Column(db.Text, nullable=False)
    severity = db.Column(db.String(20), default='medium')  # low, medium, high, critical
    status = db.Column(db.String(20), default='pending')  # pending, scheduled, in_progress, completed, cancelled
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    scheduled_for = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)
    notes = db.Column(db.Text)
    # Track what triggered this maintenance
    trigger_event_ids = db.Column(db.Text)  # JSON list of event IDs
    recovery_attempts = db.Column(db.Integer, default=0)

class RecoveryLog(db.Model):
    """Log all recovery actions taken by the system"""
    id = db.Column(db.Integer, primary_key=True)
    bmc_ip = db.Column(db.String(45), nullable=False, index=True)
    server_name = db.Column(db.String(50), nullable=False)
    action_type = db.Column(db.String(50), nullable=False)  # 'gpu_reset', 'reboot', 'power_cycle', 'clock_limit'
    target_device = db.Column(db.String(100))  # e.g., 'GPU0:0000:01:00.0'
    reason = db.Column(db.Text)  # Why action was taken
    result = db.Column(db.String(20))  # 'success', 'failed', 'pending'
    initiated_by = db.Column(db.String(50), default='system')  # 'system', 'user', 'ai_agent'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)
    error_message = db.Column(db.Text)

class ServerConfig(db.Model):
    """Per-server configuration (IPMI credentials, SSH credentials)"""
    id = db.Column(db.Integer, primary_key=True)
    bmc_ip = db.Column(db.String(20), nullable=False, unique=True)
    server_name = db.Column(db.String(50), nullable=False)
    server_ip = db.Column(db.String(20))  # OS IP (usually .1 instead of .0)
    ipmi_user = db.Column(db.String(50))
    ipmi_pass = db.Column(db.String(100))
    ssh_user = db.Column(db.String(50), default='root')
    ssh_pass = db.Column(db.String(100))  # SSH password (alternative to key)
    ssh_key = db.Column(db.Text)  # Private key content (direct paste - deprecated)
    ssh_key_id = db.Column(db.Integer, db.ForeignKey('ssh_key.id'), nullable=True)  # Reference to stored key
    ssh_port = db.Column(db.Integer, default=22)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class SSHKey(db.Model):
    """Stored SSH keys that can be assigned to servers"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False, unique=True)  # e.g., "DGX Key", "Default Key"
    key_content = db.Column(db.Text, nullable=False)  # Private key content
    fingerprint = db.Column(db.String(100))  # Key fingerprint for display
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    @staticmethod
    def get_fingerprint(key_content):
        """Get fingerprint from SSH key content"""
        import hashlib
        import base64
        try:
            # Simple fingerprint from key content
            lines = [l for l in key_content.strip().split('\n') if not l.startswith('-----')]
            key_data = ''.join(lines)
            decoded = base64.b64decode(key_data)
            fp = hashlib.md5(decoded).hexdigest()
            return ':'.join(fp[i:i+2] for i in range(0, len(fp), 2))
        except:
            return None


class SensorReading(db.Model):
    """Sensor readings from BMC"""
    id = db.Column(db.Integer, primary_key=True)
    bmc_ip = db.Column(db.String(20), nullable=False, index=True)
    server_name = db.Column(db.String(50), nullable=False)
    sensor_name = db.Column(db.String(50), nullable=False, index=True)
    sensor_type = db.Column(db.String(30), nullable=False, index=True)  # temperature, fan, voltage, power
    value = db.Column(db.Float)
    unit = db.Column(db.String(20))  # degrees C, RPM, Volts, Watts
    status = db.Column(db.String(20))  # ok, warning, critical, nr (non-recoverable)
    lower_critical = db.Column(db.Float)
    lower_warning = db.Column(db.Float)
    upper_warning = db.Column(db.Float)
    upper_critical = db.Column(db.Float)
    collected_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    __table_args__ = (
        db.Index('idx_sensor_bmc_time', 'bmc_ip', 'collected_at'),
    )

class PowerReading(db.Model):
    """Power consumption readings"""
    id = db.Column(db.Integer, primary_key=True)
    bmc_ip = db.Column(db.String(20), nullable=False, index=True)
    server_name = db.Column(db.String(50), nullable=False)
    current_watts = db.Column(db.Float)
    min_watts = db.Column(db.Float)
    max_watts = db.Column(db.Float)
    avg_watts = db.Column(db.Float)
    collected_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

# ============== Alerting Models ==============

class AlertRule(db.Model):
    """Configurable alert rules"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    alert_type = db.Column(db.String(50), nullable=False)  # fan, temperature, memory, psu, pci, server
    condition = db.Column(db.String(50), nullable=False)  # eq, lt, gt, lte, gte, contains
    threshold = db.Column(db.Float)  # For numeric comparisons
    threshold_str = db.Column(db.String(100))  # For string matching
    severity = db.Column(db.String(20), default='warning')  # info, warning, critical
    enabled = db.Column(db.Boolean, default=True)
    cooldown_minutes = db.Column(db.Integer, default=30)  # Don't re-alert for X minutes
    confirm_count = db.Column(db.Integer, default=3)  # Consecutive failures before alerting (prevents false positives)
    notify_telegram = db.Column(db.Boolean, default=True)
    notify_email = db.Column(db.Boolean, default=False)
    notify_webhook = db.Column(db.Boolean, default=False)
    notify_on_resolve = db.Column(db.Boolean, default=True)  # Send notification when alert is resolved
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class AlertHistory(db.Model):
    """History of fired alerts"""
    id = db.Column(db.Integer, primary_key=True)
    rule_id = db.Column(db.Integer, db.ForeignKey('alert_rule.id'))
    rule_name = db.Column(db.String(100))
    bmc_ip = db.Column(db.String(20), index=True)
    server_name = db.Column(db.String(50))
    alert_type = db.Column(db.String(50))
    severity = db.Column(db.String(20))
    source_type = db.Column(db.String(20), default='RULE_ALERT')  # RULE_ALERT or BMC_EVENT
    message = db.Column(db.Text)
    value = db.Column(db.String(100))  # The value that triggered the alert
    threshold = db.Column(db.String(100))  # The threshold that was exceeded
    sensor_id = db.Column(db.String(50))  # For ECC: which DIMM/sensor triggered
    notified_telegram = db.Column(db.Boolean, default=False)
    notified_email = db.Column(db.Boolean, default=False)
    notified_webhook = db.Column(db.Boolean, default=False)
    acknowledged = db.Column(db.Boolean, default=False)
    acknowledged_by = db.Column(db.String(50))
    acknowledged_at = db.Column(db.DateTime)
    resolved = db.Column(db.Boolean, default=False)
    resolved_at = db.Column(db.DateTime)
    resolved_notified_telegram = db.Column(db.Boolean, default=False)
    resolved_notified_email = db.Column(db.Boolean, default=False)
    resolved_notified_webhook = db.Column(db.Boolean, default=False)
    fired_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

class ECCErrorTracker(db.Model):
    """Track ECC errors per module per machine for rate alerting"""
    id = db.Column(db.Integer, primary_key=True)
    bmc_ip = db.Column(db.String(20), nullable=False, index=True)
    server_name = db.Column(db.String(50), nullable=False)
    sensor_id = db.Column(db.String(50), nullable=False)  # e.g., "0xD1" or "CPU1_ECC1"
    sensor_name = db.Column(db.String(100))  # Human-readable name
    error_type = db.Column(db.String(30), default='correctable')  # correctable, uncorrectable
    count_1h = db.Column(db.Integer, default=0)  # Errors in last hour
    count_24h = db.Column(db.Integer, default=0)  # Errors in last 24h
    count_total = db.Column(db.Integer, default=0)  # Total errors seen
    last_error_at = db.Column(db.DateTime)
    last_checked = db.Column(db.DateTime, default=datetime.utcnow)
    alerted_at = db.Column(db.DateTime)  # When we last alerted for this module
    
    __table_args__ = (
        db.UniqueConstraint('bmc_ip', 'sensor_id', 'error_type', name='unique_ecc_tracker'),
    )

class NotificationConfig(db.Model):
    """Global notification channel configuration"""
    id = db.Column(db.Integer, primary_key=True)
    channel_type = db.Column(db.String(20), nullable=False, unique=True)  # telegram, email, webhook
    enabled = db.Column(db.Boolean, default=False)
    config_json = db.Column(db.Text)  # JSON config for the channel
    test_successful = db.Column(db.Boolean, default=False)
    last_test = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class User(db.Model):
    """User accounts with role-based access
    
    Roles:
        - admin: Full access including user management and AI service signup
        - readwrite: Full operational access (power control, clear SEL, manage servers, alerts, etc.)
                    Cannot: promote to admin, remove admins, or manage AI service subscription
        - readonly: View-only access (same as anonymous when anonymous is enabled)
    """
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False, unique=True)
    # NOTE: Historically this was a raw SHA256 hex digest. We now store
    # Werkzeug password hashes (pbkdf2/scrypt) and transparently support
    # legacy hashes for upgrade-on-login.
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='readonly')  # admin, readwrite, readonly
    enabled = db.Column(db.Boolean, default=True)
    password_changed = db.Column(db.Boolean, default=False)  # True after first password change
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    # CryptoLabs/WordPress account linking
    wp_user_id = db.Column(db.Integer, nullable=True)  # WordPress user ID
    wp_email = db.Column(db.String(100), nullable=True)  # WordPress email
    wp_linked_at = db.Column(db.DateTime, nullable=True)  # When linked
    
    @staticmethod
    def hash_password(password):
        # New default: slow password hashing
        return generate_password_hash(password)

    def set_password(self, password: str) -> None:
        self.password_hash = User.hash_password(password)
    
    def verify_password(self, password):
        stored = (self.password_hash or '').strip()
        # Legacy SHA256 hex (unsalted) support
        if re.fullmatch(r"[0-9a-f]{64}", stored):
            import hashlib
            ok = hmac.compare_digest(stored, hashlib.sha256(password.encode()).hexdigest())
            if ok:
                # Upgrade hash in-place on successful login
                try:
                    self.password_hash = generate_password_hash(password)
                    self.password_changed = True
                    db.session.commit()
                except Exception:
                    db.session.rollback()
            return ok
        # Modern Werkzeug hash
        try:
            return check_password_hash(stored, password)
        except Exception:
            return False
    
    def is_admin(self):
        return self.role == 'admin'
    
    @staticmethod
    def initialize_default():
        """Create default admin if none exists.
        
        Password is read from ADMIN_PASS environment variable (set by quickstart).
        Falls back to 'admin' for backwards compatibility.
        """
        admin = User.query.filter_by(role='admin').first()
        if not admin:
            # Get password from env var (set by quickstart via .env file)
            admin_pass = os.environ.get('ADMIN_PASS', 'admin')
            is_custom = admin_pass != 'admin'
            
            admin = User(
                username='admin',
                password_hash=User.hash_password(admin_pass),
                role='admin',
                password_changed=is_custom  # Mark as changed if custom password
            )
            db.session.add(admin)
            db.session.commit()
            
            if is_custom:
                app.logger.info("✓ Admin user created with custom password from ADMIN_PASS")
            else:
                app.logger.info("✓ Admin user created with default password (admin/admin)")
        return admin

class SystemSettings(db.Model):
    """Global system settings"""
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(50), nullable=False, unique=True)
    value = db.Column(db.String(200))
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    @staticmethod
    def get(key, default=None):
        setting = SystemSettings.query.filter_by(key=key).first()
        return setting.value if setting else default
    
    @staticmethod
    def set(key, value):
        setting = SystemSettings.query.filter_by(key=key).first()
        if setting:
            setting.value = str(value)
        else:
            setting = SystemSettings(key=key, value=str(value))
            db.session.add(setting)
        db.session.commit()
        return setting
    
    @staticmethod
    def initialize_defaults():
        """Initialize default settings"""
        # Check environment variables for overrides
        enable_ssh_logs = os.environ.get('ENABLE_SSH_LOGS', 'false').lower()
        collect_vastai = os.environ.get('COLLECT_VASTAI_LOGS', 'false').lower()
        collect_runpod = os.environ.get('COLLECT_RUNPOD_LOGS', 'false').lower()
        
        defaults = {
            'allow_anonymous_read': 'false',  # SECURITY: Require login by default (safer)
            'session_timeout_hours': '24',
            'enable_ssh_inventory': 'true',  # SSH to OS for detailed inventory (requires SSH creds)
            'collection_workers': 'auto',  # 'auto' = use CPU count, or a fixed number
            'collect_vastai_logs': collect_vastai,  # Optional: Collect Vast.ai daemon logs (from env)
            'collect_runpod_logs': collect_runpod,  # Optional: Collect RunPod agent logs (from env)
            'enable_ssh_log_collection': enable_ssh_logs,  # SSH log collection (set by quickstart)
            'ssh_log_interval': '15',  # SSH log collection interval in minutes
        }
        for key, value in defaults.items():
            existing = SystemSettings.query.filter_by(key=key).first()
            if not existing:
                db.session.add(SystemSettings(key=key, value=value))
            elif key == 'enable_ssh_log_collection' and enable_ssh_logs == 'true':
                # Override from env var if explicitly enabled
                existing.value = enable_ssh_logs
            elif key == 'collect_vastai_logs' and collect_vastai == 'true':
                # Override from env var if explicitly enabled
                existing.value = collect_vastai
            elif key == 'collect_runpod_logs' and collect_runpod == 'true':
                # Override from env var if explicitly enabled
                existing.value = collect_runpod
        db.session.commit()

# Backwards compatibility alias
class AdminConfig(db.Model):
    """Deprecated - use User model instead. Kept for migration."""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False, default='admin')
    password_hash = db.Column(db.String(255), nullable=False)
    password_changed = db.Column(db.Boolean, default=False)  # True after first password change
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    @staticmethod
    def hash_password(password):
        return generate_password_hash(password)
    
    @staticmethod
    def initialize_default():
        """Create default admin if none exists - delegates to User model"""
        return User.initialize_default()


# ============== Cloud Sync (AI Features) ==============

class CloudSync(db.Model):
    """Configuration for CryptoLabs AI cloud sync"""
    id = db.Column(db.Integer, primary_key=True)
    license_key = db.Column(db.String(128), nullable=True)
    sync_enabled = db.Column(db.Boolean, default=False)
    sync_interval = db.Column(db.Integer, default=300)  # 5 minutes
    last_sync = db.Column(db.DateTime, nullable=True)
    last_sync_status = db.Column(db.String(50), nullable=True)  # 'success', 'error', 'pending'
    last_sync_message = db.Column(db.Text, nullable=True)
    subscription_tier = db.Column(db.String(50), nullable=True)  # 'free', 'standard', 'professional'
    subscription_valid = db.Column(db.Boolean, default=False)
    max_servers = db.Column(db.Integer, default=50)
    features = db.Column(db.Text, nullable=True)  # JSON array of enabled features
    # Multi-site support: One customer can have multiple IPMI Monitor instances at different sites
    site_id = db.Column(db.String(64), nullable=True)  # Auto-generated unique site ID
    site_name = db.Column(db.String(128), nullable=True)  # Human-friendly name: "NYC Datacenter", "London Office"
    site_location = db.Column(db.String(256), nullable=True)  # Optional location details
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # AI Service endpoint - hardcoded for now, can be made configurable later
    AI_SERVICE_URL = os.environ.get('AI_SERVICE_URL', 'https://ipmi-ai.cryptolabs.co.za')  # CryptoLabs AI Service
    
    @staticmethod
    def get_config():
        """Get or create cloud sync configuration"""
        config = CloudSync.query.first()
        if not config:
            config = CloudSync()
            db.session.add(config)
            db.session.commit()
        return config
    
    @staticmethod
    def is_ai_enabled():
        """Check if AI features are enabled and valid"""
        config = CloudSync.query.first()
        return config and config.sync_enabled and config.subscription_valid and config.license_key
    
    def get_features_list(self):
        """Get list of enabled features"""
        if self.features:
            try:
                return json.loads(self.features)
            except:
                pass
        return []
    
    def to_dict(self):
        return {
            'license_key': '***' + self.license_key[-4:] if self.license_key else None,
            'sync_enabled': self.sync_enabled,
            'sync_interval': self.sync_interval,
            # Add 'Z' suffix to indicate UTC time so browser interprets correctly
            'last_sync': (self.last_sync.isoformat() + 'Z') if self.last_sync else None,
            'last_sync_status': self.last_sync_status,
            'last_sync_message': self.last_sync_message,
            'subscription_tier': self.subscription_tier,
            'subscription_valid': self.subscription_valid,
            'max_servers': self.max_servers,
            'features': self.get_features_list(),
            # Multi-site support
            'site_id': self.site_id,
            'site_name': self.site_name,
            'site_location': self.site_location
        }


class AIResult(db.Model):
    """Cached AI results from cloud service"""
    id = db.Column(db.Integer, primary_key=True)
    result_type = db.Column(db.String(50), nullable=False)  # 'summary', 'tasks', 'predictions', 'rca'
    content = db.Column(db.Text, nullable=True)  # JSON or HTML content
    server_name = db.Column(db.String(100), nullable=True)  # NULL for fleet-wide results
    generated_at = db.Column(db.DateTime, nullable=True)
    fetched_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=True)
    
    @staticmethod
    def get_latest(result_type, server_name=None):
        """Get the latest result of a type"""
        query = AIResult.query.filter_by(result_type=result_type)
        if server_name:
            query = query.filter_by(server_name=server_name)
        else:
            query = query.filter(AIResult.server_name.is_(None))
        return query.order_by(AIResult.fetched_at.desc()).first()
    
    @staticmethod
    def store_result(result_type, content, server_name=None, generated_at=None):
        """Store an AI result"""
        result = AIResult(
            result_type=result_type,
            content=json.dumps(content) if isinstance(content, (dict, list)) else content,
            server_name=server_name,
            generated_at=datetime.fromisoformat(generated_at) if generated_at else datetime.utcnow(),
            fetched_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(hours=24)
        )
        db.session.add(result)
        db.session.commit()
        return result


class ServerInventory(db.Model):
    """Hardware inventory collected via IPMI FRU data"""
    id = db.Column(db.Integer, primary_key=True)
    bmc_ip = db.Column(db.String(20), nullable=False, unique=True, index=True)
    server_name = db.Column(db.String(50), nullable=False)
    # System info
    manufacturer = db.Column(db.String(100))
    product_name = db.Column(db.String(100))
    serial_number = db.Column(db.String(100))
    part_number = db.Column(db.String(100))
    # BMC info
    bmc_mac_address = db.Column(db.String(20))
    bmc_firmware = db.Column(db.String(50))
    # Board info
    board_manufacturer = db.Column(db.String(100))
    board_product = db.Column(db.String(100))
    board_serial = db.Column(db.String(100))
    # CPU info (from dmidecode via SSH if available)
    cpu_model = db.Column(db.String(150))
    cpu_count = db.Column(db.Integer)
    cpu_cores = db.Column(db.Integer)
    # Memory info
    memory_total_gb = db.Column(db.Float)
    memory_slots_used = db.Column(db.Integer)
    memory_slots_total = db.Column(db.Integer)
    memory_dimms = db.Column(db.Text)  # JSON: detailed DIMM info from Redfish
    # Network MACs (JSON list)
    network_macs = db.Column(db.Text)  # JSON: [{"interface": "eth0", "mac": "aa:bb:cc:dd:ee:ff"}]
    # Storage info (JSON)
    storage_info = db.Column(db.Text)  # JSON: [{"device": "/dev/sda", "size": "1TB", "model": "..."}]
    # GPU info (JSON)
    gpu_info = db.Column(db.Text)  # JSON: [{"name": "NVIDIA A100", "memory": "80GB", "uuid": "..."}]
    gpu_count = db.Column(db.Integer)
    # NIC info (JSON) - collected via lspci
    nic_info = db.Column(db.Text)  # JSON: [{"pci_address": "04:00.0", "model": "Intel I350..."}]
    nic_count = db.Column(db.Integer)
    # PCIe devices (JSON) - collected via Redfish
    pcie_devices = db.Column(db.Text)  # JSON: [{"Id": "GPU1", "Name": "NVIDIA H100", ...}]
    # PCIe health (JSON) - collected via lspci -vvv and setpci
    pcie_health = db.Column(db.Text)  # JSON: [{"device": "01:00.0", "name": "GPU", "status": "ok|error", "errors": [...]}]
    pcie_errors_count = db.Column(db.Integer, default=0)  # Count of devices with errors
    # System details (collected via SSH) - NEW
    os_name = db.Column(db.String(100))  # e.g., "Ubuntu 22.04.3 LTS"
    os_version = db.Column(db.String(50))  # e.g., "22.04"
    kernel_version = db.Column(db.String(100))  # e.g., "5.15.0-91-generic"
    kernel_arch = db.Column(db.String(20))  # e.g., "x86_64"
    hostname = db.Column(db.String(100))  # FQDN hostname
    docker_version = db.Column(db.String(50))  # e.g., "24.0.7"
    docker_compose_version = db.Column(db.String(50))  # e.g., "2.21.0"
    docker_containers = db.Column(db.Integer)  # Number of running containers
    nvidia_driver = db.Column(db.String(50))  # e.g., "535.129.03"
    cuda_version = db.Column(db.String(20))  # e.g., "12.2"
    mellanox_ofed = db.Column(db.String(50))  # e.g., "MLNX_OFED_LINUX-5.8-1.0.1.1"
    uptime_seconds = db.Column(db.Integer)  # System uptime in seconds
    load_average = db.Column(db.String(50))  # e.g., "0.15, 0.10, 0.09"
    # IP addresses
    primary_ip = db.Column(db.String(20))  # OS IP (e.g., 88.0.x.1)
    primary_ip_reachable = db.Column(db.Boolean, default=True)
    primary_ip_last_check = db.Column(db.DateTime)
    # Raw FRU data
    fru_data = db.Column(db.Text)  # Full FRU output for reference
    # Timestamps
    collected_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def _format_bytes(self, bytes_val):
        """Convert bytes to human-readable format (GB/TB)"""
        if not bytes_val:
            return None
        try:
            bytes_val = int(bytes_val)
            if bytes_val >= 1e12:
                return f"{bytes_val / 1e12:.1f}TB"
            elif bytes_val >= 1e9:
                return f"{bytes_val / 1e9:.0f}GB"
            elif bytes_val >= 1e6:
                return f"{bytes_val / 1e6:.0f}MB"
            else:
                return f"{bytes_val}B"
        except:
            return None
    
    def to_dict(self):
        # Normalize storage_info to consistent lowercase field names
        # Redfish uses: Name, Model, CapacityBytes, MediaType
        # SSH uses: name, size, model, type
        # Frontend expects: name, model, size, type
        storage = []
        if self.storage_info:
            try:
                raw_storage = json.loads(self.storage_info)
                for drive in raw_storage:
                    # Normalize to lowercase and expected field names
                    normalized = {
                        'name': drive.get('name') or drive.get('Name') or drive.get('Id') or 'Unknown',
                        'model': drive.get('model') or drive.get('Model') or 'Unknown',
                        'size': drive.get('size') or self._format_bytes(drive.get('CapacityBytes')) or 'N/A',
                        'type': drive.get('type') or drive.get('MediaType') or drive.get('Protocol') or 'disk'
                    }
                    storage.append(normalized)
            except:
                pass
        
        return {
            'bmc_ip': self.bmc_ip,
            'server_name': self.server_name,
            'manufacturer': self.manufacturer,
            'product_name': self.product_name,
            'serial_number': self.serial_number,
            'part_number': self.part_number,
            'bmc_mac_address': self.bmc_mac_address,
            'bmc_firmware': self.bmc_firmware,
            'board_manufacturer': self.board_manufacturer,
            'board_product': self.board_product,
            'board_serial': self.board_serial,
            'cpu_model': self.cpu_model,
            'cpu_count': self.cpu_count,
            'cpu_cores': self.cpu_cores,
            'memory_total_gb': self.memory_total_gb,
            'memory_slots_used': self.memory_slots_used,
            'memory_slots_total': self.memory_slots_total,
            'memory_dimms': json.loads(self.memory_dimms) if self.memory_dimms else [],
            'network_macs': json.loads(self.network_macs) if self.network_macs else [],
            'storage_info': storage,
            'gpu_info': json.loads(self.gpu_info) if self.gpu_info else [],
            'gpu_count': self.gpu_count,
            'nic_info': json.loads(self.nic_info) if self.nic_info else [],
            'nic_count': self.nic_count,
            'pcie_devices': json.loads(self.pcie_devices) if self.pcie_devices else [],
            'pcie_health': json.loads(self.pcie_health) if self.pcie_health else [],
            'pcie_errors_count': self.pcie_errors_count or 0,
            # System details
            'os_name': self.os_name,
            'os_version': self.os_version,
            'kernel_version': self.kernel_version,
            'kernel_arch': self.kernel_arch,
            'hostname': self.hostname,
            'docker_version': self.docker_version,
            'docker_compose_version': self.docker_compose_version,
            'docker_containers': self.docker_containers,
            'nvidia_driver': self.nvidia_driver,
            'cuda_version': self.cuda_version,
            'mellanox_ofed': self.mellanox_ofed,
            'uptime_seconds': self.uptime_seconds,
            'load_average': self.load_average,
            # Network
            'primary_ip': self.primary_ip,
            'primary_ip_reachable': self.primary_ip_reachable,
            'primary_ip_last_check': self.primary_ip_last_check.isoformat() if self.primary_ip_last_check else None,
            'collected_at': self.collected_at.isoformat() if self.collected_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }


class RecoveryPermissions(db.Model):
    """
    System-wide and per-server GPU recovery action permissions.
    Controls what automated recovery actions the agent can take.
    """
    id = db.Column(db.Integer, primary_key=True)
    bmc_ip = db.Column(db.String(20), unique=True, nullable=True)  # NULL = system default
    server_name = db.Column(db.String(50))
    
    # Soft recovery (non-disruptive)
    allow_kill_workload = db.Column(db.Boolean, default=True)    # Kill container/VM
    allow_soft_reset = db.Column(db.Boolean, default=True)       # nvidia-smi reset
    allow_clock_limit = db.Column(db.Boolean, default=True)      # Reduce GPU clocks
    
    # Moderate recovery (may affect other workloads)
    allow_pci_reset = db.Column(db.Boolean, default=False)       # PCI device reset
    
    # Aggressive recovery (affects all workloads)
    allow_reboot = db.Column(db.Boolean, default=False)          # System reboot
    allow_power_cycle = db.Column(db.Boolean, default=False)     # IPMI power cycle
    
    # Maintenance flag
    allow_maintenance_flag = db.Column(db.Boolean, default=True)
    
    # Limits
    max_soft_attempts = db.Column(db.Integer, default=3)
    max_reboot_per_day = db.Column(db.Integer, default=2)
    max_power_cycle_per_day = db.Column(db.Integer, default=1)
    
    # Notifications
    notify_on_action = db.Column(db.Boolean, default=True)
    notify_on_escalation = db.Column(db.Boolean, default=True)
    
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    @classmethod
    def get_system_default(cls):
        """Get or create system-wide default permissions"""
        default = cls.query.filter_by(bmc_ip=None).first()
        if not default:
            default = cls(bmc_ip=None, server_name='SYSTEM_DEFAULT')
            db.session.add(default)
            db.session.commit()
        return default
    
    @classmethod
    def get_for_server(cls, bmc_ip):
        """Get permissions for a server (falls back to system default)"""
        server_perms = cls.query.filter_by(bmc_ip=bmc_ip).first()
        if server_perms:
            return server_perms
        return cls.get_system_default()
    
    def to_dict(self):
        return {
            'id': self.id,
            'bmc_ip': self.bmc_ip,
            'server_name': self.server_name,
            'is_default': self.bmc_ip is None,
            'allow_kill_workload': self.allow_kill_workload,
            'allow_soft_reset': self.allow_soft_reset,
            'allow_clock_limit': self.allow_clock_limit,
            'allow_pci_reset': self.allow_pci_reset,
            'allow_reboot': self.allow_reboot,
            'allow_power_cycle': self.allow_power_cycle,
            'allow_maintenance_flag': self.allow_maintenance_flag,
            'max_soft_attempts': self.max_soft_attempts,
            'max_reboot_per_day': self.max_reboot_per_day,
            'max_power_cycle_per_day': self.max_power_cycle_per_day,
            'notify_on_action': self.notify_on_action,
            'notify_on_escalation': self.notify_on_escalation,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }


class RecoveryActionLog(db.Model):
    """Audit log for GPU recovery actions taken"""
    id = db.Column(db.Integer, primary_key=True)
    bmc_ip = db.Column(db.String(20), nullable=False, index=True)
    server_name = db.Column(db.String(50))
    gpu_pci_address = db.Column(db.String(20))
    xid_code = db.Column(db.Integer)
    action_taken = db.Column(db.String(30), nullable=False)  # kill_workload, soft_reset, clock_limit, pci_reset, reboot, power_cycle
    action_result = db.Column(db.String(20))  # success, failed, skipped
    error_message = db.Column(db.Text)
    triggered_by = db.Column(db.String(20))  # auto, manual, escalation
    executed_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'bmc_ip': self.bmc_ip,
            'server_name': self.server_name,
            'gpu_pci_address': self.gpu_pci_address,
            'xid_code': self.xid_code,
            'action_taken': self.action_taken,
            'action_result': self.action_result,
            'error_message': self.error_message,
            'triggered_by': self.triggered_by,
            'executed_at': self.executed_at.isoformat() if self.executed_at else None
        }


# XID error configurations for UI display and recovery ladder
# Each Xid has: name, severity, actions (recovery ladder), and user_message (hides technical details)
XID_RECOVERY_CONFIGS = {
    8: {
        'name': 'GPU Reset Detected',
        'severity': 'warning',
        'actions': ['monitor'],
        'user_message': 'GPU experienced a reset - monitoring for recurrence'
    },
    13: {
        'name': 'Graphics Exception',
        'severity': 'warning',
        'actions': ['kill_workload', 'soft_reset'],
        'user_message': 'GPU graphics error - workload may need restart'
    },
    31: {
        'name': 'Memory Page Fault',
        'severity': 'critical',
        'actions': ['kill_workload', 'soft_reset', 'clock_limit', 'reboot'],
        'user_message': 'GPU memory error detected - may require recovery'
    },
    32: {
        'name': 'Invalid Push Buffer',
        'severity': 'warning',
        'actions': ['kill_workload', 'soft_reset'],
        'user_message': 'GPU command error - workload may need restart'
    },
    43: {
        'name': 'GPU Stopped Responding',
        'severity': 'critical',
        'actions': ['kill_workload', 'soft_reset', 'clock_limit', 'pci_reset', 'reboot'],
        'user_message': 'GPU not responding - recovery in progress'
    },
    45: {
        'name': 'Preemptive Cleanup',
        'severity': 'critical',
        'actions': ['kill_workload', 'soft_reset'],
        'user_message': 'GPU cleanup required - recovering'
    },
    48: {
        'name': 'Double-Bit ECC Error',
        'severity': 'critical',
        'actions': ['kill_workload', 'reboot', 'maintenance'],
        'user_message': 'GPU memory hardware error - may need maintenance'
    },
    61: {
        'name': 'Microcontroller Breakpoint',
        'severity': 'critical',
        'actions': ['power_cycle', 'maintenance'],
        'user_message': 'GPU firmware error - power cycle required'
    },
    62: {
        'name': 'Microcontroller Halt',
        'severity': 'critical',
        'actions': ['power_cycle', 'maintenance'],
        'user_message': 'GPU firmware halted - power cycle required'
    },
    63: {
        'name': 'ECC Page Retirement',
        'severity': 'warning',
        'actions': ['monitor'],
        'user_message': 'GPU memory page retired - monitoring'
    },
    64: {
        'name': 'ECC DBE Page Retirement',
        'severity': 'critical',
        'actions': ['reboot', 'maintenance'],
        'user_message': 'GPU memory error - reboot required'
    },
    69: {
        'name': 'Video Processor Exception',
        'severity': 'warning',
        'actions': ['kill_workload', 'soft_reset'],
        'user_message': 'Video processing error - recovering'
    },
    74: {
        'name': 'GPU Exception',
        'severity': 'critical',
        'actions': ['kill_workload', 'soft_reset', 'clock_limit', 'pci_reset', 'reboot'],
        'user_message': 'GPU error detected - recovery in progress'
    },
    79: {
        'name': 'GPU Fell Off Bus',
        'severity': 'critical',
        'actions': ['pci_reset', 'reboot', 'power_cycle'],
        'user_message': 'GPU disconnected - hardware recovery needed'
    },
    92: {
        'name': 'High Single-Bit ECC Rate',
        'severity': 'warning',
        'actions': ['clock_limit', 'maintenance'],
        'user_message': 'GPU memory showing wear - reduced performance'
    },
    94: {
        'name': 'Contained ECC Error',
        'severity': 'warning',
        'actions': ['monitor'],
        'user_message': 'GPU memory error corrected - monitoring'
    },
    95: {
        'name': 'Uncontained ECC Error',
        'severity': 'critical',
        'actions': ['reboot', 'maintenance'],
        'user_message': 'GPU memory failure - reboot required'
    },
    119: {
        'name': 'GSP Error',
        'severity': 'critical',
        'actions': ['soft_reset', 'pci_reset', 'reboot'],
        'user_message': 'GPU processor error - recovery in progress'
    },
    154: {
        'name': 'Recovery Required',
        'severity': 'critical',
        'actions': ['soft_reset', 'reboot', 'power_cycle'],
        'user_message': 'GPU requires recovery - automated recovery in progress'
    },
}

# Action descriptions for user display
RECOVERY_ACTION_DESCRIPTIONS = {
    'monitor': 'Monitoring GPU status',
    'kill_workload': 'Stopping affected workload',
    'soft_reset': 'Performing GPU soft reset',
    'clock_limit': 'Applying GPU clock limit for stability',
    'pci_reset': 'Performing PCI bus reset',
    'reboot': 'Initiating system reboot',
    'power_cycle': 'Performing power cycle',
    'maintenance': 'Flagged for maintenance review'
}


# ============== Instance Fingerprinting ==============
_instance_fingerprint = None
_instance_fingerprint_data = None
_hardware_fingerprint = None

def get_public_ip():
    """Get public IP address for fingerprinting"""
    try:
        import urllib.request
        return urllib.request.urlopen('https://api.ipify.org', timeout=5).read().decode('utf8')
    except:
        return None


def collect_hardware_identifiers():
    """
    Collect stable hardware identifiers from all monitored servers.
    These are used to identify reinstalled sites and detect duplicates.
    
    Priority identifiers (most stable/reliable):
    1. BMC MAC addresses - unique to each BMC, rarely changes
    2. System serial numbers - unique to each server
    3. Board serial numbers - unique to each motherboard
    4. Storage serial numbers - helps identify same storage arrays
    5. GPU UUIDs - stable identifiers for GPUs
    6. CPU model + count - helps with confidence scoring
    """
    hardware_ids = {
        'bmc_macs': [],          # List of BMC MAC addresses
        'system_serials': [],    # System serial numbers
        'board_serials': [],     # Motherboard serials
        'storage_serials': [],   # Storage device serials
        'gpu_uuids': [],         # GPU UUIDs
        'network_macs': [],      # All network interface MACs
        'cpu_signatures': [],    # CPU model signatures
    }
    
    try:
        inventories = ServerInventory.query.all()
        
        for inv in inventories:
            # BMC MAC (most stable - unique to BMC)
            if inv.bmc_mac_address:
                mac = inv.bmc_mac_address.upper().replace('-', ':')
                if mac and mac not in hardware_ids['bmc_macs'] and mac != '00:00:00:00:00:00':
                    hardware_ids['bmc_macs'].append(mac)
            
            # System serial number
            if inv.serial_number:
                serial = inv.serial_number.strip()
                if serial and serial.lower() not in ('', 'none', 'to be filled', 'default string', 'not specified'):
                    if serial not in hardware_ids['system_serials']:
                        hardware_ids['system_serials'].append(serial)
            
            # Board serial
            if inv.board_serial:
                serial = inv.board_serial.strip()
                if serial and serial.lower() not in ('', 'none', 'to be filled', 'default string', 'not specified'):
                    if serial not in hardware_ids['board_serials']:
                        hardware_ids['board_serials'].append(serial)
            
            # Storage serials from storage_info JSON
            if inv.storage_info:
                try:
                    storage = json.loads(inv.storage_info) if isinstance(inv.storage_info, str) else inv.storage_info
                    for device in storage if isinstance(storage, list) else []:
                        serial = device.get('serial') or device.get('SerialNumber', '')
                        if serial and serial.strip() and serial not in hardware_ids['storage_serials']:
                            hardware_ids['storage_serials'].append(serial.strip())
                except (json.JSONDecodeError, TypeError):
                    pass
            
            # GPU UUIDs from gpu_info JSON
            if inv.gpu_info:
                try:
                    gpus = json.loads(inv.gpu_info) if isinstance(inv.gpu_info, str) else inv.gpu_info
                    for gpu in gpus if isinstance(gpus, list) else []:
                        uuid = gpu.get('uuid') or gpu.get('serial', '')
                        if uuid and uuid.strip() and uuid not in hardware_ids['gpu_uuids']:
                            hardware_ids['gpu_uuids'].append(uuid.strip())
                except (json.JSONDecodeError, TypeError):
                    pass
            
            # Network MACs
            if inv.network_macs:
                try:
                    macs = json.loads(inv.network_macs) if isinstance(inv.network_macs, str) else inv.network_macs
                    for entry in macs if isinstance(macs, list) else []:
                        mac = entry.get('mac', '').upper().replace('-', ':')
                        if mac and mac not in hardware_ids['network_macs'] and mac != '00:00:00:00:00:00':
                            hardware_ids['network_macs'].append(mac)
                except (json.JSONDecodeError, TypeError):
                    pass
            
            # CPU signature (model + count for matching)
            if inv.cpu_model:
                sig = f"{inv.cpu_model}:{inv.cpu_count or 1}"
                if sig not in hardware_ids['cpu_signatures']:
                    hardware_ids['cpu_signatures'].append(sig)
    
    except Exception as e:
        app.logger.warning(f"Error collecting hardware identifiers: {e}")
    
    # Sort all lists for consistency
    for key in hardware_ids:
        hardware_ids[key] = sorted(hardware_ids[key])
    
    return hardware_ids


def generate_hardware_id(hardware_ids):
    """
    Generate a stable hardware ID that persists across reinstalls.
    Uses the most stable identifiers available in priority order.
    
    The hardware_id is a hash of immutable hardware characteristics
    that uniquely identifies this physical site/fleet of servers.
    """
    import hashlib
    
    # Priority order for generating hardware ID:
    # 1. BMC MACs (most stable - unique to each BMC)
    # 2. System serials (unique to each server)
    # 3. Board serials (unique to each motherboard)
    
    stable_ids = []
    
    # Use BMC MACs as primary identifier
    if hardware_ids.get('bmc_macs'):
        stable_ids.extend(hardware_ids['bmc_macs'])
    
    # Add system serials
    if hardware_ids.get('system_serials'):
        stable_ids.extend(hardware_ids['system_serials'])
    
    # Add board serials
    if hardware_ids.get('board_serials'):
        stable_ids.extend(hardware_ids['board_serials'])
    
    if not stable_ids:
        # Fallback: use GPU UUIDs if no BMC/serial data
        if hardware_ids.get('gpu_uuids'):
            stable_ids.extend(hardware_ids['gpu_uuids'])
    
    if not stable_ids:
        # No stable identifiers available
        return None
    
    # Generate deterministic hash from sorted identifiers
    id_string = '|'.join(sorted(set(stable_ids)))
    hardware_id = hashlib.sha256(id_string.encode()).hexdigest()[:32]
    
    return f"hw_{hardware_id}"


def get_or_create_site_id():
    """
    Get or create a unique site ID for this IPMI Monitor instance.
    
    NEW: Uses hardware-based identification when available for stability
    across reinstalls. Falls back to IP-based ID for new sites.
    """
    import hashlib
    
    config = CloudSync.get_config()
    
    # Check for SITE_NAME environment variable (from dc-overview quickstart)
    env_site_name = os.environ.get('SITE_NAME', '')
    
    # If site_id exists, use it (but update site_name from env if changed)
    if config.site_id:
        # Update site_name from env var if set and different
        if env_site_name and config.site_name != env_site_name:
            config.site_name = env_site_name
            db.session.commit()
        return config.site_id, config.site_name
    
    # Try to generate hardware-based site ID first (stable across reinstalls)
    hardware_ids = collect_hardware_identifiers()
    hardware_id = generate_hardware_id(hardware_ids)
    
    if hardware_id:
        # Use hardware-based site ID
        site_id = hardware_id
        app.logger.info(f"Generated hardware-based site ID: {site_id[:16]}...")
    else:
        # Fallback: Generate site ID based on instance characteristics
        import socket
        hostname = socket.gethostname()
        public_ip = get_public_ip() or 'unknown'
        
        # Create a deterministic site ID
        site_hash = hashlib.sha256(f"{public_ip}:{hostname}".encode()).hexdigest()[:16]
        site_id = f"site_{site_hash}"
        app.logger.info(f"Generated IP-based site ID: {site_id} (no hardware data available)")
    
    # Set site name from env var, config, or default
    public_ip = get_public_ip() or 'unknown'
    site_name = env_site_name or config.site_name or f"Site at {public_ip}"
    
    # Save to database
    config.site_id = site_id
    config.site_name = site_name
    db.session.commit()
    
    return site_id, site_name


def generate_instance_fingerprint():
    """
    Generate a unique fingerprint for this IPMI Monitor instance.
    Used to track instances and prevent trial abuse.
    
    NEW: Includes hardware identifiers for better duplicate detection
    and site identification across reinstalls.
    """
    global _instance_fingerprint, _instance_fingerprint_data, _hardware_fingerprint
    
    if _instance_fingerprint:
        return _instance_fingerprint, _instance_fingerprint_data
    
    with app.app_context():
        import hashlib
        import socket
        
        # Collect fingerprint components
        servers = Server.query.all()
        configs = ServerConfig.query.all()
        ssh_keys = SSHKey.query.all()
        users = User.query.all()
        
        # Get site info
        site_id, site_name = get_or_create_site_id()
        config = CloudSync.get_config()
        
        # Get BMC IPs sorted for consistency
        bmc_ips = sorted([s.bmc_ip for s in servers])
        server_names = sorted([s.server_name for s in servers])
        
        # Check SSH usage
        ssh_configured_count = sum(1 for c in configs if c.ssh_key_id or c.ssh_key)
        
        # Get admin username
        admin_user = next((u.username for u in users if u.role == 'admin'), 'admin')
        
        # NEW: Collect hardware identifiers for duplicate detection
        hardware_ids = collect_hardware_identifiers()
        hardware_id = generate_hardware_id(hardware_ids)
        _hardware_fingerprint = hardware_id
        
        # Build fingerprint data with site info and hardware identifiers
        fingerprint_data = {
            'public_ip': get_public_ip(),
            'hostname': socket.gethostname(),
            'site_id': site_id,
            'site_name': site_name,
            'site_location': config.site_location,
            'server_count': len(servers),
            'server_names': server_names[:20],  # First 20 for privacy
            'bmc_ip_range': f"{bmc_ips[0]}-{bmc_ips[-1]}" if bmc_ips else None,
            'bmc_ip_hash': hashlib.sha256(','.join(bmc_ips).encode()).hexdigest()[:16],
            'admin_user': admin_user,
            'uses_ssh': ssh_configured_count > 0,
            'ssh_key_count': len(ssh_keys),
            'ssh_coverage': f"{ssh_configured_count}/{len(servers)}" if servers else "0/0",
            # NEW: Hardware identifiers for duplicate detection
            'hardware_id': hardware_id,  # Stable ID based on hardware
            'hardware': {
                'bmc_macs': hardware_ids.get('bmc_macs', []),
                'system_serials': hardware_ids.get('system_serials', []),
                'board_serials': hardware_ids.get('board_serials', []),
                'storage_serials': hardware_ids.get('storage_serials', [])[:10],  # Limit for size
                'gpu_uuids': hardware_ids.get('gpu_uuids', [])[:20],  # Limit for size
                'cpu_signatures': hardware_ids.get('cpu_signatures', []),
            }
        }
        
        # Generate stable fingerprint hash
        # NEW: Uses hardware_id if available, falls back to old method
        if hardware_id:
            # Hardware-based fingerprint (stable across reinstalls)
            fingerprint_str = json.dumps({
                'hardware_id': hardware_id,
                'bmc_ips': bmc_ips,
                'server_names': server_names,
            }, sort_keys=True)
        else:
            # Fallback: Uses site_id, public IP, BMC IPs, server names (main identifiers)
            fingerprint_str = json.dumps({
                'site_id': site_id,
                'public_ip': fingerprint_data['public_ip'],
                'bmc_ips': bmc_ips,
                'server_names': server_names,
                'admin_user': admin_user,
            }, sort_keys=True)
        
        _instance_fingerprint = hashlib.sha256(fingerprint_str.encode()).hexdigest()[:32]
        _instance_fingerprint_data = fingerprint_data
        
        app.logger.info(f"Instance fingerprint generated: {_instance_fingerprint[:8]}... (site: {site_name}, hardware_id: {hardware_id[:8] if hardware_id else 'none'})")
        
        return _instance_fingerprint, _instance_fingerprint_data


def sync_telemetry():
    """
    Send basic telemetry for ALL instances (free or paid).
    This helps track usage and prevent trial abuse.
    Only sends: fingerprint, server count, basic stats.
    """
    with app.app_context():
        try:
            instance_id, fingerprint_data = generate_instance_fingerprint()
            
            # Get basic stats
            servers = Server.query.all()
            server_statuses = ServerStatus.query.all()
            
            healthy = sum(1 for s in server_statuses if s.is_reachable)
            critical = sum(1 for s in server_statuses if not s.is_reachable)
            
            # Get tier info
            config = CloudSync.get_config()
            tier = 'free'
            if config.license_key:
                tier = config.subscription_tier or 'trial'
            
            telemetry = {
                'instance_id': instance_id,
                'fingerprint': fingerprint_data,
                'app_version': get_version_string(),
                'tier': tier,
                'stats': {
                    'server_count': len(servers),
                    'healthy': healthy,
                    'critical': critical,
                    'uses_ssh': fingerprint_data.get('uses_ssh', False),
                },
                'timestamp': datetime.utcnow().isoformat(),
            }
            
            # Send to telemetry endpoint (doesn't require auth)
            response = requests.post(
                f"{config.AI_SERVICE_URL}/api/v1/telemetry",
                json=telemetry,
                timeout=10
            )
            
            if response.ok:
                app.logger.debug(f"Telemetry sent: {instance_id[:8]}...")
            
        except Exception as e:
            app.logger.debug(f"Telemetry failed (non-critical): {e}")


# =============================================================================
# HEALTH REPORTING & CRASH DETECTION
# Report instance health, crashes, and lifecycle events to AI service
# Works even without a license key - helps detect and diagnose issues
# =============================================================================

_instance_start_time = datetime.utcnow()
_last_health_report = None
_crash_buffer = []  # Buffer crashes if network is down

def report_health_status(event_type='heartbeat', extra_data=None):
    """
    Send health status to AI service. Works without license key.
    
    Args:
        event_type: 'heartbeat', 'startup', 'shutdown', 'error', 'warning'
        extra_data: Additional data to include in report
    """
    global _last_health_report
    
    with app.app_context():
        try:
            instance_id, fingerprint_data = generate_instance_fingerprint()
            config = CloudSync.get_config()
            
            # Collect health metrics
            servers = Server.query.all()
            server_statuses = ServerStatus.query.all()
            
            healthy = sum(1 for s in server_statuses if s.is_reachable)
            unreachable = sum(1 for s in server_statuses if not s.is_reachable)
            
            # System health
            import psutil
            try:
                memory = psutil.virtual_memory()
                disk = psutil.disk_usage('/app/data') if os.path.exists('/app/data') else psutil.disk_usage('/')
                cpu_percent = psutil.cpu_percent(interval=0.1)
                system_health = {
                    'memory_percent': memory.percent,
                    'disk_percent': disk.percent,
                    'cpu_percent': cpu_percent,
                }
            except:
                system_health = {}
            
            # Calculate uptime
            uptime_seconds = (datetime.utcnow() - _instance_start_time).total_seconds()
            
            health_report = {
                'instance_id': instance_id,
                'event_type': event_type,
                'timestamp': datetime.utcnow().isoformat(),
                'app_version': get_version_string(),
                'uptime_seconds': uptime_seconds,
                'tier': config.subscription_tier or 'free',
                'license_key_present': bool(config.license_key),
                'fingerprint': fingerprint_data,
                'fleet_health': {
                    'server_count': len(servers),
                    'healthy': healthy,
                    'unreachable': unreachable,
                },
                'system_health': system_health,
                'extra': extra_data or {},
            }
            
            # Include any buffered crashes
            if _crash_buffer:
                health_report['buffered_crashes'] = _crash_buffer.copy()
                _crash_buffer.clear()
            
            response = requests.post(
                f"{config.AI_SERVICE_URL}/api/v1/health-report",
                json=health_report,
                timeout=10
            )
            
            if response.ok:
                _last_health_report = datetime.utcnow()
                app.logger.debug(f"Health report sent: {event_type}")
            
        except Exception as e:
            app.logger.debug(f"Health report failed: {e}")


def report_crash(error_type, error_message, stack_trace=None, context=None):
    """
    Report a crash or critical error to AI service.
    Buffers if network is unavailable.
    
    Args:
        error_type: Exception class name
        error_message: Error message
        stack_trace: Full stack trace string
        context: Additional context (route, function, etc.)
    """
    global _crash_buffer
    
    crash_report = {
        'error_type': error_type,
        'error_message': str(error_message)[:1000],  # Limit size
        'stack_trace': stack_trace[:5000] if stack_trace else None,  # Limit size
        'context': context or {},
        'timestamp': datetime.utcnow().isoformat(),
    }
    
    with app.app_context():
        try:
            instance_id, fingerprint_data = generate_instance_fingerprint()
            config = CloudSync.get_config()
            
            payload = {
                'instance_id': instance_id,
                'event_type': 'crash',
                'app_version': get_version_string(),
                'tier': config.subscription_tier or 'free',
                'fingerprint': fingerprint_data,
                'crash': crash_report,
                'timestamp': datetime.utcnow().isoformat(),
            }
            
            response = requests.post(
                f"{config.AI_SERVICE_URL}/api/v1/health-report",
                json=payload,
                timeout=10
            )
            
            if response.ok:
                app.logger.info(f"Crash report sent: {error_type}")
            else:
                # Buffer for later
                _crash_buffer.append(crash_report)
                if len(_crash_buffer) > 10:
                    _crash_buffer.pop(0)  # Keep last 10
                    
        except Exception as e:
            # Buffer for later
            _crash_buffer.append(crash_report)
            if len(_crash_buffer) > 10:
                _crash_buffer.pop(0)
            app.logger.debug(f"Crash report buffered: {e}")


def report_startup():
    """Report instance startup to AI service"""
    report_health_status('startup', {
        'python_version': sys.version,
        'platform': sys.platform,
    })


def report_shutdown():
    """Report graceful shutdown to AI service"""
    report_health_status('shutdown', {
        'reason': 'graceful',
    })


# Global exception handler for Flask
@app.errorhandler(Exception)
def handle_exception(e):
    """Catch unhandled exceptions and report them"""
    import traceback
    
    # Don't report 404s and other HTTP errors
    if hasattr(e, 'code') and e.code < 500:
        return e
    
    stack_trace = traceback.format_exc()
    error_type = type(e).__name__
    
    # Report the crash
    try:
        report_crash(
            error_type=error_type,
            error_message=str(e),
            stack_trace=stack_trace,
            context={
                'url': request.url if request else None,
                'method': request.method if request else None,
                'endpoint': request.endpoint if request else None,
            }
        )
    except:
        pass  # Don't fail if reporting fails
    
    # Log it
    app.logger.error(f"Unhandled exception: {error_type}: {e}\n{stack_trace}")
    
    # Re-raise for default handling
    raise e


# Register shutdown handler
import atexit
atexit.register(report_shutdown)


def sync_to_cloud(initial_sync=False):
    """
    Sync data to CryptoLabs AI service.
    Called periodically by background thread.
    
    Args:
        initial_sync: If True, sends 30 days of data instead of 72 hours
    """
    with app.app_context():
        # Always send telemetry (even if full sync fails)
        sync_telemetry()
        
        config = CloudSync.get_config()
        
        if not config.sync_enabled or not config.license_key:
            return {'success': False, 'message': 'Sync not enabled'}
        
        # Check if this is first sync (no last_sync timestamp)
        is_first_sync = initial_sync or config.last_sync is None
        
        try:
            # Collect data to sync
            servers = Server.query.all()
            
            # Get events - ALL data for initial/first sync, 72 hours for regular sync
            if is_first_sync:
                # Send ALL historical SEL data on first sync
                events = IPMIEvent.query.all()
                app.logger.info(f"Initial sync: sending ALL historical data ({len(events)} events)")
            else:
                cutoff = datetime.utcnow() - timedelta(hours=72)
                events = IPMIEvent.query.filter(IPMIEvent.event_date > cutoff).all()
            
            # Get LATEST sensor readings only (not all historical data!)
            # Use a subquery to get the most recent reading for each server+sensor
            from sqlalchemy import func
            subquery = db.session.query(
                SensorReading.server_name,
                SensorReading.sensor_name,
                func.max(SensorReading.collected_at).label('max_ts')
            ).group_by(SensorReading.server_name, SensorReading.sensor_name).subquery()
            
            sensors = db.session.query(SensorReading).join(
                subquery,
                db.and_(
                    SensorReading.server_name == subquery.c.server_name,
                    SensorReading.sensor_name == subquery.c.sensor_name,
                    SensorReading.collected_at == subquery.c.max_ts
                )
            ).all()
            
            app.logger.info(f"Sync: {len(servers)} servers, {len(events)} events, {len(sensors)} sensors")
            
            # Get inventory data for all servers
            inventories = ServerInventory.query.all()
            
            # Generate instance fingerprint
            instance_id, fingerprint_data = generate_instance_fingerprint()
            
            payload = {
                # Instance identification (always sent)
                'instance_id': instance_id,
                'fingerprint': fingerprint_data,
                'app_version': get_version_string(),
                'sync_type': 'initial' if is_first_sync else 'regular',
                
                'servers': [{
                    'name': s.server_name,
                    'bmc_ip': s.bmc_ip,
                    'server_ip': s.server_ip,  # OS IP for SSH access
                    'description': s.notes or ''
                } for s in servers],
                'events': [{
                    'id': str(e.id),
                    'server_name': e.server_name,
                    'timestamp': e.event_date.isoformat() if e.event_date else None,
                    'type': e.sensor_type,
                    'description': e.event_description,
                    'severity': e.severity
                } for e in events],
                'sensors': [{
                    'server_name': s.server_name,
                    'name': s.sensor_name,
                    'type': s.sensor_type,
                    'value': s.value,
                    'unit': s.unit,
                    'status': s.status
                } for s in sensors],
                'inventory': [{
                    'server_name': inv.server_name,
                    'bmc_ip': inv.bmc_ip,
                    # Include server_ip from Server table (OS IP for SSH)
                    'server_ip': next((s.server_ip for s in servers if s.bmc_ip == inv.bmc_ip), None),
                    'manufacturer': inv.manufacturer,
                    'product_name': inv.product_name,
                    'serial_number': inv.serial_number,
                    'cpu_model': inv.cpu_model,
                    'cpu_count': inv.cpu_count,
                    'cpu_cores': inv.cpu_cores,
                    'memory_total_gb': inv.memory_total_gb,
                    'memory_slots_used': inv.memory_slots_used,
                    'memory_slots_total': inv.memory_slots_total,
                    'storage_info': json.loads(inv.storage_info) if inv.storage_info else [],
                    'gpu_info': json.loads(inv.gpu_info) if inv.gpu_info else [],
                    'gpu_count': inv.gpu_count,
                    'nic_info': json.loads(inv.nic_info) if inv.nic_info else [],
                    'nic_count': inv.nic_count,
                    'pcie_health': json.loads(inv.pcie_health) if inv.pcie_health else [],
                    'pcie_errors_count': inv.pcie_errors_count or 0,
                    'bmc_firmware': inv.bmc_firmware,
                    # OS and driver info for AI queries like "which servers aren't on 24.04"
                    'os_version': getattr(inv, 'os_version', None),
                    'kernel_version': getattr(inv, 'kernel_version', None),
                    'docker_version': getattr(inv, 'docker_version', None),
                    'nvidia_driver': getattr(inv, 'nvidia_driver', None),
                    'cuda_version': getattr(inv, 'cuda_version', None),
                    'memory_dimms': json.loads(inv.memory_dimms) if getattr(inv, 'memory_dimms', None) else [],
                    'pcie_devices': json.loads(inv.pcie_devices) if getattr(inv, 'pcie_devices', None) else [],
                    'collected_at': inv.collected_at.isoformat() if inv.collected_at else None
                } for inv in inventories]
            }
            
            # Add SSH logs if table exists
            try:
                from sqlalchemy import inspect as sa_inspect
                inspector = sa_inspect(db.engine)
                if 'ssh_logs' in inspector.get_table_names():
                    # Get SSH logs from last 72 hours - prioritize critical/warning logs
                    ssh_cutoff = (datetime.utcnow() - timedelta(hours=72)).isoformat()
                    ssh_logs_result = db.session.execute(db.text('''
                        SELECT server_name, log_type, severity, timestamp, message, source_file
                        FROM ssh_logs 
                        WHERE collected_at >= :cutoff
                        ORDER BY 
                            CASE severity 
                                WHEN 'critical' THEN 0 
                                WHEN 'warning' THEN 1 
                                ELSE 2 
                            END,
                            timestamp DESC
                        LIMIT 10000
                    '''), {'cutoff': ssh_cutoff}).fetchall()
                    
                    payload['ssh_logs'] = [{
                        'server_name': row[0],
                        'log_type': row[1],
                        'severity': row[2],
                        'timestamp': row[3],
                        'message': row[4],
                        'source': row[5]
                    } for row in ssh_logs_result]
                    
                    app.logger.info(f"Sync: Including {len(payload['ssh_logs'])} SSH log entries")
            except Exception as ssh_err:
                app.logger.debug(f"SSH logs sync skipped: {ssh_err}")
            
            app.logger.info(f"Sync: {len(servers)} servers, {len(events)} events, {len(sensors)} sensors, {len(inventories)} inventory records")
            
            # Send to AI service
            response = requests.post(
                f"{config.AI_SERVICE_URL}/api/v1/sync",
                json=payload,
                headers={'Authorization': f'Bearer {config.license_key}'},
                timeout=30
            )
            
            if response.ok:
                result = response.json()
                config.last_sync = datetime.utcnow()
                config.last_sync_status = 'success'
                config.last_sync_message = f"Synced {len(events)} events, {len(sensors)} sensors"
                db.session.commit()
                
                # Fetch AI results after sync
                fetch_ai_results()
                
                return {'success': True, 'message': config.last_sync_message}
            else:
                config.last_sync_status = 'error'
                config.last_sync_message = f"HTTP {response.status_code}: {response.text[:200]}"
                db.session.commit()
                return {'success': False, 'message': config.last_sync_message}
                
        except Exception as e:
            config.last_sync_status = 'error'
            config.last_sync_message = str(e)[:500]
            db.session.commit()
            app.logger.error(f"Cloud sync failed: {e}")
            return {'success': False, 'message': str(e)}


def poll_agent_tasks():
    """
    Poll the AI service for pending agent tasks and execute them.
    Part of v0.7.5 Agent Task Queue feature.
    """
    with app.app_context():
        config = CloudSync.get_config()
        
        if not config.sync_enabled or not config.license_key:
            return
        
        try:
            instance_id, _ = generate_instance_fingerprint()
            
            # Get pending tasks
            response = requests.get(
                f"{config.AI_SERVICE_URL}/api/v1/agent/tasks/pending",
                params={'instance_id': instance_id, 'limit': 5},
                headers={'Authorization': f'Bearer {config.license_key}'},
                timeout=10
            )
            
            if not response.ok:
                return
            
            tasks = response.json().get('tasks', [])
            
            for task in tasks:
                try:
                    execute_agent_task(task, config, instance_id)
                except Exception as e:
                    app.logger.error(f"Task {task.get('id')} failed: {e}")
                    
        except Exception as e:
            app.logger.debug(f"Task poll failed (non-critical): {e}")


def execute_agent_task(task, config, instance_id):
    """Execute a single agent task from the AI service"""
    task_id = task.get('id')
    action = task.get('action')
    bmc_ip = task.get('target_bmc_ip')
    server_name = task.get('target_server')
    params = json.loads(task.get('parameters', '{}'))
    
    app.logger.info(f"Executing task {task_id}: {action} on {bmc_ip or server_name}")
    
    # Claim the task
    requests.post(
        f"{config.AI_SERVICE_URL}/api/v1/agent/tasks/{task_id}/claim",
        json={'instance_id': instance_id},
        headers={'Authorization': f'Bearer {config.license_key}'},
        timeout=10
    )
    
    result = None
    success = False
    error = None
    start_time = datetime.utcnow()
    
    try:
        # Route to appropriate action handler
        if action == 'power_cycle':
            result = execute_power_action(bmc_ip, 'cycle')
            success = True
        elif action == 'power_reset':
            result = execute_power_action(bmc_ip, 'reset')
            success = True
        elif action == 'bmc_reset':
            result = execute_bmc_reset(bmc_ip, params.get('reset_type', 'cold'))
            success = True
        elif action == 'collect_inventory':
            result = collect_server_inventory(bmc_ip)
            success = True
        elif action == 'ssh_command':
            result = execute_ssh_command_for_task(bmc_ip, params.get('command'))
            success = True
        elif action == 'check_connectivity':
            # Use existing check function
            server = Server.query.filter_by(bmc_ip=bmc_ip).first()
            if server:
                result = f"Server {server.server_name} check initiated"
            success = True
        else:
            error = f"Unknown action: {action}"
            
    except Exception as e:
        error = str(e)
        app.logger.error(f"Task {task_id} execution error: {e}")
    
    duration_ms = int((datetime.utcnow() - start_time).total_seconds() * 1000)
    
    # Report completion
    requests.post(
        f"{config.AI_SERVICE_URL}/api/v1/agent/tasks/{task_id}/complete",
        json={'success': success, 'result': str(result), 'error': error},
        headers={'Authorization': f'Bearer {config.license_key}'},
        timeout=10
    )
    
    # Log the action
    requests.post(
        f"{config.AI_SERVICE_URL}/api/v1/agent/actions",
        json={
            'instance_id': instance_id,
            'server_name': server_name,
            'bmc_ip': bmc_ip,
            'action': action,
            'trigger_reason': 'remote_task',
            'result': str(result) if success else error,
            'success': success,
            'duration_ms': duration_ms
        },
        headers={'Authorization': f'Bearer {config.license_key}'},
        timeout=10
    )
    
    app.logger.info(f"Task {task_id} completed: {'success' if success else 'failed'}")


def execute_power_action(bmc_ip, action):
    """Execute power action via IPMI"""
    config = ServerConfig.query.filter_by(bmc_ip=bmc_ip).first()
    if not config:
        raise Exception(f"No config for {bmc_ip}")
    
    cmd = [
        'ipmitool', '-I', 'lanplus',
        '-H', bmc_ip,
        '-U', config.ipmi_user,
        '-P', config.ipmi_pass,
        'chassis', 'power', action
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    return result.stdout or result.stderr


def execute_bmc_reset(bmc_ip, reset_type='cold'):
    """Execute BMC reset via IPMI"""
    config = ServerConfig.query.filter_by(bmc_ip=bmc_ip).first()
    if not config:
        raise Exception(f"No config for {bmc_ip}")
    
    cmd = [
        'ipmitool', '-I', 'lanplus',
        '-H', bmc_ip,
        '-U', config.ipmi_user,
        '-P', config.ipmi_pass,
        'mc', 'reset', reset_type
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    return result.stdout or result.stderr


def run_ssh_command(server_ip, command, ssh_user='root', ssh_key_content=None, ssh_pass=None):
    """
    Run SSH command on a server using key or password.
    Returns stdout on success, raises exception on failure.
    """
    import tempfile
    
    ssh_opts = ['-o', 'ConnectTimeout=10', '-o', 'StrictHostKeyChecking=no']
    key_file_path = None
    
    try:
        if ssh_key_content:
            # Write key to temp file
            key_content_clean = ssh_key_content.replace('\r\n', '\n').strip() + '\n'
            key_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.pem')
            key_file.write(key_content_clean)
            key_file.close()
            os.chmod(key_file.name, 0o600)
            key_file_path = key_file.name
            cmd = ['ssh'] + ssh_opts + ['-o', 'BatchMode=yes', '-i', key_file_path, 
                   f'{ssh_user}@{server_ip}', command]
        elif ssh_pass:
            cmd = ['sshpass', '-p', ssh_pass, 'ssh'] + ssh_opts + [f'{ssh_user}@{server_ip}', command]
        else:
            # Try default SSH key
            cmd = ['ssh'] + ssh_opts + ['-o', 'BatchMode=yes', f'{ssh_user}@{server_ip}', command]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            return result.stdout
        else:
            raise Exception(f"SSH failed: {result.stderr}")
            
    finally:
        if key_file_path:
            try:
                os.unlink(key_file_path)
            except:
                pass


def execute_ssh_command_for_task(bmc_ip, command):
    """Execute SSH command on server (for agent tasks)"""
    if not command:
        raise Exception("No command specified")
    
    config = ServerConfig.query.filter_by(bmc_ip=bmc_ip).first()
    if not config or not config.server_ip:
        raise Exception(f"No SSH config for {bmc_ip}")
    
    # Get SSH key if configured
    ssh_key_content = None
    if config.ssh_key_id:
        key = SSHKey.query.get(config.ssh_key_id)
        if key:
            ssh_key_content = key.key_content
    
    return run_ssh_command(
        config.server_ip,
        command,
        config.ssh_user or 'root',
        ssh_key_content=ssh_key_content,
        ssh_pass=getattr(config, 'ssh_pass', None)
    )


def investigate_dark_recovery(bmc_ip, server_name, downtime_start, downtime_end):
    """
    v0.7.6: Post-Event RCA - Investigate what happened during a DARK period.
    Called when a server recovers from an unreachable state.
    
    Checks:
    1. SSH uptime - Did the OS reboot?
    2. SEL logs - Any power/voltage events?
    3. IPMI Monitor logs - What did we see?
    
    Returns dict with investigation results.
    """
    investigation = {
        'server': server_name,
        'bmc_ip': bmc_ip,
        'downtime_start': downtime_start.isoformat() if downtime_start else None,
        'downtime_end': downtime_end.isoformat() if downtime_end else None,
        'duration_seconds': (downtime_end - downtime_start).total_seconds() if downtime_start and downtime_end else None,
        'findings': [],
        'likely_cause': 'unknown',
        'confidence': 0
    }
    
    try:
        config = ServerConfig.query.filter_by(bmc_ip=bmc_ip).first()
        if not config:
            investigation['findings'].append('No configuration found for server')
            return investigation
        
        # 1. Check OS uptime via SSH
        if config.server_ip:
            try:
                ssh_key_content = None
                if config.ssh_key_id:
                    stored_key = SSHKey.query.get(config.ssh_key_id)
                    if stored_key:
                        ssh_key_content = stored_key.key_content
                
                uptime_result = run_ssh_command(
                    config.server_ip,
                    'uptime -s 2>/dev/null || cat /proc/uptime',
                    config.ssh_user or 'root',
                    ssh_key_content=ssh_key_content,
                    ssh_pass=getattr(config, 'ssh_pass', None)
                )
                
                if uptime_result:
                    investigation['ssh_uptime_raw'] = uptime_result.strip()
                    
                    # Parse uptime to see if reboot occurred during downtime
                    # uptime -s gives boot time like "2024-01-15 10:30:00"
                    import re
                    boot_match = re.search(r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})', uptime_result)
                    if boot_match:
                        boot_time = datetime.strptime(boot_match.group(1), '%Y-%m-%d %H:%M:%S')
                        investigation['os_boot_time'] = boot_time.isoformat()
                        
                        if downtime_start and boot_time > downtime_start:
                            investigation['findings'].append(f'OS rebooted at {boot_time}')
                            investigation['likely_cause'] = 'reboot'
                            investigation['confidence'] = 0.8
                    else:
                        # /proc/uptime gives seconds since boot
                        try:
                            uptime_secs = float(uptime_result.split()[0])
                            boot_time = datetime.utcnow() - timedelta(seconds=uptime_secs)
                            investigation['os_boot_time'] = boot_time.isoformat()
                            
                            if downtime_start and boot_time > downtime_start:
                                investigation['findings'].append(f'OS rebooted during downtime')
                                investigation['likely_cause'] = 'reboot'
                                investigation['confidence'] = 0.8
                        except:
                            pass
                            
            except Exception as ssh_err:
                investigation['findings'].append(f'SSH check failed: {str(ssh_err)[:100]}')
        
        # 2. Check SEL for power/voltage events during downtime
        try:
            events_during = IPMIEvent.query.filter(
                IPMIEvent.bmc_ip == bmc_ip,
                IPMIEvent.event_date >= downtime_start,
                IPMIEvent.event_date <= downtime_end
            ).order_by(IPMIEvent.event_date.desc()).limit(20).all()
            
            power_events = [e for e in events_during if any(kw in e.event_description.lower() 
                           for kw in ['power', 'voltage', 'reset', 'ac lost', 'power off', 'power on'])]
            
            if power_events:
                investigation['findings'].append(f'{len(power_events)} power-related events in SEL')
                investigation['power_events'] = [{'time': e.event_date.isoformat(), 
                                                   'desc': e.event_description} for e in power_events[:5]]
                
                if any('ac lost' in e.event_description.lower() for e in power_events):
                    investigation['likely_cause'] = 'power_outage'
                    investigation['confidence'] = 0.9
                elif any('reset' in e.event_description.lower() for e in power_events):
                    investigation['likely_cause'] = 'bmc_reset'
                    investigation['confidence'] = 0.7
                    
        except Exception as sel_err:
            investigation['findings'].append(f'SEL check failed: {str(sel_err)[:100]}')
        
        # 3. If no clear cause, might be network issue
        if investigation['likely_cause'] == 'unknown':
            # Check if any other servers went offline at same time
            concurrent_offline = ServerStatus.query.filter(
                ServerStatus.bmc_ip != bmc_ip,
                ServerStatus.last_failure_time >= downtime_start - timedelta(minutes=5),
                ServerStatus.last_failure_time <= downtime_start + timedelta(minutes=5)
            ).count()
            
            if concurrent_offline > 0:
                investigation['findings'].append(f'{concurrent_offline} other servers went offline simultaneously')
                investigation['likely_cause'] = 'network_issue'
                investigation['confidence'] = 0.7
            else:
                investigation['likely_cause'] = 'bmc_unresponsive'
                investigation['confidence'] = 0.5
                investigation['findings'].append('BMC was unresponsive, no other clear cause found')
        
    except Exception as e:
        investigation['error'] = str(e)
        app.logger.error(f"Dark recovery investigation failed for {bmc_ip}: {e}")
    
    return investigation


def report_connectivity_to_ai(server_name, bmc_ip, event_type, last_event=None, duration=None):
    """
    Report server connectivity change to AI service for tracking.
    
    Args:
        server_name: Name of the server
        bmc_ip: BMC IP address
        event_type: 'offline', 'online', or 'unreachable'
        last_event: Last known event timestamp before going offline
        duration: Duration offline in minutes (for 'online' events)
    """
    with app.app_context():
        config = CloudSync.get_config()
        
        if not config.sync_enabled or not config.license_key:
            return  # Silently skip if not syncing
        
        try:
            payload = {
                'server_name': server_name,
                'bmc_ip': bmc_ip,
                'event_type': event_type,
                'last_event': last_event,
                'duration_minutes': duration
            }
            
            response = requests.post(
                f"{config.AI_SERVICE_URL}/api/v1/log-connectivity",
                json=payload,
                headers={'Authorization': f'Bearer {config.license_key}'},
                timeout=10
            )
            
            if response.ok:
                app.logger.info(f"Reported connectivity event to AI: {server_name} -> {event_type}")
            else:
                app.logger.warning(f"Failed to report connectivity to AI: {response.status_code}")
                
        except Exception as e:
            app.logger.debug(f"Could not report connectivity to AI: {e}")


# Track previous connectivity states to detect changes
_connectivity_states = {}

def check_and_report_connectivity_changes():
    """
    Check all servers for connectivity changes and report to AI service.
    Called periodically by background collector.
    
    Severity Matrix:
    ┌──────────┬────────────┬──────────┬─────────────────────┐
    │ BMC/IPMI │ Primary IP │ Severity │ Alert Type          │
    ├──────────┼────────────┼──────────┼─────────────────────┤
    │    ❌    │     ❌     │ CRITICAL │ System Dark         │
    │    ✅    │     ❌     │ WARNING  │ OS Down/Reboot      │
    │    ❌    │     ✅     │ WARNING  │ BMC Unreachable     │
    │    ✅    │     ✅     │   OK     │ All Online          │
    └──────────┴────────────┴──────────┴─────────────────────┘
    """
    global _connectivity_states
    import socket
    
    def check_port(ip, port, timeout=2):
        if not ip:
            return False
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def check_ping(ip, timeout=2):
        """Check if host is reachable via ping (ICMP)"""
        if not ip:
            return False
        try:
            import subprocess
            # Use ping with count=1 and timeout
            result = subprocess.run(
                ['ping', '-c', '1', '-W', str(timeout), ip],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=timeout + 1
            )
            return result.returncode == 0
        except:
            return False
    
    def check_bmc_with_ipmi(ip, timeout=5):
        """
        Check if BMC is actually responding to IPMI commands.
        More reliable than ping/TCP - actually validates the BMC is working.
        """
        if not ip:
            return False
        try:
            import subprocess
            user, password = get_ipmi_credentials(ip)
            result = subprocess.run(
                ['ipmitool', '-I', 'lanplus', '-H', ip,
                 '-U', user, '-P', password, 'mc', 'info'],
                capture_output=True, text=True, timeout=timeout
            )
            return result.returncode == 0
        except subprocess.TimeoutExpired:
            return False
        except Exception as e:
            app.logger.debug(f"IPMI check failed for {ip}: {e}")
            return False
    
    def check_bmc_with_redfish(ip, timeout=5):
        """
        Check if BMC responds to Redfish API.
        Works for modern BMCs that support Redfish.
        """
        if not ip:
            return False
        try:
            import requests
            # Most Redfish endpoints are at /redfish/v1
            url = f"https://{ip}/redfish/v1"
            resp = requests.get(url, timeout=timeout, verify=False)
            return resp.status_code in [200, 401]  # 401 = auth required but responding
        except:
            return False
    
    def check_ssh(ip, timeout=3):
        """Check if SSH port is open and responding with banner"""
        if not ip:
            return False
        try:
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, 22))
            if result == 0:
                # Try to read SSH banner
                sock.settimeout(2)
                try:
                    banner = sock.recv(256)
                    sock.close()
                    return b'SSH' in banner
                except:
                    sock.close()
                    return True  # Port open, assume SSH
            sock.close()
            return False
        except:
            return False
    
    def check_bmc_reachable(ip, timeout=5):
        """
        Check if BMC is reachable using rigorous methods.
        Uses actual IPMI/Redfish commands, not just ping.
        Returns True only if BMC is actually responding.
        """
        if not ip:
            return False
        
        # Method 1: Try IPMI command (most reliable)
        if check_bmc_with_ipmi(ip, timeout):
            return True
        
        # Method 2: Try Redfish API (modern BMCs)
        if check_bmc_with_redfish(ip, timeout):
            return True
        
        # Method 3: Fall back to TCP port 623 + ping (less reliable but fast)
        if check_port(ip, 623, 2) and check_ping(ip, 2):
            # Both port and ping work - likely online but IPMI might be slow
            return True
        
        return False
    
    def check_single_server(server_data):
        """Check connectivity for a single server (for parallel execution)"""
        bmc_ip, server_name, server_ip = server_data
        try:
            bmc_reachable = check_bmc_reachable(bmc_ip, timeout=5)
            # Use SSH banner check for primary IP (more reliable than just port check)
            primary_reachable = check_ssh(server_ip, timeout=3) if server_ip else None
            return (bmc_ip, server_name, server_ip, bmc_reachable, primary_reachable)
        except:
            return (bmc_ip, server_name, server_ip, False, None)
    
    with app.app_context():
        # Include NULL status for backward compatibility
        servers = Server.query.filter(
            Server.enabled == True,
            db.or_(Server.status == 'active', Server.status.is_(None))
        ).all()
        server_list = [(s.bmc_ip, s.server_name, s.server_ip) for s in servers]
        
        print(f"[Connectivity] Checking {len(server_list)} servers with 20 workers...", flush=True)
        
        # Parallel connectivity checks - 20 workers for fast checking
        from concurrent.futures import ThreadPoolExecutor, as_completed
        results = []
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(check_single_server, s): s for s in server_list}
            for future in as_completed(futures):
                try:
                    results.append(future.result())
                except:
                    pass
        
        online_count = sum(1 for r in results if r[3])  # r[3] is bmc_reachable
        print(f"[Connectivity] Check complete: {online_count} online / {len(results)} checked", flush=True)
        
        # Process results
        for bmc_ip, server_name, server_ip, bmc_reachable, primary_reachable in results:
            server = Server.query.filter_by(bmc_ip=bmc_ip).first()
            if not server:
                continue
                
            try:
                primary_ip = server_ip
                
                # Get previous states
                bmc_key = f"{server.bmc_ip}_bmc"
                primary_key = f"{server.bmc_ip}_primary"
                prev_bmc = _connectivity_states.get(bmc_key)
                prev_primary = _connectivity_states.get(primary_key)
                
                # Determine current status and severity
                if not bmc_reachable and not primary_reachable:
                    current_status = 'system_dark'
                    severity = 'critical'
                elif bmc_reachable and not primary_reachable and primary_ip:
                    current_status = 'os_down'
                    severity = 'warning'
                elif not bmc_reachable and primary_reachable:
                    current_status = 'bmc_down'
                    severity = 'warning'
                else:
                    current_status = 'online'
                    severity = 'info'
                
                # Get previous combined status
                prev_status = _connectivity_states.get(f"{server.bmc_ip}_status")
                
                # Detect status changes
                if prev_status is not None and prev_status != current_status:
                    # Status changed - log event
                    if current_status == 'system_dark':
                        description = "🚨 SYSTEM DARK - Both BMC and OS unreachable"
                        app.logger.critical(f"CRITICAL: {server.server_name} ({server.bmc_ip}) - SYSTEM DARK")
                        report_connectivity_to_ai(server.server_name, server.bmc_ip, 'system_dark')
