#!/usr/bin/env python3
"""
IPMI/BMC Event Monitor
A Flask-based dashboard for monitoring IPMI SEL logs across all servers

GitHub: https://github.com/jjziets/ipmi-monitor
License: MIT
"""

from flask import Flask, render_template, render_template_string, jsonify, request, Response, session, redirect, url_for, make_response
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
import requests
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed

# Suppress SSL warnings for self-signed BMC certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
# Use absolute path for database - data volume is mounted at /app/data
DATA_DIR = os.environ.get('DATA_DIR', '/app/data')
os.makedirs(DATA_DIR, exist_ok=True)
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DATA_DIR}/ipmi_events.db'
app.config['DATA_DIR'] = DATA_DIR
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

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

db = SQLAlchemy(app)

# Branding - customize for your organization
APP_NAME = os.environ.get('APP_NAME', 'IPMI Monitor')

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
# Mount a config file to /app/config/servers.yaml (or .json, .csv)
CONFIG_DIR = os.environ.get('CONFIG_DIR', '/app/config')
SERVERS_CONFIG_FILE = os.environ.get('SERVERS_CONFIG_FILE', '')  # Override specific file

# Setup complete flag
SETUP_COMPLETE_FILE = os.path.join(DATA_DIR, '.setup_complete')

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
        setting = SystemSettings.get('allow_anonymous_read', 'true')
        return setting.lower() == 'true'
    except Exception:
        return True  # Default to allow

def is_api_request():
    """Check if this is an API request that expects JSON"""
    return (request.is_json or 
            request.path.startswith('/api/') or
            request.headers.get('Accept', '').startswith('application/json') or
            request.headers.get('X-Requested-With') == 'XMLHttpRequest')

def admin_required(f):
    """Decorator to require admin login for a route"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
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
        """Get System Event Log entries via Redfish"""
        events = []
        try:
            managers_uri = self.get_managers_uri()
            if not managers_uri:
                return events
            
            managers = self._get(managers_uri)
            if not managers or 'Members' not in managers or not managers['Members']:
                return events
            
            # Get first manager
            manager_uri = managers['Members'][0].get('@odata.id')
            manager = self._get(manager_uri)
            
            if not manager or 'LogServices' not in manager:
                return events
            
            # Get LogServices
            log_services_uri = manager['LogServices'].get('@odata.id')
            log_services = self._get(log_services_uri)
            
            if not log_services or 'Members' not in log_services:
                return events
            
            # Look for SEL or Log service
            for member in log_services['Members']:
                log_uri = member.get('@odata.id', '')
                if 'SEL' in log_uri.upper() or 'LOG' in log_uri.upper():
                    log_service = self._get(log_uri)
                    if log_service and 'Entries' in log_service:
                        entries_uri = log_service['Entries'].get('@odata.id')
                        # Allow longer timeout for large logs
                        entries_resp = self._get(entries_uri, timeout=120)
                        if entries_resp and 'Members' in entries_resp:
                            for entry in entries_resp['Members']:
                                event = self._parse_log_entry(entry)
                                if event:
                                    events.append(event)
                    break
            
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
        """Get memory (DIMM) information via Redfish"""
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
            
            # Get Memory collection
            if 'Memory' in system:
                mem_uri = system['Memory'].get('@odata.id')
                mem_coll = self._get(mem_uri)
                
                if mem_coll and 'Members' in mem_coll:
                    for member in mem_coll['Members']:
                        dimm = self._get(member.get('@odata.id'))
                        if dimm:
                            memory.append({
                                'Id': dimm.get('Id'),
                                'Name': dimm.get('Name', ''),
                                'CapacityMiB': dimm.get('CapacityMiB', 0),
                                'Manufacturer': dimm.get('Manufacturer', ''),
                                'PartNumber': dimm.get('PartNumber', ''),
                                'SerialNumber': dimm.get('SerialNumber', ''),
                                'MemoryType': dimm.get('MemoryDeviceType', dimm.get('MemoryType', '')),
                                'OperatingSpeedMhz': dimm.get('OperatingSpeedMhz'),
                                'Status': dimm.get('Status', {}).get('Health', 'OK')
                            })
            
            return memory
        except Exception as e:
            app.logger.debug(f"Redfish memory failed for {self.host}: {e}")
            return memory
    
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
            
            # Method 3: PCIeDevices - look for NVIDIA/GPU devices
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
                                        
                                        if 'GPU' in dev_type or 'NVIDIA' in manufacturer or 'GPU' in name:
                                            gpus.append({
                                                'name': device.get('Name', 'GPU'),
                                                'manufacturer': device.get('Manufacturer', 'NVIDIA'),
                                                'id': device.get('Id', ''),
                                                'pci_id': device.get('PCIeInterface', {}).get('PCIeType', ''),
                                                'status': device.get('Status', {}).get('Health', 'OK'),
                                            })
            
            if gpus:
                app.logger.info(f"Redfish GPUs for {self.host}: {len(gpus)} found")
            
            return gpus
        except Exception as e:
            app.logger.debug(f"Redfish GPU collection failed for {self.host}: {e}")
            return gpus


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
                    Server.status.in_(['active', None])  # None for backwards compat
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
    notify_telegram = db.Column(db.Boolean, default=True)
    notify_email = db.Column(db.Boolean, default=False)
    notify_webhook = db.Column(db.Boolean, default=False)
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
    password_hash = db.Column(db.String(64), nullable=False)  # SHA256 hash
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
        import hashlib
        return hashlib.sha256(password.encode()).hexdigest()
    
    def verify_password(self, password):
        return self.password_hash == User.hash_password(password)
    
    def is_admin(self):
        return self.role == 'admin'
    
    @staticmethod
    def initialize_default():
        """Create default admin if none exists"""
        admin = User.query.filter_by(role='admin').first()
        if not admin:
            admin = User(
                username='admin',
                password_hash=User.hash_password('admin'),
                role='admin',
                password_changed=False
            )
            db.session.add(admin)
            db.session.commit()
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
        defaults = {
            'allow_anonymous_read': 'true',  # Allow anonymous users to view dashboard
            'session_timeout_hours': '24',
            'enable_ssh_inventory': 'false',  # SSH to OS for detailed inventory (requires SSH creds)
            'collection_workers': 'auto',  # 'auto' = use CPU count, or a fixed number
        }
        for key, value in defaults.items():
            if not SystemSettings.query.filter_by(key=key).first():
                db.session.add(SystemSettings(key=key, value=value))
        db.session.commit()

# Backwards compatibility alias
class AdminConfig(db.Model):
    """Deprecated - use User model instead. Kept for migration."""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False, default='admin')
    password_hash = db.Column(db.String(64), nullable=False)  # SHA256 hash
    password_changed = db.Column(db.Boolean, default=False)  # True after first password change
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    @staticmethod
    def hash_password(password):
        import hashlib
        return hashlib.sha256(password.encode()).hexdigest()
    
    @staticmethod
    def initialize_default():
        """Create default admin if none exists - now uses User model"""
        admin = User.query.filter_by(role='admin').first()
        if not admin:
            admin = User(
                username='admin',
                password_hash=AdminConfig.hash_password('admin'),
                password_changed=False
            )
            db.session.add(admin)
            db.session.commit()
        return admin


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
            'features': self.get_features_list()
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
    # PCIe health (JSON) - collected via lspci -vvv and setpci
    pcie_health = db.Column(db.Text)  # JSON: [{"device": "01:00.0", "name": "GPU", "status": "ok|error", "errors": [...]}]
    pcie_errors_count = db.Column(db.Integer, default=0)  # Count of devices with errors
    # IP addresses
    primary_ip = db.Column(db.String(20))  # OS IP (e.g., 88.0.x.1)
    primary_ip_reachable = db.Column(db.Boolean, default=True)
    primary_ip_last_check = db.Column(db.DateTime)
    # Raw FRU data
    fru_data = db.Column(db.Text)  # Full FRU output for reference
    # Timestamps
    collected_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self):
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
            'network_macs': json.loads(self.network_macs) if self.network_macs else [],
            'storage_info': json.loads(self.storage_info) if self.storage_info else [],
            'gpu_info': json.loads(self.gpu_info) if self.gpu_info else [],
            'gpu_count': self.gpu_count,
            'nic_info': json.loads(self.nic_info) if self.nic_info else [],
            'nic_count': self.nic_count,
            'pcie_health': json.loads(self.pcie_health) if self.pcie_health else [],
            'pcie_errors_count': self.pcie_errors_count or 0,
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


# XID error configurations for UI display
XID_RECOVERY_CONFIGS = {
    8: {'name': 'GPU Reset Detected', 'severity': 'warning', 'actions': ['none']},
    13: {'name': 'Graphics Exception', 'severity': 'warning', 'actions': ['kill_workload', 'soft_reset']},
    31: {'name': 'GPU Memory Page Fault', 'severity': 'critical', 'actions': ['kill_workload', 'soft_reset', 'clock_limit', 'reboot']},
    32: {'name': 'Invalid Push Buffer', 'severity': 'warning', 'actions': ['kill_workload', 'soft_reset']},
    43: {'name': 'GPU Stopped Responding', 'severity': 'critical', 'actions': ['kill_workload', 'soft_reset', 'clock_limit', 'pci_reset', 'reboot']},
    45: {'name': 'Preemptive Cleanup', 'severity': 'critical', 'actions': ['kill_workload', 'soft_reset']},
    48: {'name': 'Double-Bit ECC Error', 'severity': 'critical', 'actions': ['kill_workload', 'reboot', 'maintenance']},
    61: {'name': 'Internal uC Breakpoint', 'severity': 'critical', 'actions': ['power_cycle', 'maintenance']},
    62: {'name': 'Internal uC Halt', 'severity': 'critical', 'actions': ['power_cycle', 'maintenance']},
    63: {'name': 'ECC Page Retirement', 'severity': 'warning', 'actions': ['none']},
    64: {'name': 'ECC DBE Page Retirement', 'severity': 'critical', 'actions': ['reboot', 'maintenance']},
    69: {'name': 'Video Processor Exception', 'severity': 'warning', 'actions': ['kill_workload', 'soft_reset']},
    74: {'name': 'GPU Exception', 'severity': 'critical', 'actions': ['kill_workload', 'soft_reset', 'clock_limit', 'pci_reset', 'reboot']},
    79: {'name': 'GPU Fell Off Bus', 'severity': 'critical', 'actions': ['pci_reset', 'reboot', 'power_cycle', 'maintenance']},
    92: {'name': 'High Single-Bit ECC Rate', 'severity': 'warning', 'actions': ['clock_limit', 'maintenance']},
    94: {'name': 'Contained ECC Error', 'severity': 'warning', 'actions': ['none']},
    95: {'name': 'Uncontained ECC Error', 'severity': 'critical', 'actions': ['reboot', 'maintenance']},
    119: {'name': 'GSP Error', 'severity': 'critical', 'actions': ['soft_reset', 'pci_reset', 'reboot']},
    154: {'name': 'GPU Recovery Action Required', 'severity': 'critical', 'actions': ['soft_reset', 'reboot', 'power_cycle', 'maintenance']},
}


def sync_to_cloud(initial_sync=False):
    """
    Sync data to CryptoLabs AI service.
    Called periodically by background thread.
    
    Args:
        initial_sync: If True, sends 30 days of data instead of 72 hours
    """
    with app.app_context():
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
            
            payload = {
                'servers': [{
                    'name': s.server_name,
                    'bmc_ip': s.bmc_ip,
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
                    'collected_at': inv.collected_at.isoformat() if inv.collected_at else None
                } for inv in inventories]
            }
            
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
    
    with app.app_context():
        servers = Server.query.filter(Server.status == 'active').all()
        
        for server in servers:
            try:
                # Check BMC connectivity (IPMI port 623)
                bmc_reachable = check_port(server.bmc_ip, 623, timeout=2)
                
                # Check Primary/OS IP (SSH port 22)
                primary_ip = server.server_ip
                primary_reachable = check_port(primary_ip, 22, timeout=2) if primary_ip else None
                
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
                        
                    elif current_status == 'os_down':
                        description = "⚠️ OS/Primary IP unreachable (BMC still responding)"
                        app.logger.warning(f"WARNING: {server.server_name} - OS down, BMC up")
                        report_connectivity_to_ai(server.server_name, server.bmc_ip, 'os_down')
                        
                    elif current_status == 'bmc_down':
                        description = "⚠️ BMC/IPMI unreachable (OS still responding)"
                        app.logger.warning(f"WARNING: {server.server_name} - BMC down, OS up")
                        report_connectivity_to_ai(server.server_name, server.bmc_ip, 'bmc_down')
                        
                    elif current_status == 'online':
                        # Recovered - calculate duration
                        offline_start = _connectivity_states.get(f"{server.bmc_ip}_offline_time")
                        duration = None
                        if offline_start:
                            duration = int((datetime.utcnow() - offline_start).total_seconds() / 60)
                        
                        if prev_status == 'system_dark':
                            description = f"✅ System recovered from DARK state (offline {duration or '?'} min)"
                            severity = 'info'
                        elif prev_status == 'os_down':
                            description = f"✅ OS/Primary IP back online (was down {duration or '?'} min)"
                            severity = 'info'
                        elif prev_status == 'bmc_down':
                            description = f"✅ BMC back online (was down {duration or '?'} min)"
                            severity = 'info'
                        else:
                            description = f"✅ System fully online"
                            severity = 'info'
                        
                        app.logger.info(f"RECOVERED: {server.server_name} - {description}")
                        report_connectivity_to_ai(server.server_name, server.bmc_ip, 'online', duration=duration)
                        _connectivity_states.pop(f"{server.bmc_ip}_offline_time", None)
                    
                    # Log the event
                    event = IPMIEvent(
                        bmc_ip=server.bmc_ip,
                        server_name=server.server_name,
                        event_date=datetime.utcnow(),
                        event_description=description,
                        sensor_type="Connectivity",
                        severity=severity
                    )
                    db.session.add(event)
                    db.session.commit()
                    
                    # Evaluate alert rules for this connectivity change
                    try:
                        is_reachable = current_status == 'online'
                        evaluate_alerts_for_server(
                            server.bmc_ip, 
                            server.server_name, 
                            is_reachable, 
                            'Online' if bmc_reachable else 'Unreachable'
                        )
                    except Exception as e:
                        app.logger.debug(f"Alert evaluation failed: {e}")
                
                # Update states
                _connectivity_states[bmc_key] = bmc_reachable
                _connectivity_states[primary_key] = primary_reachable
                _connectivity_states[f"{server.bmc_ip}_status"] = current_status
                
                # Track offline start time
                if current_status != 'online' and prev_status == 'online':
                    _connectivity_states[f"{server.bmc_ip}_offline_time"] = datetime.utcnow()
                    
            except Exception as e:
                app.logger.debug(f"Connectivity check failed for {server.bmc_ip}: {e}")


def auto_sync_to_cloud():
    """
    Auto-sync to AI service if enabled.
    Called by background collector every collection cycle.
    Only syncs if:
    - Sync is enabled
    - License key is set
    - Last sync was more than sync_interval ago
    """
    with app.app_context():
        config = CloudSync.get_config()
        
        # Check if sync is enabled
        if not config.sync_enabled or not config.license_key:
            return
        
        # Check sync interval (default 5 minutes)
        if config.last_sync:
            time_since_sync = (datetime.utcnow() - config.last_sync).total_seconds()
            if time_since_sync < config.sync_interval:
                return  # Not time to sync yet
        
        # Perform sync
        print(f"[IPMI Monitor] Auto-syncing to AI service...", flush=True)
        result = sync_to_cloud()
        
        if result.get('success'):
            print(f"[IPMI Monitor] Auto-sync complete: {result.get('message')}", flush=True)
        else:
            print(f"[IPMI Monitor] Auto-sync failed: {result.get('message')}", flush=True)


def fetch_ai_results():
    """Fetch AI results from cloud service"""
    with app.app_context():
        config = CloudSync.get_config()
        
        if not config.sync_enabled or not config.license_key:
            return None
        
        try:
            response = requests.get(
                f"{config.AI_SERVICE_URL}/api/v1/results",
                headers={'Authorization': f'Bearer {config.license_key}'},
                timeout=30
            )
            
            if response.ok:
                results = response.json()
                
                # Store summary
                if results.get('summary'):
                    AIResult.store_result(
                        'summary',
                        results['summary'],
                        generated_at=results['summary'].get('generated_at')
                    )
                
                # Store tasks
                if results.get('tasks'):
                    AIResult.store_result('tasks', results['tasks'])
                
                # Store predictions
                if results.get('predictions'):
                    AIResult.store_result('predictions', results['predictions'])
                
                return results
        except Exception as e:
            app.logger.error(f"Failed to fetch AI results: {e}")
        
        return None


def validate_license_key(license_key):
    """Validate license key with AI service"""
    try:
        config = CloudSync.get_config()
        response = requests.post(
            f"{config.AI_SERVICE_URL}/api/v1/validate",
            json={'license_key': license_key},
            timeout=10
        )
        
        if response.ok:
            result = response.json()
            return {
                'valid': result.get('valid', False),
                'tier': result.get('tier', 'free'),
                'max_servers': result.get('max_servers', 50),
                'features': result.get('features', [])
            }
    except Exception as e:
        app.logger.error(f"License validation failed: {e}")
    
    return {'valid': False}


# ============== Default Alert Rules ==============

DEFAULT_ALERT_RULES = [
    # Fan alerts
    {
        'name': 'Fan Stopped',
        'description': 'Fan RPM is 0 or critically low - immediate hardware failure risk',
        'alert_type': 'fan',
        'condition': 'lt',
        'threshold': 500,
        'severity': 'critical',
        'cooldown_minutes': 5
    },
    {
        'name': 'Fan Speed Low',
        'description': 'Fan running below normal speed - may indicate bearing failure',
        'alert_type': 'fan',
        'condition': 'lt',
        'threshold': 2000,
        'severity': 'warning',
        'cooldown_minutes': 15
    },
    # Temperature alerts
    {
        'name': 'CPU Temperature Critical',
        'description': 'CPU temperature exceeds safe operating limit - thermal throttling or shutdown imminent',
        'alert_type': 'temperature',
        'condition': 'gt',
        'threshold': 85,
        'severity': 'critical',
        'cooldown_minutes': 5
    },
    {
        'name': 'CPU Temperature Warning',
        'description': 'CPU temperature elevated - check cooling',
        'alert_type': 'temperature',
        'condition': 'gt',
        'threshold': 75,
        'severity': 'warning',
        'cooldown_minutes': 15
    },
    {
        'name': 'System Temperature Critical',
        'description': 'Ambient/inlet temperature too high - check datacenter cooling',
        'alert_type': 'temperature',
        'condition': 'gt',
        'threshold': 45,
        'severity': 'critical',
        'cooldown_minutes': 10
    },
    # Memory alerts - Rate-based tracking per module
    {
        'name': 'ECC Error Rate High (Per Module)',
        'description': 'High rate of correctable ECC errors on specific DIMM - indicates failing memory module. This is a RULE ALERT based on error rate analysis, not a direct BMC event.',
        'alert_type': 'memory_ecc_rate',
        'condition': 'gt',
        'threshold': 10,  # More than 10 errors per hour per module
        'severity': 'warning',
        'cooldown_minutes': 60
    },
    {
        'name': 'ECC Uncorrectable Error',
        'description': 'Uncorrectable memory error detected - data corruption possible. This is a direct BMC event.',
        'alert_type': 'memory_ecc_uncorrectable',
        'condition': 'contains',
        'threshold_str': 'Uncorrectable',
        'severity': 'critical',
        'cooldown_minutes': 5
    },
    # PSU alerts
    {
        'name': 'PSU Failure',
        'description': 'Power supply unit failure detected',
        'alert_type': 'psu',
        'condition': 'contains',
        'threshold_str': 'Failure|failure|failed',
        'severity': 'critical',
        'cooldown_minutes': 5
    },
    {
        'name': 'PSU Redundancy Lost',
        'description': 'Redundant power supply offline - single point of failure',
        'alert_type': 'psu',
        'condition': 'contains',
        'threshold_str': 'Redundancy|redundancy lost|non-redundant',
        'severity': 'critical',
        'cooldown_minutes': 5
    },
    {
        'name': 'Voltage Out of Range',
        'description': 'Power rail voltage outside acceptable range',
        'alert_type': 'voltage',
        'condition': 'contains',
        'threshold_str': 'Lower Critical|Upper Critical|out of range',
        'severity': 'critical',
        'cooldown_minutes': 10
    },
    # PCI/GPU alerts
    {
        'name': 'PCI Device Error',
        'description': 'PCI bus error detected - possible hardware failure',
        'alert_type': 'pci',
        'condition': 'contains',
        'threshold_str': 'PCI|PERR|SERR|Bus Error',
        'severity': 'critical',
        'cooldown_minutes': 10
    },
    {
        'name': 'GPU Error',
        'description': 'GPU or accelerator error detected',
        'alert_type': 'pci',
        'condition': 'contains',
        'threshold_str': 'GPU|Xid|NVSwitch|accelerator',
        'severity': 'critical',
        'cooldown_minutes': 10
    },
    # Server availability
    {
        'name': 'Server Unreachable',
        'description': 'BMC not responding - server may be down or network issue',
        'alert_type': 'server',
        'condition': 'eq',
        'threshold': 0,  # is_reachable = 0
        'severity': 'critical',
        'cooldown_minutes': 5
    },
    {
        'name': 'Server Power Off',
        'description': 'Server powered off unexpectedly',
        'alert_type': 'server_power',
        'condition': 'contains',
        'threshold_str': 'off|Off|OFF',
        'severity': 'critical',
        'cooldown_minutes': 5
    }
]

# Thread locks for global state
import threading as _threading
_sensor_cache_lock = _threading.Lock()
_nvidia_bmcs_lock = _threading.Lock()
_alert_lock = _threading.Lock()

# Alert cooldown tracking (rule_id -> {bmc_ip: last_fired_time})
_alert_cooldowns = {}

# ============== Notification Functions ==============

def get_notification_config(channel_type):
    """Get notification channel configuration"""
    with app.app_context():
        config = NotificationConfig.query.filter_by(channel_type=channel_type).first()
        if config and config.config_json:
            try:
                return json.loads(config.config_json), config.enabled
            except Exception:
                pass
    return {}, False

def send_telegram_notification(message, severity='info'):
    """Send notification via Telegram"""
    try:
        config, enabled = get_notification_config('telegram')
        if not enabled or not config.get('bot_token') or not config.get('chat_id'):
            return False
        
        bot_token = config['bot_token']
        chat_id = config['chat_id']
        
        # Add severity emoji
        emoji_map = {
            'critical': '🚨',
            'warning': '⚠️',
            'info': 'ℹ️'
        }
        emoji = emoji_map.get(severity, 'ℹ️')
        
        full_message = f"{emoji} *IPMI Alert*\n\n{message}"
        
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        payload = {
            'chat_id': chat_id,
            'text': full_message,
            'parse_mode': 'Markdown',
            'disable_web_page_preview': True
        }
        
        response = requests.post(url, json=payload, timeout=10)
        return response.status_code == 200
    except Exception as e:
        app.logger.error(f"Telegram notification failed: {e}")
        return False

def send_email_notification(subject, message, severity='info'):
    """Send notification via Email (SMTP)"""
    try:
        config, enabled = get_notification_config('email')
        if not enabled:
            return False
        
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart
        
        smtp_server = config.get('smtp_server')
        smtp_port = config.get('smtp_port', 587)
        smtp_user = config.get('smtp_user')
        smtp_pass = config.get('smtp_pass')
        from_addr = config.get('from_address', smtp_user)
        to_addrs = config.get('to_addresses', [])
        
        if not smtp_server or not to_addrs:
            return False
        
        msg = MIMEMultipart('alternative')
        msg['Subject'] = f"[{severity.upper()}] {subject}"
        msg['From'] = from_addr
        msg['To'] = ', '.join(to_addrs) if isinstance(to_addrs, list) else to_addrs
        
        # Plain text version
        text_part = MIMEText(message, 'plain')
        msg.attach(text_part)
        
        # HTML version
        severity_colors = {
            'critical': '#ff4757',
            'warning': '#ffaa00',
            'info': '#4a9eff'
        }
        html = f"""
        <html>
        <body style="font-family: Arial, sans-serif;">
            <div style="border-left: 4px solid {severity_colors.get(severity, '#4a9eff')}; padding-left: 15px;">
                <h2 style="color: {severity_colors.get(severity, '#4a9eff')};">IPMI Alert: {severity.upper()}</h2>
                <pre style="background: #f5f5f5; padding: 15px; border-radius: 5px;">{message}</pre>
            </div>
            <p style="color: #888; font-size: 12px;">Sent by {APP_NAME}</p>
        </body>
        </html>
        """
        html_part = MIMEText(html, 'html')
        msg.attach(html_part)
        
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            if config.get('use_tls', True):
                server.starttls()
            if smtp_user and smtp_pass:
                server.login(smtp_user, smtp_pass)
            server.sendmail(from_addr, to_addrs, msg.as_string())
        
        return True
    except Exception as e:
        app.logger.error(f"Email notification failed: {e}")
        return False

def send_webhook_notification(alert_data):
    """Send notification via Webhook (for custom integrations)"""
    try:
        config, enabled = get_notification_config('webhook')
        if not enabled or not config.get('url'):
            return False
        
        url = config['url']
        headers = config.get('headers', {'Content-Type': 'application/json'})
        
        payload = {
            'source': 'ipmi-monitor',
            'timestamp': datetime.utcnow().isoformat(),
            **alert_data
        }
        
        response = requests.post(url, json=payload, headers=headers, timeout=10)
        return response.status_code in [200, 201, 202, 204]
    except Exception as e:
        app.logger.error(f"Webhook notification failed: {e}")
        return False

def send_alert_notifications(alert_history, rule):
    """Send notifications for an alert based on rule configuration"""
    message = f"""
Server: {alert_history.server_name} ({alert_history.bmc_ip})
Alert: {alert_history.rule_name}
Severity: {alert_history.severity.upper()}
Type: {alert_history.alert_type}

{alert_history.message}

Value: {alert_history.value}
Threshold: {alert_history.threshold}
Time: {alert_history.fired_at.strftime('%Y-%m-%d %H:%M:%S UTC')}
"""
    
    # Telegram
    if rule.notify_telegram:
        if send_telegram_notification(message, alert_history.severity):
            alert_history.notified_telegram = True
    
    # Email
    if rule.notify_email:
        subject = f"{alert_history.rule_name} - {alert_history.server_name}"
        if send_email_notification(subject, message, alert_history.severity):
            alert_history.notified_email = True
    
    # Webhook
    if rule.notify_webhook:
        alert_data = {
            'rule_name': alert_history.rule_name,
            'server_name': alert_history.server_name,
            'bmc_ip': alert_history.bmc_ip,
            'severity': alert_history.severity,
            'alert_type': alert_history.alert_type,
            'message': alert_history.message,
            'value': alert_history.value,
            'threshold': alert_history.threshold
        }
        if send_webhook_notification(alert_data):
            alert_history.notified_webhook = True

def check_alert_cooldown(rule_id, bmc_ip, cooldown_minutes):
    """Check if alert is in cooldown period"""
    with _alert_lock:
        key = f"{rule_id}_{bmc_ip}"
        if key in _alert_cooldowns:
            last_fired = _alert_cooldowns[key]
            if datetime.utcnow() - last_fired < timedelta(minutes=cooldown_minutes):
                return True
        return False

def set_alert_cooldown(rule_id, bmc_ip):
    """Set cooldown for an alert"""
    with _alert_lock:
        key = f"{rule_id}_{bmc_ip}"
        _alert_cooldowns[key] = datetime.utcnow()

def evaluate_alert_condition(condition, value, threshold, threshold_str=None):
    """Evaluate if an alert condition is met"""
    try:
        if condition == 'eq':
            return float(value) == float(threshold)
        elif condition == 'lt':
            return float(value) < float(threshold)
        elif condition == 'gt':
            return float(value) > float(threshold)
        elif condition == 'lte':
            return float(value) <= float(threshold)
        elif condition == 'gte':
            return float(value) >= float(threshold)
        elif condition == 'contains' and threshold_str:
            patterns = threshold_str.split('|')
            value_str = str(value).lower()
            return any(p.lower() in value_str for p in patterns)
        return False
    except (ValueError, TypeError):
        return False

def evaluate_alerts_for_event(event, bmc_ip, server_name):
    """Evaluate alert rules for a SEL event"""
    try:
        rules = AlertRule.query.filter_by(enabled=True).all()
        
        # Check event type
        event_desc = event.event_description.lower() if hasattr(event, 'event_description') else str(event).lower()
        sensor_type = event.sensor_type.lower() if hasattr(event, 'sensor_type') else ''
        sensor_number = event.sensor_number if hasattr(event, 'sensor_number') else None
        event_data = event.event_data if hasattr(event, 'event_data') else None  # DIMM location
        
        # For ECC events, prefer DIMM location as identifier, fall back to sensor number
        # DIMM location (e.g., "DIMM G1") is more actionable for replacements
        sensor_id = event_data if event_data else sensor_number
        sensor_name = None
        
        # Extract sensor name from event description if available (e.g., "[CPU1_ECC1]")
        import re
        sensor_match = re.search(r'\[([^\]]+)\]', event.event_description if hasattr(event, 'event_description') else '')
        if sensor_match:
            sensor_name = sensor_match.group(1)
        
        # For ECC errors with DIMM location, use that as the display name
        if event_data and 'dimm' in event_data.lower():
            sensor_name = event_data
        
        # Track ECC errors for rate alerting
        if 'ecc' in event_desc and 'memory' in sensor_type:
            error_type = 'uncorrectable' if 'uncorrectable' in event_desc else 'correctable'
            track_ecc_error(
                bmc_ip=bmc_ip,
                server_name=server_name,
                sensor_id=sensor_id or 'unknown',
                sensor_name=sensor_name or event_data,  # Use DIMM location if available
                error_type=error_type
            )
        
        for rule in rules:
            # Skip if in cooldown
            if check_alert_cooldown(rule.id, bmc_ip, rule.cooldown_minutes):
                continue
            
            triggered = False
            value_str = ''
            
            # Memory ECC rate alerts are handled by track_ecc_error
            if rule.alert_type in ['memory_ecc', 'memory_ecc_rate']:
                continue  # Rate-based alerting is handled separately
                
            # Uncorrectable ECC is always critical - immediate alert
            if rule.alert_type == 'memory_ecc_uncorrectable' and 'uncorrectable' in event_desc:
                triggered = True
                value_str = event_desc
                
            elif rule.alert_type == 'psu' and 'power' in sensor_type:
                triggered = evaluate_alert_condition('contains', event_desc, None, rule.threshold_str)
                value_str = event_desc
                
            elif rule.alert_type == 'voltage' and 'voltage' in sensor_type:
                triggered = evaluate_alert_condition('contains', event_desc, None, rule.threshold_str)
                value_str = event_desc
                
            elif rule.alert_type == 'pci' and ('pci' in event_desc or 'gpu' in event_desc or 'xid' in event_desc):
                triggered = evaluate_alert_condition('contains', event_desc, None, rule.threshold_str)
                value_str = event_desc
            
            if triggered:
                fire_alert(rule, bmc_ip, server_name, value_str, event_desc, sensor_id=sensor_id, source_type='BMC_EVENT')
                
    except Exception as e:
        app.logger.error(f"Error evaluating alerts for event: {e}")

def evaluate_alerts_for_sensor(sensor, bmc_ip, server_name):
    """Evaluate alert rules for a sensor reading"""
    try:
        rules = AlertRule.query.filter_by(enabled=True).all()
        
        for rule in rules:
            if check_alert_cooldown(rule.id, bmc_ip, rule.cooldown_minutes):
                continue
            
            triggered = False
            sensor_type = sensor.sensor_type.lower() if hasattr(sensor, 'sensor_type') else ''
            sensor_name = sensor.sensor_name.lower() if hasattr(sensor, 'sensor_name') else ''
            value = sensor.value if hasattr(sensor, 'value') else None
            
            if value is None:
                continue
            
            # Fan alerts
            if rule.alert_type == 'fan' and sensor_type == 'fan':
                triggered = evaluate_alert_condition(rule.condition, value, rule.threshold)
            
            # Temperature alerts
            elif rule.alert_type == 'temperature' and sensor_type == 'temperature':
                # Only CPU temps for CPU alerts
                if 'cpu' in rule.name.lower() and 'cpu' not in sensor_name:
                    continue
                triggered = evaluate_alert_condition(rule.condition, value, rule.threshold)
            
            if triggered:
                fire_alert(
                    rule, bmc_ip, server_name, 
                    f"{value} {sensor.unit if hasattr(sensor, 'unit') else ''}",
                    f"Sensor: {sensor.sensor_name}"
                )
                
    except Exception as e:
        app.logger.error(f"Error evaluating alerts for sensor: {e}")

def evaluate_alerts_for_server(bmc_ip, server_name, is_reachable, power_status):
    """Evaluate alert rules for server status"""
    try:
        rules = AlertRule.query.filter_by(enabled=True).all()
        
        for rule in rules:
            if check_alert_cooldown(rule.id, bmc_ip, rule.cooldown_minutes):
                continue
            
            triggered = False
            value_str = ''
            
            if rule.alert_type == 'server' and not is_reachable:
                triggered = evaluate_alert_condition('eq', 0, rule.threshold)
                value_str = 'Unreachable'
                
            elif rule.alert_type == 'server_power' and power_status:
                triggered = evaluate_alert_condition('contains', power_status, None, rule.threshold_str)
                value_str = power_status
            
            if triggered:
                fire_alert(rule, bmc_ip, server_name, value_str, f"Server status: {value_str}")
                
    except Exception as e:
        app.logger.error(f"Error evaluating alerts for server: {e}")

def fire_alert(rule, bmc_ip, server_name, value, detail_message, sensor_id=None, source_type='RULE_ALERT'):
    """Fire an alert and send notifications
    
    source_type: 'RULE_ALERT' for alerts triggered by monitoring rules
                 'BMC_EVENT' for alerts directly from BMC SEL
    """
    try:
        with app.app_context():
            # Create alert history record
            alert = AlertHistory(
                rule_id=rule.id,
                rule_name=rule.name,
                bmc_ip=bmc_ip,
                server_name=server_name,
                alert_type=rule.alert_type,
                severity=rule.severity,
                source_type=source_type,
                sensor_id=sensor_id,
                message=f"[{source_type}] {rule.description}\n\n{detail_message}",
                value=str(value),
                threshold=str(rule.threshold or rule.threshold_str)
            )
            
            db.session.add(alert)
            db.session.commit()
            
            # Send notifications
            send_alert_notifications(alert, rule)
            db.session.commit()
            
            # Set cooldown
            set_alert_cooldown(rule.id, bmc_ip)
            
            app.logger.warning(f"Alert fired [{source_type}]: {rule.name} for {server_name} ({bmc_ip})")
            
    except Exception as e:
        app.logger.error(f"Error firing alert: {e}")
        db.session.rollback()

def track_ecc_error(bmc_ip, server_name, sensor_id, sensor_name=None, error_type='correctable'):
    """Track an ECC error for a specific module and check for rate alerting"""
    try:
        with app.app_context():
            # Find or create tracker
            tracker = ECCErrorTracker.query.filter_by(
                bmc_ip=bmc_ip,
                sensor_id=sensor_id,
                error_type=error_type
            ).first()
            
            if not tracker:
                tracker = ECCErrorTracker(
                    bmc_ip=bmc_ip,
                    server_name=server_name,
                    sensor_id=sensor_id,
                    sensor_name=sensor_name,
                    error_type=error_type
                )
                db.session.add(tracker)
            
            # Update counts
            tracker.count_total += 1
            tracker.count_1h += 1
            tracker.count_24h += 1
            tracker.last_error_at = datetime.utcnow()
            tracker.server_name = server_name  # Update in case it changed
            if sensor_name:
                tracker.sensor_name = sensor_name
            
            db.session.commit()
            
            # Check if rate is high enough to alert
            check_ecc_rate_alert(tracker)
            
    except Exception as e:
        app.logger.error(f"Error tracking ECC error: {e}")
        db.session.rollback()

def check_ecc_rate_alert(tracker):
    """Check if ECC error rate warrants an alert"""
    # Get the ECC rate alert rule
    rule = AlertRule.query.filter(
        AlertRule.alert_type.in_(['memory_ecc', 'memory_ecc_rate']),
        AlertRule.enabled == True
    ).first()
    
    if not rule:
        return
    
    threshold = rule.threshold or 10  # Default: 10 errors in 1 hour
    
    # Check if we've exceeded the threshold
    if tracker.count_1h >= threshold:
        # Check cooldown per module
        cooldown_key = f"ecc_{tracker.bmc_ip}_{tracker.sensor_id}"
        if cooldown_key in _alert_cooldowns:
            last_alert = _alert_cooldowns[cooldown_key]
            if datetime.utcnow() - last_alert < timedelta(minutes=rule.cooldown_minutes):
                return  # Still in cooldown
        
        # Fire the alert
        sensor_display = tracker.sensor_name or tracker.sensor_id
        detail = f"""
⚠️ HIGH ECC ERROR RATE DETECTED

Server: {tracker.server_name} ({tracker.bmc_ip})
Memory Module: {sensor_display}
Error Type: {tracker.error_type.upper()}

Error Counts:
  • Last 1 hour: {tracker.count_1h} errors
  • Last 24 hours: {tracker.count_24h} errors  
  • Total: {tracker.count_total} errors

This is a RULE-GENERATED WARNING based on error rate analysis.
It is NOT a direct BMC SEL event.

Recommended Action: Schedule DIMM replacement for {sensor_display}
"""
        
        fire_alert(
            rule=rule,
            bmc_ip=tracker.bmc_ip,
            server_name=tracker.server_name,
            value=f"{tracker.count_1h} errors/hour",
            detail_message=detail,
            sensor_id=tracker.sensor_id,
            source_type='RULE_ALERT'
        )
        
        # Set cooldown for this specific module
        _alert_cooldowns[cooldown_key] = datetime.utcnow()
        tracker.alerted_at = datetime.utcnow()
        db.session.commit()

def reset_hourly_ecc_counts():
    """Reset hourly ECC counts (called periodically)"""
    try:
        with app.app_context():
            ECCErrorTracker.query.update({ECCErrorTracker.count_1h: 0})
            db.session.commit()
    except Exception as e:
        app.logger.error(f"Error resetting hourly ECC counts: {e}")
        db.session.rollback()

def reset_daily_ecc_counts():
    """Reset daily ECC counts (called periodically)"""
    try:
        with app.app_context():
            ECCErrorTracker.query.update({ECCErrorTracker.count_24h: 0})
            db.session.commit()
    except Exception as e:
        app.logger.error(f"Error resetting daily ECC counts: {e}")
        db.session.rollback()
        db.session.rollback()

def initialize_default_alerts():
    """Initialize default alert rules if none exist"""
    with app.app_context():
        try:
            existing = AlertRule.query.count()
            if existing == 0:
                for rule_data in DEFAULT_ALERT_RULES:
                    rule = AlertRule(**rule_data)
                    db.session.add(rule)
                db.session.commit()
                app.logger.info(f"Initialized {len(DEFAULT_ALERT_RULES)} default alert rules")
        except Exception as e:
            app.logger.error(f"Error initializing default alerts: {e}")
            db.session.rollback()

# Sensor name cache (bmc_ip -> {sensor_hex_id: sensor_name})
SENSOR_NAME_CACHE = {}

def get_sensor_name_from_cache(bmc_ip, sensor_hex_id):
    """Look up sensor name from cache only (non-blocking, thread-safe)"""
    if not sensor_hex_id:
        return None
    
    # Clean up hex ID  
    hex_id = sensor_hex_id.replace('#', '').replace('0x', '').upper()
    
    # Check cache with lock
    with _sensor_cache_lock:
        if bmc_ip in SENSOR_NAME_CACHE:
            return SENSOR_NAME_CACHE[bmc_ip].get(hex_id)
    
    return None

def build_sensor_cache(bmc_ip):
    """Build sensor name cache for a BMC (thread-safe)"""
    # Check if already cached
    with _sensor_cache_lock:
        if bmc_ip in SENSOR_NAME_CACHE:
            return True
    
    try:
        user, password = get_ipmi_credentials(bmc_ip)
        # Use 'sdr elist' which shows sensor IDs in hex format
        # Allow 600 seconds - some BMCs are very slow
        cmd = ['ipmitool', '-I', 'lanplus', '-H', bmc_ip, 
               '-U', user, '-P', password, 'sdr', 'elist']
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        
        cache_data = {}
        for line in result.stdout.strip().split('\n'):
            # Format: "CPU1 Temperature | 31h | ok  |  3.0 | 41 degrees C"
            # Or:     "CPU1_ECC1        | D1h | ok  |  0.0 | Presence Detected"
            parts = [p.strip() for p in line.split('|')]
            if len(parts) >= 2:
                sensor_name = parts[0].strip()
                sensor_id_str = parts[1].strip().upper()
                # Extract hex value (e.g., "D1H" -> "D1")
                sensor_id = sensor_id_str.replace('H', '').strip()
                if sensor_id and sensor_name:
                    cache_data[sensor_id] = sensor_name
        
        # Update cache with lock
        with _sensor_cache_lock:
            SENSOR_NAME_CACHE[bmc_ip] = cache_data
        
        app.logger.info(f"Built sensor cache for {bmc_ip}: {len(cache_data)} sensors")
        return True
    except subprocess.TimeoutExpired:
        app.logger.warning(f"Timeout building sensor cache for {bmc_ip}")
        return False
    except Exception as e:
        app.logger.warning(f"Failed to build sensor cache for {bmc_ip}: {e}")
        return False

# Helper functions
def validate_ip_address(ip):
    """Validate IP address format - SECURITY CRITICAL
    
    This function is used to prevent command injection attacks.
    Any string that passes this validation will be safe to use
    in subprocess calls as it can only contain digits and dots.
    """
    if not ip:
        return False
    if not isinstance(ip, str):
        return False
    # Only allow digits and dots (no special chars that could be used for injection)
    if not re.match(r'^[0-9.]+$', ip):
        return False
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(part) <= 255 for part in parts)
    except (ValueError, TypeError):
        return False

def require_valid_bmc_ip(f):
    """Decorator to validate bmc_ip parameter - SECURITY CRITICAL
    
    Use this decorator on any route that takes bmc_ip and uses it
    in subprocess calls or other security-sensitive operations.
    """
    @wraps(f)
    def decorated_function(bmc_ip, *args, **kwargs):
        if not validate_ip_address(bmc_ip):
            return jsonify({'error': 'Invalid BMC IP address format'}), 400
        return f(bmc_ip, *args, **kwargs)
    return decorated_function

def safe_error_message(e, default_msg="An error occurred"):
    """Sanitize exception messages to prevent information leakage
    
    In production, we don't want to expose:
    - File paths
    - Database queries
    - Internal server details
    - Credential-related information
    """
    error_str = str(e).lower()
    # List of patterns that might indicate sensitive information
    sensitive_patterns = ['password', 'credential', 'secret', 'key', 'token', 
                         'sqlite', 'postgresql', '/home/', '/usr/', '/etc/',
                         'traceback', 'file not found', 'permission denied']
    
    for pattern in sensitive_patterns:
        if pattern in error_str:
            app.logger.error(f"Sanitized error (original: {e})")
            return default_msg
    
    # For database errors, be more specific but safe
    if 'sqlalchemy' in error_str or 'database' in error_str:
        return "Database operation failed"
    
    # For relatively safe errors, return the message (but truncate)
    error_msg = str(e)
    if len(error_msg) > 200:
        error_msg = error_msg[:200] + "..."
    
    return error_msg

def classify_severity(event_text):
    """Classify event severity based on keywords"""
    event_lower = event_text.lower()
    
    critical_keywords = ['critical', 'fail', 'fault', 'error', 'non-recoverable', 
                         'power supply ac lost', 'temperature.*upper critical',
                         'voltage.*lower critical', 'voltage.*upper critical']
    warning_keywords = ['warning', 'non-critical', 'predictive', 'threshold']
    
    for keyword in critical_keywords:
        if re.search(keyword, event_lower):
            return 'critical'
    
    for keyword in warning_keywords:
        if re.search(keyword, event_lower):
            return 'warning'
    
    return 'info'

def decode_ecc_event_data(event_data_hex):
    """Decode memory ECC Event Data to extract DIMM info
    
    Event Data format for Memory ECC (IPMI spec):
    - Byte 1: Event type flags
    - Byte 2: Memory bank/module in DIMM (0xff = unspecified)  
    - Byte 3: DIMM number/slot
    
    Returns DIMM identifier if decodable, None otherwise.
    """
    if not event_data_hex or len(event_data_hex) < 6:
        return None
    
    try:
        # Event Data is typically 3 bytes as hex string (e.g., "a0ff18")
        byte1 = int(event_data_hex[0:2], 16)
        byte2 = int(event_data_hex[2:4], 16)
        byte3 = int(event_data_hex[4:6], 16)
        
        # Byte 3 often contains DIMM slot number
        # Common mappings: 0-7 = A-H, 8-15 = A1-H1, etc.
        if byte3 < 8:
            dimm_letter = chr(ord('A') + byte3)
            return f"DIMM {dimm_letter}1"
        elif byte3 < 16:
            dimm_letter = chr(ord('A') + (byte3 - 8))
            return f"DIMM {dimm_letter}2"
        elif byte3 < 24:
            dimm_letter = chr(ord('A') + (byte3 - 16))
            return f"DIMM {dimm_letter}1"
        elif byte3 < 32:
            dimm_letter = chr(ord('A') + (byte3 - 24))
            return f"DIMM {dimm_letter}2"
        else:
            # Return raw slot number if we can't decode
            return f"DIMM Slot {byte3}"
    except (ValueError, IndexError):
        return None


# NVIDIA BMC-specific event descriptions
NVIDIA_SEL_DESCRIPTIONS = {
    # SEL_NV_* events from NVIDIA BMC firmware
    'SEL_NV_AUDIT': {
        'name': 'Security Audit',
        'description': 'BMC security audit event - user login/logout or configuration change',
        'category': 'security'
    },
    'SEL_NV_MAXP_MAXQ': {
        'name': 'Power Mode Change',
        'description': 'GPU power mode changed (MaxP = Maximum Performance, MaxQ = Maximum Efficiency)',
        'category': 'power'
    },
    'SEL_NV_POST_ERR': {
        'name': 'POST Error',
        'description': 'Power-On Self Test error detected during boot sequence',
        'category': 'boot'
    },
    'SEL_NV_BIOS': {
        'name': 'BIOS Event',
        'description': 'BIOS/UEFI firmware event during system initialization',
        'category': 'boot'
    },
    'SEL_NV_CPU': {
        'name': 'CPU Event',
        'description': 'CPU-related event (thermal, error, state change)',
        'category': 'processor'
    },
    'SEL_NV_MEM': {
        'name': 'Memory Event',
        'description': 'Memory subsystem event (ECC, training, configuration)',
        'category': 'memory'
    },
    'SEL_NV_GPU': {
        'name': 'GPU Event',
        'description': 'NVIDIA GPU subsystem event (thermal, power, error)',
        'category': 'gpu'
    },
    'SEL_NV_NVL': {
        'name': 'NVLink Event',
        'description': 'NVLink interconnect event (link status, errors)',
        'category': 'nvlink'
    },
    'SEL_NV_PWR': {
        'name': 'Power Event',
        'description': 'Power subsystem event (PSU, power rail)',
        'category': 'power'
    },
    'SEL_NV_FAN': {
        'name': 'Fan Event',
        'description': 'Cooling fan event (speed, failure)',
        'category': 'cooling'
    },
    'SEL_NV_TEMP': {
        'name': 'Temperature Event',
        'description': 'Temperature threshold event',
        'category': 'thermal'
    },
    'SEL_NV_PCIE': {
        'name': 'PCIe Event',
        'description': 'PCIe bus event (link errors, device detection)',
        'category': 'pcie'
    },
    'SEL_NV_BOOT': {
        'name': 'Boot Event',
        'description': 'System boot/restart event',
        'category': 'boot'
    },
    'SEL_NV_WATCHDOG': {
        'name': 'Watchdog Event',
        'description': 'Hardware watchdog timer event (timeout, reset)',
        'category': 'system'
    },
}

# NVIDIA-specific sensor IDs (hex)
NVIDIA_SENSOR_DESCRIPTIONS = {
    '0xD2': 'NV Sensor D2 (OEM-specific diagnostic sensor)',
    '0xD7': 'NV Sensor D7 (OEM-specific system state sensor)',
    '0xD0': 'NV GPU Status Sensor',
    '0xD1': 'NV GPU Thermal Sensor',
    '0xD3': 'NV NVLink Status Sensor',
    '0xD4': 'NV PCIe Status Sensor',
    '0xD5': 'NV Power Status Sensor',
    '0xD6': 'NV Memory Status Sensor',
    '0xD8': 'NV Fan Status Sensor',
    '0xD9': 'NV System Health Sensor',
}


def decode_nvidia_event(sensor_type, event_desc):
    """Decode NVIDIA-specific BMC events to provide better descriptions"""
    sensor_upper = sensor_type.upper() if sensor_type else ''
    desc_upper = event_desc.upper() if event_desc else ''
    
    enhanced_info = []
    category = 'system'
    
    # Check for SEL_NV_* patterns in sensor type
    for key, info in NVIDIA_SEL_DESCRIPTIONS.items():
        if key in sensor_upper or key in desc_upper:
            enhanced_info.append(f"[{info['name']}]")
            enhanced_info.append(info['description'])
            category = info['category']
            break
    
    # Check for sensor ID patterns - handles [Sensor 0xD2] or Sensor 0xD2
    sensor_id_match = re.search(r'(?:\[)?Sensor\s*(0x[A-F0-9]+)(?:\])?', event_desc, re.IGNORECASE)
    if sensor_id_match:
        sensor_id = '0x' + sensor_id_match.group(1).replace('0x', '').replace('0X', '').upper()
        if sensor_id in NVIDIA_SENSOR_DESCRIPTIONS:
            enhanced_info.append(f"({NVIDIA_SENSOR_DESCRIPTIONS[sensor_id]})")
        else:
            # Even if not in our list, provide some context
            enhanced_info.append(f"(NVIDIA OEM Sensor {sensor_id})")
    
    return {
        'enhanced_desc': ' '.join(enhanced_info) if enhanced_info else None,
        'category': category
    }


def parse_sel_line(line, bmc_ip, server_name):
    """Parse a single SEL log line with extended details for ECC events
    
    The elist format can vary:
    Format 1: "37dd | 11/30/25 | 14:27:12 | Memory #0xD1 | Correctable ECC | Asserted"
    Format 2: "37dd | 11/30/25 | 14:27:12 | Memory #0xD1 | Correctable ECC | Asserted | DIMM_G1"
    Format 3 (verbose): "CPU1_ECC1        | 11/30/25 | 14:27:12 | Memory #0xD1 | Correctable ECC logging limit reached | Asserted | DIMM G1"
    """
    try:
        parts = [p.strip() for p in line.split('|')]
        if len(parts) >= 5:
            sel_id = parts[0].strip()
            date_str = parts[1].strip()
            time_str = parts[2].strip().split()[0]  # Remove timezone
            sensor_info = parts[3].strip()
            
            # Collect all remaining parts for event description
            remaining_parts = parts[4:]
            event_desc = ' | '.join(remaining_parts)
            
            # Parse date - handle both MM/DD/YY and MM/DD/YYYY
            try:
                if len(date_str.split('/')[-1]) == 2:
                    event_date = datetime.strptime(f"{date_str} {time_str}", "%m/%d/%y %H:%M:%S")
                else:
                    event_date = datetime.strptime(f"{date_str} {time_str}", "%m/%d/%Y %H:%M:%S")
            except ValueError:
                event_date = datetime.utcnow()
            
            # Extract sensor type, ID and number
            # Pattern: "Memory #0x53" or "CPU Temp" or "Fan1 #0x30"
            sensor_match = re.match(r'(.+?)\s*(#0x[a-fA-F0-9]+)?$', sensor_info)
            sensor_type = sensor_match.group(1).strip() if sensor_match else sensor_info
            sensor_id = sensor_match.group(2) if sensor_match and sensor_match.group(2) else ''
            
            # Extract sensor number and name from hex ID
            sensor_number = ''
            sensor_name_lookup = ''
            if sensor_id:
                try:
                    hex_id = sensor_id.replace('#', '').replace('0x', '').upper()
                    sensor_num = int(hex_id, 16)
                    sensor_number = f"0x{hex_id}"
                    # Try to look up the actual sensor name from cache (if available)
                    sensor_name_lookup = get_sensor_name_from_cache(bmc_ip, hex_id)
                    # Fallback: For common ECC sensors, infer name from ID
                    # 0xD1 = CPU1_ECC1, 0xD2 = CPU2_ECC1 (common on ASUS/ASRock boards)
                    if not sensor_name_lookup and 'memory' in sensor_type.lower():
                        if hex_id == 'D1':
                            sensor_name_lookup = 'CPU1_ECC1'
                        elif hex_id == 'D2':
                            sensor_name_lookup = 'CPU2_ECC1'
                        elif hex_id == 'D3':
                            sensor_name_lookup = 'CPU1_ECC2'
                        elif hex_id == 'D4':
                            sensor_name_lookup = 'CPU2_ECC2'
                except (ValueError, TypeError) as e:
                    sensor_number = sensor_id
                    app.logger.debug(f"Could not parse sensor ID {sensor_id}: {e}")
            
            # For Memory/ECC events, extract DIMM info from remaining parts
            event_direction = ''
            event_data = ''
            dimm_location = ''
            
            for part in remaining_parts:
                part_stripped = part.strip()
                part_lower = part_stripped.lower()
                
                if 'asserted' in part_lower and 'deasserted' not in part_lower:
                    event_direction = 'Asserted'
                elif 'deasserted' in part_lower:
                    event_direction = 'Deasserted'
                
                # Look for DIMM identifiers - multiple patterns
                # Pattern 1: "DIMM_G1" or "DIMM G1" or "DIMM_A1"
                # Pattern 2: "DIMMG1" (no separator)
                # Pattern 3: Just "G1" or "A1" at end of parts
                dimm_match = re.search(r'DIMM[_\s]?([A-Z]\d+|[A-Z][A-Z]?\d+)', part_stripped, re.IGNORECASE)
                if dimm_match:
                    dimm_location = f"DIMM {dimm_match.group(1).upper()}"
                    event_data = dimm_location
                # Also check for "at DIMM" pattern in verbose format
                elif 'at dimm' in part_lower:
                    at_match = re.search(r'at\s+DIMM\s*([A-Z]\d+|[A-Z][A-Z]?\d+)', part_stripped, re.IGNORECASE)
                    if at_match:
                        dimm_location = f"DIMM {at_match.group(1).upper()}"
                        event_data = dimm_location
            
            # Build enhanced description
            base_event = remaining_parts[0] if remaining_parts else event_desc
            enhanced_parts = [base_event]
            
            # Add direction
            if event_direction and event_direction not in base_event:
                enhanced_parts.append(event_direction)
            
            # Add DIMM location prominently for ECC events
            if dimm_location and ('ecc' in event_desc.lower() or 'memory' in sensor_type.lower()):
                enhanced_parts.append(f"**{dimm_location}**")
            elif dimm_location:
                enhanced_parts.append(dimm_location)
            
            # Add sensor name/number for identification
            if sensor_name_lookup:
                enhanced_parts.append(f"[{sensor_name_lookup}]")
            elif sensor_number:
                enhanced_parts.append(f"[Sensor {sensor_number}]")
            
            # Check for NVIDIA-specific events (SEL_NV_* or Unknown sensors)
            if 'SEL_NV' in sensor_type.upper() or 'Unknown' in sensor_type:
                nvidia_info = decode_nvidia_event(sensor_type, event_desc)
                if nvidia_info.get('enhanced_desc'):
                    enhanced_parts.append(nvidia_info['enhanced_desc'])
            
            enhanced_desc = ' | '.join(enhanced_parts)
            
            severity = classify_severity(event_desc)
            
            return IPMIEvent(
                bmc_ip=bmc_ip,
                server_name=server_name,
                sel_id=sel_id,
                event_date=event_date,
                sensor_type=sensor_type,
                sensor_id=sensor_id,
                sensor_number=sensor_number,
                event_description=enhanced_desc,
                event_direction=event_direction,
                event_data=event_data,  # This now stores the DIMM location
                severity=severity,
                raw_entry=line
            )
    except Exception as e:
        app.logger.error(f"Failed to parse SEL line: {line} - {e}")
    return None

def get_ipmi_credentials(bmc_ip):
    """Get IPMI credentials for a BMC (per-server config or defaults)"""
    with app.app_context():
        # First check for per-server custom credentials
        config = ServerConfig.query.filter_by(bmc_ip=bmc_ip).first()
        if config and config.ipmi_user and config.ipmi_pass:
            return config.ipmi_user, config.ipmi_pass
        
        # Check if server has use_nvidia_password flag set in database
        server = Server.query.filter_by(bmc_ip=bmc_ip).first()
        if server and server.use_nvidia_password:
            return IPMI_USER, IPMI_PASS_NVIDIA
    
    # Fall back to defaults - check environment variable
    password = IPMI_PASS_NVIDIA if bmc_ip in NVIDIA_BMCS else IPMI_PASS
    return IPMI_USER, password

def get_ipmi_password(bmc_ip):
    """Get the correct password for a BMC (legacy function)"""
    _, password = get_ipmi_credentials(bmc_ip)
    return password

def get_server_protocol(bmc_ip):
    """Get the protocol preference for a server (auto, ipmi, redfish)"""
    with app.app_context():
        try:
            server = Server.query.filter_by(bmc_ip=bmc_ip).first()
            if server and server.protocol:
                return server.protocol
        except Exception:
            pass
    return 'auto'

def should_use_redfish(bmc_ip):
    """Determine if we should use Redfish for this BMC"""
    protocol = get_server_protocol(bmc_ip)
    
    if protocol == 'ipmi':
        return False
    elif protocol == 'redfish':
        return True
    else:  # 'auto' - check cache first, then probe
        with _redfish_cache_lock:
            if bmc_ip in _redfish_cache:
                return _redfish_cache[bmc_ip]
        
        # Probe for Redfish
        available = check_redfish_available(bmc_ip)
        with _redfish_cache_lock:
            _redfish_cache[bmc_ip] = available
        return available

def get_redfish_client(bmc_ip):
    """Get a Redfish client for the given BMC"""
    user, password = get_ipmi_credentials(bmc_ip)
    return RedfishClient(bmc_ip, user, password)

# ============== Collection Functions (with Redfish support) ==============

def collect_sel_redfish(bmc_ip, server_name):
    """Collect SEL via Redfish"""
    try:
        client = get_redfish_client(bmc_ip)
        rf_events = client.get_sel_entries()
        
        events = []
        for evt in rf_events:
            event = IPMIEvent(
                bmc_ip=bmc_ip,
                server_name=server_name,
                sel_id=evt.get('sel_id', ''),
                event_date=evt.get('event_date', datetime.utcnow()),
                sensor_type=evt.get('sensor_type', 'System'),
                event_description=evt.get('event_description', ''),
                severity=evt.get('severity', 'info'),
                raw_entry=evt.get('raw_entry', '')
            )
            events.append(event)
        
        return events
    except Exception as e:
        app.logger.error(f"Redfish SEL collection failed for {bmc_ip}: {e}")
        return []

def decode_threshold_event_data(event_data_hex, sensor_type, sensor_name=''):
    """Decode threshold event data (Temperature, Voltage, Power)
    
    Event Data format for Threshold events:
    - Byte 1 [7:6]: Event Data byte definitions
        00 = unspecified, 01 = trigger in byte2/threshold in byte3
    - Byte 1 [5:4]: Threshold type (00=LNC, 01=LC, 02=LNR, 04=UNC, 05=UC, 06=UNR)
    - Byte 1 [3:0]: Event type offset
    - Byte 2: Trigger reading (raw sensor value when event occurred)
    - Byte 3: Threshold value that was crossed
    """
    if not event_data_hex or len(event_data_hex) < 6:
        return ''
    
    try:
        event_data_hex = event_data_hex.strip().lower()
        byte1 = int(event_data_hex[0:2], 16)
        byte2 = int(event_data_hex[2:4], 16)
        byte3 = int(event_data_hex[4:6], 16)
        
        # Check if bytes 2&3 contain trigger/threshold (bit 6 set, bit 7 clear)
        if (byte1 & 0xC0) != 0x40:
            return ''
        
        # Decode based on sensor type
        sensor_lower = sensor_type.lower()
        
        if 'temperature' in sensor_lower:
            # Temperature sensors typically report in degrees C directly
            return f'Reading: {byte2}°C, Threshold: {byte3}°C'
        
        elif 'voltage' in sensor_lower:
            # Voltage requires conversion - depends on sensor
            # Common ASUS formula: voltage = raw * factor + offset
            # For 12V rail: typical factor is ~0.06V/unit
            # For 3.3V/5V: typical factor is ~0.02V/unit
            sensor_name_lower = sensor_name.lower() if sensor_name else ''
            
            if '12v' in sensor_name_lower:
                trigger_v = byte2 * 0.06
                thresh_v = byte3 * 0.06
            elif '5v' in sensor_name_lower:
                trigger_v = byte2 * 0.024
                thresh_v = byte3 * 0.024
            elif '3.3v' in sensor_name_lower or '3v3' in sensor_name_lower:
                trigger_v = byte2 * 0.016
                thresh_v = byte3 * 0.016
            else:
                # Unknown voltage, show raw values
                return f'Reading: {byte2} raw, Threshold: {byte3} raw'
            
            return f'Reading: {trigger_v:.2f}V, Threshold: {thresh_v:.2f}V'
        
        elif 'power' in sensor_lower:
            # Power supply events - values are often watts or percentage
            return f'Reading: {byte2}W, Threshold: {byte3}W'
        
        return ''
    except (ValueError, IndexError):
        return ''

def decode_psu_event(sensor_number, description, sensor_name=''):
    """Decode Power Supply event to identify which PSU
    
    Common PSU sensor mappings on ASUS boards:
    - 0x94: PSU1 AC Lost
    - 0x95: PSU1 Slow FAN
    - 0x97: PSU1 PWR Detect
    - 0x9A: PSU2 Over Temp  
    - 0x9C: PSU2 AC Lost
    - 0x9D: PSU2 Slow FAN
    - 0x9F: PSU2 PWR Detect
    """
    try:
        sensor_num = int(sensor_number, 16) if sensor_number else 0
        
        # Determine PSU number from sensor
        if sensor_name:
            if 'psu1' in sensor_name.lower():
                psu_num = 1
            elif 'psu2' in sensor_name.lower():
                psu_num = 2
            else:
                psu_num = None
        elif 0x90 <= sensor_num <= 0x99:
            psu_num = 1
        elif 0x9A <= sensor_num <= 0x9F:
            psu_num = 2
        elif sensor_num in [0xE1, 0xE2]:
            # E1 and E2 are often aggregate PSU power sensors
            psu_num = sensor_num - 0xE0
        else:
            psu_num = None
        
        if psu_num:
            return f'PSU{psu_num}'
        return ''
    except (ValueError, TypeError):
        return ''

def decode_drive_event(sensor_number, sensor_name=''):
    """Decode Drive Slot event to identify which drive bay
    
    Common mappings:
    - 0x68-0x6F: Backplane1 HD01-HD08
    - 0x70-0x77: Backplane2 HD01-HD08 (if present)
    """
    try:
        sensor_num = int(sensor_number, 16) if sensor_number else 0
        
        # Use sensor name if available
        if sensor_name:
            return sensor_name
        
        # Fall back to calculating from sensor number
        if 0x68 <= sensor_num <= 0x6F:
            drive_num = sensor_num - 0x67
            return f'Drive Bay {drive_num}'
        elif 0x70 <= sensor_num <= 0x77:
            drive_num = sensor_num - 0x6F
            return f'Drive Bay {drive_num + 8}'
        
        return ''
    except (ValueError, TypeError):
        return ''

def parse_verbose_sel_record(record_lines, bmc_ip, server_name):
    """Parse a single verbose SEL record (multiple lines) into an IPMIEvent"""
    try:
        data = {}
        for line in record_lines:
            if ':' in line:
                key, value = line.split(':', 1)
                data[key.strip()] = value.strip()
        
        if not data.get('SEL Record ID'):
            return None
        
        sel_id = data.get('SEL Record ID', '').strip()
        timestamp = data.get('Timestamp', '')
        sensor_type = data.get('Sensor Type', 'Unknown')
        sensor_number = data.get('Sensor Number', '')
        event_direction = data.get('Event Direction', '')
        event_data_hex = data.get('Event Data', '')
        description = data.get('Description', '')
        event_type = data.get('Event Type', '')
        
        # Parse timestamp - format: "11/30/25 11/30/25" (date repeated)
        event_date = datetime.utcnow()
        if timestamp:
            try:
                date_part = timestamp.split()[0]
                parts = date_part.split('/')
                if len(parts) == 3:
                    if len(parts[2]) == 2:
                        event_date = datetime.strptime(date_part, "%m/%d/%y")
                    else:
                        event_date = datetime.strptime(date_part, "%m/%d/%Y")
            except (ValueError, IndexError):
                pass
        
        # Get sensor name from cache
        sensor_name_lookup = ''
        if sensor_number:
            hex_id = sensor_number.upper()
            sensor_name_lookup = get_sensor_name_from_cache(bmc_ip, hex_id)
            # Fallback for common ECC sensors
            if not sensor_name_lookup and 'memory' in sensor_type.lower():
                if hex_id == 'D1':
                    sensor_name_lookup = 'CPU1_ECC1'
                elif hex_id == 'D2':
                    sensor_name_lookup = 'CPU2_ECC1'
        
        # Build enhanced description based on sensor type
        enhanced_parts = [description]
        extra_info = ''
        event_data_decoded = ''
        
        sensor_type_lower = sensor_type.lower()
        
        # Decode event-specific details from Event Data
        if 'memory' in sensor_type_lower and event_data_hex:
            # ECC/Memory events - decode DIMM location
            dimm_location = decode_dimm_from_event_data(event_data_hex)
            if dimm_location:
                extra_info = f'**{dimm_location}**'
                event_data_decoded = dimm_location
        
        elif ('temperature' in sensor_type_lower or 'voltage' in sensor_type_lower) and 'threshold' in event_type.lower():
            # Threshold events - decode reading and threshold values
            threshold_info = decode_threshold_event_data(event_data_hex, sensor_type, sensor_name_lookup)
            if threshold_info:
                extra_info = f'({threshold_info})'
                event_data_decoded = threshold_info
        
        elif 'power supply' in sensor_type_lower:
            # PSU events - identify which PSU
            psu_info = decode_psu_event(sensor_number, description, sensor_name_lookup)
            if psu_info:
                extra_info = f'[{psu_info}]'
                event_data_decoded = psu_info
            # Also decode threshold if applicable
            if 'threshold' in event_type.lower() and event_data_hex:
                threshold_info = decode_threshold_event_data(event_data_hex, sensor_type, sensor_name_lookup)
                if threshold_info:
                    extra_info += f' ({threshold_info})'
        
        elif 'drive' in sensor_type_lower:
            # Drive slot events - identify which drive bay
            drive_info = decode_drive_event(sensor_number, sensor_name_lookup)
            if drive_info:
                extra_info = f'[{drive_info}]'
                event_data_decoded = drive_info
        
        # Add direction
        if 'assertion' in event_direction.lower() and 'deassertion' not in event_direction.lower():
            enhanced_parts.append('Asserted')
        elif 'deassertion' in event_direction.lower():
            enhanced_parts.append('Deasserted')
        
        # Add extra decoded info
        if extra_info:
            enhanced_parts.append(extra_info)
        
        # Add sensor name (except for PSU which already has it)
        if sensor_name_lookup and 'power supply' not in sensor_type_lower:
            enhanced_parts.append(f'[{sensor_name_lookup}]')
        elif sensor_number and not extra_info:
            enhanced_parts.append(f'[Sensor 0x{sensor_number.upper()}]')
        
        enhanced_desc = ' | '.join(enhanced_parts)
        severity = classify_severity(description)
        
        return IPMIEvent(
            bmc_ip=bmc_ip,
            server_name=server_name,
            sel_id=sel_id,
            event_date=event_date,
            sensor_type=sensor_type,
            sensor_id=f'#0x{sensor_number}' if sensor_number else '',
            sensor_number=f'0x{sensor_number.upper()}' if sensor_number else '',
            event_description=enhanced_desc,
            event_direction='Asserted' if 'assertion' in event_direction.lower() and 'deassertion' not in event_direction.lower() else 'Deasserted' if 'deassertion' in event_direction.lower() else '',
            event_data=event_data_decoded,  # Store decoded info
            severity=severity,
            raw_entry='|'.join(record_lines)
        )
    except Exception as e:
        app.logger.error(f"Failed to parse verbose SEL record: {e}")
        return None

def decode_dimm_from_event_data(event_data_hex):
    """Decode DIMM slot from IPMI Memory Event Data
    
    Event Data format for Memory ECC (per IPMI spec):
    - Byte 1 [7:4]: Event type indicator  
    - Byte 1 [3:0]: Memory module/DIMM index (0-15)
    - Byte 2: OEM data (often 0xFF)
    - Byte 3: DIMM slot number (vendor-specific)
    
    Common ASUS/ASRock mappings for 8-DIMM dual-CPU systems:
    - 0x00-0x07: CPU0 DIMMs A-H (rank 1)
    - 0x08-0x0F: CPU0 DIMMs A-H (rank 2) 
    - 0x10-0x17: CPU1 DIMMs A-H (rank 1)
    - 0x18-0x1F: CPU1 DIMMs A-H (rank 2)
    """
    if not event_data_hex or len(event_data_hex) < 6:
        return ''
    
    try:
        event_data_hex = event_data_hex.strip().lower()
        byte1 = int(event_data_hex[0:2], 16)
        byte2 = int(event_data_hex[2:4], 16)
        byte3 = int(event_data_hex[4:6], 16)
        
        dimm_letters = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H']
        
        # Decode based on common ASUS/ASRock dual-CPU encoding
        slot_in_group = byte3 % 8
        group = byte3 // 8
        
        if slot_in_group < len(dimm_letters):
            dimm_letter = dimm_letters[slot_in_group]
            
            # Determine CPU and rank from group
            # Groups 0,1 = CPU0; Groups 2,3 = CPU1
            # Even groups = rank 1; Odd groups = rank 2
            if group == 0:
                return f'DIMM {dimm_letter}1'  # CPU0, rank 1
            elif group == 1:
                return f'DIMM {dimm_letter}2'  # CPU0, rank 2  
            elif group == 2:
                return f'DIMM {dimm_letter}1 (CPU1)'  # CPU1, rank 1
            elif group == 3:
                return f'DIMM {dimm_letter}2 (CPU1)'  # CPU1, rank 2
            else:
                # Higher groups - just show letter with slot for clarity
                return f'DIMM {dimm_letter} (Slot {byte3})'
        
        return f'DIMM Slot {byte3}'
    except (ValueError, IndexError) as e:
        app.logger.debug(f"Could not decode DIMM from event data {event_data_hex}: {e}")
        return ''

def collect_ipmi_sel(bmc_ip, server_name):
    """Collect IPMI SEL from a single server using elist for timestamps and verbose for details"""
    try:
        user, password = get_ipmi_credentials(bmc_ip)
        
        # Use elist format first - it has proper timestamps with time
        # Allow 600 seconds (10 min) for large SEL logs - some BMCs are very slow
        result = subprocess.run(
            ['ipmitool', '-I', 'lanplus', '-H', bmc_ip, 
             '-U', user, '-P', password, 'sel', 'elist'],
            capture_output=True, text=True, timeout=600
        )
        
        if result.returncode != 0:
            app.logger.warning(f"IPMI SEL elist failed for {bmc_ip}: {result.stderr}")
            return []
        
        # Parse elist format - has proper timestamps
        events = []
        for line in result.stdout.strip().split('\n'):
            if line.strip():
                event = parse_sel_line(line, bmc_ip, server_name)
                if event:
                    events.append(event)
        
        # For memory events without DIMM info, try to get from verbose output
        memory_events = [e for e in events if 'memory' in e.sensor_type.lower() and not e.event_data]
        if memory_events:
            try:
                # Get verbose output for DIMM details
                verbose_result = subprocess.run(
                    ['ipmitool', '-I', 'lanplus', '-H', bmc_ip, 
                     '-U', user, '-P', password, 'sel', 'list', '-v'],
                    capture_output=True, text=True, timeout=300
                )
                if verbose_result.returncode == 0:
                    # Parse verbose to get event data mapping by SEL ID
                    dimm_map = {}
                    current_record = []
                    for line in verbose_result.stdout.split('\n'):
                        if line.strip():
                            current_record.append(line.strip())
                        elif current_record:
                            # Parse this record for SEL ID and Event Data
                            record_data = {}
                            for rec_line in current_record:
                                if ':' in rec_line:
                                    key, value = rec_line.split(':', 1)
                                    record_data[key.strip()] = value.strip()
                            sel_id = record_data.get('SEL Record ID', '').strip().lower()
                            event_data_hex = record_data.get('Event Data', '')
                            if sel_id and event_data_hex and 'Memory' in record_data.get('Sensor Type', ''):
                                dimm_location = decode_dimm_from_event_data(event_data_hex)
                                if dimm_location:
                                    dimm_map[sel_id] = dimm_location
                            current_record = []
                    
                    # Update memory events with DIMM info
                    for event in memory_events:
                        sel_id_lower = event.sel_id.lower()
                        if sel_id_lower in dimm_map:
                            dimm_loc = dimm_map[sel_id_lower]
                            event.event_data = dimm_loc
                            # Update description to include DIMM
                            if dimm_loc not in event.event_description:
                                parts = event.event_description.split(' | ')
                                # Insert DIMM info before sensor name tag
                                if parts and parts[-1].startswith('['):
                                    parts.insert(-1, f'**{dimm_loc}**')
                                else:
                                    parts.append(f'**{dimm_loc}**')
                                event.event_description = ' | '.join(parts)
            except Exception as e:
                app.logger.debug(f"Could not get verbose DIMM details for {bmc_ip}: {e}")
        
        return events
    except subprocess.TimeoutExpired:
        app.logger.warning(f"IPMI timeout for {bmc_ip}")
        return []
    except Exception as e:
        app.logger.error(f"Error collecting from {bmc_ip}: {e}")
        return []

def collect_sel(bmc_ip, server_name):
    """Unified SEL collection - chooses Redfish or IPMI based on config/availability"""
    if should_use_redfish(bmc_ip):
        app.logger.debug(f"Using Redfish for {bmc_ip}")
        events = collect_sel_redfish(bmc_ip, server_name)
        if events:
            return events
        # Fall back to IPMI if Redfish returns nothing
        app.logger.debug(f"Redfish returned no events for {bmc_ip}, falling back to IPMI")
    
    return collect_ipmi_sel(bmc_ip, server_name)

def collect_power_status_redfish(bmc_ip):
    """Get power status via Redfish"""
    try:
        client = get_redfish_client(bmc_ip)
        status = client.get_power_status()
        if status:
            return status
        return None
    except Exception as e:
        app.logger.debug(f"Redfish power status failed for {bmc_ip}: {e}")
        return None

def collect_power_status(bmc_ip):
    """Get power status from BMC (tries Redfish first if available)"""
    # Try Redfish first
    if should_use_redfish(bmc_ip):
        status = collect_power_status_redfish(bmc_ip)
        if status:
            return status
    
    # Fall back to IPMI
    try:
        user, password = get_ipmi_credentials(bmc_ip)
        result = subprocess.run(
            ['ipmitool', '-I', 'lanplus', '-H', bmc_ip,
             '-U', user, '-P', password, 'power', 'status'],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            return result.stdout.strip()
        return 'Unknown'
    except subprocess.TimeoutExpired:
        app.logger.debug(f"Timeout getting power status for {bmc_ip}")
        return 'Unreachable'
    except Exception as e:
        app.logger.debug(f"Error getting power status for {bmc_ip}: {e}")
        return 'Unreachable'

def collect_sensors_redfish(bmc_ip, server_name):
    """Collect sensor readings via Redfish"""
    sensors = []
    try:
        client = get_redfish_client(bmc_ip)
        
        # Get thermal sensors (temps and fans)
        thermal = client.get_thermal()
        for s in thermal:
            sensor = SensorReading(
                bmc_ip=bmc_ip,
                server_name=server_name,
                sensor_name=s.get('sensor_name', 'Unknown'),
                sensor_type=s.get('sensor_type'),
                value=s.get('value'),
                unit=s.get('unit', ''),
                status=s.get('status', 'ok'),
                upper_critical=s.get('upper_critical'),
                upper_warning=s.get('upper_warning'),
                lower_warning=s.get('lower_warning'),
                lower_critical=s.get('lower_critical'),
                collected_at=datetime.utcnow()
            )
            sensors.append(sensor)
        
        # Get power/voltage sensors
        power_data, voltages = client.get_power()
        for v in voltages:
            sensor = SensorReading(
                bmc_ip=bmc_ip,
                server_name=server_name,
                sensor_name=v.get('sensor_name', 'Unknown'),
                sensor_type='voltage',
                value=v.get('value'),
                unit='Volts',
                status=v.get('status', 'ok'),
                upper_critical=v.get('upper_critical'),
                upper_warning=v.get('upper_warning'),
                lower_warning=v.get('lower_warning'),
                lower_critical=v.get('lower_critical'),
                collected_at=datetime.utcnow()
            )
            sensors.append(sensor)
        
        return sensors, power_data
    except Exception as e:
        app.logger.debug(f"Redfish sensor collection failed for {bmc_ip}: {e}")
        return sensors, None

def collect_sensors(bmc_ip, server_name):
    """Collect sensor readings from BMC"""
    sensors = []
    try:
        user, password = get_ipmi_credentials(bmc_ip)
        # NVIDIA BMCs with 180+ sensors can take 40+ seconds
        result = subprocess.run(
            ['ipmitool', '-I', 'lanplus', '-H', bmc_ip,
             '-U', user, '-P', password, 'sensor', 'list'],
            capture_output=True, text=True, timeout=120
        )
        if result.returncode != 0:
            return sensors
        
        for line in result.stdout.strip().split('\n'):
            parts = [p.strip() for p in line.split('|')]
            if len(parts) >= 3:
                sensor_name = parts[0]
                value_str = parts[1]
                unit = parts[2] if len(parts) > 2 else ''
                status = parts[3] if len(parts) > 3 else 'ok'
                
                # Parse value
                try:
                    value = float(value_str) if value_str and value_str != 'na' else None
                except ValueError:
                    value = None
                
                # Determine sensor type
                sensor_type = 'other'
                unit_lower = unit.lower() if unit else ''
                name_lower = sensor_name.lower()
                
                if 'degrees c' in unit_lower or 'temp' in name_lower:
                    sensor_type = 'temperature'
                elif 'rpm' in unit_lower or 'fan' in name_lower:
                    sensor_type = 'fan'
                elif 'volts' in unit_lower or 'volt' in name_lower:
                    sensor_type = 'voltage'
                elif 'watts' in unit_lower or 'power' in name_lower:
                    sensor_type = 'power'
                elif 'amps' in unit_lower:
                    sensor_type = 'current'
                
                # Parse thresholds if available
                lc = float(parts[4]) if len(parts) > 4 and parts[4] and parts[4] != 'na' else None
                lw = float(parts[5]) if len(parts) > 5 and parts[5] and parts[5] != 'na' else None
                uw = float(parts[7]) if len(parts) > 7 and parts[7] and parts[7] != 'na' else None
                uc = float(parts[8]) if len(parts) > 8 and parts[8] and parts[8] != 'na' else None
                
                sensor = SensorReading(
                    bmc_ip=bmc_ip,
                    server_name=server_name,
                    sensor_name=sensor_name,
                    sensor_type=sensor_type,
                    value=value,
                    unit=unit,
                    status=status.lower() if status else 'ok',
                    lower_critical=lc,
                    lower_warning=lw,
                    upper_warning=uw,
                    upper_critical=uc
                )
                sensors.append(sensor)
    except Exception as e:
        app.logger.error(f"Error collecting sensors from {bmc_ip}: {e}")
    
    return sensors

def collect_power_reading(bmc_ip, server_name):
    """Collect power consumption from BMC using DCMI"""
    try:
        user, password = get_ipmi_credentials(bmc_ip)
        result = subprocess.run(
            ['ipmitool', '-I', 'lanplus', '-H', bmc_ip,
             '-U', user, '-P', password, 'dcmi', 'power', 'reading'],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode != 0:
            return None
        
        reading = PowerReading(bmc_ip=bmc_ip, server_name=server_name)
        
        for line in result.stdout.strip().split('\n'):
            line_lower = line.lower()
            if 'instantaneous' in line_lower or 'current' in line_lower:
                match = re.search(r'(\d+)\s*watts', line_lower)
                if match:
                    reading.current_watts = float(match.group(1))
            elif 'minimum' in line_lower:
                match = re.search(r'(\d+)\s*watts', line_lower)
                if match:
                    reading.min_watts = float(match.group(1))
            elif 'maximum' in line_lower:
                match = re.search(r'(\d+)\s*watts', line_lower)
                if match:
                    reading.max_watts = float(match.group(1))
            elif 'average' in line_lower:
                match = re.search(r'(\d+)\s*watts', line_lower)
                if match:
                    reading.avg_watts = float(match.group(1))
        
        return reading
    except Exception as e:
        app.logger.error(f"Error collecting power from {bmc_ip}: {e}")
        return None

def update_server_status(bmc_ip, server_name):
    """Update server status in database"""
    with app.app_context():
        # Use get_or_create pattern with retry for race conditions
        try:
            status = ServerStatus.query.filter_by(bmc_ip=bmc_ip).first()
            if not status:
                status = ServerStatus(bmc_ip=bmc_ip, server_name=server_name)
                db.session.add(status)
                db.session.flush()  # Try to insert now to catch duplicates
        except Exception:
            db.session.rollback()
            status = ServerStatus.query.filter_by(bmc_ip=bmc_ip).first()
        
        status.power_status = collect_power_status(bmc_ip)
        status.last_check = datetime.utcnow()
        status.is_reachable = status.power_status != 'Unreachable'
        
        # Count events - 24h
        cutoff = datetime.utcnow() - timedelta(hours=24)
        status.total_events = IPMIEvent.query.filter_by(bmc_ip=bmc_ip).count()
        status.total_events_24h = IPMIEvent.query.filter(
            IPMIEvent.bmc_ip == bmc_ip,
            IPMIEvent.event_date >= cutoff
        ).count()
        status.critical_events_24h = IPMIEvent.query.filter(
            IPMIEvent.bmc_ip == bmc_ip,
            IPMIEvent.severity == 'critical',
            IPMIEvent.event_date >= cutoff
        ).count()
        status.warning_events_24h = IPMIEvent.query.filter(
            IPMIEvent.bmc_ip == bmc_ip,
            IPMIEvent.severity == 'warning',
            IPMIEvent.event_date >= cutoff
        ).count()
        status.info_events_24h = IPMIEvent.query.filter(
            IPMIEvent.bmc_ip == bmc_ip,
            IPMIEvent.severity == 'info',
            IPMIEvent.event_date >= cutoff
        ).count()
        
        # Count events - Total (all time)
        status.critical_events_total = IPMIEvent.query.filter(
            IPMIEvent.bmc_ip == bmc_ip,
            IPMIEvent.severity == 'critical'
        ).count()
        status.warning_events_total = IPMIEvent.query.filter(
            IPMIEvent.bmc_ip == bmc_ip,
            IPMIEvent.severity == 'warning'
        ).count()
        status.info_events_total = IPMIEvent.query.filter(
            IPMIEvent.bmc_ip == bmc_ip,
            IPMIEvent.severity == 'info'
        ).count()
        
        db.session.commit()

def collect_single_server(bmc_ip, server_name):
    """Collect events from a single server (for parallel execution)"""
    try:
        events = collect_ipmi_sel(bmc_ip, server_name)
        return (bmc_ip, server_name, events, None)
    except Exception as e:
        return (bmc_ip, server_name, [], str(e))

def collect_all_events():
    """Background task to collect events from all servers in parallel"""
    with app.app_context():
        app.logger.info("Starting IPMI event collection (parallel)...")
        servers = get_servers()  # Get current server list
        
        if not servers:
            app.logger.warning("No servers configured for collection")
            return
        
        # Use ThreadPoolExecutor for parallel collection
        try:
            with ThreadPoolExecutor(max_workers=get_collection_workers()) as executor:
                futures = {
                    executor.submit(collect_single_server, bmc_ip, server_name): (bmc_ip, server_name)
                    for bmc_ip, server_name in servers.items()
                }
                
                for future in as_completed(futures):
                    try:
                        bmc_ip, server_name, events, error = future.result(timeout=660)
                    except Exception as e:
                        app.logger.error(f"Future result error: {e}")
                        continue
                    
                    if error:
                        app.logger.error(f"Error collecting from {bmc_ip}: {error}")
                        continue
                    
                    try:
                        new_events = 0
                        for event in events:
                            # Check if event already exists
                            existing = IPMIEvent.query.filter_by(
                                bmc_ip=event.bmc_ip, 
                                sel_id=event.sel_id
                            ).first()
                            
                            if not existing:
                                db.session.add(event)
                                new_events += 1
                        
                        db.session.commit()
                        update_server_status(bmc_ip, server_name)
                        if new_events > 0:
                            app.logger.info(f"Collected {new_events} new events from {server_name} ({len(events)} total)")
                        
                    except Exception as e:
                        app.logger.error(f"Error processing {bmc_ip}: {e}")
                        db.session.rollback()
        except Exception as e:
            app.logger.error(f"ThreadPoolExecutor error: {e}")
        
        app.logger.info("IPMI event collection complete")

_shutdown_event = _threading.Event()

# Data retention settings for FREE tier (self-hosted)
# Events older than this are automatically deleted
DATA_RETENTION_DAYS = int(os.environ.get('DATA_RETENTION_DAYS', 30))  # 30 days default
CLEANUP_INTERVAL_HOURS = 6  # Run cleanup every 6 hours

def cleanup_old_data():
    """
    Clean up old data to enforce retention policy.
    FREE tier: 30 days max retention.
    This keeps the database size manageable and ensures privacy.
    """
    with app.app_context():
        try:
            cutoff = datetime.utcnow() - timedelta(days=DATA_RETENTION_DAYS)
            
            # Delete old events
            old_events = IPMIEvent.query.filter(IPMIEvent.event_date < cutoff).count()
            if old_events > 0:
                IPMIEvent.query.filter(IPMIEvent.event_date < cutoff).delete()
                print(f"[IPMI Monitor] Data cleanup: Deleted {old_events} events older than {DATA_RETENTION_DAYS} days", flush=True)
            
            # Delete old sensor readings (keep last 7 days only for sensors)
            sensor_cutoff = datetime.utcnow() - timedelta(days=7)
            old_sensors = SensorReading.query.filter(SensorReading.timestamp < sensor_cutoff).count()
            if old_sensors > 0:
                SensorReading.query.filter(SensorReading.timestamp < sensor_cutoff).delete()
                print(f"[IPMI Monitor] Data cleanup: Deleted {old_sensors} old sensor readings", flush=True)
            
            # Delete old power readings (keep last 7 days)
            old_power = PowerReading.query.filter(PowerReading.timestamp < sensor_cutoff).count()
            if old_power > 0:
                PowerReading.query.filter(PowerReading.timestamp < sensor_cutoff).delete()
                print(f"[IPMI Monitor] Data cleanup: Deleted {old_power} old power readings", flush=True)
            
            # Delete old alert history (keep last 30 days)
            old_alerts = AlertHistory.query.filter(AlertHistory.triggered_at < cutoff).count()
            if old_alerts > 0:
                AlertHistory.query.filter(AlertHistory.triggered_at < cutoff).delete()
                print(f"[IPMI Monitor] Data cleanup: Deleted {old_alerts} old alert history", flush=True)
            
            # Delete expired AI results (if any)
            try:
                old_ai = AIResult.query.filter(AIResult.expires_at < datetime.utcnow()).count()
                if old_ai > 0:
                    AIResult.query.filter(AIResult.expires_at < datetime.utcnow()).delete()
                    print(f"[IPMI Monitor] Data cleanup: Deleted {old_ai} expired AI results", flush=True)
            except Exception:
                pass  # AIResult table might not exist yet
            
            db.session.commit()
            
        except Exception as e:
            db.session.rollback()
            print(f"[IPMI Monitor] Data cleanup error: {e}", flush=True)


# ============== Job Queue Architecture ==============
# Separate threads for: Collection Scheduler, Collection Workers, Sync, Cleanup

from queue import Queue, Empty

# Job queues
_collection_queue = Queue()
_sensor_queue = Queue()

# Configuration
# Default workers to CPU count, can be overridden by env var or settings
CPU_COUNT = os.cpu_count() or 4  # Fallback to 4 if cpu_count() returns None
COLLECTION_WORKERS = int(os.environ.get('COLLECTION_WORKERS', CPU_COUNT))
SYNC_INTERVAL = int(os.environ.get('SYNC_INTERVAL', 300))  # 5 minutes

def get_collection_workers():
    """Get the configured number of collection workers.
    Priority: SystemSettings > Environment > CPU count
    Returns: int - number of workers, or 0 for 'auto' (use CPU count)
    """
    try:
        with app.app_context():
            setting = SystemSettings.get('collection_workers', 'auto')
            if setting == 'auto' or setting == '0':
                return CPU_COUNT
            return int(setting)
    except:
        return COLLECTION_WORKERS

def collection_worker(worker_id):
    """Worker thread that processes collection jobs from the queue"""
    print(f"[Worker {worker_id}] Started", flush=True)
    
    while not _shutdown_event.is_set():
        try:
            # Get job from queue with timeout (allows checking shutdown)
            job = _collection_queue.get(timeout=5)
            
            if job is None:  # Poison pill for shutdown
                break
                
            job_type, bmc_ip, server_name = job
            
            try:
                if job_type == 'sel':
                    events = collect_ipmi_sel(bmc_ip, server_name)
                    if events:
                        with app.app_context():
                            save_events_to_db(bmc_ip, server_name, events)
                    # Also check for GPU Xid errors via SSH (after SEL collection)
                    with app.app_context():
                        check_ssh_xid_errors(bmc_ip, server_name)
                elif job_type == 'sensor':
                    with app.app_context():
                        collect_single_server_sensors(bmc_ip, server_name)
            except Exception as e:
                print(f"[Worker {worker_id}] Error processing {bmc_ip}: {e}", flush=True)
            finally:
                _collection_queue.task_done()
                
        except Empty:
            continue  # Timeout, check shutdown and loop
        except Exception as e:
            print(f"[Worker {worker_id}] Unexpected error: {e}", flush=True)
    
    print(f"[Worker {worker_id}] Stopped", flush=True)

def check_ssh_xid_errors(bmc_ip, server_name):
    """Check for GPU Xid errors via SSH (runs every collection cycle if SSH enabled)"""
    import subprocess
    import tempfile
    import re
    
    try:
        # Check if SSH inventory is enabled
        ssh_enabled = SystemSettings.get('enable_ssh_inventory', 'false').lower() == 'true'
        if not ssh_enabled:
            return
        
        # Get server record to find server_ip
        server = Server.query.filter_by(bmc_ip=bmc_ip).first()
        if not server or not server.server_ip:
            return
        
        server_ip = server.server_ip
        
        # Get SSH credentials
        server_config = ServerConfig.query.filter_by(bmc_ip=bmc_ip).first()
        ssh_key_content = None
        
        if server_config:
            ssh_user = server_config.ssh_user or 'root'
            if server_config.ssh_key_id:
                stored_key = SSHKey.query.get(server_config.ssh_key_id)
                if stored_key:
                    ssh_key_content = stored_key.key_content
            elif server_config.ssh_key:
                ssh_key_content = server_config.ssh_key
        else:
            ssh_user = SystemSettings.get('ssh_user') or os.environ.get('SSH_USER', 'root')
            default_key_id = SystemSettings.get('default_ssh_key_id')
            if default_key_id:
                stored_key = SSHKey.query.get(int(default_key_id))
                if stored_key:
                    ssh_key_content = stored_key.key_content
        
        # Build SSH command
        ssh_opts = ['-o', 'ConnectTimeout=10', '-o', 'StrictHostKeyChecking=no', '-o', 'BatchMode=yes']
        
        if ssh_key_content:
            key_content_clean = ssh_key_content.replace('\r\n', '\n').strip() + '\n'
            key_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.pem')
            key_file.write(key_content_clean)
            key_file.close()
            os.chmod(key_file.name, 0o600)
            ssh_cmd = ['ssh'] + ssh_opts + ['-i', key_file.name, f'{ssh_user}@{server_ip}', 
                       'dmesg 2>/dev/null | grep -i "NVRM.*Xid" | tail -20']
        else:
            # No SSH key, skip
            return
        
        try:
            result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=15)
        finally:
            try:
                os.unlink(key_file.name)
            except:
                pass
        
        if result.returncode != 0 or not result.stdout:
            return
        
        # Parse Xid errors
        xid_pattern = r'\[([\d.]+)\].*Xid.*\(PCI:([0-9a-f:]+)\).*?(\d+),?\s*(.*)'
        critical_xids = {
            31: 'GPU memory page fault', 43: 'GPU stopped responding',
            45: 'Preemptive cleanup', 48: 'Double bit ECC error',
            79: 'GPU fell off the bus', 94: 'Contained ECC error',
            95: 'Uncontained ECC error', 119: 'GSP error',
            154: 'GPU recovery action required'
        }
        
        xid_events_detected = []
        for line in result.stdout.strip().split('\n'):
            match = re.search(xid_pattern, line, re.IGNORECASE)
            if match:
                xid_code = int(match.group(3))
                pci_address = match.group(2)
                message = match.group(4).strip()
                
                if xid_code in critical_xids:
                    xid_events_detected.append({
                        'pci_address': pci_address,
                        'xid_code': xid_code,
                        'message': message,
                        'description': critical_xids[xid_code]
                    })
        
        if xid_events_detected:
            app.logger.warning(f"🔴 GPU Xid for {bmc_ip}: {len(xid_events_detected)} critical errors detected")
            
            # Create events for new Xid errors (deduplicated by PCI+code)
            seen = set()
            for xid in xid_events_detected:
                key = f"{xid['pci_address']}:{xid['xid_code']}"
                if key not in seen:
                    seen.add(key)
                    xid_sel_id = f"XID-{xid['pci_address'][-5:]}-{xid['xid_code']}"
                    
                    existing = IPMIEvent.query.filter(
                        IPMIEvent.bmc_ip == bmc_ip,
                        IPMIEvent.sel_id == xid_sel_id
                    ).first()
                    
                    if not existing:
                        # User-friendly description (hides Xid code from clients)
                        event_desc = get_gpu_error_description(xid['xid_code'], xid.get('recovery_action'))
                        event_desc += f" (GPU:{xid['pci_address'][-5:]})"  # Short PCI ID only
                        event = IPMIEvent(
                            bmc_ip=bmc_ip,
                            server_name=server_name,
                            sel_id=xid_sel_id,
                            event_date=datetime.utcnow(),
                            sensor_type='GPU Health',  # User-friendly name
                            sensor_id=xid['pci_address'],
                            event_description=event_desc,
                            severity='critical',
                            raw_entry=json.dumps({'xid': xid['xid_code'], 'message': xid['message']})  # Technical details in raw
                        )
                        db.session.add(event)
                        app.logger.warning(f"🔴 NEW: {event_desc} on {server_name}")
            
            try:
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                app.logger.error(f"Failed to save Xid events: {e}")
                
    except Exception as e:
        # Don't log as error - SSH may not be available for all servers
        app.logger.debug(f"SSH Xid check failed for {bmc_ip}: {e}")


# =============================================================================
# SYSTEM EVENT & RECOVERY LOGGING FUNCTIONS
# =============================================================================

def create_system_event(bmc_ip, server_name, event_type, description, severity='info', 
                        device_id=None, raw_data=None):
    """
    Create a system event (logged like SEL events for unified display).
    
    Event types:
    - 'gpu_error': GPU error detected (hides Xid code from client)
    - 'recovery_action': Recovery action taken
    - 'unexpected_reboot': Server rebooted unexpectedly
    - 'maintenance_created': Maintenance task created
    - 'uptime_alert': Uptime-related event
    """
    try:
        # Generate unique SEL-like ID for system events
        sel_id = f"SYS-{event_type[:3].upper()}-{datetime.utcnow().strftime('%H%M%S')}"
        
        # Map event_type to sensor_type for display
        sensor_type_map = {
            'gpu_error': 'GPU Health',
            'recovery_action': 'System Recovery',
            'unexpected_reboot': 'System Reboot',
            'maintenance_created': 'Maintenance',
            'uptime_alert': 'System Uptime',
        }
        sensor_type = sensor_type_map.get(event_type, 'System Event')
        
        event = IPMIEvent(
            bmc_ip=bmc_ip,
            server_name=server_name,
            sel_id=sel_id,
            event_date=datetime.utcnow(),
            sensor_type=sensor_type,
            sensor_id=device_id or 'system',
            event_description=description,
            severity=severity,
            raw_entry=json.dumps(raw_data) if raw_data else None
        )
        db.session.add(event)
        db.session.commit()
        
        app.logger.info(f"[{severity.upper()}] {server_name}: {description}")
        return event
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Failed to create system event: {e}")
        return None

def log_recovery_action(bmc_ip, server_name, action_type, target_device=None, 
                        reason=None, result='pending', initiated_by='system'):
    """
    Log a recovery action and create corresponding system event.
    
    Action types: 'gpu_reset', 'reboot', 'power_cycle', 'clock_limit', 'workload_kill'
    """
    try:
        # Create recovery log entry
        recovery = RecoveryLog(
            bmc_ip=bmc_ip,
            server_name=server_name,
            action_type=action_type,
            target_device=target_device,
            reason=reason,
            result=result,
            initiated_by=initiated_by
        )
        db.session.add(recovery)
        db.session.commit()
        
        # Also create a system event so it shows in the event log
        action_desc = RECOVERY_ACTIONS.get(action_type, action_type)
        device_str = f" on {target_device}" if target_device else ""
        description = f"{action_desc}{device_str}"
        if reason:
            description += f" - {reason}"
        
        create_system_event(
            bmc_ip=bmc_ip,
            server_name=server_name,
            event_type='recovery_action',
            description=description,
            severity='warning',
            device_id=target_device,
            raw_data={'action': action_type, 'reason': reason, 'result': result}
        )
        
        return recovery
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Failed to log recovery action: {e}")
        return None

def check_maintenance_needed(bmc_ip, server_name):
    """
    Check if maintenance task should be created based on recovery patterns.
    Creates maintenance task if:
    - 3+ reboots in 24 hours
    - 5+ GPU errors in 24 hours for same device
    - 2+ power cycles in 24 hours
    """
    try:
        cutoff = datetime.utcnow() - timedelta(hours=24)
        
        # Count recent recovery actions
        recent_reboots = RecoveryLog.query.filter(
            RecoveryLog.bmc_ip == bmc_ip,
            RecoveryLog.action_type.in_(['reboot', 'node_reboot']),
            RecoveryLog.created_at >= cutoff
        ).count()
        
        recent_power_cycles = RecoveryLog.query.filter(
            RecoveryLog.bmc_ip == bmc_ip,
            RecoveryLog.action_type == 'power_cycle',
            RecoveryLog.created_at >= cutoff
        ).count()
        
        # Count GPU errors by device
        recent_gpu_events = IPMIEvent.query.filter(
            IPMIEvent.bmc_ip == bmc_ip,
            IPMIEvent.sensor_type.in_(['GPU Health', 'GPU Xid Error']),
            IPMIEvent.severity == 'critical',
            IPMIEvent.event_date >= cutoff
        ).all()
        
        # Group by device
        gpu_error_counts = {}
        for event in recent_gpu_events:
            device = event.sensor_id or 'unknown'
            gpu_error_counts[device] = gpu_error_counts.get(device, 0) + 1
        
        # Check thresholds
        maintenance_needed = False
        task_description = []
        task_severity = 'medium'
        
        if recent_reboots >= 3:
            task_description.append(f"{recent_reboots} reboots in 24h")
            task_severity = 'high'
            maintenance_needed = True
        
        if recent_power_cycles >= 2:
            task_description.append(f"{recent_power_cycles} power cycles in 24h")
            task_severity = 'high'
            maintenance_needed = True
        
        for device, count in gpu_error_counts.items():
            if count >= 5:
                task_description.append(f"GPU {device}: {count} errors in 24h")
                task_severity = 'critical'
                maintenance_needed = True
        
        if maintenance_needed:
            # Check if there's already a pending task for this server
            existing = MaintenanceTask.query.filter(
                MaintenanceTask.bmc_ip == bmc_ip,
                MaintenanceTask.status.in_(['pending', 'scheduled'])
            ).first()
            
            if not existing:
                description = f"Automated maintenance required: {'; '.join(task_description)}"
                task = MaintenanceTask(
                    bmc_ip=bmc_ip,
                    server_name=server_name,
                    task_type='automated_maintenance',
                    description=description,
                    severity=task_severity,
                    recovery_attempts=recent_reboots + recent_power_cycles
                )
                db.session.add(task)
                db.session.commit()
                
                # Create system event for the maintenance task
                create_system_event(
                    bmc_ip=bmc_ip,
                    server_name=server_name,
                    event_type='maintenance_created',
                    description=f"Maintenance task created: {description}",
                    severity='warning'
                )
                
                app.logger.warning(f"🔧 Maintenance task created for {server_name}: {description}")
                return task
        
        return None
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error checking maintenance needs: {e}")
        return None

def check_uptime_and_detect_reboot(bmc_ip, server_name, current_uptime_seconds):
    """
    Check server uptime and detect unexpected reboots.
    Creates an event if server has rebooted since last check.
    """
    try:
        uptime_record = ServerUptime.query.filter_by(bmc_ip=bmc_ip).first()
        
        if not uptime_record:
            # First time seeing this server
            uptime_record = ServerUptime(
                bmc_ip=bmc_ip,
                server_name=server_name,
                last_uptime_seconds=current_uptime_seconds,
                last_boot_time=datetime.utcnow() - timedelta(seconds=current_uptime_seconds),
                reboot_count=0,
                unexpected_reboot_count=0
            )
            db.session.add(uptime_record)
            db.session.commit()
            return None
        
        # If current uptime is less than last known uptime, server rebooted
        if current_uptime_seconds < uptime_record.last_uptime_seconds:
            uptime_record.reboot_count += 1
            new_boot_time = datetime.utcnow() - timedelta(seconds=current_uptime_seconds)
            
            # Check if we initiated this reboot (look for recent recovery action)
            recent_recovery = RecoveryLog.query.filter(
                RecoveryLog.bmc_ip == bmc_ip,
                RecoveryLog.action_type.in_(['reboot', 'node_reboot', 'power_cycle']),
                RecoveryLog.created_at >= datetime.utcnow() - timedelta(minutes=30)
            ).first()
            
            if not recent_recovery:
                # Unexpected reboot
                uptime_record.unexpected_reboot_count += 1
                
                create_system_event(
                    bmc_ip=bmc_ip,
                    server_name=server_name,
                    event_type='unexpected_reboot',
                    description=f"Unexpected server reboot detected (uptime was {uptime_record.last_uptime_seconds//3600}h)",
                    severity='warning',
                    raw_data={
                        'previous_uptime_seconds': uptime_record.last_uptime_seconds,
                        'new_uptime_seconds': current_uptime_seconds,
                        'reboot_count': uptime_record.reboot_count
                    }
                )
                app.logger.warning(f"⚠️ Unexpected reboot detected: {server_name}")
            else:
                # Expected reboot (we initiated it)
                app.logger.info(f"✅ Server {server_name} rebooted as expected (recovery action)")
            
            uptime_record.last_boot_time = new_boot_time
        
        uptime_record.last_uptime_seconds = current_uptime_seconds
        uptime_record.last_check = datetime.utcnow()
        db.session.commit()
        
        return uptime_record
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error checking uptime for {bmc_ip}: {e}")
        return None

def save_events_to_db(bmc_ip, server_name, events):
    """Save collected events to database"""
    try:
        new_events = 0
        for event in events:
            # Events from collect_ipmi_sel are already IPMIEvent objects
            if hasattr(event, 'bmc_ip'):
                # It's an IPMIEvent object
                existing = IPMIEvent.query.filter_by(
                    bmc_ip=event.bmc_ip,
                    sel_id=event.sel_id
                ).first()
                
                if not existing:
                    db.session.add(event)
                    new_events += 1
            else:
                # It's a dict
                existing = IPMIEvent.query.filter_by(
                    bmc_ip=bmc_ip,
                    record_id=event.get('record_id')
                ).first()
                
                if not existing:
                    new_event = IPMIEvent(
                        bmc_ip=bmc_ip,
                        server_name=server_name,
                        record_id=event.get('record_id'),
                        event_type=event.get('event_type', 'Unknown'),
                        sensor_type=event.get('sensor_type', 'Unknown'),
                        sensor_name=event.get('sensor_name', 'Unknown'),
                        event_data=event.get('event_data', ''),
                        event_description=event.get('event_description', ''),
                        event_date=event.get('event_date'),
                        severity=event.get('severity', 'info')
                    )
                    db.session.add(new_event)
                    new_events += 1
        
        db.session.commit()
        
        # Update server status/stats
        update_server_status(bmc_ip, server_name)
        
        if new_events > 0:
            app.logger.info(f"Saved {new_events} new events from {server_name}")
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error saving events for {bmc_ip}: {e}")

def collection_scheduler():
    """Scheduler thread that queues collection jobs at intervals"""
    print(f"[Scheduler] Started (interval: {POLL_INTERVAL}s, workers: {get_collection_workers()})", flush=True)
    
    collection_count = 0
    
    while not _shutdown_event.is_set():
        try:
            with app.app_context():
                servers = get_servers()
            
            if servers:
                print(f"[Scheduler] Queueing SEL collection for {len(servers)} servers...", flush=True)
                
                # Queue SEL collection jobs
                for bmc_ip, server_name in servers.items():
                    _collection_queue.put(('sel', bmc_ip, server_name))
                
                # Queue sensor jobs based on multiplier
                collection_count += 1
                if collection_count >= SENSOR_POLL_MULTIPLIER:
                    collection_count = 0
                    print(f"[Scheduler] Queueing sensor collection for {len(servers)} servers...", flush=True)
                    for bmc_ip, server_name in servers.items():
                        _collection_queue.put(('sensor', bmc_ip, server_name))
                
                # Wait for all jobs to complete (with timeout)
                try:
                    # Don't block forever - check every 10s
                    while not _collection_queue.empty() and not _shutdown_event.is_set():
                        _shutdown_event.wait(10)
                except:
                    pass
                
                print(f"[Scheduler] Collection cycle complete. Next in {POLL_INTERVAL}s", flush=True)
            
        except Exception as e:
            print(f"[Scheduler] Error: {e}", flush=True)
        
        # Wait for next cycle
        _shutdown_event.wait(POLL_INTERVAL)
    
    # Shutdown: send poison pills to workers
    for _ in range(get_collection_workers()):
        _collection_queue.put(None)
    
    print(f"[Scheduler] Stopped", flush=True)

def sync_timer():
    """Independent sync timer - runs on its own schedule, doesn't block collection"""
    print(f"[Sync Timer] Started (interval: {SYNC_INTERVAL}s)", flush=True)
    
    # Initial delay to let first collection complete
    _shutdown_event.wait(60)
    
    while not _shutdown_event.is_set():
        try:
            with app.app_context():
                config = CloudSync.get_config()
                
                if config.sync_enabled and config.license_key:
                    print(f"[Sync Timer] Starting sync to AI service...", flush=True)
                    result = sync_to_cloud()
                    
                    if result.get('success'):
                        print(f"[Sync Timer] Sync complete: {result.get('message')}", flush=True)
                    else:
                        print(f"[Sync Timer] Sync failed: {result.get('message')}", flush=True)
                        
        except Exception as e:
            print(f"[Sync Timer] Error: {e}", flush=True)
        
        # Wait for next sync
        _shutdown_event.wait(SYNC_INTERVAL)
    
    print(f"[Sync Timer] Stopped", flush=True)

def connectivity_timer():
    """Independent connectivity check timer - monitors server availability"""
    print(f"[Connectivity Timer] Started (interval: 60s)", flush=True)
    
    # Initial delay to let system stabilize
    _shutdown_event.wait(120)
    
    while not _shutdown_event.is_set():
        try:
            check_and_report_connectivity_changes()
        except Exception as e:
            print(f"[Connectivity Timer] Error: {e}", flush=True)
        
        # Check every 60 seconds
        _shutdown_event.wait(60)
    
    print(f"[Connectivity Timer] Stopped", flush=True)


def cleanup_timer():
    """Independent cleanup timer"""
    print(f"[Cleanup Timer] Started (interval: {CLEANUP_INTERVAL_HOURS}h)", flush=True)
    
    # Initial delay
    _shutdown_event.wait(300)
    
    while not _shutdown_event.is_set():
        try:
            with app.app_context():
                cleanup_old_data()
        except Exception as e:
            print(f"[Cleanup Timer] Error: {e}", flush=True)
        
        # Wait for next cleanup
        _shutdown_event.wait(CLEANUP_INTERVAL_HOURS * 3600)
    
    print(f"[Cleanup Timer] Stopped", flush=True)

def background_collector():
    """Start all background threads - job queue architecture"""
    print(f"[IPMI Monitor] Starting job queue architecture...", flush=True)
    print(f"[IPMI Monitor] Collection interval: {POLL_INTERVAL}s, Workers: {get_collection_workers()} (CPU cores: {CPU_COUNT})", flush=True)
    print(f"[IPMI Monitor] Sync interval: {SYNC_INTERVAL}s (independent)", flush=True)
    print(f"[IPMI Monitor] Data retention: {DATA_RETENTION_DAYS} days", flush=True)
    
    threads = []
    
    # Start collection workers (based on configured worker count)
    worker_count = get_collection_workers()
    for i in range(worker_count):
        t = threading.Thread(target=collection_worker, args=(i,), daemon=True)
        t.start()
        threads.append(t)
    
    # Start scheduler
    scheduler_thread = threading.Thread(target=collection_scheduler, daemon=True)
    scheduler_thread.start()
    threads.append(scheduler_thread)
    
    # Start independent sync timer
    sync_thread = threading.Thread(target=sync_timer, daemon=True)
    sync_thread.start()
    threads.append(sync_thread)
    
    # Start cleanup timer
    cleanup_thread = threading.Thread(target=cleanup_timer, daemon=True)
    cleanup_thread.start()
    threads.append(cleanup_thread)
    
    # Start connectivity monitoring timer
    connectivity_thread = threading.Thread(target=connectivity_timer, daemon=True)
    connectivity_thread.start()
    threads.append(connectivity_thread)
    
    print(f"[IPMI Monitor] All background threads started ({len(threads)} threads)", flush=True)
    
    # Keep main collector thread alive (for compatibility with existing startup code)
    while not _shutdown_event.is_set():
        _shutdown_event.wait(60)

def collect_all_sensors_background():
    """Collect sensors from all servers in background (parallel)"""
    with app.app_context():
        print(f"[IPMI Monitor] Starting background sensor collection...", flush=True)
        servers = get_servers()
        
        if not servers:
            print(f"[IPMI Monitor] No servers configured for sensor collection", flush=True)
            return
        
        print(f"[IPMI Monitor] Collecting sensors from {len(servers)} servers...", flush=True)
        collected = 0
        try:
            with ThreadPoolExecutor(max_workers=get_collection_workers()) as executor:
                futures = {
                    executor.submit(collect_single_server_sensors, bmc_ip, server_name): (bmc_ip, server_name)
                    for bmc_ip, server_name in servers.items()
                }
                
                for future in as_completed(futures):
                    try:
                        result = future.result(timeout=120)
                        if result:
                            collected += 1
                    except Exception as e:
                        pass  # Individual server failures are logged in collect_single_server_sensors
        except Exception as e:
            print(f"[IPMI Monitor] Error in background sensor collection: {e}", flush=True)
        
        print(f"[IPMI Monitor] Background sensor collection complete: {collected}/{len(servers)} servers", flush=True)

# Template context processor - inject APP_NAME into all templates
@app.context_processor
def inject_app_name():
    return {'app_name': APP_NAME}

# Routes
@app.route('/')
@view_required
def dashboard():
    """Main dashboard - requires login or anonymous access enabled"""
    return render_template('dashboard.html')

@app.route('/api/servers')
@view_required
def api_servers():
    """Get all server statuses with configurable time range"""
    hours = request.args.get('hours', 24, type=int)
    cutoff = datetime.utcnow() - timedelta(hours=hours)
    
    servers = ServerStatus.query.all()
    result = []
    
    for s in servers:
        # Calculate counts for the specified time range
        critical = IPMIEvent.query.filter(
            IPMIEvent.bmc_ip == s.bmc_ip,
            IPMIEvent.severity == 'critical',
            IPMIEvent.event_date >= cutoff
        ).count()
        warning = IPMIEvent.query.filter(
            IPMIEvent.bmc_ip == s.bmc_ip,
            IPMIEvent.severity == 'warning',
            IPMIEvent.event_date >= cutoff
        ).count()
        info = IPMIEvent.query.filter(
            IPMIEvent.bmc_ip == s.bmc_ip,
            IPMIEvent.severity == 'info',
            IPMIEvent.event_date >= cutoff
        ).count()
        total = IPMIEvent.query.filter(
            IPMIEvent.bmc_ip == s.bmc_ip,
            IPMIEvent.event_date >= cutoff
        ).count()
        
        result.append({
            'bmc_ip': s.bmc_ip,
            'server_name': s.server_name,
            'power_status': s.power_status,
            'last_check': s.last_check.isoformat() if s.last_check else None,
            'is_reachable': s.is_reachable,
            'total_events': s.total_events,
            'critical': critical,
            'warning': warning,
            'info': info,
            'total': total
        })
    
    return jsonify(result)

@app.route('/api/events')
@view_required
def api_events():
    """Get events with filtering"""
    severity = request.args.get('severity')
    server = request.args.get('server')
    hours = request.args.get('hours', 24, type=int)
    limit = request.args.get('limit', 100, type=int)
    
    query = IPMIEvent.query
    
    if severity:
        query = query.filter_by(severity=severity)
    if server:
        # Support filtering by either server_name or bmc_ip
        query = query.filter(
            db.or_(IPMIEvent.server_name == server, IPMIEvent.bmc_ip == server)
        )
    
    cutoff = datetime.utcnow() - timedelta(hours=hours)
    query = query.filter(IPMIEvent.event_date >= cutoff)
    
    events = query.order_by(IPMIEvent.event_date.desc()).limit(limit).all()
    
    return jsonify({
        'events': [{
            'id': e.id,
            'bmc_ip': e.bmc_ip,
            'server_name': e.server_name,
            'sel_id': e.sel_id,
            'event_date': e.event_date.isoformat(),
            'timestamp': e.event_date.isoformat(),  # Alias for frontend
            'sensor_type': e.sensor_type,
            'event_description': e.event_description,
            'description': e.event_description,  # Alias for frontend
            'severity': e.severity
        } for e in events],
        'total': len(events),
        'hours': hours
    })

@app.route('/api/maintenance')
@view_required
def api_maintenance_tasks():
    """Get maintenance tasks"""
    status = request.args.get('status')  # pending, scheduled, completed, all
    server = request.args.get('server')
    
    query = MaintenanceTask.query
    
    if status and status != 'all':
        query = query.filter_by(status=status)
    if server:
        query = query.filter(
            db.or_(MaintenanceTask.server_name == server, MaintenanceTask.bmc_ip == server)
        )
    
    tasks = query.order_by(MaintenanceTask.created_at.desc()).limit(50).all()
    
    return jsonify({
        'tasks': [{
            'id': t.id,
            'bmc_ip': t.bmc_ip,
            'server_name': t.server_name,
            'task_type': t.task_type,
            'description': t.description,
            'severity': t.severity,
            'status': t.status,
            'created_at': t.created_at.isoformat() if t.created_at else None,
            'scheduled_for': t.scheduled_for.isoformat() if t.scheduled_for else None,
            'completed_at': t.completed_at.isoformat() if t.completed_at else None,
            'recovery_attempts': t.recovery_attempts,
            'notes': t.notes
        } for t in tasks],
        'total': len(tasks)
    })

@app.route('/api/maintenance/<int:task_id>', methods=['PUT'])
@auth_required
def api_update_maintenance_task(task_id):
    """Update maintenance task status"""
    task = MaintenanceTask.query.get_or_404(task_id)
    data = request.get_json()
    
    if 'status' in data:
        task.status = data['status']
        if data['status'] == 'completed':
            task.completed_at = datetime.utcnow()
    if 'notes' in data:
        task.notes = data['notes']
    if 'scheduled_for' in data:
        task.scheduled_for = datetime.fromisoformat(data['scheduled_for'])
    
    db.session.commit()
    return jsonify({'success': True, 'task_id': task_id})

@app.route('/api/recovery-logs')
@view_required
def api_recovery_logs():
    """Get recovery action logs"""
    server = request.args.get('server')
    hours = request.args.get('hours', 72, type=int)
    
    query = RecoveryLog.query
    
    if server:
        query = query.filter(
            db.or_(RecoveryLog.server_name == server, RecoveryLog.bmc_ip == server)
        )
    
    cutoff = datetime.utcnow() - timedelta(hours=hours)
    query = query.filter(RecoveryLog.created_at >= cutoff)
    
    logs = query.order_by(RecoveryLog.created_at.desc()).limit(100).all()
    
    return jsonify({
        'logs': [{
            'id': l.id,
            'bmc_ip': l.bmc_ip,
            'server_name': l.server_name,
            'action_type': l.action_type,
            'target_device': l.target_device,
            'reason': l.reason,
            'result': l.result,
            'initiated_by': l.initiated_by,
            'created_at': l.created_at.isoformat() if l.created_at else None,
            'completed_at': l.completed_at.isoformat() if l.completed_at else None,
            'error_message': l.error_message
        } for l in logs],
        'total': len(logs),
        'hours': hours
    })

@app.route('/api/uptime')
@view_required
def api_server_uptime():
    """Get server uptime information"""
    server = request.args.get('server')
    
    query = ServerUptime.query
    
    if server:
        query = query.filter(
            db.or_(ServerUptime.server_name == server, ServerUptime.bmc_ip == server)
        )
    
    uptimes = query.all()
    
    return jsonify({
        'servers': [{
            'bmc_ip': u.bmc_ip,
            'server_name': u.server_name,
            'uptime_seconds': u.last_uptime_seconds,
            'uptime_days': round(u.last_uptime_seconds / 86400, 1) if u.last_uptime_seconds else None,
            'last_boot_time': u.last_boot_time.isoformat() if u.last_boot_time else None,
            'last_check': u.last_check.isoformat() if u.last_check else None,
            'reboot_count': u.reboot_count,
            'unexpected_reboot_count': u.unexpected_reboot_count
        } for u in uptimes],
        'total': len(uptimes)
    })

@app.route('/api/stats')
@view_required
def api_stats():
    """Get dashboard statistics with configurable time range"""
    hours = request.args.get('hours', 24, type=int)
    cutoff = datetime.utcnow() - timedelta(hours=hours)
    
    return jsonify({
        'total_servers': ServerStatus.query.count(),
        'reachable_servers': ServerStatus.query.filter_by(is_reachable=True).count(),
        'total': IPMIEvent.query.filter(IPMIEvent.event_date >= cutoff).count(),
        'critical': IPMIEvent.query.filter(
            IPMIEvent.severity == 'critical',
            IPMIEvent.event_date >= cutoff
        ).count(),
        'warning': IPMIEvent.query.filter(
            IPMIEvent.severity == 'warning',
            IPMIEvent.event_date >= cutoff
        ).count(),
        'info': IPMIEvent.query.filter(
            IPMIEvent.severity == 'info',
            IPMIEvent.event_date >= cutoff
        ).count(),
        'hours': hours
    })

@app.route('/api/event_types')
def api_event_types():
    """Get event type breakdown"""
    results = db.session.query(
        IPMIEvent.sensor_type,
        IPMIEvent.severity,
        db.func.count(IPMIEvent.id)
    ).group_by(IPMIEvent.sensor_type, IPMIEvent.severity).all()
    
    return jsonify([{
        'sensor_type': r[0],
        'severity': r[1],
        'count': r[2]
    } for r in results])

@app.route('/api/collect', methods=['POST'])
def api_trigger_collection():
    """Manually trigger event collection"""
    bmc_ip = request.args.get('bmc_ip')
    if bmc_ip:
        # Collect from single server
        def collect_single():
            with app.app_context():
                server_name = get_server_name(bmc_ip)
                # Build sensor cache first
                build_sensor_cache(bmc_ip)
                events = collect_ipmi_sel(bmc_ip, server_name)
                for event in events:
                    # Check if event already exists
                    existing = IPMIEvent.query.filter_by(
                        bmc_ip=bmc_ip, sel_id=event.sel_id
                    ).first()
                    if not existing:
                        db.session.add(event)
                db.session.commit()
                # Update server status
                update_server_status(bmc_ip, server_name)
                app.logger.info(f"Collected {len(events)} events from {bmc_ip}")
        threading.Thread(target=collect_single, daemon=True).start()
        return jsonify({'status': f'Collection started for {bmc_ip}'})
    else:
        threading.Thread(target=collect_all_events).start()
        return jsonify({'status': 'Collection started'})

def get_server_name(bmc_ip):
    """Get server name for a BMC IP"""
    # Check database first
    server = Server.query.filter_by(bmc_ip=bmc_ip).first()
    if server:
        return server.server_name
    # Check defaults
    if bmc_ip in DEFAULT_SERVERS:
        return DEFAULT_SERVERS[bmc_ip]
    return f"unknown-{bmc_ip}"

def check_bmc_reachable(bmc_ip):
    """Quick check if BMC is reachable"""
    try:
        user, password = get_ipmi_credentials(bmc_ip)
        result = subprocess.run(
            ['ipmitool', '-I', 'lanplus', '-H', bmc_ip,
             '-U', user, '-P', password, 'power', 'status'],
            capture_output=True, text=True, timeout=10
        )
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        return False
    except Exception as e:
        app.logger.debug(f"BMC reachability check failed for {bmc_ip}: {e}")
        return False

@app.route('/server/<bmc_ip>')
@view_required
@require_valid_bmc_ip
def server_detail(bmc_ip):
    """Server detail page - requires login or anonymous access enabled"""
    return render_template('server_detail.html', bmc_ip=bmc_ip)

def enhance_event_display(sensor_type, event_description):
    """Enhance event display for NVIDIA and other OEM events.
    
    Translates cryptic codes into human-readable descriptions.
    """
    # Already enhanced or not NVIDIA - return as-is
    if not sensor_type:
        return sensor_type, event_description
    
    sensor_upper = sensor_type.upper()
    
    # NVIDIA SEL_NV_* event translations
    nvidia_translations = {
        'SEL_NV_AUDIT': ('Security Audit', 'BMC login/logout or config change'),
        'SEL_NV_MAXP_MAXQ': ('Power Mode', 'GPU power mode changed (MaxP/MaxQ)'),
        'SEL_NV_POST_ERR': ('POST Error', 'Power-On Self Test error during boot'),
        'SEL_NV_BIOS': ('BIOS Event', 'BIOS/UEFI firmware event'),
        'SEL_NV_CPU': ('CPU Event', 'CPU thermal/error/state change'),
        'SEL_NV_MEM': ('Memory Event', 'Memory ECC/training event'),
        'SEL_NV_GPU': ('GPU Event', 'NVIDIA GPU subsystem event'),
        'SEL_NV_NVL': ('NVLink Event', 'NVLink interconnect status'),
        'SEL_NV_PWR': ('Power Event', 'Power subsystem event'),
        'SEL_NV_FAN': ('Fan Event', 'Cooling fan status'),
        'SEL_NV_TEMP': ('Temperature', 'Thermal threshold event'),
        'SEL_NV_PCIE': ('PCIe Event', 'PCIe bus/device event'),
        'SEL_NV_BOOT': ('Boot Event', 'System boot/restart'),
        'SEL_NV_WATCHDOG': ('Watchdog', 'Hardware watchdog event'),
    }
    
    # NVIDIA OEM Sensor ID translations
    nvidia_sensors = {
        '0xD2': 'NV Power Sensor',
        '0xD7': 'NV GPU Status',
        '0xD8': 'NV NVLink Status',
        '0xD9': 'NV Memory',
        '0xDA': 'NV Boot Progress',
        '0xDB': 'NV Temperature',
        '0xDC': 'NV Fan Control',
    }
    
    enhanced_type = sensor_type
    enhanced_desc = event_description
    
    # Check for SEL_NV_* in sensor type
    for key, (friendly_name, description) in nvidia_translations.items():
        if key in sensor_upper:
            enhanced_type = friendly_name
            # Improve description
            if '| Asserted' in enhanced_desc or enhanced_desc.strip() == '| Asserted':
                enhanced_desc = f"{description} | Asserted"
            break
    
    # Handle "Unknown" sensor types with SEL_NV_* in description
    if 'UNKNOWN' in sensor_upper:
        for key, (friendly_name, description) in nvidia_translations.items():
            if key in (event_description or '').upper():
                enhanced_type = friendly_name
                enhanced_desc = f"{description} | Asserted"
                break
    
    # Enhance sensor IDs like [Sensor 0xD2]
    import re
    sensor_match = re.search(r'\[Sensor\s*(0x[A-Fa-f0-9]+)\]', enhanced_desc)
    if sensor_match:
        sensor_id = sensor_match.group(1).upper()
        if sensor_id in nvidia_sensors:
            enhanced_desc = enhanced_desc.replace(
                sensor_match.group(0), 
                f"[{nvidia_sensors[sensor_id]}]"
            )
    
    return enhanced_type, enhanced_desc


@app.route('/api/server/<bmc_ip>/events')
@view_required
@require_valid_bmc_ip
def api_server_events(bmc_ip):
    """Get events for a specific server"""
    limit = request.args.get('limit', 500, type=int)
    events = IPMIEvent.query.filter_by(bmc_ip=bmc_ip)\
        .order_by(IPMIEvent.event_date.desc()).limit(limit).all()
    
    result = []
    for e in events:
        # Enhance display for NVIDIA events
        display_sensor_type, display_description = enhance_event_display(
            e.sensor_type, e.event_description
        )
        result.append({
            'id': e.id,
            'sel_id': e.sel_id,
            'event_date': e.event_date.isoformat(),
            'timestamp': e.event_date.isoformat(),  # Alias for frontend
            'sensor_type': display_sensor_type,
            'sensor_id': e.sensor_id,
            'event_description': display_description,
            'description': display_description,  # Alias for frontend
            'severity': e.severity,
            'raw_entry': e.raw_entry
        })
    
    return jsonify(result)

@app.route('/api/server/<bmc_ip>/clear_sel', methods=['POST'])
@write_required
@require_valid_bmc_ip
def api_clear_sel(bmc_ip):
    """Clear SEL log on a specific BMC - Requires write access"""
    try:
        password = get_ipmi_password(bmc_ip)
        result = subprocess.run(
            ['ipmitool', '-I', 'lanplus', '-H', bmc_ip,
             '-U', IPMI_USER, '-P', password, 'sel', 'clear'],
            capture_output=True, text=True, timeout=30
        )
        
        if result.returncode == 0:
            # Also clear from local database
            IPMIEvent.query.filter_by(bmc_ip=bmc_ip).delete()
            db.session.commit()
            
            # Update server status
            server_name = SERVERS.get(bmc_ip, bmc_ip)
            update_server_status(bmc_ip, server_name)
            
            return jsonify({
                'status': 'success',
                'message': f'SEL cleared for {bmc_ip}',
                'output': result.stdout.strip()
            })
        else:
            return jsonify({
                'status': 'error',
                'message': f'Failed to clear SEL: {result.stderr}'
            }), 500
    except subprocess.TimeoutExpired:
        return jsonify({'status': 'error', 'message': 'Timeout clearing SEL'}), 500
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


# ============== Power Management API ==============

@app.route('/api/server/<bmc_ip>/power', methods=['GET'])
@require_valid_bmc_ip
def api_get_power_status(bmc_ip):
    """Get power status for a server"""
    try:
        password = get_ipmi_password(bmc_ip)
        result = subprocess.run(
            ['ipmitool', '-I', 'lanplus', '-H', bmc_ip,
             '-U', IPMI_USER, '-P', password, 'power', 'status'],
            capture_output=True, text=True, timeout=30
        )
        
        if result.returncode == 0:
            output = result.stdout.strip().lower()
            is_on = 'on' in output
            return jsonify({
                'status': 'success',
                'power_status': 'on' if is_on else 'off',
                'raw_output': result.stdout.strip()
            })
        else:
            return jsonify({
                'status': 'error',
                'message': f'Failed to get power status: {result.stderr}'
            }), 500
    except subprocess.TimeoutExpired:
        return jsonify({'status': 'error', 'message': 'Timeout getting power status'}), 500
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/server/<bmc_ip>/power/<action>', methods=['POST'])
@write_required
@require_valid_bmc_ip
def api_power_control(bmc_ip, action):
    """Control server power - Requires write access
    
    Actions:
        - on: Power on
        - off: Power off (hard)
        - soft: Soft shutdown (graceful, sends ACPI signal)
        - cycle: Power cycle (off then on)
        - reset: Reset (warm reboot)
    """
    valid_actions = ['on', 'off', 'soft', 'cycle', 'reset']
    
    if action not in valid_actions:
        return jsonify({
            'status': 'error',
            'message': f'Invalid action. Valid actions: {", ".join(valid_actions)}'
        }), 400
    
    try:
        password = get_ipmi_password(bmc_ip)
        result = subprocess.run(
            ['ipmitool', '-I', 'lanplus', '-H', bmc_ip,
             '-U', IPMI_USER, '-P', password, 'power', action],
            capture_output=True, text=True, timeout=30
        )
        
        if result.returncode == 0:
            # Log the power action as an event
            server = Server.query.filter_by(bmc_ip=bmc_ip).first()
            server_name = server.server_name if server else bmc_ip
            
            action_names = {
                'on': 'Power On',
                'off': 'Power Off (Hard)',
                'soft': 'Soft Shutdown',
                'cycle': 'Power Cycle',
                'reset': 'Reset'
            }
            
            # Log as an IPMI event for audit trail
            event = IPMIEvent(
                bmc_ip=bmc_ip,
                server_name=server_name,
                event_date=datetime.utcnow(),
                sensor_type='System Event',
                event_description=f'{action_names[action]} initiated via dashboard',
                severity='info',
                sel_id='ADMIN'
            )
            db.session.add(event)
            db.session.commit()
            
            app.logger.info(f"Power {action} executed on {bmc_ip} ({server_name})")
            
            return jsonify({
                'status': 'success',
                'message': f'{action_names[action]} command sent to {server_name}',
                'output': result.stdout.strip()
            })
        else:
            return jsonify({
                'status': 'error',
                'message': f'Power {action} failed: {result.stderr}'
            }), 500
    except subprocess.TimeoutExpired:
        return jsonify({'status': 'error', 'message': f'Timeout executing power {action}'}), 500
    except Exception as e:
        app.logger.error(f"Power {action} error for {bmc_ip}: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/clear_all_sel', methods=['POST'])
@write_required
def api_clear_all_sel():
    """Clear SEL logs on all BMCs - Requires write access"""
    results = {'success': [], 'failed': []}
    
    for bmc_ip, server_name in SERVERS.items():
        try:
            password = get_ipmi_password(bmc_ip)
            result = subprocess.run(
                ['ipmitool', '-I', 'lanplus', '-H', bmc_ip,
                 '-U', IPMI_USER, '-P', password, 'sel', 'clear'],
                capture_output=True, text=True, timeout=30
            )
            
            if result.returncode == 0:
                IPMIEvent.query.filter_by(bmc_ip=bmc_ip).delete()
                results['success'].append(bmc_ip)
            else:
                results['failed'].append({'bmc_ip': bmc_ip, 'error': result.stderr})
        except Exception as e:
            results['failed'].append({'bmc_ip': bmc_ip, 'error': str(e)})
    
    db.session.commit()
    
    return jsonify({
        'status': 'completed',
        'cleared': len(results['success']),
        'failed': len(results['failed']),
        'details': results
    })

@app.route('/api/server/<bmc_ip>/clear_db_events', methods=['POST'])
@write_required
@require_valid_bmc_ip
def api_clear_db_events(bmc_ip):
    """Clear events from database only - Requires write access"""
    try:
        count = IPMIEvent.query.filter_by(bmc_ip=bmc_ip).delete()
        db.session.commit()
        
        # Update server status
        server_name = SERVERS.get(bmc_ip, bmc_ip)
        update_server_status(bmc_ip, server_name)
        
        return jsonify({
            'status': 'success',
            'message': f'Cleared {count} events from database for {bmc_ip}'
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500

# Prometheus Metrics Endpoint
def update_prometheus_metrics():
    """Update all Prometheus metrics from database"""
    cutoff_24h = datetime.utcnow() - timedelta(hours=24)
    cutoff_1h = datetime.utcnow() - timedelta(hours=1)
    
    # Per-server metrics
    servers = ServerStatus.query.all()
    for s in servers:
        labels = {'bmc_ip': s.bmc_ip, 'server_name': s.server_name}
        prom_server_reachable.labels(**labels).set(1 if s.is_reachable else 0)
        prom_server_power_on.labels(**labels).set(1 if s.power_status and 'on' in s.power_status.lower() else 0)
        prom_events_total.labels(**labels).set(s.total_events or 0)
        prom_events_critical_24h.labels(**labels).set(s.critical_events_24h or 0)
        prom_events_warning_24h.labels(**labels).set(s.warning_events_24h or 0)
    
    # Sensor metrics - get latest reading per sensor (within last hour)
    try:
        sensors = SensorReading.query.filter(
            SensorReading.collected_at >= cutoff_1h
        ).all()
        
        # Track latest reading per sensor
        latest_sensors = {}
        for sensor in sensors:
            key = (sensor.bmc_ip, sensor.sensor_name)
            if key not in latest_sensors or sensor.collected_at > latest_sensors[key].collected_at:
                latest_sensors[key] = sensor
        
        # Export sensor metrics
        for sensor in latest_sensors.values():
            if sensor.value is None:
                continue
            
            labels = {
                'bmc_ip': sensor.bmc_ip,
                'server_name': sensor.server_name,
                'sensor_name': sensor.sensor_name
            }
            
            if sensor.sensor_type == 'temperature':
                prom_temperature.labels(**labels).set(sensor.value)
            elif sensor.sensor_type == 'fan':
                prom_fan_speed.labels(**labels).set(sensor.value)
            elif sensor.sensor_type == 'voltage':
                prom_voltage.labels(**labels).set(sensor.value)
        
        # Power readings
        power_readings = PowerReading.query.filter(
            PowerReading.collected_at >= cutoff_1h
        ).all()
        
        latest_power = {}
        for reading in power_readings:
            if reading.bmc_ip not in latest_power or reading.collected_at > latest_power[reading.bmc_ip].collected_at:
                latest_power[reading.bmc_ip] = reading
        
        for reading in latest_power.values():
            if reading.current_watts is not None:
                prom_power_watts.labels(
                    bmc_ip=reading.bmc_ip,
                    server_name=reading.server_name
                ).set(reading.current_watts)
    except Exception as e:
        app.logger.warning(f"Error updating sensor metrics: {e}")
    
    # Aggregate metrics
    prom_total_servers.set(len(servers))
    prom_reachable_servers.set(sum(1 for s in servers if s.is_reachable))
    prom_total_critical_24h.set(IPMIEvent.query.filter(
        IPMIEvent.severity == 'critical',
        IPMIEvent.event_date >= cutoff_24h
    ).count())
    prom_total_warning_24h.set(IPMIEvent.query.filter(
        IPMIEvent.severity == 'warning',
        IPMIEvent.event_date >= cutoff_24h
    ).count())
    prom_collection_timestamp.set(time.time())
    
    # Alert metrics
    try:
        prom_alerts_total.set(AlertHistory.query.count())
        prom_alerts_unacknowledged.set(AlertHistory.query.filter_by(acknowledged=False).count())
        prom_alerts_critical_24h.set(AlertHistory.query.filter(
            AlertHistory.fired_at >= cutoff_24h,
            AlertHistory.severity == 'critical'
        ).count())
        prom_alerts_warning_24h.set(AlertHistory.query.filter(
            AlertHistory.fired_at >= cutoff_24h,
            AlertHistory.severity == 'warning'
        ).count())
    except Exception as e:
        app.logger.debug(f"Error updating alert metrics: {e}")

# ============== Server Management API ==============

@app.route('/api/servers/managed')
def api_managed_servers():
    """Get all managed servers from database
    
    Query params:
        status: Filter by status (active, deprecated, all). Default: active
        include_deprecated: If 'true', include deprecated servers (legacy param)
    """
    status_filter = request.args.get('status', 'active')
    include_deprecated = request.args.get('include_deprecated', 'false').lower() == 'true'
    
    if status_filter == 'all' or include_deprecated:
        servers = Server.query.all()
    elif status_filter == 'deprecated':
        servers = Server.query.filter_by(status='deprecated').all()
    else:
        # Default: only active servers
        servers = Server.query.filter(
            Server.status.in_(['active', None])
        ).all()
    
    return jsonify([{
        'id': s.id,
        'bmc_ip': s.bmc_ip,
        'server_name': s.server_name,
        'server_ip': s.server_ip,
        'public_ip': s.public_ip,
        'enabled': s.enabled,
        'status': s.status or 'active',
        'deprecated_at': s.deprecated_at.isoformat() if s.deprecated_at else None,
        'deprecated_reason': s.deprecated_reason,
        'use_nvidia_password': s.use_nvidia_password,
        'notes': s.notes,
        'created_at': s.created_at.isoformat() if s.created_at else None,
        'updated_at': s.updated_at.isoformat() if s.updated_at else None
    } for s in servers])

@app.route('/api/servers/add', methods=['POST'])
@write_required
def api_add_server():
    """Add a new server to monitor - Requires write access"""
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Request body must be JSON'}), 400
    
    bmc_ip = data.get('bmc_ip', '').strip()
    server_name = data.get('server_name', '').strip()
    
    if not bmc_ip or not server_name:
        return jsonify({'error': 'bmc_ip and server_name are required'}), 400
    
    # Validate IP address format
    if not validate_ip_address(bmc_ip):
        return jsonify({'error': f'Invalid IP address format: {bmc_ip}'}), 400
    
    # Check if already exists
    existing = Server.query.filter_by(bmc_ip=bmc_ip).first()
    if existing:
        return jsonify({'error': f'Server with BMC IP {bmc_ip} already exists'}), 409
    
    protocol = data.get('protocol', 'auto')
    if protocol not in ['auto', 'ipmi', 'redfish']:
        protocol = 'auto'
    
    server = Server(
        bmc_ip=bmc_ip,
        server_name=server_name,
        server_ip=data.get('server_ip', bmc_ip.replace('.0', '.1')),
        enabled=data.get('enabled', True),
        use_nvidia_password=data.get('use_nvidia_password', False),
        protocol=protocol,
        notes=data.get('notes', '')
    )
    
    db.session.add(server)
    db.session.commit()
    
    # Also update NVIDIA_BMCS set if needed (thread-safe)
    if server.use_nvidia_password:
        with _nvidia_bmcs_lock:
            NVIDIA_BMCS.add(bmc_ip)
    
    return jsonify({'status': 'success', 'message': f'Added server {server_name} ({bmc_ip})', 'id': server.id})

@app.route('/api/servers/<bmc_ip>', methods=['GET', 'PUT', 'DELETE'])
@require_valid_bmc_ip
def api_manage_server(bmc_ip):
    """Get, update, or delete a server (PUT/DELETE require admin)"""
    # Require admin for modifications
    if request.method in ['PUT', 'DELETE'] and not is_admin():
        return jsonify({'error': 'Admin authentication required'}), 401
    
    server = Server.query.filter_by(bmc_ip=bmc_ip).first()
    
    if request.method == 'GET':
        if not server:
            # Check if in default list
            if bmc_ip in DEFAULT_SERVERS:
                return jsonify({
                    'bmc_ip': bmc_ip,
                    'server_name': DEFAULT_SERVERS[bmc_ip],
                    'enabled': True,
                    'is_default': True
                })
            return jsonify({'error': 'Server not found'}), 404
        
        return jsonify({
            'id': server.id,
            'bmc_ip': server.bmc_ip,
            'server_name': server.server_name,
            'server_ip': server.server_ip,
            'enabled': server.enabled,
            'status': server.status or 'active',
            'deprecated_at': server.deprecated_at.isoformat() if server.deprecated_at else None,
            'deprecated_reason': server.deprecated_reason,
            'use_nvidia_password': server.use_nvidia_password,
            'protocol': server.protocol or 'auto',
            'notes': server.notes,
            'is_default': False
        })
    
    elif request.method == 'PUT':
        data = request.get_json()
        
        if not server:
            # Create from default if exists
            if bmc_ip in DEFAULT_SERVERS:
                server = Server(
                    bmc_ip=bmc_ip,
                    server_name=DEFAULT_SERVERS[bmc_ip]
                )
                db.session.add(server)
            else:
                return jsonify({'error': 'Server not found'}), 404
        
        if 'server_name' in data:
            server.server_name = data['server_name']
        if 'server_ip' in data:
            server.server_ip = data['server_ip']
        if 'enabled' in data:
            server.enabled = data['enabled']
        if 'use_nvidia_password' in data:
            server.use_nvidia_password = data['use_nvidia_password']
            # Thread-safe update of NVIDIA_BMCS
            with _nvidia_bmcs_lock:
                if data['use_nvidia_password']:
                    NVIDIA_BMCS.add(bmc_ip)
                else:
                    NVIDIA_BMCS.discard(bmc_ip)
        if 'protocol' in data:
            protocol = data['protocol']
            if protocol in ['auto', 'ipmi', 'redfish']:
                server.protocol = protocol
                # Clear Redfish cache when protocol changes
                with _redfish_cache_lock:
                    _redfish_cache.pop(bmc_ip, None)
        if 'notes' in data:
            server.notes = data['notes']
        
        db.session.commit()
        return jsonify({'status': 'success', 'message': f'Updated server {bmc_ip}'})
    
    elif request.method == 'DELETE':
        if not server:
            return jsonify({'error': 'Server not found'}), 404
        
        # Also delete related data
        ServerStatus.query.filter_by(bmc_ip=bmc_ip).delete()
        IPMIEvent.query.filter_by(bmc_ip=bmc_ip).delete()
        ServerConfig.query.filter_by(bmc_ip=bmc_ip).delete()
        SensorReading.query.filter_by(bmc_ip=bmc_ip).delete()
        PowerReading.query.filter_by(bmc_ip=bmc_ip).delete()
        
        db.session.delete(server)
        db.session.commit()
        
        return jsonify({'status': 'success', 'message': f'Deleted server {bmc_ip} and all related data'})


# ============== Server Lifecycle Management ==============

@app.route('/api/servers/<bmc_ip>/deprecate', methods=['POST'])
@write_required
@require_valid_bmc_ip
def api_deprecate_server(bmc_ip):
    """Deprecate a server - stops collection but preserves all data"""
    server = Server.query.filter_by(bmc_ip=bmc_ip).first()
    if not server:
        return jsonify({'error': 'Server not found'}), 404
    
    data = request.get_json() or {}
    reason = data.get('reason', 'Server deprecated by admin')
    
    server.deprecate(reason)
    db.session.commit()
    
    app.logger.info(f"Server {bmc_ip} ({server.server_name}) deprecated: {reason}")
    
    return jsonify({
        'status': 'success',
        'message': f'Server {server.server_name} has been deprecated',
        'server': {
            'bmc_ip': server.bmc_ip,
            'server_name': server.server_name,
            'status': server.status,
            'deprecated_at': server.deprecated_at.isoformat() if server.deprecated_at else None,
            'deprecated_reason': server.deprecated_reason
        }
    })


@app.route('/api/servers/<bmc_ip>/restore', methods=['POST'])
@write_required
@require_valid_bmc_ip
def api_restore_server(bmc_ip):
    """Restore a deprecated server to active status"""
    server = Server.query.filter_by(bmc_ip=bmc_ip).first()
    if not server:
        return jsonify({'error': 'Server not found'}), 404
    
    if server.status != 'deprecated':
        return jsonify({'error': f'Server is not deprecated (status: {server.status})'}), 400
    
    server.restore()
    db.session.commit()
    
    app.logger.info(f"Server {bmc_ip} ({server.server_name}) restored to active")
    
    return jsonify({
        'status': 'success',
        'message': f'Server {server.server_name} has been restored to active',
        'server': {
            'bmc_ip': server.bmc_ip,
            'server_name': server.server_name,
            'status': server.status
        }
    })


@app.route('/api/servers/<bmc_ip>/purge', methods=['DELETE'])
@write_required
@require_valid_bmc_ip
def api_purge_server(bmc_ip):
    """Permanently delete a deprecated server and ALL its data
    
    This is destructive - removes:
    - Server record
    - All events
    - All sensor readings
    - All power readings
    - Server status
    - Server inventory
    - Server config
    """
    server = Server.query.filter_by(bmc_ip=bmc_ip).first()
    if not server:
        return jsonify({'error': 'Server not found'}), 404
    
    # Safety: only allow purge of deprecated servers (or force with param)
    force = request.args.get('force', 'false').lower() == 'true'
    if server.status != 'deprecated' and not force:
        return jsonify({
            'error': 'Server must be deprecated before purging. Use ?force=true to override.',
            'status': server.status
        }), 400
    
    server_name = server.server_name
    
    # Count data being deleted
    event_count = IPMIEvent.query.filter_by(bmc_ip=bmc_ip).count()
    sensor_count = SensorReading.query.filter_by(bmc_ip=bmc_ip).count()
    
    # Delete all related data
    IPMIEvent.query.filter_by(bmc_ip=bmc_ip).delete()
    SensorReading.query.filter_by(bmc_ip=bmc_ip).delete()
    PowerReading.query.filter_by(bmc_ip=bmc_ip).delete()
    ServerStatus.query.filter_by(bmc_ip=bmc_ip).delete()
    ServerConfig.query.filter_by(bmc_ip=bmc_ip).delete()
    ServerInventory.query.filter_by(bmc_ip=bmc_ip).delete()
    
    # Delete server
    db.session.delete(server)
    db.session.commit()
    
    app.logger.warning(f"Server {bmc_ip} ({server_name}) PURGED: {event_count} events, {sensor_count} sensor readings deleted")
    
    return jsonify({
        'status': 'success',
        'message': f'Server {server_name} and all data permanently deleted',
        'deleted': {
            'events': event_count,
            'sensors': sensor_count
        }
    })


@app.route('/api/servers/deprecated')
@login_required
def api_deprecated_servers():
    """Get list of deprecated servers"""
    servers = Server.query.filter_by(status='deprecated').all()
    
    return jsonify([{
        'id': s.id,
        'bmc_ip': s.bmc_ip,
        'server_name': s.server_name,
        'server_ip': s.server_ip,
        'deprecated_at': s.deprecated_at.isoformat() if s.deprecated_at else None,
        'deprecated_reason': s.deprecated_reason,
        'event_count': IPMIEvent.query.filter_by(bmc_ip=s.bmc_ip).count()
    } for s in servers])


@app.route('/api/servers/<bmc_ip>/fix-event-names', methods=['POST'])
@write_required
@require_valid_bmc_ip
def api_fix_event_names(bmc_ip):
    """Fix mismatched server names in events table"""
    server = Server.query.filter_by(bmc_ip=bmc_ip).first()
    if not server:
        return jsonify({'error': 'Server not found'}), 404
    
    # Count events with wrong names
    wrong_name_count = IPMIEvent.query.filter(
        IPMIEvent.bmc_ip == bmc_ip,
        IPMIEvent.server_name != server.server_name
    ).count()
    
    if wrong_name_count == 0:
        return jsonify({
            'status': 'success',
            'message': 'No mismatched event names found',
            'fixed': 0
        })
    
    # Update all events to use correct server name
    IPMIEvent.query.filter(
        IPMIEvent.bmc_ip == bmc_ip
    ).update({IPMIEvent.server_name: server.server_name})
    
    db.session.commit()
    
    app.logger.info(f"Fixed {wrong_name_count} event names for {bmc_ip} -> {server.server_name}")
    
    return jsonify({
        'status': 'success',
        'message': f'Updated {wrong_name_count} events to use server name: {server.server_name}',
        'fixed': wrong_name_count
    })


@app.route('/api/servers/import', methods=['POST'])
@write_required
def api_import_servers():
    """Import servers from INI format or JSON - Requires write access"""
    content_type = request.content_type
    
    if 'application/json' in content_type:
        data = request.get_json()
        servers_data = data.get('servers', [])
    else:
        # Parse INI format
        ini_content = request.get_data(as_text=True)
        servers_data = parse_ini_servers(ini_content)
    
    added = 0
    updated = 0
    errors = []
    
    for server_data in servers_data:
        bmc_ip = server_data.get('bmc_ip')
        server_name = server_data.get('server_name')
        
        if not bmc_ip or not server_name:
            errors.append(f"Missing bmc_ip or server_name: {server_data}")
            continue
        
        try:
            existing = Server.query.filter_by(bmc_ip=bmc_ip).first()
            if existing:
                existing.server_name = server_name
                existing.server_ip = server_data.get('server_ip', bmc_ip.replace('.0', '.1'))
                existing.public_ip = server_data.get('public_ip')
                existing.enabled = server_data.get('enabled', True)
                existing.use_nvidia_password = server_data.get('use_nvidia_password', False)
                existing.notes = server_data.get('notes', '')
                updated += 1
            else:
                server = Server(
                    bmc_ip=bmc_ip,
                    server_name=server_name,
                    server_ip=server_data.get('server_ip', bmc_ip.replace('.0', '.1')),
                    public_ip=server_data.get('public_ip'),
                    enabled=server_data.get('enabled', True),
                    use_nvidia_password=server_data.get('use_nvidia_password', False),
                    notes=server_data.get('notes', '')
                )
                db.session.add(server)
                added += 1
        except Exception as e:
            errors.append(f"Error processing {bmc_ip}: {str(e)}")
    
    db.session.commit()
    
    return jsonify({
        'status': 'success',
        'added': added,
        'updated': updated,
        'errors': errors
    })

@app.route('/api/servers/export')
def api_export_servers():
    """Export servers in INI format"""
    format_type = request.args.get('format', 'ini')
    servers = Server.query.all()
    
    if format_type == 'json':
        return jsonify([{
            'bmc_ip': s.bmc_ip,
            'server_name': s.server_name,
            'server_ip': s.server_ip,
            'enabled': s.enabled,
            'use_nvidia_password': s.use_nvidia_password,
            'notes': s.notes
        } for s in servers])
    
    # INI format
    ini_lines = [f"# {APP_NAME} - Server List", "# Format: bmc_ip = server_name", ""]
    ini_lines.append("[servers]")
    for s in servers:
        line = f"{s.bmc_ip} = {s.server_name}"
        if s.use_nvidia_password:
            line += "  # nvidia"
        ini_lines.append(line)
    
    return Response('\n'.join(ini_lines), mimetype='text/plain')


# ============== Server Inventory API ==============

@app.route('/api/servers/<bmc_ip>/inventory')
@require_valid_bmc_ip
def api_get_server_inventory(bmc_ip):
    """Get hardware inventory for a server"""
    inventory = ServerInventory.query.filter_by(bmc_ip=bmc_ip).first()
    if not inventory:
        return jsonify({
            'status': 'not_collected',
            'message': 'Inventory not yet collected. Use POST to collect.',
            'bmc_ip': bmc_ip
        })
    return jsonify(inventory.to_dict())


@app.route('/api/servers/<bmc_ip>/inventory', methods=['POST'])
@write_required
@require_valid_bmc_ip
def api_collect_server_inventory(bmc_ip):
    """Collect hardware inventory via IPMI FRU - Requires write access"""
    server = Server.query.filter_by(bmc_ip=bmc_ip).first()
    if not server:
        return jsonify({'error': 'Server not found'}), 404
    
    # Get IPMI credentials (pass bmc_ip string, not server object)
    ipmi_user, ipmi_pass = get_ipmi_credentials(bmc_ip)
    
    try:
        inventory_data = collect_server_inventory(bmc_ip, server.server_name, ipmi_user, ipmi_pass, server.server_ip)
        return jsonify({
            'status': 'success',
            'message': 'Inventory collected successfully',
            'inventory': inventory_data
        })
    except Exception as e:
        app.logger.error(f"Failed to collect inventory for {bmc_ip}: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/inventory/collect-all', methods=['POST'])
@write_required
def api_collect_all_inventory():
    """Collect inventory for all servers - Requires write access"""
    servers = Server.query.filter_by(enabled=True).all()
    results = {'success': 0, 'failed': 0, 'errors': []}
    
    for server in servers:
        try:
            ipmi_user, ipmi_pass = get_ipmi_credentials(server.bmc_ip)  # Pass bmc_ip string
            collect_server_inventory(server.bmc_ip, server.server_name, ipmi_user, ipmi_pass, server.server_ip)
            results['success'] += 1
        except Exception as e:
            results['failed'] += 1
            results['errors'].append({'bmc_ip': server.bmc_ip, 'error': str(e)})
    
    return jsonify(results)


def infer_manufacturer(product_name, board_product=None):
    """Infer manufacturer from product name patterns
    
    Many BMCs don't report manufacturer explicitly, but we can often
    determine it from the product naming conventions.
    """
    # Combine product and board names for matching
    combined = f"{product_name or ''} {board_product or ''}".upper()
    
    # Known product name patterns -> manufacturer
    patterns = {
        # ASUS / ASUSTeK
        'ESC': 'ASUS',
        'RS': 'ASUS',  # RS700, RS720, etc.
        'KRPG': 'ASUS',
        'Z10': 'ASUS',  # Z10PA, Z10PE, etc.
        'Z11': 'ASUS',
        'WS': 'ASUS',  # Workstation boards
        
        # Supermicro
        'X10': 'Supermicro',
        'X11': 'Supermicro',
        'X12': 'Supermicro',
        'X13': 'Supermicro',
        'H11': 'Supermicro',
        'H12': 'Supermicro',
        'SYS-': 'Supermicro',
        'SMC': 'Supermicro',
        
        # Dell
        'POWEREDGE': 'Dell',
        'DELL': 'Dell',
        'R6': 'Dell',  # R640, R650, etc.
        'R7': 'Dell',  # R740, R750, etc.
        'R8': 'Dell',
        
        # HPE / HP
        'PROLIANT': 'HPE',
        'DL3': 'HPE',  # DL360, DL380, etc.
        'DL5': 'HPE',
        'DL1': 'HPE',
        'APOLLO': 'HPE',
        
        # Lenovo
        'THINKSYSTEM': 'Lenovo',
        'SR6': 'Lenovo',  # SR650, etc.
        'SR5': 'Lenovo',
        'THINKSTATION': 'Lenovo',
        
        # Gigabyte
        'R2': 'Gigabyte',  # R281, R282, etc.
        'G2': 'Gigabyte',  # G291, G292, etc.
        'MZ': 'Gigabyte',
        
        # NVIDIA DGX
        'DGX': 'NVIDIA',
        
        # Intel
        'S2600': 'Intel',
        'S2400': 'Intel',
        
        # Inspur
        'NF': 'Inspur',  # NF5280, etc.
        
        # Fujitsu
        'PRIMERGY': 'Fujitsu',
        'RX': 'Fujitsu',  # RX2530, etc.
    }
    
    for pattern, manufacturer in patterns.items():
        if pattern in combined:
            return manufacturer
    
    return None


def collect_server_inventory(bmc_ip, server_name, ipmi_user, ipmi_pass, server_ip=None):
    """Collect hardware inventory from a server via IPMI FRU, Redfish, and SDR"""
    import subprocess
    import json
    
    inventory = ServerInventory.query.filter_by(bmc_ip=bmc_ip).first()
    if not inventory:
        inventory = ServerInventory(bmc_ip=bmc_ip, server_name=server_name)
        db.session.add(inventory)
    
    inventory.server_name = server_name
    inventory.primary_ip = server_ip
    
    # Collect FRU data (device 0 = builtin FRU)
    try:
        cmd = ['ipmitool', '-I', 'lanplus', '-H', bmc_ip, '-U', ipmi_user, '-P', ipmi_pass, 'fru', 'print', '0']
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        fru_output = result.stdout
        inventory.fru_data = fru_output
        
        # Parse FRU data
        for line in fru_output.split('\n'):
            line = line.strip()
            if ':' in line:
                key, _, value = line.partition(':')
                key = key.strip().lower()
                value = value.strip()
                
                if 'product manufacturer' in key:
                    inventory.manufacturer = value
                elif 'chassis manufacturer' in key and not inventory.manufacturer:
                    inventory.manufacturer = value
                elif 'product name' in key:
                    inventory.product_name = value
                elif 'product serial' in key:
                    inventory.serial_number = value
                elif 'product part' in key:
                    inventory.part_number = value
                elif 'board mfg' in key and 'date' not in key:
                    inventory.board_manufacturer = value
                elif 'board product' in key:
                    inventory.board_product = value
                elif 'board serial' in key:
                    inventory.board_serial = value
        
        # Infer manufacturer from product name if not explicitly set
        if not inventory.manufacturer and inventory.product_name:
            inventory.manufacturer = infer_manufacturer(inventory.product_name, inventory.board_product)
            
    except Exception as e:
        app.logger.warning(f"FRU collection failed for {bmc_ip}: {e}")
    
    # Get BMC MAC address
    try:
        cmd = ['ipmitool', '-I', 'lanplus', '-H', bmc_ip, '-U', ipmi_user, '-P', ipmi_pass, 'lan', 'print', '1']
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        for line in result.stdout.split('\n'):
            if 'MAC Address' in line and ':' in line:
                inventory.bmc_mac_address = line.split(':',1)[1].strip()
                break
    except Exception as e:
        app.logger.warning(f"BMC MAC collection failed for {bmc_ip}: {e}")
    
    # Get BMC firmware version
    try:
        cmd = ['ipmitool', '-I', 'lanplus', '-H', bmc_ip, '-U', ipmi_user, '-P', ipmi_pass, 'mc', 'info']
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        for line in result.stdout.split('\n'):
            if 'Firmware Revision' in line and ':' in line:
                inventory.bmc_firmware = line.split(':',1)[1].strip()
                break
    except Exception as e:
        app.logger.warning(f"BMC firmware version collection failed for {bmc_ip}: {e}")
    
    # ========== CPU/Memory/Storage from Redfish ==========
    try:
        if should_use_redfish(bmc_ip):
            client = get_redfish_client(bmc_ip)
            
            # Get System info (Manufacturer, Model) from Redfish
            try:
                sys_info = client.get_system_info()
                if sys_info:
                    # Use Redfish manufacturer if not already set from FRU
                    if not inventory.manufacturer and sys_info.get('Manufacturer'):
                        inventory.manufacturer = sys_info['Manufacturer']
                    # Use Redfish model/serial if not already set
                    if not inventory.product_name and sys_info.get('Model'):
                        inventory.product_name = sys_info['Model']
                    if not inventory.serial_number and sys_info.get('SerialNumber'):
                        inventory.serial_number = sys_info['SerialNumber']
                    app.logger.info(f"Redfish system info for {bmc_ip}: {sys_info.get('Manufacturer')} {sys_info.get('Model')}")
            except Exception as e:
                app.logger.debug(f"Redfish system info failed for {bmc_ip}: {e}")
            
            # Get CPU info from Redfish
            try:
                cpu_info = client.get_processors()
                if cpu_info:
                    inventory.cpu_count = len(cpu_info)
                    if cpu_info:
                        first_cpu = cpu_info[0]
                        inventory.cpu_model = first_cpu.get('Model', first_cpu.get('ProcessorId', {}).get('VendorId', ''))
                        inventory.cpu_cores = first_cpu.get('TotalCores', 0)
                        app.logger.info(f"Redfish CPU for {bmc_ip}: {inventory.cpu_model}, {inventory.cpu_count} CPUs, {inventory.cpu_cores} cores")
            except Exception as e:
                app.logger.debug(f"Redfish CPU collection failed for {bmc_ip}: {e}")
            
            # Get Memory info from Redfish
            try:
                memory_info = client.get_memory()
                if memory_info:
                    total_gb = sum(m.get('CapacityMiB', 0) for m in memory_info) / 1024
                    slots_used = len([m for m in memory_info if m.get('CapacityMiB', 0) > 0])
                    inventory.memory_total_gb = round(total_gb, 1)
                    inventory.memory_slots_used = slots_used
                    inventory.memory_slots_total = len(memory_info)
                    app.logger.info(f"Redfish Memory for {bmc_ip}: {inventory.memory_total_gb}GB, {slots_used}/{len(memory_info)} slots")
            except Exception as e:
                app.logger.debug(f"Redfish memory collection failed for {bmc_ip}: {e}")
            
            # Get Storage info from Redfish
            try:
                storage_info = client.get_storage()
                if storage_info:
                    inventory.storage_info = json.dumps(storage_info)
                    app.logger.info(f"Redfish Storage for {bmc_ip}: {len(storage_info)} drives")
            except Exception as e:
                app.logger.debug(f"Redfish storage collection failed for {bmc_ip}: {e}")
            
            # Get GPU info from Redfish (NVIDIA DGX, etc.)
            try:
                gpu_info = client.get_gpus()
                if gpu_info:
                    inventory.gpu_info = json.dumps(gpu_info)
                    inventory.gpu_count = len(gpu_info)
                    app.logger.info(f"Redfish GPU for {bmc_ip}: {len(gpu_info)} GPUs - {gpu_info[0].get('name', 'GPU')}")
            except Exception as e:
                app.logger.debug(f"Redfish GPU collection failed for {bmc_ip}: {e}")
                
    except Exception as e:
        app.logger.debug(f"Redfish inventory collection failed for {bmc_ip}: {e}")
    
    # ========== CPU/Memory from IPMI SDR (fallback) ==========
    if not inventory.cpu_model or not inventory.memory_total_gb:
        try:
            cmd = ['ipmitool', '-I', 'lanplus', '-H', bmc_ip, '-U', ipmi_user, '-P', ipmi_pass, 'sdr', 'elist', 'full']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            cpu_count = 0
            dimm_count = 0
            
            for line in result.stdout.split('\n'):
                line_lower = line.lower()
                # Count CPUs from temperature sensors
                if ('cpu' in line_lower or 'processor' in line_lower) and 'temp' in line_lower:
                    cpu_count += 1
                # Count DIMMs from temperature sensors
                if 'dimm' in line_lower and 'temp' in line_lower:
                    dimm_count += 1
            
            if cpu_count > 0 and not inventory.cpu_count:
                inventory.cpu_count = cpu_count
                app.logger.info(f"SDR found {cpu_count} CPUs for {bmc_ip}")
            
            if dimm_count > 0 and not inventory.memory_slots_used:
                inventory.memory_slots_used = dimm_count
                app.logger.info(f"SDR found {dimm_count} DIMMs for {bmc_ip}")
                
        except Exception as e:
            app.logger.debug(f"SDR inventory collection failed for {bmc_ip}: {e}")
    
    # ========== CPU/Memory/Storage/GPU from SSH to OS (if enabled and reachable) ==========
    # SSH is opt-in - must be enabled in settings
    ssh_enabled = SystemSettings.get('enable_ssh_inventory', 'false').lower() == 'true'
    needs_ssh = (not inventory.cpu_model or not inventory.memory_total_gb or 
                 not inventory.memory_slots_total or not inventory.storage_info or
                 not inventory.gpu_info)  # Also need SSH for GPU detection
    if ssh_enabled and server_ip and needs_ssh:
        try:
            # Check if SSH port is open
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            ssh_available = sock.connect_ex((server_ip, 22)) == 0
            sock.close()
            
            if ssh_available:
                app.logger.info(f"SSH available for {bmc_ip} ({server_ip}), collecting detailed inventory")
                
                # Get SSH credentials - check per-server config first, then settings, then env vars
                server_config = ServerConfig.query.filter_by(bmc_ip=bmc_ip).first()
                ssh_key_content = None
                
                if server_config:
                    ssh_user = server_config.ssh_user or 'root'
                    ssh_pass = server_config.ssh_pass or ''
                    
                    # Check for stored SSH key by ID first
                    if server_config.ssh_key_id:
                        stored_key = SSHKey.query.get(server_config.ssh_key_id)
                        if stored_key:
                            ssh_key_content = stored_key.key_content
                            app.logger.info(f"Using stored SSH key '{stored_key.name}' for {bmc_ip}")
                    # Fall back to inline key if set
                    elif server_config.ssh_key:
                        ssh_key_content = server_config.ssh_key
                        app.logger.info(f"Using inline SSH key for {bmc_ip}")
                    else:
                        app.logger.info(f"Using per-server SSH credentials (password) for {bmc_ip}")
                else:
                    ssh_user = SystemSettings.get('ssh_user') or os.environ.get('SSH_USER', 'root')
                    ssh_pass = SystemSettings.get('ssh_password') or os.environ.get('SSH_PASS', '')
                    # Check for default SSH key
                    default_key_id = SystemSettings.get('default_ssh_key_id')
                    if default_key_id:
                        stored_key = SSHKey.query.get(int(default_key_id))
                        if stored_key:
                            ssh_key_content = stored_key.key_content
                            app.logger.info(f"Using default stored SSH key '{stored_key.name}' for {bmc_ip}")
                
                # Build SSH command - prefer key auth, fall back to password
                def build_ssh_cmd(remote_cmd):
                    ssh_opts = ['-o', 'ConnectTimeout=5', '-o', 'StrictHostKeyChecking=no', '-o', 'BatchMode=no']
                    
                    # Key-based auth takes priority
                    if ssh_key_content:
                        # Write key to temp file for use
                        # Ensure proper line endings and trailing newline
                        import tempfile
                        key_content_clean = ssh_key_content.replace('\r\n', '\n').strip() + '\n'
                        key_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.pem')
                        key_file.write(key_content_clean)
                        key_file.close()
                        os.chmod(key_file.name, 0o600)
                        return ['ssh'] + ssh_opts + ['-i', key_file.name, '-o', 'BatchMode=yes', f'{ssh_user}@{server_ip}', remote_cmd]
                    elif ssh_pass:
                        # Use sshpass for password auth
                        return ['sshpass', '-p', ssh_pass, 'ssh'] + ssh_opts + [f'{ssh_user}@{server_ip}', remote_cmd]
                    else:
                        # Try passwordless (default key from ~/.ssh) auth
                        return ['ssh'] + ssh_opts + ['-o', 'BatchMode=yes', f'{ssh_user}@{server_ip}', remote_cmd]
                
                # ========== UPTIME CHECK (detect unexpected reboots) ==========
                try:
                    cmd = build_ssh_cmd('cat /proc/uptime')
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                    if result.returncode == 0 and result.stdout:
                        uptime_parts = result.stdout.strip().split()
                        if uptime_parts:
                            uptime_seconds = int(float(uptime_parts[0]))
                            check_uptime_and_detect_reboot(bmc_ip, server_name, uptime_seconds)
                except Exception as e:
                    app.logger.debug(f"SSH uptime check failed for {bmc_ip}: {e}")
                
                # CPU info via /proc/cpuinfo (most complete and reliable)
                try:
                    cmd = build_ssh_cmd('cat /proc/cpuinfo | grep -E "model name|vendor_id|physical id|cpu cores|siblings" | head -50')
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                    if result.returncode == 0 and result.stdout:
                        # Parse CPU info
                        physical_ids = set()
                        cpu_model = None
                        cpu_vendor = None
                        cpu_cores = None
                        siblings = None
                        for line in result.stdout.split('\n'):
                            if 'model name' in line and not cpu_model:
                                cpu_model = line.split(':')[1].strip() if ':' in line else None
                            if 'vendor_id' in line and not cpu_vendor:
                                cpu_vendor = line.split(':')[1].strip() if ':' in line else None
                            if 'physical id' in line:
                                physical_ids.add(line.split(':')[1].strip() if ':' in line else '0')
                            if 'cpu cores' in line and not cpu_cores:
                                try:
                                    cpu_cores = int(line.split(':')[1].strip())
                                except:
                                    pass
                            if 'siblings' in line and not siblings:
                                try:
                                    siblings = int(line.split(':')[1].strip())
                                except:
                                    pass
                        
                        # Build full CPU model with vendor if available
                        if cpu_model:
                            if cpu_vendor and cpu_vendor not in cpu_model:
                                inventory.cpu_model = f"{cpu_vendor} {cpu_model}"
                            else:
                                inventory.cpu_model = cpu_model
                        if physical_ids:
                            inventory.cpu_count = len(physical_ids)
                        if cpu_cores:
                            inventory.cpu_cores = cpu_cores
                        
                        app.logger.info(f"SSH CPU for {bmc_ip}: {inventory.cpu_model}, {inventory.cpu_count} sockets, {inventory.cpu_cores} cores/socket")
                except Exception as e:
                    app.logger.debug(f"SSH CPU collection failed for {bmc_ip}: {e}")
                
                # Memory info via /proc/meminfo
                try:
                    cmd = build_ssh_cmd('cat /proc/meminfo | grep MemTotal')
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                    if result.returncode == 0 and result.stdout:
                        # Parse: MemTotal:       32780132 kB
                        match = re.search(r'MemTotal:\s+(\d+)', result.stdout)
                        if match:
                            mem_kb = int(match.group(1))
                            inventory.memory_total_gb = round(mem_kb / 1024 / 1024, 1)
                            app.logger.info(f"SSH Memory for {bmc_ip}: {inventory.memory_total_gb}GB")
                except Exception as e:
                    app.logger.debug(f"SSH memory collection failed for {bmc_ip}: {e}")
                
                # Memory slots via dmidecode
                try:
                    cmd = build_ssh_cmd('dmidecode -t memory 2>/dev/null | grep -E "Number Of Devices|Size:" | head -30')
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                    if result.returncode == 0 and result.stdout:
                        # Parse: Number Of Devices: 8
                        match = re.search(r'Number Of Devices:\s+(\d+)', result.stdout)
                        if match:
                            inventory.memory_slots_total = int(match.group(1))
                        # Count populated slots (Size: XX GB, not "No Module Installed")
                        populated = len(re.findall(r'Size:\s+\d+\s*(GB|MB)', result.stdout, re.IGNORECASE))
                        if populated > 0:
                            inventory.memory_slots_used = populated
                        app.logger.info(f"SSH Memory slots for {bmc_ip}: {inventory.memory_slots_used}/{inventory.memory_slots_total}")
                except Exception as e:
                    app.logger.debug(f"SSH memory slots collection failed for {bmc_ip}: {e}")
                
                # Storage info via lsblk
                try:
                    cmd = build_ssh_cmd('lsblk -J -d -o NAME,SIZE,MODEL,TYPE 2>/dev/null || lsblk -d -o NAME,SIZE,MODEL,TYPE')
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                    if result.returncode == 0 and result.stdout:
                        try:
                            # Try JSON output first
                            storage_data = json.loads(result.stdout)
                            drives = [d for d in storage_data.get('blockdevices', []) if d.get('type') == 'disk']
                            if drives:
                                inventory.storage_info = json.dumps(drives)
                                app.logger.info(f"SSH Storage for {bmc_ip}: {len(drives)} drives")
                        except json.JSONDecodeError:
                            # Parse text output
                            drives = []
                            for line in result.stdout.strip().split('\n')[1:]:  # Skip header
                                parts = line.split()
                                if len(parts) >= 2:
                                    drives.append({
                                        'name': parts[0],
                                        'size': parts[1] if len(parts) > 1 else 'Unknown',
                                        'model': ' '.join(parts[2:-1]) if len(parts) > 3 else 'Unknown'
                                    })
                            if drives:
                                inventory.storage_info = json.dumps(drives)
                                app.logger.info(f"SSH Storage for {bmc_ip}: {len(drives)} drives")
                except Exception as e:
                    app.logger.debug(f"SSH storage collection failed for {bmc_ip}: {e}")
                
                # GPU info via lspci (VGA and 3D controllers)
                try:
                    cmd = build_ssh_cmd('lspci 2>/dev/null | grep -iE "vga|3d controller|display"')
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                    if result.returncode == 0 and result.stdout:
                        gpus = []
                        for line in result.stdout.strip().split('\n'):
                            if line:
                                # Parse: "01:00.0 VGA compatible controller: NVIDIA Corporation GA100 [A100 80GB PCIe]"
                                parts = line.split(': ', 1)
                                if len(parts) >= 2:
                                    pci_info = parts[0]  # "01:00.0 VGA compatible controller"
                                    vendor_model = parts[1]  # "NVIDIA Corporation GA100 [A100 80GB PCIe]"
                                    pci_addr = pci_info.split()[0] if pci_info else None
                                    gpus.append({
                                        'pci_address': pci_addr,
                                        'name': vendor_model.strip(),
                                        'type': 'VGA' if 'VGA' in line.upper() else '3D Controller'
                                    })
                        if gpus:
                            # Only update if we don't have GPU info from Redfish
                            if not inventory.gpu_info:
                                inventory.gpu_info = json.dumps(gpus)
                                inventory.gpu_count = len(gpus)
                            app.logger.info(f"SSH GPUs for {bmc_ip}: {len(gpus)} - {gpus[0].get('name', 'GPU')[:50]}")
                except Exception as e:
                    app.logger.debug(f"SSH GPU collection failed for {bmc_ip}: {e}")
                
                # NVIDIA Xid error detection via dmesg (CRITICAL GPU health events)
                try:
                    # Get Xid errors from dmesg - look for NVRM Xid messages
                    cmd = build_ssh_cmd('dmesg 2>/dev/null | grep -i "NVRM.*Xid" | tail -50')
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                    if result.returncode == 0 and result.stdout:
                        # Parse Xid errors
                        xid_pattern = r'\[([\d.]+)\].*Xid.*\(PCI:([0-9a-f:]+)\).*?(\d+),?\s*(.*)'
                        
                        # Xid severity mapping
                        critical_xids = {
                            31: 'GPU memory page fault',
                            43: 'GPU stopped responding', 
                            45: 'Preemptive cleanup',
                            48: 'Double bit ECC error',
                            61: 'Internal micro-controller breakpoint',
                            62: 'Internal micro-controller halt',
                            63: 'ECC page retirement',
                            64: 'ECC page retirement (DBE)',
                            74: 'GPU exception',
                            79: 'GPU fell off the bus',
                            92: 'High single-bit ECC error rate',
                            94: 'Contained ECC error',
                            95: 'Uncontained ECC error',
                            119: 'GSP error',
                            154: 'GPU recovery action required'
                        }
                        
                        xid_events = []
                        for line in result.stdout.strip().split('\n'):
                            match = re.search(xid_pattern, line, re.IGNORECASE)
                            if match:
                                kernel_time = match.group(1)
                                pci_address = match.group(2)
                                xid_code = int(match.group(3))
                                message = match.group(4).strip()
                                
                                # Check if this is a critical Xid
                                severity = 'critical' if xid_code in critical_xids else 'warning'
                                description = critical_xids.get(xid_code, f'Xid {xid_code} error')
                                
                                # Check for recovery action in message
                                recovery_action = None
                                if 'recovery action' in message.lower():
                                    if 'Node Reboot Required' in message or '0x2' in message:
                                        recovery_action = 'node_reboot'
                                    elif 'Power Cycle' in message or '0x3' in message:
                                        recovery_action = 'power_cycle'
                                    elif 'GPU Reset' in message or '0x1' in message:
                                        recovery_action = 'gpu_reset'
                                
                                xid_events.append({
                                    'kernel_time': kernel_time,
                                    'pci_address': pci_address,
                                    'xid_code': xid_code,
                                    'severity': severity,
                                    'description': description,
                                    'message': message,
                                    'recovery_action': recovery_action
                                })
                        
                        # Log critical Xid errors as events
                        if xid_events:
                            critical_count = sum(1 for x in xid_events if x['severity'] == 'critical')
                            app.logger.info(f"SSH Xid for {bmc_ip}: {len(xid_events)} errors ({critical_count} critical)")
                            
                            # Create events for critical Xid errors (deduplicated by PCI + code)
                            seen = set()
                            for xid in xid_events:
                                if xid['severity'] == 'critical':
                                    key = f"{xid['pci_address']}:{xid['xid_code']}"
                                    if key not in seen:
                                        seen.add(key)
                                        
                                        # Get server record
                                        server_record = Server.query.filter_by(bmc_ip=bmc_ip).first()
                                        if server_record:
                                            # Generate a unique sel_id for Xid events (XID-pci-code)
                                            xid_sel_id = f"XID-{xid['pci_address'][-5:]}-{xid['xid_code']}"
                                            
                                            # Check if we already logged this (using unique constraint)
                                            recent_event = IPMIEvent.query.filter(
                                                IPMIEvent.bmc_ip == bmc_ip,
                                                IPMIEvent.sel_id == xid_sel_id
                                            ).first()
                                            
                                            if not recent_event:
                                                # User-friendly description (hides Xid code from clients)
                                                event_desc = get_gpu_error_description(xid['xid_code'], xid.get('recovery_action'))
                                                event_desc += f" (GPU:{xid['pci_address'][-5:]})"
                                                
                                                event = IPMIEvent(
                                                    bmc_ip=bmc_ip,
                                                    server_name=server_record.server_name,
                                                    sel_id=xid_sel_id,
                                                    event_date=datetime.utcnow(),
                                                    sensor_type='GPU Health',
                                                    sensor_id=xid['pci_address'],
                                                    event_description=event_desc,
                                                    severity='critical',
                                                    raw_entry=json.dumps({'xid': xid['xid_code'], 'message': xid.get('message'), 'recovery': xid.get('recovery_action')})
                                                )
                                                db.session.add(event)
                                                app.logger.warning(f"🔴 CRITICAL: {event_desc} on {server_record.server_name}")
                            
                            try:
                                db.session.commit()
                            except Exception as e:
                                db.session.rollback()
                                app.logger.error(f"Failed to save Xid events for {bmc_ip}: {e}")
                            
                            # Store Xid summary in inventory for display
                            inventory.raw_inventory = inventory.raw_inventory or '{}'
                            try:
                                raw = json.loads(inventory.raw_inventory)
                            except:
                                raw = {}
                            raw['xid_errors'] = xid_events[-10:]  # Last 10 Xid errors
                            raw['xid_critical_count'] = critical_count
                            inventory.raw_inventory = json.dumps(raw)
                            
                            # Check if maintenance task should be created based on error patterns
                            if critical_count >= 3:
                                check_maintenance_needed(bmc_ip, server_name)
                            
                except Exception as e:
                    app.logger.debug(f"SSH Xid collection failed for {bmc_ip}: {e}")
                
                # NIC info via lspci (Ethernet controllers)
                try:
                    cmd = build_ssh_cmd('lspci 2>/dev/null | grep -i ethernet')
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                    if result.returncode == 0 and result.stdout:
                        nics = []
                        for line in result.stdout.strip().split('\n'):
                            if line:
                                # Parse: "04:00.0 Ethernet controller: Intel Corporation I350 Gigabit..."
                                parts = line.split(': ', 1)
                                if len(parts) >= 2:
                                    pci_addr = parts[0].split()[0] if parts[0] else None
                                    nic_model = parts[1].strip()
                                    nics.append({
                                        'pci_address': pci_addr,
                                        'model': nic_model
                                    })
                        if nics:
                            # Store NIC info
                            if not inventory.nic_info:
                                inventory.nic_info = json.dumps(nics)
                                inventory.nic_count = len(nics)
                            app.logger.info(f"SSH NICs for {bmc_ip}: {len(nics)} - {nics[0].get('model', 'NIC')[:50]}")
                except Exception as e:
                    app.logger.debug(f"SSH NIC collection failed for {bmc_ip}: {e}")
                
                # NVMe devices via lspci
                try:
                    cmd = build_ssh_cmd('lspci 2>/dev/null | grep -i nvme')
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                    if result.returncode == 0 and result.stdout:
                        nvme_devices = []
                        for line in result.stdout.strip().split('\n'):
                            if line:
                                # Parse: "05:00.0 Non-Volatile memory controller: Samsung Electronics..."
                                parts = line.split(': ', 1)
                                if len(parts) >= 2:
                                    pci_addr = parts[0].split()[0] if parts[0] else None
                                    nvme_model = parts[1].strip()
                                    nvme_devices.append({
                                        'pci_address': pci_addr,
                                        'model': nvme_model,
                                        'type': 'nvme'
                                    })
                        if nvme_devices:
                            # Append NVMe info to storage_info
                            existing_storage = json.loads(inventory.storage_info) if inventory.storage_info else []
                            for nvme in nvme_devices:
                                existing_storage.append({
                                    'name': nvme['pci_address'],
                                    'model': nvme['model'],
                                    'type': 'nvme'
                                })
                            inventory.storage_info = json.dumps(existing_storage)
                            if not inventory.storage_count:
                                inventory.storage_count = len(existing_storage)
                            app.logger.info(f"SSH NVMe for {bmc_ip}: {len(nvme_devices)} devices")
                except Exception as e:
                    app.logger.debug(f"SSH NVMe collection failed for {bmc_ip}: {e}")
                
                # PCIe health check via lspci -vvv (checks AER, link status)
                # AER Error Types:
                # - UESta (Uncorrectable Error Status): DLP, SDES, TLP, FCP, CmpltTO, CmpltAbrt, UnxCmplt, RxOF, MalfTLP, ECRC, UnsupReq, ACSViol
                # - CESta (Correctable Error Status): RxErr, BadTLP, BadDLLP, Rollover, Timeout, NonFatalErr
                try:
                    # Get PCIe devices with verbose info including AER status
                    cmd = build_ssh_cmd('lspci -vvv 2>/dev/null | grep -E "^[0-9a-f]|DevSta:|LnkSta:|UESta:|UEMsk:|CESta:|CEMsk:|AER" | head -500')
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                    
                    pcie_devices = []
                    current_device = None
                    error_count = 0
                    
                    # Known AER error types with descriptions
                    ue_error_descriptions = {
                        'DLP': 'Data Link Protocol Error',
                        'SDES': 'Surprise Down Error',
                        'TLP': 'TLP Prefix Blocked',
                        'FCP': 'Flow Control Protocol Error',
                        'CmpltTO': 'Completion Timeout',
                        'CmpltAbrt': 'Completer Abort',
                        'UnxCmplt': 'Unexpected Completion',
                        'RxOF': 'Receiver Overflow',
                        'MalfTLP': 'Malformed TLP',
                        'ECRC': 'ECRC Error',
                        'UnsupReq': 'Unsupported Request',
                        'ACSViol': 'ACS Violation',
                        'UncorrIntErr': 'Uncorrectable Internal Error',
                        'BlockedTLP': 'Blocked TLP',
                        'AtomicOpBlocked': 'Atomic Op Blocked',
                        'TLPBlockedErr': 'TLP Blocked Error',
                    }
                    ce_error_descriptions = {
                        'RxErr': 'Receiver Error',
                        'BadTLP': 'Bad TLP',
                        'BadDLLP': 'Bad DLLP',
                        'Rollover': 'Replay Number Rollover',
                        'Timeout': 'Replay Timer Timeout',
                        'NonFatalErr': 'Non-Fatal Error (Advisory)',
                        'CorrIntErr': 'Corrected Internal Error',
                        'HeaderOF': 'Header Log Overflow',
                    }
                    
                    if result.returncode == 0 and result.stdout:
                        for line in result.stdout.split('\n'):
                            line = line.strip()
                            
                            # New device header: "01:00.0 VGA compatible controller: NVIDIA..."
                            if re.match(r'^[0-9a-f]{2}:[0-9a-f]{2}\.[0-9a-f]', line):
                                if current_device:
                                    pcie_devices.append(current_device)
                                    if current_device.get('errors'):
                                        error_count += 1
                                
                                parts = line.split(' ', 1)
                                device_id = parts[0]
                                device_name = parts[1] if len(parts) > 1 else 'Unknown'
                                current_device = {
                                    'device': device_id,
                                    'name': device_name[:100],  # Truncate long names
                                    'status': 'ok',
                                    'errors': [],
                                    'ue_errors': [],  # Uncorrectable (critical)
                                    'ce_errors': [],  # Correctable (warning)
                                    'link_status': None
                                }
                            
                            elif current_device:
                                # DevSta: CorrErr+ NonFatalErr- FatalErr- UnsupportedReq+
                                if 'DevSta:' in line:
                                    # Check for error flags
                                    if 'FatalErr+' in line:
                                        current_device['errors'].append('FatalError')
                                        current_device['status'] = 'critical'
                                    if 'NonFatalErr+' in line:
                                        current_device['errors'].append('NonFatalError')
                                        if current_device['status'] != 'critical':
                                            current_device['status'] = 'warning'
                                    if 'UnsupportedReq+' in line or 'UnssupportReq+' in line or 'UnsupReq+' in line:
                                        current_device['errors'].append('UnsupportedRequest')
                                        if current_device['status'] == 'ok':
                                            current_device['status'] = 'warning'
                                    if 'CorrErr+' in line:
                                        # Correctable error flag set - will be detailed in CESta
                                        pass
                                
                                # LnkSta: Speed 16GT/s, Width x16
                                if 'LnkSta:' in line:
                                    speed_match = re.search(r'Speed\s+(\S+)', line)
                                    width_match = re.search(r'Width\s+(x\d+)', line)
                                    if speed_match or width_match:
                                        current_device['link_status'] = {
                                            'speed': speed_match.group(1) if speed_match else None,
                                            'width': width_match.group(1) if width_match else None
                                        }
                                
                                # UESta: DLP+ SDES- TLP- ... (Uncorrectable Error Status - CRITICAL)
                                if 'UESta:' in line:
                                    # Parse error flags: word followed by + means error is set
                                    # Example: "UESta:  DLP- SDES- TLP- FCP- CmpltTO+ CmpltAbrt-"
                                    ue_errors = re.findall(r'(\w+)\+', line)
                                    for err in ue_errors:
                                        desc = ue_error_descriptions.get(err, err)
                                        current_device['ue_errors'].append({'code': err, 'desc': desc})
                                        current_device['errors'].append(f'UE:{err}')
                                        current_device['status'] = 'critical'
                                
                                # CESta: RxErr+ BadTLP+ BadDLLP+ ... (Correctable Error Status - WARNING)
                                if 'CESta:' in line:
                                    ce_errors = re.findall(r'(\w+)\+', line)
                                    for err in ce_errors:
                                        desc = ce_error_descriptions.get(err, err)
                                        current_device['ce_errors'].append({'code': err, 'desc': desc})
                                        current_device['errors'].append(f'CE:{err}')
                                        if current_device['status'] == 'ok':
                                            current_device['status'] = 'warning'
                        
                        # Don't forget last device
                        if current_device:
                            pcie_devices.append(current_device)
                            if current_device.get('errors'):
                                error_count += 1
                        
                        # Filter to only include GPUs and devices with errors (to reduce noise)
                        important_devices = [d for d in pcie_devices 
                                           if d.get('errors') 
                                           or 'VGA' in d.get('name', '') 
                                           or 'NVIDIA' in d.get('name', '')
                                           or '3D controller' in d.get('name', '')
                                           or 'GPU' in d.get('name', '')]
                        
                        if important_devices:
                            inventory.pcie_health = json.dumps(important_devices)
                            inventory.pcie_errors_count = error_count
                            
                            # Log summary
                            error_devices = [d for d in important_devices if d.get('errors')]
                            if error_devices:
                                app.logger.warning(f"PCIe errors for {bmc_ip}: {len(error_devices)} devices with errors")
                                for d in error_devices:
                                    app.logger.warning(f"  {d['device']}: {', '.join(d['errors'])}")
                            else:
                                app.logger.info(f"PCIe health for {bmc_ip}: {len(important_devices)} GPU/VGA devices, no errors")
                        
                except Exception as e:
                    app.logger.debug(f"SSH PCIe health check failed for {bmc_ip}: {e}")
                    
        except Exception as e:
            app.logger.debug(f"SSH inventory collection failed for {bmc_ip}: {e}")
    
    # ========== ALWAYS check for GPU Xid errors via SSH (if SSH is enabled) ==========
    # This runs independently of inventory collection since Xid errors are critical
    if ssh_enabled and server_ip:
        try:
            # Get SSH credentials
            server_config = ServerConfig.query.filter_by(bmc_ip=bmc_ip).first()
            ssh_key_content = None
            
            if server_config:
                ssh_user = server_config.ssh_user or 'root'
                if server_config.ssh_key_id:
                    stored_key = SSHKey.query.get(server_config.ssh_key_id)
                    if stored_key:
                        ssh_key_content = stored_key.key_content
                elif server_config.ssh_key:
                    ssh_key_content = server_config.ssh_key
            else:
                ssh_user = SystemSettings.get('ssh_user') or os.environ.get('SSH_USER', 'root')
                default_key_id = SystemSettings.get('default_ssh_key_id')
                if default_key_id:
                    stored_key = SSHKey.query.get(int(default_key_id))
                    if stored_key:
                        ssh_key_content = stored_key.key_content
            
            # Build SSH command
            def build_xid_ssh_cmd(remote_cmd):
                ssh_opts = ['-o', 'ConnectTimeout=10', '-o', 'StrictHostKeyChecking=no', '-o', 'BatchMode=yes']
                if ssh_key_content:
                    key_content_clean = ssh_key_content.replace('\r\n', '\n').strip() + '\n'
                    key_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.pem')
                    key_file.write(key_content_clean)
                    key_file.close()
                    os.chmod(key_file.name, 0o600)
                    return ['ssh'] + ssh_opts + ['-i', key_file.name, f'{ssh_user}@{server_ip}', remote_cmd]
                return None
            
            # Check for Xid errors
            xid_cmd = build_xid_ssh_cmd('dmesg 2>/dev/null | grep -i "NVRM.*Xid" | tail -20')
            if xid_cmd:
                result = subprocess.run(xid_cmd, capture_output=True, text=True, timeout=15)
                if result.returncode == 0 and result.stdout:
                    xid_pattern = r'\[([\d.]+)\].*Xid.*\(PCI:([0-9a-f:]+)\).*?(\d+),?\s*(.*)'
                    critical_xids = {
                        31: 'GPU memory page fault', 43: 'GPU stopped responding',
                        45: 'Preemptive cleanup', 48: 'Double bit ECC error',
                        79: 'GPU fell off the bus', 94: 'Contained ECC error',
                        95: 'Uncontained ECC error', 119: 'GSP error',
                        154: 'GPU recovery action required'
                    }
                    
                    xid_events_detected = []
                    for line in result.stdout.strip().split('\n'):
                        match = re.search(xid_pattern, line, re.IGNORECASE)
                        if match:
                            xid_code = int(match.group(3))
                            pci_address = match.group(2)
                            message = match.group(4).strip()
                            
                            if xid_code in critical_xids:
                                xid_events_detected.append({
                                    'pci_address': pci_address,
                                    'xid_code': xid_code,
                                    'message': message,
                                    'description': critical_xids[xid_code]
                                })
                    
                    if xid_events_detected:
                        app.logger.warning(f"🔴 GPU Xid for {bmc_ip}: {len(xid_events_detected)} critical errors detected")
                        
                        # Create events for new Xid errors
                        server_record = Server.query.filter_by(bmc_ip=bmc_ip).first()
                        if server_record:
                            seen = set()
                            for xid in xid_events_detected:
                                key = f"{xid['pci_address']}:{xid['xid_code']}"
                                if key not in seen:
                                    seen.add(key)
                                    xid_sel_id = f"XID-{xid['pci_address'][-5:]}-{xid['xid_code']}"
                                    
                                    existing = IPMIEvent.query.filter(
                                        IPMIEvent.bmc_ip == bmc_ip,
                                        IPMIEvent.sel_id == xid_sel_id
                                    ).first()
                                    
                                    if not existing:
                                        # User-friendly description (hides Xid code from clients)
                                        event_desc = get_gpu_error_description(xid['xid_code'], xid.get('recovery_action'))
                                        event_desc += f" (GPU:{xid['pci_address'][-5:]})"
                                        event = IPMIEvent(
                                            bmc_ip=bmc_ip,
                                            server_name=server_record.server_name,
                                            sel_id=xid_sel_id,
                                            event_date=datetime.utcnow(),
                                            sensor_type='GPU Health',
                                            sensor_id=xid['pci_address'],
                                            event_description=event_desc,
                                            severity='critical',
                                            raw_entry=json.dumps({'xid': xid['xid_code'], 'message': xid.get('message')})
                                        )
                                        db.session.add(event)
                                        app.logger.warning(f"🔴 GPU Error: {event_desc} on {server_record.server_name}")
                            
                            try:
                                db.session.commit()
                            except Exception as e:
                                db.session.rollback()
                                app.logger.error(f"Failed to save Xid events: {e}")
        except Exception as e:
            app.logger.debug(f"SSH Xid check failed for {bmc_ip}: {e}")
    
    # Check primary IP reachability (use socket instead of ping)
    if server_ip:
        try:
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((server_ip, 22))
            sock.close()
            inventory.primary_ip_reachable = result == 0
            inventory.primary_ip_last_check = datetime.utcnow()
        except:
            inventory.primary_ip_reachable = False
            inventory.primary_ip_last_check = datetime.utcnow()
    
    inventory.collected_at = datetime.utcnow()
    db.session.commit()
    
    return inventory.to_dict()


@app.route('/api/servers/<bmc_ip>/check-connectivity', methods=['GET', 'POST'])
@require_valid_bmc_ip
def api_check_server_connectivity(bmc_ip):
    """Check both BMC and primary IP connectivity"""
    import socket
    
    def check_port(ip, port, timeout=2):
        """Check if a port is reachable"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def check_host(ip, timeout=2):
        """Check if host is reachable via common ports"""
        # Try IPMI port 623 for BMC, SSH port 22 for OS
        for port in [623, 22, 80, 443]:
            if check_port(ip, port, timeout):
                return True
        return False
    
    server = Server.query.filter_by(bmc_ip=bmc_ip).first()
    if not server:
        return jsonify({'error': 'Server not found'}), 404
    
    results = {
        'bmc_ip': bmc_ip,
        'server_name': server.server_name,
        'bmc_reachable': False,
        'primary_ip': server.server_ip,
        'primary_ip_reachable': False,
        'status': 'unknown',
        'checked_at': datetime.utcnow().isoformat()
    }
    
    # Check BMC via IPMI port (623)
    try:
        results['bmc_reachable'] = check_port(bmc_ip, 623, timeout=3)
    except:
        pass
    
    # Check primary IP via SSH port (22)
    if server.server_ip:
        try:
            results['primary_ip_reachable'] = check_port(server.server_ip, 22, timeout=3)
        except:
            pass
    
    # Determine status
    if results['bmc_reachable'] and results['primary_ip_reachable']:
        results['status'] = 'online'
    elif results['bmc_reachable'] and not results['primary_ip_reachable']:
        results['status'] = 'os_offline'  # BMC up, OS down - may need attention
    elif not results['bmc_reachable'] and results['primary_ip_reachable']:
        results['status'] = 'bmc_offline'  # Unusual - OS up but BMC down
    else:
        results['status'] = 'offline'  # Both down
    
    # Update inventory if exists
    inventory = ServerInventory.query.filter_by(bmc_ip=bmc_ip).first()
    if inventory:
        inventory.primary_ip_reachable = results['primary_ip_reachable']
        inventory.primary_ip_last_check = datetime.utcnow()
        db.session.commit()
    
    return jsonify(results)


def parse_ini_servers(ini_content):
    """Parse INI format server list"""
    servers = []
    for line in ini_content.strip().split('\n'):
        line = line.strip()
        if not line or line.startswith('#') or line.startswith('['):
            continue
        
        # Parse: bmc_ip = server_name  # optional comment
        match = re.match(r'([0-9.]+)\s*=\s*(\S+)(?:\s*#\s*(.*))?', line)
        if match:
            bmc_ip = match.group(1)
            server_name = match.group(2)
            comment = match.group(3) or ''
            
            servers.append({
                'bmc_ip': bmc_ip,
                'server_name': server_name,
                'use_nvidia_password': 'nvidia' in comment.lower(),
                'notes': comment
            })
    
    return servers


def parse_yaml_servers(yaml_content):
    """
    Parse YAML format server list with global defaults support.
    
    Example servers.yaml:
    
    # Global defaults - applied to all servers unless overridden
    defaults:
      ipmi_user: admin
      ipmi_pass: BBccc321
      ssh_user: root
      ssh_key_name: bbmait          # Reference to stored SSH key by name
      ssh_port: 22
    
    # Server list
    servers:
      - name: brickbox-01
        bmc_ip: 88.0.1.0
        server_ip: 88.0.1.1         # OS IP for SSH
        
      - name: brickbox-02
        bmc_ip: 88.0.2.0
        server_ip: 88.0.2.1
        ipmi_user: custom_user      # Override default
        ipmi_pass: custom_pass
        
      - name: gpu-server
        bmc_ip: 88.0.43.0
        server_ip: 88.0.43.1
        ssh_key_name: gpu_key       # Different SSH key for this server
        notes: GPU compute server
    """
    servers = []
    defaults = {}
    current_server = None
    in_defaults = False
    in_servers = False
    
    # Key mappings for both defaults and servers
    key_map = {
        'name': 'server_name', 'server_name': 'server_name', 'hostname': 'server_name',
        'bmc_ip': 'bmc_ip', 'ip': 'bmc_ip', 'bmc': 'bmc_ip',
        'ipmi_user': 'ipmi_user', 'username': 'ipmi_user', 'user': 'ipmi_user',
        'ipmi_pass': 'ipmi_pass', 'password': 'ipmi_pass', 'pass': 'ipmi_pass',
        'server_ip': 'server_ip', 'os_ip': 'server_ip',
        'ssh_user': 'ssh_user', 'ssh_port': 'ssh_port', 
        'ssh_key': 'ssh_key', 'ssh_key_name': 'ssh_key_name',
        'ssh_pass': 'ssh_pass', 'ssh_password': 'ssh_pass',
        'notes': 'notes', 'description': 'notes', 'protocol': 'protocol'
    }
    
    for line in yaml_content.split('\n'):
        trimmed = line.strip()
        if not trimmed or trimmed.startswith('#'):
            continue
        
        # Check for section headers
        if trimmed == 'defaults:' or trimmed.startswith('defaults:'):
            in_defaults = True
            in_servers = False
            continue
        elif trimmed == 'servers:' or trimmed.startswith('servers:'):
            in_defaults = False
            in_servers = True
            continue
        
        # Parse defaults section
        if in_defaults and ':' in trimmed and not trimmed.startswith('-'):
            key_value = trimmed.split(':', 1)
            if len(key_value) == 2:
                key = key_value[0].strip()
                value = key_value[1].strip().strip('"\'').split('#')[0].strip()
                if key in key_map and value:
                    mapped_key = key_map[key]
                    if mapped_key == 'ssh_port':
                        defaults[mapped_key] = int(value) if value.isdigit() else 22
                    else:
                        defaults[mapped_key] = value
        
        # Parse servers section
        elif in_servers or (not in_defaults and not in_servers):
            # Check for list item start
            if trimmed.startswith('- name:') or trimmed.startswith('- server_name:'):
                if current_server and current_server.get('bmc_ip'):
                    # Apply defaults before appending
                    for k, v in defaults.items():
                        if k not in current_server:
                            current_server[k] = v
                    servers.append(current_server)
                current_server = {'server_name': trimmed.split(':')[1].strip().strip('"\'').split('#')[0].strip()}
                in_servers = True  # Auto-detect servers section
            elif current_server and ':' in trimmed:
                key_value = trimmed.replace('-', '').split(':', 1)
                if len(key_value) == 2:
                    key = key_value[0].strip()
                    value = key_value[1].strip().strip('"\'').split('#')[0].strip()
                    
                    if key in key_map and value:
                        mapped_key = key_map[key]
                        if mapped_key == 'ssh_port':
                            current_server[mapped_key] = int(value) if value.isdigit() else 22
                        else:
                            current_server[mapped_key] = value
    
    # Don't forget the last server
    if current_server and current_server.get('bmc_ip'):
        for k, v in defaults.items():
            if k not in current_server:
                current_server[k] = v
        servers.append(current_server)
    
    return servers


def parse_csv_servers(csv_content):
    """Parse CSV format server list"""
    servers = []
    lines = csv_content.strip().split('\n')
    if len(lines) < 2:
        return servers
    
    headers = [h.strip().lower() for h in lines[0].split(',')]
    
    # Header mappings
    header_map = {
        'name': 'server_name', 'server_name': 'server_name', 'hostname': 'server_name',
        'bmc_ip': 'bmc_ip', 'ip': 'bmc_ip', 'bmc': 'bmc_ip',
        'ipmi_user': 'ipmi_user', 'username': 'ipmi_user', 'user': 'ipmi_user',
        'ipmi_pass': 'ipmi_pass', 'password': 'ipmi_pass', 'pass': 'ipmi_pass',
        'server_ip': 'server_ip', 'os_ip': 'server_ip',
        'nvidia': 'use_nvidia_password',
        'notes': 'notes', 'description': 'notes'
    }
    
    for line in lines[1:]:
        if not line.strip():
            continue
        values = [v.strip() for v in line.split(',')]
        server = {}
        
        for idx, header in enumerate(headers):
            if idx < len(values) and header in header_map:
                key = header_map[header]
                value = values[idx]
                
                if key == 'use_nvidia_password':
                    server[key] = value.lower() == 'true'
                elif value:  # Only add non-empty values
                    server[key] = value
        
        if server.get('bmc_ip') and server.get('server_name'):
            servers.append(server)
    
    return servers


def load_servers_from_config_file():
    """
    Load servers from a config file on startup.
    
    Looks for:
    1. SERVERS_CONFIG_FILE environment variable
    2. /app/config/servers.yaml
    3. /app/config/servers.yml
    4. /app/config/servers.json
    5. /app/config/servers.csv
    6. /app/config/servers.ini
    
    Returns list of server dicts or empty list if no file found.
    """
    config_files = []
    
    # Check specific file first
    if SERVERS_CONFIG_FILE and os.path.exists(SERVERS_CONFIG_FILE):
        config_files.append(SERVERS_CONFIG_FILE)
    
    # Then check default locations
    for ext in ['yaml', 'yml', 'json', 'csv', 'ini', 'txt']:
        path = os.path.join(CONFIG_DIR, f'servers.{ext}')
        if os.path.exists(path):
            config_files.append(path)
    
    if not config_files:
        return []
    
    config_file = config_files[0]
    app.logger.info(f"📂 Loading servers from config file: {config_file}")
    
    try:
        with open(config_file, 'r') as f:
            content = f.read()
        
        ext = config_file.rsplit('.', 1)[-1].lower()
        
        if ext in ['yaml', 'yml']:
            servers = parse_yaml_servers(content)
        elif ext == 'json':
            data = json.loads(content)
            servers = data.get('servers', data) if isinstance(data, dict) else data
        elif ext == 'csv':
            servers = parse_csv_servers(content)
        else:  # ini, txt
            servers = parse_ini_servers(content)
        
        app.logger.info(f"✅ Loaded {len(servers)} servers from {config_file}")
        return servers
        
    except Exception as e:
        app.logger.error(f"❌ Error loading servers from {config_file}: {e}")
        return []


def import_servers_to_database(servers_data):
    """
    Import servers and their configurations to the database.
    
    Args:
        servers_data: List of server dicts with keys like:
            - server_name/name: Server display name
            - bmc_ip: BMC IP address
            - ipmi_user: Custom IPMI username (optional)
            - ipmi_pass: Custom IPMI password (optional)
            - server_ip: OS IP address (optional)
            - use_nvidia_password: Use NVIDIA 16-char password (optional)
            - ssh_user, ssh_port, ssh_key: SSH credentials (optional)
    
    Returns:
        dict with added, updated, errors counts
    """
    added = 0
    updated = 0
    errors = []
    
    for server_data in servers_data:
        bmc_ip = server_data.get('bmc_ip')
        server_name = server_data.get('server_name') or server_data.get('name')
        
        if not bmc_ip or not server_name:
            errors.append(f"Missing bmc_ip or server_name: {server_data}")
            continue
        
        try:
            # Update or create Server
            existing = Server.query.filter_by(bmc_ip=bmc_ip).first()
            if existing:
                existing.server_name = server_name
                existing.server_ip = server_data.get('server_ip', bmc_ip.replace('.0', '.1'))
                existing.public_ip = server_data.get('public_ip')
                existing.enabled = server_data.get('enabled', True)
                existing.use_nvidia_password = server_data.get('use_nvidia_password', False)
                existing.notes = server_data.get('notes', '')
                updated += 1
            else:
                server = Server(
                    bmc_ip=bmc_ip,
                    server_name=server_name,
                    server_ip=server_data.get('server_ip', bmc_ip.replace('.0', '.1')),
                    public_ip=server_data.get('public_ip'),
                    enabled=server_data.get('enabled', True),
                    use_nvidia_password=server_data.get('use_nvidia_password', False),
                    notes=server_data.get('notes', '')
                )
                db.session.add(server)
                added += 1
            
            # Handle per-server credentials (IPMI, SSH)
            has_credentials = any([
                server_data.get('ipmi_user'), server_data.get('ipmi_pass'),
                server_data.get('ssh_key'), server_data.get('ssh_key_name'),
                server_data.get('ssh_user'), server_data.get('ssh_pass'),
                server_data.get('server_ip')
            ])
            
            if has_credentials:
                config = ServerConfig.query.filter_by(bmc_ip=bmc_ip).first()
                if not config:
                    config = ServerConfig(bmc_ip=bmc_ip, server_name=server_name)
                    db.session.add(config)
                
                config.server_name = server_name
                
                # Server IP
                if server_data.get('server_ip'):
                    config.server_ip = server_data['server_ip']
                
                # IPMI credentials
                if server_data.get('ipmi_user'):
                    config.ipmi_user = server_data['ipmi_user']
                if server_data.get('ipmi_pass'):
                    config.ipmi_pass = server_data['ipmi_pass']
                
                # SSH credentials
                if server_data.get('ssh_user'):
                    config.ssh_user = server_data['ssh_user']
                if server_data.get('ssh_port'):
                    config.ssh_port = int(server_data['ssh_port'])
                if server_data.get('ssh_pass'):
                    config.ssh_pass = server_data['ssh_pass']
                
                # SSH key - can be inline content or reference by name
                if server_data.get('ssh_key'):
                    # Direct key content
                    config.ssh_key = server_data['ssh_key']
                elif server_data.get('ssh_key_name'):
                    # Look up SSH key by name
                    ssh_key = SSHKey.query.filter_by(name=server_data['ssh_key_name']).first()
                    if ssh_key:
                        config.ssh_key_id = ssh_key.id
                        app.logger.info(f"Assigned SSH key '{ssh_key.name}' to {bmc_ip}")
                    else:
                        app.logger.warning(f"SSH key '{server_data['ssh_key_name']}' not found for {bmc_ip}")
                    
        except Exception as e:
            errors.append(f"Error processing {bmc_ip}: {str(e)}")
    
    db.session.commit()
    return {'added': added, 'updated': updated, 'errors': errors}


def is_setup_complete():
    """Check if initial setup has been completed"""
    # Check for setup complete file
    if os.path.exists(SETUP_COMPLETE_FILE):
        return True
    
    # Check if we have any servers configured
    try:
        with app.app_context():
            if Server.query.first():
                return True
    except:
        pass
    
    return False


def mark_setup_complete():
    """Mark setup as complete"""
    try:
        with open(SETUP_COMPLETE_FILE, 'w') as f:
            f.write(datetime.utcnow().isoformat())
    except Exception as e:
        app.logger.warning(f"Could not write setup complete file: {e}")


@app.route('/setup')
def setup_page():
    """First-run setup wizard"""
    # If setup is complete, redirect to dashboard
    if is_setup_complete():
        return redirect(url_for('dashboard'))
    
    return render_template('setup.html', app_name=APP_NAME)


@app.route('/api/setup/status')
def api_setup_status():
    """Check if setup is needed"""
    return jsonify({
        'setup_complete': is_setup_complete(),
        'has_servers': Server.query.first() is not None,
        'has_admin': User.query.first() is not None
    })


@app.route('/api/setup/complete', methods=['POST'])
def api_complete_setup():
    """
    Complete the initial setup.
    
    Expects JSON body:
    {
        "admin": { "username": "admin", "password": "..." },
        "ipmi": { "user": "admin", "pass": "...", "pass_nvidia": "...", "poll_interval": 300 },
        "servers": [
            { "name": "server1", "bmc_ip": "192.168.1.100", "ipmi_user": "...", "ipmi_pass": "..." },
            ...
        ],
        "ai": { "api_key": "sk-...", "enabled": true }
    }
    """
    data = request.get_json() or {}
    
    try:
        # 1. Create/update admin user
        admin_data = data.get('admin', {})
        if admin_data.get('username') and admin_data.get('password'):
            admin_user = User.query.filter_by(username=admin_data['username']).first()
            if not admin_user:
                admin_user = User(
                    username=admin_data['username'],
                    role='admin',
                    enabled=True,
                    password_changed=True
                )
                db.session.add(admin_user)
            admin_user.set_password(admin_data['password'])
            admin_user.password_changed = True
        
        # 2. Store default IPMI credentials in system settings
        ipmi_data = data.get('ipmi', {})
        if ipmi_data:
            if ipmi_data.get('user'):
                SystemSettings.set('ipmi_default_user', ipmi_data['user'])
            if ipmi_data.get('pass'):
                SystemSettings.set('ipmi_default_pass', ipmi_data['pass'])
            if ipmi_data.get('pass_nvidia'):
                SystemSettings.set('ipmi_nvidia_pass', ipmi_data['pass_nvidia'])
            if ipmi_data.get('poll_interval'):
                SystemSettings.set('poll_interval', str(ipmi_data['poll_interval']))
        
        # 3. Import servers
        servers_data = data.get('servers', [])
        servers_result = {'added': 0, 'updated': 0, 'errors': []}
        if servers_data:
            servers_result = import_servers_to_database(servers_data)
        
        # 4. Configure AI
        ai_data = data.get('ai', {})
        if ai_data.get('api_key'):
            config = CloudSync.get_config()
            config.license_key = ai_data['api_key']
            config.sync_enabled = ai_data.get('enabled', True)
            
            # Validate the key
            try:
                validation = validate_license_key(ai_data['api_key'])
                if validation.get('valid'):
                    config.subscription_tier = validation.get('tier', 'standard')
                    config.subscription_valid = True
                    config.max_servers = validation.get('max_servers', 50)
            except:
                pass
        
        db.session.commit()
        
        # Mark setup as complete
        mark_setup_complete()
        
        # Auto-login the admin user
        if admin_data.get('username'):
            session['logged_in'] = True
            session['username'] = admin_data['username']
            session['user_role'] = 'admin'
            session.permanent = True
        
        app.logger.info(f"✅ Setup complete: {servers_result['added']} servers added, {servers_result['updated']} updated")
        
        return jsonify({
            'status': 'success',
            'servers': servers_result,
            'message': 'Setup complete! Redirecting to dashboard...'
        })
        
    except Exception as e:
        app.logger.error(f"Setup error: {e}")
        return jsonify({'status': 'error', 'error': str(e)}), 500


@app.route('/api/servers/init-from-defaults', methods=['POST'])
@write_required
def api_init_from_defaults():
    """Initialize database with default servers - Requires write access"""
    added = 0
    for bmc_ip, server_name in DEFAULT_SERVERS.items():
        existing = Server.query.filter_by(bmc_ip=bmc_ip).first()
        if not existing:
            server = Server(
                bmc_ip=bmc_ip,
                server_name=server_name,
                server_ip=bmc_ip.replace('.0', '.1'),
                enabled=True,
                use_nvidia_password=bmc_ip in NVIDIA_BMCS
            )
            db.session.add(server)
            added += 1
    
    db.session.commit()
    return jsonify({'status': 'success', 'added': added})

# ============== Server Configuration API ==============

@app.route('/api/config/servers')
def api_config_servers():
    """Get all server configurations"""
    configs = ServerConfig.query.all()
    return jsonify([{
        'bmc_ip': c.bmc_ip,
        'server_name': c.server_name,
        'server_ip': c.server_ip,
        'ipmi_user': c.ipmi_user,
        'has_ipmi_pass': bool(c.ipmi_pass),
        'ssh_user': c.ssh_user,
        'has_ssh_key': bool(c.ssh_key),
        'ssh_port': c.ssh_port,
        'updated_at': c.updated_at.isoformat() if c.updated_at else None
    } for c in configs])

@app.route('/api/config/server/<bmc_ip>', methods=['GET', 'POST', 'PUT'])
@require_valid_bmc_ip
def api_config_server(bmc_ip):
    """Get or update server configuration (POST/PUT require admin)"""
    # Require admin for modifications
    if request.method in ['POST', 'PUT'] and not is_admin():
        return jsonify({'error': 'Admin authentication required'}), 401
    
    if request.method == 'GET':
        config = ServerConfig.query.filter_by(bmc_ip=bmc_ip).first()
        if not config:
            # Return empty config (not an error - server may not have custom creds)
            return jsonify({
                'bmc_ip': bmc_ip,
                'ipmi_user': None,
                'has_ipmi_pass': False,
                'ssh_user': None,
                'has_ssh_pass': False,
                'has_ssh_key': False,
                'ssh_key_id': None,
                'ssh_port': 22
            })
        return jsonify({
            'bmc_ip': config.bmc_ip,
            'server_name': config.server_name,
            'server_ip': config.server_ip,
            'ipmi_user': config.ipmi_user,
            'has_ipmi_pass': bool(config.ipmi_pass),
            'ssh_user': config.ssh_user,
            'has_ssh_pass': bool(config.ssh_pass),
            'has_ssh_key': bool(config.ssh_key),
            'ssh_key_id': config.ssh_key_id,
            'ssh_port': config.ssh_port
        })
    
    # POST/PUT - Create or update config
    data = request.get_json()
    config = ServerConfig.query.filter_by(bmc_ip=bmc_ip).first()
    
    if not config:
        server_name = SERVERS.get(bmc_ip, f'server-{bmc_ip}')
        config = ServerConfig(bmc_ip=bmc_ip, server_name=server_name)
        db.session.add(config)
    
    # Update fields if provided
    if 'server_name' in data:
        config.server_name = data['server_name']
    if 'server_ip' in data:
        config.server_ip = data['server_ip']
    if 'ipmi_user' in data:
        config.ipmi_user = data['ipmi_user']
    if 'ipmi_pass' in data:
        config.ipmi_pass = data['ipmi_pass']
    if 'ssh_user' in data:
        config.ssh_user = data['ssh_user']
    if 'ssh_pass' in data:
        config.ssh_pass = data['ssh_pass']
    if 'ssh_key' in data:
        config.ssh_key = data['ssh_key']
    if 'ssh_key_id' in data:
        config.ssh_key_id = data['ssh_key_id'] if data['ssh_key_id'] else None
    if 'ssh_port' in data:
        config.ssh_port = data['ssh_port']
    
    db.session.commit()
    return jsonify({'status': 'success', 'message': f'Configuration updated for {bmc_ip}'})


# ============== SSH Key Management ==============

@app.route('/api/ssh-keys', methods=['GET'])
@login_required
def api_list_ssh_keys():
    """List all stored SSH keys"""
    keys = SSHKey.query.all()
    return jsonify([{
        'id': k.id,
        'name': k.name,
        'fingerprint': k.fingerprint,
        'created_at': k.created_at.isoformat() if k.created_at else None,
        'updated_at': k.updated_at.isoformat() if k.updated_at else None,
    } for k in keys])

@app.route('/api/ssh-keys', methods=['POST'])
@admin_required
def api_add_ssh_key():
    """Add a new SSH key"""
    data = request.get_json()
    name = data.get('name', '').strip()
    key_content = data.get('key_content', '').strip()
    
    if not name:
        return jsonify({'error': 'Key name is required'}), 400
    if not key_content:
        return jsonify({'error': 'Key content is required'}), 400
    if not key_content.startswith('-----BEGIN'):
        return jsonify({'error': 'Invalid SSH key format'}), 400
    
    # Check for duplicate name
    if SSHKey.query.filter_by(name=name).first():
        return jsonify({'error': f'Key with name "{name}" already exists'}), 400
    
    try:
        fingerprint = SSHKey.get_fingerprint(key_content)
        key = SSHKey(name=name, key_content=key_content, fingerprint=fingerprint)
        db.session.add(key)
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': f'SSH key "{name}" added',
            'id': key.id,
            'fingerprint': fingerprint
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to add key: {str(e)}'}), 500

@app.route('/api/ssh-keys/<int:key_id>', methods=['GET'])
@login_required
def api_get_ssh_key(key_id):
    """Get SSH key details (not the content)"""
    key = SSHKey.query.get(key_id)
    if not key:
        return jsonify({'error': 'Key not found'}), 404
    
    return jsonify({
        'id': key.id,
        'name': key.name,
        'fingerprint': key.fingerprint,
        'created_at': key.created_at.isoformat() if key.created_at else None,
    })

@app.route('/api/ssh-keys/<int:key_id>', methods=['DELETE'])
@admin_required
def api_delete_ssh_key(key_id):
    """Delete an SSH key"""
    key = SSHKey.query.get(key_id)
    if not key:
        return jsonify({'error': 'Key not found'}), 404
    
    # Check if key is in use
    servers_using = ServerConfig.query.filter_by(ssh_key_id=key_id).count()
    if servers_using > 0:
        return jsonify({'error': f'Key is assigned to {servers_using} server(s). Unassign first.'}), 400
    
    try:
        db.session.delete(key)
        db.session.commit()
        return jsonify({'status': 'success', 'message': f'SSH key "{key.name}" deleted'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to delete key: {str(e)}'}), 500


@app.route('/api/config/bulk', methods=['POST'])
@write_required
def api_config_bulk():
    """Bulk update server configurations - Requires write access"""
    data = request.get_json()
    updated = 0
    
    # Common credentials to apply to all or specified servers
    ipmi_user = data.get('ipmi_user')
    ipmi_pass = data.get('ipmi_pass')
    ssh_user = data.get('ssh_user')
    ssh_key = data.get('ssh_key')
    ssh_port = data.get('ssh_port')
    target_servers = data.get('servers', list(SERVERS.keys()))  # Default to all servers
    
    for bmc_ip in target_servers:
        if bmc_ip not in SERVERS:
            continue
            
        config = ServerConfig.query.filter_by(bmc_ip=bmc_ip).first()
        if not config:
            config = ServerConfig(bmc_ip=bmc_ip, server_name=SERVERS[bmc_ip])
            db.session.add(config)
        
        if ipmi_user:
            config.ipmi_user = ipmi_user
        if ipmi_pass:
            config.ipmi_pass = ipmi_pass
        if ssh_user:
            config.ssh_user = ssh_user
        if ssh_key:
            config.ssh_key = ssh_key
        if ssh_port:
            config.ssh_port = ssh_port
        
        updated += 1
    
    db.session.commit()
    return jsonify({'status': 'success', 'updated': updated})

# ============== Sensor Data API ==============

@app.route('/api/sensors/<bmc_ip>/names')
@view_required
@require_valid_bmc_ip
def api_sensor_names(bmc_ip):
    """Get sensor name mapping for a BMC (sensor_id -> sensor_name)"""
    # Try to build cache if not already present
    if bmc_ip not in SENSOR_NAME_CACHE:
        build_sensor_cache(bmc_ip)
    
    if bmc_ip in SENSOR_NAME_CACHE:
        return jsonify({
            'bmc_ip': bmc_ip,
            'sensors': SENSOR_NAME_CACHE[bmc_ip]
        })
    else:
        return jsonify({
            'bmc_ip': bmc_ip,
            'error': 'Could not build sensor cache',
            'sensors': {}
        })

@app.route('/api/sensors/<bmc_ip>')
@view_required
@require_valid_bmc_ip
def api_sensors(bmc_ip):
    """Get latest sensor readings for a server"""
    hours = request.args.get('hours', 1, type=int)
    sensor_type = request.args.get('type')  # temperature, fan, voltage, power
    cutoff = datetime.utcnow() - timedelta(hours=hours)
    
    query = SensorReading.query.filter(
        SensorReading.bmc_ip == bmc_ip,
        SensorReading.collected_at >= cutoff
    )
    
    if sensor_type:
        query = query.filter(SensorReading.sensor_type == sensor_type)
    
    # Get latest reading per sensor
    latest = {}
    for reading in query.order_by(SensorReading.collected_at.desc()).all():
        if reading.sensor_name not in latest:
            latest[reading.sensor_name] = {
                'sensor_name': reading.sensor_name,
                'sensor_type': reading.sensor_type,
                'value': reading.value,
                'unit': reading.unit,
                'status': reading.status,
                'lower_critical': reading.lower_critical,
                'lower_warning': reading.lower_warning,
                'upper_warning': reading.upper_warning,
                'upper_critical': reading.upper_critical,
                'collected_at': reading.collected_at.isoformat()
            }
    
    return jsonify(list(latest.values()))

@app.route('/api/sensors/<bmc_ip>/history')
@view_required
@require_valid_bmc_ip
def api_sensors_history(bmc_ip):
    """Get sensor history for graphing"""
    hours = request.args.get('hours', 24, type=int)
    sensor_name = request.args.get('sensor')
    sensor_type = request.args.get('type')
    cutoff = datetime.utcnow() - timedelta(hours=hours)
    
    query = SensorReading.query.filter(
        SensorReading.bmc_ip == bmc_ip,
        SensorReading.collected_at >= cutoff
    )
    
    if sensor_name:
        query = query.filter(SensorReading.sensor_name == sensor_name)
    if sensor_type:
        query = query.filter(SensorReading.sensor_type == sensor_type)
    
    readings = query.order_by(SensorReading.collected_at.asc()).all()
    
    return jsonify([{
        'sensor_name': r.sensor_name,
        'sensor_type': r.sensor_type,
        'value': r.value,
        'unit': r.unit,
        'status': r.status,
        'collected_at': r.collected_at.isoformat()
    } for r in readings])

@app.route('/api/power/<bmc_ip>')
@require_valid_bmc_ip
def api_power(bmc_ip):
    """Get latest power readings for a server"""
    hours = request.args.get('hours', 24, type=int)
    cutoff = datetime.utcnow() - timedelta(hours=hours)
    
    readings = PowerReading.query.filter(
        PowerReading.bmc_ip == bmc_ip,
        PowerReading.collected_at >= cutoff
    ).order_by(PowerReading.collected_at.desc()).all()
    
    return jsonify([{
        'current_watts': r.current_watts,
        'min_watts': r.min_watts,
        'max_watts': r.max_watts,
        'avg_watts': r.avg_watts,
        'collected_at': r.collected_at.isoformat()
    } for r in readings])

@app.route('/api/sensors/collect', methods=['POST'])
def api_collect_sensors():
    """Trigger sensor collection for all servers"""
    def collect_all_sensors():
        with app.app_context():
            app.logger.info("Starting sensor collection...")
            with ThreadPoolExecutor(max_workers=get_collection_workers()) as executor:
                futures = {
                    executor.submit(collect_single_server_sensors, bmc_ip, server_name): bmc_ip
                    for bmc_ip, server_name in SERVERS.items()
                }
                for future in as_completed(futures):
                    pass
            app.logger.info("Sensor collection complete")
    
    thread = threading.Thread(target=collect_all_sensors, daemon=True)
    thread.start()
    return jsonify({'status': 'Sensor collection started'})

def collect_single_server_sensors(bmc_ip, server_name):
    """Collect sensors from a single server"""
    try:
        sensors = collect_sensors(bmc_ip, server_name)
        power = collect_power_reading(bmc_ip, server_name)
        
        with app.app_context():
            for sensor in sensors:
                db.session.add(sensor)
            if power:
                db.session.add(power)
            db.session.commit()
        
        return True
    except Exception as e:
        app.logger.error(f"Error collecting sensors from {bmc_ip}: {e}")
        return False

# ============== Redfish API ==============

# ============== Connection Test Endpoints ==============

@app.route('/api/test/bmc', methods=['POST'])
@login_required
def api_test_bmc():
    """Test BMC/IPMI connection with provided or saved credentials"""
    import time
    data = request.get_json()
    bmc_ip = data.get('bmc_ip')
    
    if not bmc_ip or not validate_ip_address(bmc_ip):
        return jsonify({'status': 'error', 'error': 'Invalid BMC IP address'}), 400
    
    # Get credentials - use provided ones or fall back to saved/default
    ipmi_user = data.get('ipmi_user')
    ipmi_pass = data.get('ipmi_pass')
    
    if not ipmi_user or not ipmi_pass:
        default_user, default_pass = get_ipmi_credentials(bmc_ip)
        ipmi_user = ipmi_user or default_user
        ipmi_pass = ipmi_pass or default_pass
    
    try:
        start_time = time.time()
        # Test with a simple power status command
        cmd = ['ipmitool', '-I', 'lanplus', '-H', bmc_ip, '-U', ipmi_user, '-P', ipmi_pass, 'power', 'status']
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        elapsed_ms = int((time.time() - start_time) * 1000)
        
        if result.returncode == 0:
            power_status = 'on' if 'on' in result.stdout.lower() else 'off' if 'off' in result.stdout.lower() else 'unknown'
            return jsonify({
                'status': 'success',
                'message': 'BMC connection successful',
                'power_status': power_status,
                'response_time_ms': elapsed_ms
            })
        else:
            error_msg = result.stderr.strip() or result.stdout.strip() or 'Connection failed'
            # Simplify common error messages
            if 'Unable to establish' in error_msg:
                error_msg = 'Cannot connect to BMC - check IP address'
            elif 'password' in error_msg.lower() or 'authentication' in error_msg.lower():
                error_msg = 'Authentication failed - check username/password'
            return jsonify({'status': 'error', 'error': error_msg})
    except subprocess.TimeoutExpired:
        return jsonify({'status': 'error', 'error': 'Connection timed out after 15 seconds'})
    except Exception as e:
        return jsonify({'status': 'error', 'error': str(e)})


@app.route('/api/test/ssh', methods=['POST'])
@login_required
def api_test_ssh():
    """Test SSH connection to host OS with provided or saved credentials"""
    data = request.get_json()
    bmc_ip = data.get('bmc_ip')
    server_ip = data.get('server_ip')
    ssh_user = data.get('ssh_user', 'root')
    ssh_pass = data.get('ssh_pass')
    ssh_key_id = data.get('ssh_key_id')
    
    if not server_ip:
        server_ip = bmc_ip.replace('.0', '.1') if bmc_ip else None
    
    if not server_ip or not validate_ip_address(server_ip):
        return jsonify({'status': 'error', 'error': 'Invalid server IP address'}), 400
    
    # Get SSH key content if key ID provided
    ssh_key_content = None
    if ssh_key_id:
        stored_key = SSHKey.query.get(ssh_key_id)
        if stored_key:
            ssh_key_content = stored_key.key_content
    
    # If no key ID, check saved server config
    if not ssh_key_content and not ssh_pass and bmc_ip:
        server_config = ServerConfig.query.filter_by(bmc_ip=bmc_ip).first()
        if server_config:
            if server_config.ssh_key_id:
                stored_key = SSHKey.query.get(server_config.ssh_key_id)
                if stored_key:
                    ssh_key_content = stored_key.key_content
            elif server_config.ssh_pass:
                ssh_pass = server_config.ssh_pass
    
    # Fall back to default key
    if not ssh_key_content and not ssh_pass:
        default_key_id = SystemSettings.get('default_ssh_key_id')
        if default_key_id:
            stored_key = SSHKey.query.get(int(default_key_id))
            if stored_key:
                ssh_key_content = stored_key.key_content
        else:
            ssh_pass = SystemSettings.get('ssh_password') or os.environ.get('SSH_PASS', '')
    
    try:
        import tempfile
        ssh_opts = ['-o', 'ConnectTimeout=10', '-o', 'StrictHostKeyChecking=no']
        key_file_path = None
        
        if ssh_key_content:
            # Write key to temp file with proper formatting
            key_content_clean = ssh_key_content.replace('\r\n', '\n').strip() + '\n'
            key_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.pem')
            key_file.write(key_content_clean)
            key_file.close()
            os.chmod(key_file.name, 0o600)
            key_file_path = key_file.name
            cmd = ['ssh'] + ssh_opts + ['-o', 'BatchMode=yes', '-i', key_file_path, f'{ssh_user}@{server_ip}', 'hostname && uname -r']
            app.logger.info(f"SSH test using stored key for {server_ip}")
        elif ssh_pass:
            cmd = ['sshpass', '-p', ssh_pass, 'ssh'] + ssh_opts + [f'{ssh_user}@{server_ip}', 'hostname && uname -r']
            app.logger.info(f"SSH test using password for {server_ip}")
        else:
            # Try default SSH key from ~/.ssh
            cmd = ['ssh'] + ssh_opts + ['-o', 'BatchMode=yes', f'{ssh_user}@{server_ip}', 'hostname && uname -r']
            app.logger.info(f"SSH test using default ~/.ssh key for {server_ip}")
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        
        # Clean up temp key file
        if key_file_path:
            try:
                os.unlink(key_file_path)
            except:
                pass
        
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            hostname = lines[0] if len(lines) > 0 else 'Unknown'
            kernel = lines[1] if len(lines) > 1 else 'Unknown'
            return jsonify({
                'status': 'success',
                'message': 'SSH connection successful',
                'hostname': hostname,
                'kernel': kernel
            })
        else:
            error_msg = result.stderr.strip() or result.stdout.strip() or 'Connection failed'
            app.logger.warning(f"SSH test failed for {server_ip}: {error_msg}")
            
            # Provide helpful error messages while keeping details
            if 'Permission denied' in error_msg:
                error_msg = f'Authentication failed: {error_msg}'
            elif 'Connection refused' in error_msg:
                error_msg = f'Connection refused: SSH service not running or wrong port'
            elif 'No route to host' in error_msg or 'Connection timed out' in error_msg:
                error_msg = f'Cannot reach host: {error_msg}'
            elif 'Host key verification failed' in error_msg:
                error_msg = 'Host key verification failed - try with StrictHostKeyChecking=no'
            return jsonify({'status': 'error', 'error': error_msg})
    except subprocess.TimeoutExpired:
        return jsonify({'status': 'error', 'error': 'Connection timed out after 15 seconds'})
    except Exception as e:
        return jsonify({'status': 'error', 'error': str(e)})


@app.route('/api/redfish/status/<bmc_ip>')
def api_redfish_status(bmc_ip):
    """Check Redfish availability for a BMC"""
    if not validate_ip_address(bmc_ip):
        return jsonify({'error': 'Invalid IP address'}), 400
    
    available = check_redfish_available(bmc_ip)
    
    # Get current protocol setting
    server = Server.query.filter_by(bmc_ip=bmc_ip).first()
    current_protocol = server.protocol if server else 'auto'
    
    # Get cached status
    with _redfish_cache_lock:
        cached = _redfish_cache.get(bmc_ip)
    
    return jsonify({
        'bmc_ip': bmc_ip,
        'redfish_available': available,
        'current_protocol': current_protocol,
        'cached_status': cached,
        'effective_protocol': 'redfish' if should_use_redfish(bmc_ip) else 'ipmi'
    })

@app.route('/api/redfish/check_all', methods=['POST'])
def api_check_all_redfish():
    """Check Redfish availability for all servers"""
    servers = get_servers()
    results = {}
    
    def check_one(bmc_ip):
        return bmc_ip, check_redfish_available(bmc_ip)
    
    with ThreadPoolExecutor(max_workers=get_collection_workers()) as executor:
        futures = [executor.submit(check_one, ip) for ip in servers.keys()]
        for future in as_completed(futures):
            try:
                bmc_ip, available = future.result()
                results[bmc_ip] = available
                # Update cache
                with _redfish_cache_lock:
                    _redfish_cache[bmc_ip] = available
            except Exception as e:
                app.logger.error(f"Error checking Redfish: {e}")
    
    total = len(results)
    available_count = sum(1 for v in results.values() if v)
    
    return jsonify({
        'total_servers': total,
        'redfish_available': available_count,
        'results': results
    })

@app.route('/api/redfish/clear_cache', methods=['POST'])
@write_required
def api_clear_redfish_cache():
    """Clear the Redfish availability cache"""
    with _redfish_cache_lock:
        _redfish_cache.clear()
    return jsonify({'status': 'success', 'message': 'Redfish cache cleared'})

# ============== Alerting API ==============

@app.route('/api/alerts/rules')
def api_get_alert_rules():
    """Get all alert rules"""
    rules = AlertRule.query.all()
    return jsonify([{
        'id': r.id,
        'name': r.name,
        'description': r.description,
        'alert_type': r.alert_type,
        'condition': r.condition,
        'threshold': r.threshold,
        'threshold_str': r.threshold_str,
        'severity': r.severity,
        'enabled': r.enabled,
        'cooldown_minutes': r.cooldown_minutes,
        'notify_telegram': r.notify_telegram,
        'notify_email': r.notify_email,
        'notify_webhook': r.notify_webhook
    } for r in rules])

@app.route('/api/alerts/rules/<int:rule_id>', methods=['GET', 'PUT', 'DELETE'])
def api_manage_alert_rule(rule_id):
    """Get, update, or delete an alert rule"""
    rule = AlertRule.query.get(rule_id)
    if not rule:
        return jsonify({'error': 'Rule not found'}), 404
    
    if request.method == 'GET':
        return jsonify({
            'id': rule.id,
            'name': rule.name,
            'description': rule.description,
            'alert_type': rule.alert_type,
            'condition': rule.condition,
            'threshold': rule.threshold,
            'threshold_str': rule.threshold_str,
            'severity': rule.severity,
            'enabled': rule.enabled,
            'cooldown_minutes': rule.cooldown_minutes,
            'notify_telegram': rule.notify_telegram,
            'notify_email': rule.notify_email,
            'notify_webhook': rule.notify_webhook
        })
    
    elif request.method == 'PUT':
        if not is_admin():
            return jsonify({'error': 'Admin authentication required'}), 401
        
        data = request.get_json()
        if 'name' in data:
            rule.name = data['name']
        if 'description' in data:
            rule.description = data['description']
        if 'alert_type' in data:
            rule.alert_type = data['alert_type']
        if 'condition' in data:
            rule.condition = data['condition']
        if 'threshold' in data:
            rule.threshold = data['threshold']
        if 'threshold_str' in data:
            rule.threshold_str = data['threshold_str']
        if 'severity' in data:
            rule.severity = data['severity']
        if 'enabled' in data:
            rule.enabled = data['enabled']
        if 'cooldown_minutes' in data:
            rule.cooldown_minutes = data['cooldown_minutes']
        if 'notify_telegram' in data:
            rule.notify_telegram = data['notify_telegram']
        if 'notify_email' in data:
            rule.notify_email = data['notify_email']
        if 'notify_webhook' in data:
            rule.notify_webhook = data['notify_webhook']
        
        db.session.commit()
        return jsonify({'status': 'success', 'message': f'Updated rule: {rule.name}'})
    
    elif request.method == 'DELETE':
        if not is_admin():
            return jsonify({'error': 'Admin authentication required'}), 401
        
        db.session.delete(rule)
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'Rule deleted'})

@app.route('/api/alerts/rules', methods=['POST'])
@write_required
def api_create_alert_rule():
    """Create a new alert rule"""
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Request body required'}), 400
    
    required = ['name', 'alert_type', 'condition', 'severity']
    for field in required:
        if field not in data:
            return jsonify({'error': f'{field} is required'}), 400
    
    rule = AlertRule(
        name=data['name'],
        description=data.get('description', ''),
        alert_type=data['alert_type'],
        condition=data['condition'],
        threshold=data.get('threshold'),
        threshold_str=data.get('threshold_str'),
        severity=data['severity'],
        enabled=data.get('enabled', True),
        cooldown_minutes=data.get('cooldown_minutes', 30),
        notify_telegram=data.get('notify_telegram', True),
        notify_email=data.get('notify_email', False),
        notify_webhook=data.get('notify_webhook', False)
    )
    
    db.session.add(rule)
    db.session.commit()
    return jsonify({'status': 'success', 'message': f'Created rule: {rule.name}', 'id': rule.id})

@app.route('/api/alerts/history')
def api_get_alert_history():
    """Get alert history with optional filters"""
    limit = request.args.get('limit', 100, type=int)
    severity = request.args.get('severity')
    bmc_ip = request.args.get('bmc_ip')
    acknowledged = request.args.get('acknowledged')
    
    query = AlertHistory.query
    
    if severity:
        query = query.filter_by(severity=severity)
    if bmc_ip:
        query = query.filter_by(bmc_ip=bmc_ip)
    if acknowledged is not None:
        query = query.filter_by(acknowledged=acknowledged.lower() == 'true')
    
    alerts = query.order_by(AlertHistory.fired_at.desc()).limit(limit).all()
    
    return jsonify([{
        'id': a.id,
        'rule_name': a.rule_name,
        'bmc_ip': a.bmc_ip,
        'server_name': a.server_name,
        'alert_type': a.alert_type,
        'severity': a.severity,
        'source_type': a.source_type or 'RULE_ALERT',
        'sensor_id': a.sensor_id,
        'message': a.message,
        'value': a.value,
        'threshold': a.threshold,
        'notified_telegram': a.notified_telegram,
        'notified_email': a.notified_email,
        'notified_webhook': a.notified_webhook,
        'acknowledged': a.acknowledged,
        'acknowledged_by': a.acknowledged_by,
        'acknowledged_at': a.acknowledged_at.isoformat() if a.acknowledged_at else None,
        'resolved': a.resolved,
        'resolved_at': a.resolved_at.isoformat() if a.resolved_at else None,
        'fired_at': a.fired_at.isoformat()
    } for a in alerts])

@app.route('/api/alerts/history/<int:alert_id>/acknowledge', methods=['POST'])
@write_required
def api_acknowledge_alert(alert_id):
    """Acknowledge an alert"""
    alert = AlertHistory.query.get(alert_id)
    if not alert:
        return jsonify({'error': 'Alert not found'}), 404
    
    alert.acknowledged = True
    alert.acknowledged_by = session.get('admin_user', 'admin')
    alert.acknowledged_at = datetime.utcnow()
    db.session.commit()
    
    return jsonify({'status': 'success', 'message': 'Alert acknowledged'})

@app.route('/api/alerts/history/<int:alert_id>/resolve', methods=['POST'])
@write_required
def api_resolve_alert(alert_id):
    """Mark an alert as resolved"""
    alert = AlertHistory.query.get(alert_id)
    if not alert:
        return jsonify({'error': 'Alert not found'}), 404
    
    alert.resolved = True
    alert.resolved_at = datetime.utcnow()
    db.session.commit()
    
    return jsonify({'status': 'success', 'message': 'Alert resolved'})

@app.route('/api/alerts/notifications')
def api_get_notification_config():
    """Get notification channel configurations"""
    configs = NotificationConfig.query.all()
    
    result = {}
    for config in configs:
        parsed_config = {}
        if config.config_json:
            try:
                parsed_config = json.loads(config.config_json)
                # Mask sensitive fields
                if 'bot_token' in parsed_config:
                    parsed_config['bot_token'] = '***' + parsed_config['bot_token'][-6:] if len(parsed_config.get('bot_token', '')) > 6 else '***'
                if 'smtp_pass' in parsed_config:
                    parsed_config['smtp_pass'] = '********'
            except Exception:
                pass
        
        result[config.channel_type] = {
            'enabled': config.enabled,
            'config': parsed_config,
            'test_successful': config.test_successful,
            'last_test': config.last_test.isoformat() if config.last_test else None
        }
    
    return jsonify(result)

@app.route('/api/alerts/notifications/<channel_type>', methods=['PUT'])
@write_required
def api_update_notification_config(channel_type):
    """Update notification channel configuration"""
    if channel_type not in ['telegram', 'email', 'webhook']:
        return jsonify({'error': 'Invalid channel type'}), 400
    
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Request body required'}), 400
    
    config = NotificationConfig.query.filter_by(channel_type=channel_type).first()
    if not config:
        config = NotificationConfig(channel_type=channel_type)
        db.session.add(config)
    
    if 'enabled' in data:
        config.enabled = data['enabled']
    
    if 'config' in data:
        config.config_json = json.dumps(data['config'])
    
    db.session.commit()
    return jsonify({'status': 'success', 'message': f'Updated {channel_type} configuration'})

@app.route('/api/alerts/notifications/<channel_type>/test', methods=['POST'])
@write_required
def api_test_notification(channel_type):
    """Test a notification channel - works even if not enabled (for testing config before enabling)"""
    config = NotificationConfig.query.filter_by(channel_type=channel_type).first()
    
    if not config or not config.config_json:
        return jsonify({'error': 'Channel not configured. Please save configuration first.'}), 400
    
    test_message = f"🧪 Test notification from {APP_NAME}\n\nIf you see this, notifications are working correctly!"
    
    success = False
    if channel_type == 'telegram':
        success = send_telegram_notification(test_message, 'info')
    elif channel_type == 'email':
        success = send_email_notification("Test Notification", test_message, 'info')
    elif channel_type == 'webhook':
        success = send_webhook_notification({
            'type': 'test',
            'message': test_message
        })
    
    config.test_successful = success
    config.last_test = datetime.utcnow()
    db.session.commit()
    
    if success:
        return jsonify({'status': 'success', 'message': f'Test notification sent to {channel_type}'})
    else:
        return jsonify({'error': f'Failed to send test notification to {channel_type}'}), 500

@app.route('/api/alerts/stats')
def api_alert_stats():
    """Get alert statistics"""
    cutoff_24h = datetime.utcnow() - timedelta(hours=24)
    cutoff_7d = datetime.utcnow() - timedelta(days=7)
    
    stats = {
        'total_rules': AlertRule.query.count(),
        'enabled_rules': AlertRule.query.filter_by(enabled=True).count(),
        'alerts_24h': AlertHistory.query.filter(AlertHistory.fired_at >= cutoff_24h).count(),
        'alerts_7d': AlertHistory.query.filter(AlertHistory.fired_at >= cutoff_7d).count(),
        'unacknowledged': AlertHistory.query.filter_by(acknowledged=False).count(),
        'critical_24h': AlertHistory.query.filter(
            AlertHistory.fired_at >= cutoff_24h,
            AlertHistory.severity == 'critical'
        ).count(),
        'warning_24h': AlertHistory.query.filter(
            AlertHistory.fired_at >= cutoff_24h,
            AlertHistory.severity == 'warning'
        ).count(),
        'rule_alerts': AlertHistory.query.filter_by(source_type='RULE_ALERT').count(),
        'bmc_events': AlertHistory.query.filter_by(source_type='BMC_EVENT').count()
    }
    
    return jsonify(stats)

@app.route('/api/ecc/tracking')
def api_ecc_tracking():
    """Get ECC error tracking data per module per machine"""
    trackers = ECCErrorTracker.query.order_by(
        ECCErrorTracker.count_1h.desc(),
        ECCErrorTracker.last_error_at.desc()
    ).all()
    
    return jsonify([{
        'id': t.id,
        'bmc_ip': t.bmc_ip,
        'server_name': t.server_name,
        'sensor_id': t.sensor_id,
        'sensor_name': t.sensor_name,
        'error_type': t.error_type,
        'count_1h': t.count_1h,
        'count_24h': t.count_24h,
        'count_total': t.count_total,
        'last_error_at': t.last_error_at.isoformat() if t.last_error_at else None,
        'alerted_at': t.alerted_at.isoformat() if t.alerted_at else None
    } for t in trackers])

@app.route('/api/ecc/tracking/<bmc_ip>')
@require_valid_bmc_ip
def api_ecc_tracking_server(bmc_ip):
    """Get ECC error tracking for a specific server"""
    trackers = ECCErrorTracker.query.filter_by(bmc_ip=bmc_ip).order_by(
        ECCErrorTracker.count_total.desc()
    ).all()
    
    return jsonify([{
        'sensor_id': t.sensor_id,
        'sensor_name': t.sensor_name,
        'error_type': t.error_type,
        'count_1h': t.count_1h,
        'count_24h': t.count_24h,
        'count_total': t.count_total,
        'last_error_at': t.last_error_at.isoformat() if t.last_error_at else None,
        'alerted_at': t.alerted_at.isoformat() if t.alerted_at else None
    } for t in trackers])

@app.route('/api/ecc/reset', methods=['POST'])
@write_required
def api_reset_ecc_counts():
    """Reset ECC error counts (for testing or after maintenance)"""
    bmc_ip = request.args.get('bmc_ip')
    reset_type = request.args.get('type', 'hourly')  # hourly, daily, or all
    
    try:
        query = ECCErrorTracker.query
        if bmc_ip:
            query = query.filter_by(bmc_ip=bmc_ip)
        
        if reset_type == 'hourly':
            query.update({ECCErrorTracker.count_1h: 0})
        elif reset_type == 'daily':
            query.update({ECCErrorTracker.count_24h: 0})
        elif reset_type == 'all':
            query.update({
                ECCErrorTracker.count_1h: 0,
                ECCErrorTracker.count_24h: 0,
                ECCErrorTracker.count_total: 0
            })
        
        db.session.commit()
        return jsonify({'status': 'success', 'message': f'Reset {reset_type} ECC counts'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/grafana/dashboard')
def api_grafana_dashboard():
    """Download a pre-configured Grafana dashboard JSON"""
    dashboard = {
        "annotations": {"list": []},
        "editable": True,
        "fiscalYearStartMonth": 0,
        "graphTooltip": 0,
        "id": None,
        "links": [],
        "liveNow": False,
        "panels": [
            {
                "datasource": {"type": "prometheus", "uid": "${DS_PROMETHEUS}"},
                "fieldConfig": {"defaults": {"color": {"mode": "palette-classic"}, "custom": {"axisCenteredZero": False, "axisColorMode": "text", "axisLabel": "", "axisPlacement": "auto", "barAlignment": 0, "drawStyle": "line", "fillOpacity": 0, "gradientMode": "none", "hideFrom": {"legend": False, "tooltip": False, "viz": False}, "lineInterpolation": "linear", "lineWidth": 1, "pointSize": 5, "scaleDistribution": {"type": "linear"}, "showPoints": "auto", "spanNulls": False, "stacking": {"group": "A", "mode": "none"}, "thresholdsStyle": {"mode": "off"}}, "mappings": [], "thresholds": {"mode": "absolute", "steps": [{"color": "green", "value": None}, {"color": "red", "value": 80}]}, "unit": "celsius"}, "overrides": []},
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 0},
                "id": 1,
                "options": {"legend": {"calcs": [], "displayMode": "list", "placement": "bottom", "showLegend": True}, "tooltip": {"mode": "single", "sort": "none"}},
                "targets": [{"datasource": {"type": "prometheus", "uid": "${DS_PROMETHEUS}"}, "expr": "ipmi_temperature_celsius", "legendFormat": "{{server_name}} - {{sensor_name}}", "refId": "A"}],
                "title": "CPU/System Temperatures",
                "type": "timeseries"
            },
            {
                "datasource": {"type": "prometheus", "uid": "${DS_PROMETHEUS}"},
                "fieldConfig": {"defaults": {"color": {"mode": "palette-classic"}, "custom": {"axisCenteredZero": False, "axisColorMode": "text", "axisLabel": "", "axisPlacement": "auto", "barAlignment": 0, "drawStyle": "line", "fillOpacity": 0, "gradientMode": "none", "hideFrom": {"legend": False, "tooltip": False, "viz": False}, "lineInterpolation": "linear", "lineWidth": 1, "pointSize": 5, "scaleDistribution": {"type": "linear"}, "showPoints": "auto", "spanNulls": False, "stacking": {"group": "A", "mode": "none"}, "thresholdsStyle": {"mode": "off"}}, "mappings": [], "thresholds": {"mode": "absolute", "steps": [{"color": "green", "value": None}, {"color": "red", "value": 80}]}, "unit": "watt"}, "overrides": []},
                "gridPos": {"h": 8, "w": 12, "x": 12, "y": 0},
                "id": 2,
                "options": {"legend": {"calcs": [], "displayMode": "list", "placement": "bottom", "showLegend": True}, "tooltip": {"mode": "single", "sort": "none"}},
                "targets": [{"datasource": {"type": "prometheus", "uid": "${DS_PROMETHEUS}"}, "expr": "ipmi_power_watts", "legendFormat": "{{server_name}}", "refId": "A"}],
                "title": "Power Consumption",
                "type": "timeseries"
            },
            {
                "datasource": {"type": "prometheus", "uid": "${DS_PROMETHEUS}"},
                "fieldConfig": {"defaults": {"color": {"mode": "thresholds"}, "mappings": [], "thresholds": {"mode": "absolute", "steps": [{"color": "green", "value": None}, {"color": "yellow", "value": 1}, {"color": "red", "value": 5}]}}, "overrides": []},
                "gridPos": {"h": 4, "w": 6, "x": 0, "y": 8},
                "id": 3,
                "options": {"colorMode": "value", "graphMode": "area", "justifyMode": "auto", "orientation": "auto", "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False}, "textMode": "auto"},
                "targets": [{"datasource": {"type": "prometheus", "uid": "${DS_PROMETHEUS}"}, "expr": "ipmi_alerts_unacknowledged", "refId": "A"}],
                "title": "Unacknowledged Alerts",
                "type": "stat"
            },
            {
                "datasource": {"type": "prometheus", "uid": "${DS_PROMETHEUS}"},
                "fieldConfig": {"defaults": {"color": {"mode": "thresholds"}, "mappings": [], "thresholds": {"mode": "absolute", "steps": [{"color": "green", "value": None}, {"color": "red", "value": 1}]}}, "overrides": []},
                "gridPos": {"h": 4, "w": 6, "x": 6, "y": 8},
                "id": 4,
                "options": {"colorMode": "value", "graphMode": "area", "justifyMode": "auto", "orientation": "auto", "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False}, "textMode": "auto"},
                "targets": [{"datasource": {"type": "prometheus", "uid": "${DS_PROMETHEUS}"}, "expr": "ipmi_alerts_critical_24h", "refId": "A"}],
                "title": "Critical Alerts (24h)",
                "type": "stat"
            },
            {
                "datasource": {"type": "prometheus", "uid": "${DS_PROMETHEUS}"},
                "fieldConfig": {"defaults": {"color": {"mode": "thresholds"}, "mappings": [], "thresholds": {"mode": "absolute", "steps": [{"color": "green", "value": None}, {"color": "orange", "value": 1}]}}, "overrides": []},
                "gridPos": {"h": 4, "w": 6, "x": 12, "y": 8},
                "id": 5,
                "options": {"colorMode": "value", "graphMode": "area", "justifyMode": "auto", "orientation": "auto", "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False}, "textMode": "auto"},
                "targets": [{"datasource": {"type": "prometheus", "uid": "${DS_PROMETHEUS}"}, "expr": "ipmi_alerts_warning_24h", "refId": "A"}],
                "title": "Warning Alerts (24h)",
                "type": "stat"
            },
            {
                "datasource": {"type": "prometheus", "uid": "${DS_PROMETHEUS}"},
                "fieldConfig": {"defaults": {"color": {"mode": "thresholds"}, "mappings": [], "thresholds": {"mode": "absolute", "steps": [{"color": "blue", "value": None}]}}, "overrides": []},
                "gridPos": {"h": 4, "w": 6, "x": 18, "y": 8},
                "id": 6,
                "options": {"colorMode": "value", "graphMode": "area", "justifyMode": "auto", "orientation": "auto", "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False}, "textMode": "auto"},
                "targets": [{"datasource": {"type": "prometheus", "uid": "${DS_PROMETHEUS}"}, "expr": "ipmi_servers_monitored", "refId": "A"}],
                "title": "Servers Monitored",
                "type": "stat"
            },
            {
                "datasource": {"type": "prometheus", "uid": "${DS_PROMETHEUS}"},
                "fieldConfig": {"defaults": {"color": {"mode": "palette-classic"}, "custom": {"axisCenteredZero": False, "axisColorMode": "text", "axisLabel": "", "axisPlacement": "auto", "barAlignment": 0, "drawStyle": "line", "fillOpacity": 0, "gradientMode": "none", "hideFrom": {"legend": False, "tooltip": False, "viz": False}, "lineInterpolation": "linear", "lineWidth": 1, "pointSize": 5, "scaleDistribution": {"type": "linear"}, "showPoints": "auto", "spanNulls": False, "stacking": {"group": "A", "mode": "none"}, "thresholdsStyle": {"mode": "off"}}, "mappings": [], "thresholds": {"mode": "absolute", "steps": [{"color": "green", "value": None}]}, "unit": "rotrpm"}, "overrides": []},
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 12},
                "id": 7,
                "options": {"legend": {"calcs": [], "displayMode": "list", "placement": "bottom", "showLegend": True}, "tooltip": {"mode": "single", "sort": "none"}},
                "targets": [{"datasource": {"type": "prometheus", "uid": "${DS_PROMETHEUS}"}, "expr": "ipmi_fan_speed_rpm", "legendFormat": "{{server_name}} - {{sensor_name}}", "refId": "A"}],
                "title": "Fan Speeds",
                "type": "timeseries"
            }
        ],
        "refresh": "30s",
        "schemaVersion": 38,
        "style": "dark",
        "tags": ["ipmi", "monitoring", "hardware"],
        "templating": {"list": [{"current": {}, "hide": 0, "includeAll": False, "label": "Prometheus", "multi": False, "name": "DS_PROMETHEUS", "options": [], "query": "prometheus", "queryValue": "", "refresh": 1, "regex": "", "skipUrlSync": False, "type": "datasource"}]},
        "time": {"from": "now-6h", "to": "now"},
        "timepicker": {},
        "timezone": "",
        "title": "IPMI Monitor Dashboard",
        "uid": "ipmi-monitor",
        "version": 1,
        "weekStart": ""
    }
    
    response = make_response(json.dumps(dashboard, indent=2))
    response.headers['Content-Type'] = 'application/json'
    response.headers['Content-Disposition'] = 'attachment; filename=ipmi-monitor-dashboard.json'
    return response

# ============== Settings Page ==============

@app.route('/settings')
@write_required
def settings_page():
    """Server configuration page - Requires write access"""
    return render_template('settings.html')


@app.route('/docs')
def docs_page():
    """Documentation / Wiki page - Public access"""
    return render_template('docs.html')


@app.route('/docs/raw')
def docs_raw():
    """Raw Markdown documentation - for AI service and other consumers"""
    docs_path = os.path.join(os.path.dirname(__file__), 'docs', 'user-guide.md')
    if os.path.exists(docs_path):
        with open(docs_path, 'r') as f:
            return Response(f.read(), mimetype='text/markdown')
    return Response('# Documentation not found', mimetype='text/markdown'), 404


@app.route('/metrics')
def prometheus_metrics():
    """Prometheus metrics endpoint"""
    update_prometheus_metrics()
    return Response(generate_latest(PROM_REGISTRY), mimetype=CONTENT_TYPE_LATEST)

@app.route('/health')
def health_check():
    """Health check endpoint for container orchestration"""
    health_status = {
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'checks': {}
    }
    
    # Check database connectivity
    try:
        db.session.execute(db.text('SELECT 1'))
        health_status['checks']['database'] = 'ok'
    except Exception as e:
        health_status['status'] = 'degraded'
        health_status['checks']['database'] = f'error: {str(e)}'
    
    # Check if collector thread is alive
    if collector_thread and collector_thread.is_alive():
        health_status['checks']['collector_thread'] = 'running'
    else:
        health_status['status'] = 'degraded'
        health_status['checks']['collector_thread'] = 'not running'
    
    # Get last collection time
    try:
        latest_status = ServerStatus.query.order_by(ServerStatus.last_check.desc()).first()
        if latest_status and latest_status.last_check:
            health_status['last_collection'] = latest_status.last_check.isoformat()
    except:
        pass
    
    status_code = 200 if health_status['status'] == 'healthy' else 503
    return jsonify(health_status), status_code

# ============== Authentication ==============

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login page"""
    if request.method == 'POST':
        if request.is_json:
            data = request.get_json()
            username = data.get('username')
            password = data.get('password')
        else:
            username = request.form.get('username')
            password = request.form.get('password')
        
        user = verify_user_password(username, password)
        if user:
            # Handle default admin case (first-time setup)
            if user == 'default_admin':
                session['logged_in'] = True
                session['username'] = 'admin'
                session['user_role'] = 'admin'
                must_change = True
            else:
                session['logged_in'] = True
                session['username'] = user.username
                session['user_role'] = user.role
                user.last_login = datetime.utcnow()
                db.session.commit()
                must_change = not user.password_changed
            
            if request.is_json:
                return jsonify({
                    'status': 'success', 
                    'message': 'Logged in',
                    'role': session.get('user_role'),
                    'password_change_required': must_change
                })
            
            if must_change and session.get('user_role') == 'admin':
                return redirect(url_for('change_password'))
            
            next_url = request.args.get('next', url_for('dashboard'))
            return redirect(next_url)
        else:
            if request.is_json:
                return jsonify({'error': 'Invalid credentials'}), 401
            return render_template('login.html', error='Invalid username or password')
    
    return render_template('login.html')

@app.route('/change-password', methods=['GET', 'POST'])
def change_password():
    """Force password change page (shown after first login with default credentials)"""
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    error = None
    if request.method == 'POST':
        new_username = request.form.get('username', '').strip()
        new_password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        if len(new_username) < 3:
            error = 'Username must be at least 3 characters'
        elif len(new_password) < 6:
            error = 'Password must be at least 6 characters'
        elif new_password != confirm_password:
            error = 'Passwords do not match'
        else:
            try:
                current_username = session.get('username', 'admin')
                user = User.query.filter_by(username=current_username).first()
                
                if not user:
                    # First-time setup - create admin user
                    user = User(
                        username=new_username,
                        password_hash=User.hash_password(new_password),
                        role='admin',
                        password_changed=True
                    )
                    db.session.add(user)
                else:
                    # Check if new username already exists (if changing)
                    if new_username != user.username:
                        existing = User.query.filter_by(username=new_username).first()
                        if existing:
                            error = 'Username already taken'
                            return render_template('change_password.html', error=error, must_change=needs_password_change())
                    
                    user.username = new_username
                    user.password_hash = User.hash_password(new_password)
                    user.password_changed = True
                
                db.session.commit()
                
                session['username'] = new_username
                return redirect(url_for('dashboard'))
            except Exception as e:
                db.session.rollback()
                error = f'Error saving credentials: {str(e)}'
    
    return render_template('change_password.html', error=error, must_change=needs_password_change())

@app.route('/logout')
def logout():
    """Logout user"""
    session.pop('logged_in', None)
    session.pop('username', None)
    session.pop('user_role', None)
    return redirect(url_for('dashboard'))

@app.route('/api/auth/status')
def auth_status():
    """Check authentication status and permissions"""
    role = get_user_role()
    return jsonify({
        'logged_in': is_logged_in(),
        'is_admin': is_admin(),
        'can_write': is_readwrite(),  # admin or readwrite
        'username': session.get('username'),
        'role': role,
        'can_view': can_view(),
        'anonymous_allowed': allow_anonymous_read(),
        'password_change_required': needs_password_change() if is_logged_in() else False
    })

@app.route('/api/admin/credentials', methods=['GET'])
@admin_required
def api_get_admin_credentials():
    """Get current user info (not password)"""
    username = session.get('username', 'admin')
    user = User.query.filter_by(username=username).first()
    if user:
        return jsonify({
            'username': user.username,
            'role': user.role,
            'password_changed': user.password_changed,
            'updated_at': user.updated_at.isoformat() if user.updated_at else None,
            'last_login': user.last_login.isoformat() if user.last_login else None
        })
    return jsonify({
        'username': 'admin',
        'role': 'admin',
        'password_changed': False,
        'updated_at': None
    })

@app.route('/api/admin/credentials', methods=['PUT'])
@admin_required
def api_update_admin_credentials():
    """Update current user's credentials"""
    data = request.get_json()
    
    new_username = data.get('username', '').strip()
    current_password = data.get('current_password', '')
    new_password = data.get('new_password', '')
    
    # Validate
    if new_username and len(new_username) < 3:
        return jsonify({'error': 'Username must be at least 3 characters'}), 400
    
    if new_password and len(new_password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400
    
    # Verify current password
    current_user = session.get('username', 'admin')
    user = verify_user_password(current_user, current_password)
    if not user:
        return jsonify({'error': 'Current password is incorrect'}), 401
    
    try:
        if user == 'default_admin':
            # Create new user from defaults
            user = User(username=new_username or 'admin', role='admin')
            db.session.add(user)
        else:
            # Check if new username already exists
            if new_username and new_username != user.username:
                existing = User.query.filter_by(username=new_username).first()
                if existing:
                    return jsonify({'error': 'Username already taken'}), 400
        
        if new_username:
            user.username = new_username
            session['username'] = new_username
        
        if new_password:
            user.password_hash = User.hash_password(new_password)
            user.password_changed = True
        
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Credentials updated successfully',
            'username': user.username
        })
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error updating credentials: {e}")
        return jsonify({'error': safe_error_message(e, "Failed to update credentials")}), 500

# ============== User Management ==============

@app.route('/api/users', methods=['GET'])
@admin_required
def api_get_users():
    """Get all users"""
    users = User.query.order_by(User.role.desc(), User.username).all()
    return jsonify([{
        'id': u.id,
        'username': u.username,
        'role': u.role,
        'enabled': u.enabled,
        'password_changed': u.password_changed,
        'created_at': u.created_at.isoformat() if u.created_at else None,
        'last_login': u.last_login.isoformat() if u.last_login else None
    } for u in users])

@app.route('/api/users', methods=['POST'])
@admin_required
def api_create_user():
    """Create a new user"""
    data = request.get_json()
    
    username = data.get('username', '').strip()
    password = data.get('password', '')
    role = data.get('role', 'readonly')
    
    if len(username) < 3:
        return jsonify({'error': 'Username must be at least 3 characters'}), 400
    if len(password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400
    if role not in ['admin', 'readwrite', 'readonly']:
        return jsonify({'error': 'Role must be admin, readwrite, or readonly'}), 400
    
    # Check if username exists
    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'Username already exists'}), 400
    
    try:
        user = User(
            username=username,
            password_hash=User.hash_password(password),
            role=role,
            password_changed=True,  # New users don't need to change password
            enabled=True
        )
        db.session.add(user)
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': f'User {username} created',
            'id': user.id
        })
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error creating user: {e}")
        return jsonify({'error': safe_error_message(e, "Failed to create user")}), 500

@app.route('/api/users/<int:user_id>', methods=['PUT'])
@admin_required
def api_update_user(user_id):
    """Update a user"""
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    data = request.get_json()
    
    # Prevent disabling/demoting yourself
    if user.username == session.get('username'):
        if data.get('enabled') == False:
            return jsonify({'error': 'Cannot disable your own account'}), 400
        if data.get('role') == 'readonly' and user.role == 'admin':
            return jsonify({'error': 'Cannot demote your own account'}), 400
    
    try:
        if 'username' in data and data['username']:
            new_username = data['username'].strip()
            if new_username != user.username:
                if User.query.filter_by(username=new_username).first():
                    return jsonify({'error': 'Username already exists'}), 400
                user.username = new_username
        
        if 'role' in data and data['role'] in ['admin', 'readwrite', 'readonly']:
            user.role = data['role']
        
        if 'enabled' in data:
            user.enabled = bool(data['enabled'])
        
        if 'password' in data and data['password']:
            if len(data['password']) < 6:
                return jsonify({'error': 'Password must be at least 6 characters'}), 400
            user.password_hash = User.hash_password(data['password'])
        
        db.session.commit()
        
        return jsonify({'status': 'success', 'message': 'User updated'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@admin_required
def api_delete_user(user_id):
    """Delete a user"""
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # Prevent deleting yourself
    if user.username == session.get('username'):
        return jsonify({'error': 'Cannot delete your own account'}), 400
    
    # Prevent deleting the last admin
    if user.role == 'admin':
        admin_count = User.query.filter_by(role='admin', enabled=True).count()
        if admin_count <= 1:
            return jsonify({'error': 'Cannot delete the last admin user'}), 400
    
    try:
        db.session.delete(user)
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'User deleted'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# ============== AI Cloud Features ==============

@app.route('/api/ai/status')
def api_ai_status():
    """Get AI cloud sync status"""
    try:
        config = CloudSync.get_config()
        server_count = Server.query.count()
        
        return jsonify({
            'enabled': config.sync_enabled,
            'subscription_valid': config.subscription_valid,
            'subscription_tier': config.subscription_tier or 'free',
            'features': config.get_features_list(),
            # Add 'Z' suffix to indicate UTC time so browser interprets correctly
            'last_sync': (config.last_sync.isoformat() + 'Z') if config.last_sync else None,
            'last_sync_status': config.last_sync_status,
            'last_sync_message': config.last_sync_message,
            'server_count': server_count,
            'max_servers': config.max_servers,
            'has_license': bool(config.license_key)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/ai/model', methods=['GET'])
def api_get_ai_model_info():
    """Get AI model information from the AI service (context window size, etc.)"""
    config = CloudSync.get_config()
    
    if not config.AI_SERVICE_URL:
        return jsonify({'error': 'AI service not configured'}), 400
    
    try:
        response = requests.get(
            f"{config.AI_SERVICE_URL}/api/v1/model/info",
            timeout=10
        )
        
        if response.ok:
            return jsonify(response.json())
        else:
            return jsonify({'error': 'Could not get model info'}), 500
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/ai/config', methods=['GET'])
@admin_required
def api_get_ai_config():
    """Get AI cloud configuration including linked WordPress account"""
    config = CloudSync.get_config()
    result = config.to_dict()
    
    # Add linked WordPress account info for current user
    current_username = session.get('username')
    if current_username:
        user = User.query.filter_by(username=current_username).first()
        if user and user.wp_email:
            result['linked_account'] = {
                'wp_email': user.wp_email,
                'wp_user_id': user.wp_user_id,
                'linked_at': user.wp_linked_at.isoformat() if user.wp_linked_at else None
            }
    
    return jsonify(result)


@app.route('/api/ai/config', methods=['PUT'])
@admin_required
def api_update_ai_config():
    """Update AI cloud configuration"""
    data = request.get_json()
    
    try:
        config = CloudSync.get_config()
        
        # Update license key if provided
        if 'license_key' in data and data['license_key']:
            # Validate the license key
            validation = validate_license_key(data['license_key'])
            
            if validation['valid']:
                config.license_key = data['license_key']
                config.subscription_tier = validation.get('tier', 'standard')
                config.subscription_valid = True
                config.max_servers = validation.get('max_servers', 50)
                config.features = json.dumps(validation.get('features', []))
            else:
                return jsonify({'error': 'Invalid license key'}), 400
        
        # Update sync enabled
        if 'sync_enabled' in data:
            config.sync_enabled = data['sync_enabled']
        
        db.session.commit()
        
        # Trigger initial sync if just enabled
        if config.sync_enabled and config.license_key:
            threading.Thread(target=sync_to_cloud, daemon=True).start()
        
        return jsonify({
            'status': 'success',
            'message': 'AI configuration updated',
            'config': config.to_dict()
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/ai/sync', methods=['POST'])
@login_required
def api_trigger_sync():
    """Manually trigger AI cloud sync - any logged-in user can trigger"""
    result = sync_to_cloud()
    return jsonify(result)


@app.route('/api/ai/oauth-callback')
def api_oauth_callback():
    """
    OAuth callback endpoint for CryptoLabs SSO.
    
    Receives:
    - api_key: The API key from CryptoLabs
    - subscription: User's subscription tier
    - user_email: User's email
    - user_name: User's display name
    - wp_user_id: WordPress user ID (for account linking)
    - state: For CSRF protection
    
    Automatically configures AI features and links accounts.
    If user is not logged in, redirects to login first.
    """
    # Check if user is logged in - if not, redirect to login with return URL
    if 'username' not in session:
        # Build the full callback URL with all parameters to return to after login
        callback_url = request.url
        login_url = url_for('login', next=callback_url)
        return redirect(login_url)
    
    api_key = request.args.get('api_key')
    subscription = request.args.get('subscription', 'free')
    user_email = request.args.get('user_email', '')
    wp_user_id = request.args.get('wp_user_id')
    state = request.args.get('state', '')
    
    if not api_key:
        return render_template_string('''
            <!DOCTYPE html>
            <html>
            <head><title>Authentication Failed</title></head>
            <body style="font-family: sans-serif; text-align: center; padding: 50px;">
                <h1 style="color: #ff4757;">❌ Authentication Failed</h1>
                <p>No API key was received. Please try again.</p>
                <button onclick="window.close()">Close</button>
            </body>
            </html>
        '''), 400
    
    # Auto-configure AI settings
    try:
        config = CloudSync.get_config()
        config.license_key = api_key
        config.sync_enabled = True
        config.subscription_tier = subscription
        config.subscription_valid = True
        config.max_servers = 500 if subscription == 'professional' else 50
        
        # Link the current IPMI Monitor admin to the WordPress account
        current_username = session.get('username')
        if current_username and user_email:
            user = User.query.filter_by(username=current_username).first()
            if user:
                user.wp_user_id = int(wp_user_id) if wp_user_id else None
                user.wp_email = user_email
                user.wp_linked_at = datetime.utcnow()
                app.logger.info(f"Linked local user '{current_username}' to WordPress account '{user_email}' (ID: {wp_user_id})")
        
        db.session.commit()
        
        app.logger.info(f"OAuth callback: Configured AI with key from {user_email}, tier: {subscription}")
        
        # Trigger initial sync in background to send all historical data (30 days)
        try:
            app.logger.info("Triggering initial sync after OAuth activation (30 days of data)...")
            sync_result = sync_to_cloud(initial_sync=True)
            app.logger.info(f"Initial sync result: {sync_result}")
        except Exception as sync_error:
            app.logger.error(f"Initial sync failed (non-fatal): {sync_error}")
        
        # Return success page that posts message to parent window
        return render_template_string('''
            <!DOCTYPE html>
            <html>
            <head>
                <title>Authentication Successful</title>
                <style>
                    body {
                        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
                        background: linear-gradient(135deg, #0a0a0f 0%, #1a1a2e 100%);
                        color: #e8e8f0;
                        text-align: center;
                        padding: 50px 20px;
                        min-height: 100vh;
                        margin: 0;
                    }
                    .success-icon { font-size: 4rem; margin-bottom: 20px; }
                    h1 { color: #00d68f; }
                    p { color: #8888a0; }
                    .close-btn {
                        background: #4a9eff;
                        color: white;
                        border: none;
                        padding: 12px 24px;
                        border-radius: 8px;
                        cursor: pointer;
                        font-size: 1rem;
                        margin-top: 20px;
                    }
                </style>
            </head>
            <body>
                <div class="success-icon">✅</div>
                <h1>Authentication Successful!</h1>
                <p>Connected to CryptoLabs AI as <strong>{{ user_email }}</strong></p>
                <p>Subscription: <strong>{{ subscription|upper }}</strong></p>
                <p>This window will close automatically...</p>
                <button class="close-btn" onclick="window.close()">Close Window</button>
                <script>
                    // Send message to parent window
                    if (window.opener) {
                        window.opener.postMessage({
                            type: 'cryptolabs_ipmi_auth',
                            api_key: '{{ api_key }}',
                            subscription: '{{ subscription }}',
                            user_email: '{{ user_email }}',
                            user_name: '{{ user_name }}'
                        }, '*');
                        
                        // Auto-close after 2 seconds
                        setTimeout(() => window.close(), 2000);
                    }
                </script>
            </body>
            </html>
        ''', api_key=api_key, subscription=subscription, user_email=user_email, 
           user_name=request.args.get('user_name', ''))
        
    except Exception as e:
        app.logger.error(f"OAuth callback error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/ai/test', methods=['POST'])
@admin_required
def api_test_ai_connection():
    """
    Test AI service connection with provided API key.
    
    Request body:
    - license_key: The API key to test
    
    Returns:
    - valid: Whether the key is valid
    - tier: Subscription tier
    - max_servers: Maximum servers allowed
    - error: Error message if invalid
    """
    data = request.get_json() or {}
    license_key = data.get('license_key')
    
    if not license_key:
        return jsonify({'valid': False, 'error': 'No API key provided'}), 400
    
    config = CloudSync.get_config()
    ai_service_url = config.AI_SERVICE_URL or 'https://ipmi-ai.cryptolabs.co.za'
    
    try:
        response = requests.post(
            f"{ai_service_url}/api/v1/validate",
            json={'license_key': license_key},
            headers={'Content-Type': 'application/json'},
            timeout=10
        )
        
        if response.ok:
            result = response.json()
            return jsonify(result)
        else:
            error_data = response.json() if response.headers.get('content-type', '').startswith('application/json') else {}
            return jsonify({
                'valid': False,
                'error': error_data.get('error', f'Server returned {response.status_code}')
            }), 401
            
    except requests.exceptions.Timeout:
        return jsonify({'valid': False, 'error': 'Connection timed out. AI service may be unavailable.'}), 504
    except requests.exceptions.RequestException as e:
        return jsonify({'valid': False, 'error': f'Connection failed: {str(e)}'}), 500


@app.route('/api/ai/results')
def api_get_ai_results():
    """Get cached AI results"""
    if not CloudSync.is_ai_enabled():
        return jsonify({
            'enabled': False,
            'message': 'AI features not enabled. Upgrade to Standard plan ($100/mo) for AI insights.',
            'upgrade_url': 'https://cryptolabs.co.za/ipmi-monitor'
        })
    
    try:
        summary = AIResult.get_latest('summary')
        tasks = AIResult.get_latest('tasks')
        predictions = AIResult.get_latest('predictions')
        
        return jsonify({
            'enabled': True,
            'summary': json.loads(summary.content) if summary and summary.content else None,
            'tasks': json.loads(tasks.content) if tasks and tasks.content else [],
            'predictions': json.loads(predictions.content) if predictions and predictions.content else [],
            'last_updated': summary.fetched_at.isoformat() if summary else None
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/ai/summary/generate', methods=['POST'])
@login_required
def api_generate_summary():
    """Generate AI summary on demand - forwards user selections to AI service"""
    config = CloudSync.get_config()
    
    if not config.sync_enabled or not config.license_key:
        return jsonify({'error': 'AI features not enabled'}), 400
    
    # Forward user selections (type, hours, devices) to AI service
    # All pre-processing and LLM calls happen on AI service
    user_options = request.get_json() or {}
    
    try:
        response = requests.post(
            f"{config.AI_SERVICE_URL}/api/v1/summary/generate",
            json=user_options,  # Forward: type, hours, devices
            headers={'Authorization': f'Bearer {config.license_key}'},
            timeout=120  # Allow time for LLM processing
        )
        
        if response.ok:
            result = response.json()
            if result.get('summary'):
                AIResult.store_result('summary', result['summary'])
            return jsonify(result)
        else:
            return jsonify({'error': f"AI service error: {response.text}"}), response.status_code
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/ai/tasks/generate', methods=['POST'])
@login_required
def api_generate_tasks():
    """Generate AI maintenance tasks on demand - forwards user selections to AI service"""
    config = CloudSync.get_config()
    
    if not config.sync_enabled or not config.license_key:
        return jsonify({'error': 'AI features not enabled'}), 400
    
    # Forward user selections (issues, hours, devices) to AI service
    # All pre-processing and LLM calls happen on AI service
    user_options = request.get_json() or {}
    
    try:
        response = requests.post(
            f"{config.AI_SERVICE_URL}/api/v1/tasks/generate",
            json=user_options,  # Forward: issues, hours, devices
            headers={'Authorization': f'Bearer {config.license_key}'},
            timeout=120  # Allow time for LLM processing
        )
        
        if response.ok:
            result = response.json()
            if result.get('tasks'):
                AIResult.store_result('tasks', result['tasks'])
            return jsonify(result)
        else:
            return jsonify({'error': f"AI service error: {response.text}"}), response.status_code
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/ai/chat', methods=['POST'])
@login_required
def api_ai_chat():
    """AI chat interface - ask questions about the fleet - forwards to AI service"""
    config = CloudSync.get_config()
    
    if not CloudSync.is_ai_enabled():
        return jsonify({
            'error': 'AI features not enabled',
            'upgrade_url': 'https://cryptolabs.co.za/ipmi-monitor'
        }), 403
    
    # Forward entire request to AI service (question, conversation_id)
    # All context building and LLM calls happen on AI service
    data = request.get_json() or {}
    question = data.get('question', '')
    
    if not question:
        return jsonify({'error': 'Question required'}), 400
    
    try:
        response = requests.post(
            f"{config.AI_SERVICE_URL}/api/v1/chat",
            json=data,  # Forward: question, conversation_id
            headers={'Authorization': f'Bearer {config.license_key}'},
            timeout=120  # Allow time for LLM processing
        )
        
        if response.ok:
            return jsonify(response.json())
        else:
            return jsonify({'error': f"AI service error: {response.text}"}), response.status_code
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/ai/rca', methods=['POST'])
@login_required
def api_ai_rca():
    """AI Root Cause Analysis for an event"""
    config = CloudSync.get_config()
    
    if not CloudSync.is_ai_enabled():
        return jsonify({
            'error': 'AI features not enabled',
            'upgrade_url': 'https://cryptolabs.co.za/ipmi-monitor'
        }), 403
    
    data = request.get_json()
    
    try:
        response = requests.post(
            f"{config.AI_SERVICE_URL}/api/v1/rca",
            json=data,
            headers={'Authorization': f'Bearer {config.license_key}'},
            timeout=90
        )
        
        if response.ok:
            return jsonify(response.json())
        else:
            return jsonify({'error': f"AI service error: {response.text}"}), response.status_code
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============== AI Agent Endpoints ==============

@app.route('/api/ai/agent/status')
@login_required
def api_ai_agent_status():
    """Get AI Agent status and capabilities"""
    config = CloudSync.get_config()
    
    if not CloudSync.is_ai_enabled():
        return jsonify({
            'agent_enabled': False,
            'error': 'AI features not enabled'
        })
    
    try:
        response = requests.get(
            f"{config.AI_SERVICE_URL}/api/v1/agent/status",
            headers={'Authorization': f'Bearer {config.license_key}'},
            timeout=30
        )
        
        if response.ok:
            return jsonify(response.json())
        else:
            return jsonify({'agent_enabled': False, 'error': 'Agent unavailable'})
            
    except Exception as e:
        return jsonify({'agent_enabled': False, 'error': str(e)})


@app.route('/api/ai/agent/settings', methods=['GET', 'POST'])
@login_required
def api_ai_agent_settings():
    """Get or update AI Agent settings"""
    config = CloudSync.get_config()
    
    if not CloudSync.is_ai_enabled():
        return jsonify({'error': 'AI features not enabled'}), 403
    
    try:
        if request.method == 'POST':
            data = request.get_json()
            response = requests.post(
                f"{config.AI_SERVICE_URL}/api/v1/agent/settings",
                json=data,
                headers={'Authorization': f'Bearer {config.license_key}'},
                timeout=30
            )
        else:
            response = requests.get(
                f"{config.AI_SERVICE_URL}/api/v1/agent/settings",
                headers={'Authorization': f'Bearer {config.license_key}'},
                timeout=30
            )
        
        if response.ok:
            return jsonify(response.json())
        else:
            return jsonify({'error': f"AI service error: {response.text}"}), response.status_code
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/ai/agent/analyze', methods=['POST'])
@login_required
def api_ai_agent_analyze():
    """Analyze fleet with AI Agent"""
    config = CloudSync.get_config()
    
    if not CloudSync.is_ai_enabled():
        return jsonify({'error': 'AI features not enabled'}), 403
    
    data = request.get_json() or {}
    
    # Add local event data to the request
    try:
        # Get recent events from local database
        hours = data.get('hours', 24)
        cutoff = datetime.now() - timedelta(hours=hours)
        
        events = Event.query.filter(Event.timestamp >= cutoff).order_by(Event.timestamp.desc()).limit(1000).all()
        
        event_list = [{
            'event_id': e.id,
            'server_name': e.server.name if e.server else 'Unknown',
            'description': e.description,
            'message': e.message,
            'severity': e.severity,
            'timestamp': e.timestamp.isoformat()
        } for e in events]
        
        # Send to AI service for agent analysis
        response = requests.post(
            f"{config.AI_SERVICE_URL}/api/v1/agent/analyze",
            json={
                'events': event_list,
                'auto_recovery_enabled': data.get('auto_recovery_enabled', False),
                'server_name': data.get('server_name')
            },
            headers={'Authorization': f'Bearer {config.license_key}'},
            timeout=60
        )
        
        if response.ok:
            return jsonify(response.json())
        else:
            return jsonify({'error': f"AI service error: {response.text}"}), response.status_code
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/ai/agent/recovery/status')
@login_required
def api_ai_agent_recovery_status():
    """Get recovery status for servers"""
    config = CloudSync.get_config()
    
    if not CloudSync.is_ai_enabled():
        return jsonify({'error': 'AI features not enabled'}), 403
    
    server_id = request.args.get('server_id')
    gpu_id = request.args.get('gpu_id')
    
    try:
        params = {}
        if server_id:
            params['server_id'] = server_id
        if gpu_id:
            params['gpu_id'] = gpu_id
            
        response = requests.get(
            f"{config.AI_SERVICE_URL}/api/v1/agent/recovery/status",
            params=params,
            headers={'Authorization': f'Bearer {config.license_key}'},
            timeout=30
        )
        
        if response.ok:
            return jsonify(response.json())
        else:
            return jsonify({'error': f"AI service error: {response.text}"}), response.status_code
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/ai/agent/recovery/history')
@login_required
def api_ai_agent_recovery_history():
    """Get recovery action history from local database"""
    try:
        # Get from local recovery log
        history = RecoveryActionLog.query.order_by(
            RecoveryActionLog.executed_at.desc()
        ).limit(100).all()
        
        return jsonify({
            'history': [h.to_dict() for h in history],
            'count': len(history)
        })
            
    except Exception as e:
        return jsonify({'history': [], 'error': str(e)})


# ============== Recovery Permissions API ==============

@app.route('/api/recovery/permissions', methods=['GET'])
@login_required
def api_get_recovery_permissions():
    """Get system-wide and all per-server recovery permissions"""
    try:
        system_default = RecoveryPermissions.get_system_default()
        server_overrides = RecoveryPermissions.query.filter(
            RecoveryPermissions.bmc_ip != None
        ).all()
        
        return jsonify({
            'system_default': system_default.to_dict(),
            'server_overrides': [s.to_dict() for s in server_overrides],
            'xid_configs': XID_RECOVERY_CONFIGS
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/recovery/permissions/default', methods=['GET', 'PUT'])
@admin_required
def api_recovery_permissions_default():
    """Get or update system-wide default recovery permissions"""
    try:
        default = RecoveryPermissions.get_system_default()
        
        if request.method == 'GET':
            return jsonify(default.to_dict())
        
        # PUT - update defaults
        data = request.get_json()
        
        # Update boolean fields
        bool_fields = [
            'allow_kill_workload', 'allow_soft_reset', 'allow_clock_limit',
            'allow_pci_reset', 'allow_reboot', 'allow_power_cycle',
            'allow_maintenance_flag', 'notify_on_action', 'notify_on_escalation'
        ]
        for field in bool_fields:
            if field in data:
                setattr(default, field, bool(data[field]))
        
        # Update integer fields
        int_fields = ['max_soft_attempts', 'max_reboot_per_day', 'max_power_cycle_per_day']
        for field in int_fields:
            if field in data:
                setattr(default, field, int(data[field]))
        
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'System default permissions updated',
            'permissions': default.to_dict()
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/recovery/permissions/server/<bmc_ip>', methods=['GET', 'PUT', 'DELETE'])
@admin_required
def api_recovery_permissions_server(bmc_ip):
    """Get, update, or delete per-server recovery permissions"""
    try:
        if request.method == 'GET':
            perms = RecoveryPermissions.get_for_server(bmc_ip)
            return jsonify(perms.to_dict())
        
        elif request.method == 'DELETE':
            # Delete server override (will fall back to default)
            perms = RecoveryPermissions.query.filter_by(bmc_ip=bmc_ip).first()
            if perms:
                db.session.delete(perms)
                db.session.commit()
                return jsonify({'status': 'success', 'message': f'Permissions for {bmc_ip} deleted'})
            return jsonify({'status': 'success', 'message': 'No override existed'})
        
        # PUT - create or update server-specific permissions
        data = request.get_json()
        
        perms = RecoveryPermissions.query.filter_by(bmc_ip=bmc_ip).first()
        if not perms:
            server = Server.query.filter_by(bmc_ip=bmc_ip).first()
            perms = RecoveryPermissions(
                bmc_ip=bmc_ip,
                server_name=server.server_name if server else bmc_ip
            )
            db.session.add(perms)
        
        # Update boolean fields
        bool_fields = [
            'allow_kill_workload', 'allow_soft_reset', 'allow_clock_limit',
            'allow_pci_reset', 'allow_reboot', 'allow_power_cycle',
            'allow_maintenance_flag', 'notify_on_action', 'notify_on_escalation'
        ]
        for field in bool_fields:
            if field in data:
                setattr(perms, field, bool(data[field]))
        
        # Update integer fields
        int_fields = ['max_soft_attempts', 'max_reboot_per_day', 'max_power_cycle_per_day']
        for field in int_fields:
            if field in data:
                setattr(perms, field, int(data[field]))
        
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': f'Permissions for {bmc_ip} updated',
            'permissions': perms.to_dict()
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/recovery/xid-configs')
@login_required
def api_xid_configs():
    """Get all XID error configurations with recovery actions"""
    return jsonify({
        'configs': XID_RECOVERY_CONFIGS,
        'action_descriptions': {
            'none': 'Monitor only - no action taken',
            'kill_workload': 'Kill container/VM using the GPU',
            'soft_reset': 'NVIDIA soft reset (nvidia-smi -r)',
            'clock_limit': 'Reduce GPU clocks for stability',
            'pci_reset': 'PCI device remove and rescan',
            'reboot': 'System reboot',
            'power_cycle': 'IPMI power cycle',
            'maintenance': 'Flag for manual maintenance'
        }
    })


@app.route('/api/ai/agent/recovery/execute', methods=['POST'])
@admin_required
def api_ai_agent_execute_recovery():
    """
    Execute a recovery action on a server (Admin only)
    
    Supported actions:
    - kill_vm: Stop/destroy a KVM VM to recover GPU
    - stop_container: Stop a Docker container to recover GPU
    - soft_reset_gpu: Attempt nvidia-smi soft reset
    - pci_reset_gpu: Remove and rescan PCI device
    """
    data = request.get_json()
    
    server_id = data.get('server_id')
    action = data.get('action')
    target = data.get('target')  # VM name, container name, GPU ID, or PCI address
    force = data.get('force', False)
    
    if not server_id or not action:
        return jsonify({'error': 'server_id and action are required'}), 400
    
    # Get server
    server = Server.query.get(server_id)
    if not server:
        return jsonify({'error': 'Server not found'}), 404
    
    # Get SSH credentials
    config = ServerConfig.query.filter_by(bmc_ip=server.bmc_ip).first()
    if not config or not config.ssh_user:
        return jsonify({'error': 'SSH not configured for this server'}), 400
    
    # Get server OS IP
    server_ip = server.server_ip or server.bmc_ip.replace('.0', '.1')  # Guess OS IP if not set
    
    # Build SSH command helper
    def run_ssh(cmd, timeout=60):
        ssh_opts = ['-o', 'StrictHostKeyChecking=no', '-o', 'ConnectTimeout=10']
        
        if config.ssh_key_id:
            stored_key = SSHKey.query.get(config.ssh_key_id)
            if stored_key:
                import tempfile
                key_content = stored_key.key_content.replace('\r\n', '\n').strip() + '\n'
                key_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.pem')
                key_file.write(key_content)
                key_file.close()
                os.chmod(key_file.name, 0o600)
                ssh_cmd = ['ssh'] + ssh_opts + ['-i', key_file.name, f'{config.ssh_user}@{server_ip}', cmd]
            else:
                return {'success': False, 'error': 'SSH key not found'}
        elif config.ssh_key:
            import tempfile
            key_content = config.ssh_key.replace('\r\n', '\n').strip() + '\n'
            key_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.pem')
            key_file.write(key_content)
            key_file.close()
            os.chmod(key_file.name, 0o600)
            ssh_cmd = ['ssh'] + ssh_opts + ['-i', key_file.name, f'{config.ssh_user}@{server_ip}', cmd]
        elif config.ssh_pass:
            ssh_cmd = ['sshpass', '-p', config.ssh_pass, 'ssh'] + ssh_opts + [f'{config.ssh_user}@{server_ip}', cmd]
        else:
            ssh_cmd = ['ssh'] + ssh_opts + ['-o', 'BatchMode=yes', f'{config.ssh_user}@{server_ip}', cmd]
        
        try:
            result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=timeout)
            return {'success': result.returncode == 0, 'stdout': result.stdout, 'stderr': result.stderr}
        except subprocess.TimeoutExpired:
            return {'success': False, 'error': 'SSH command timeout'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    result = {'success': False, 'action': action, 'target': target}
    
    try:
        if action == 'kill_vm':
            # Kill KVM VM to recover GPU
            if not target:
                return jsonify({'error': 'target (VM name) is required'}), 400
            
            # Check VM state first
            check = run_ssh(f'virsh domstate {target} 2>&1')
            if not check['success'] or 'running' not in check.get('stdout', ''):
                result['error'] = f'VM {target} is not running'
                return jsonify(result), 400
            
            # Kill the VM
            if force:
                kill_result = run_ssh(f'virsh destroy {target}')
                action_name = 'destroyed'
            else:
                kill_result = run_ssh(f'virsh shutdown {target}')
                action_name = 'shutdown initiated'
            
            if kill_result['success']:
                # Log the action
                event = Event(
                    server_id=server.id,
                    description=f'GPU Recovery: VM {target} {action_name}',
                    message=f'VM {target} was {action_name} to allow GPU recovery',
                    severity='warning',
                    timestamp=datetime.utcnow(),
                    event_type='RECOVERY_ACTION'
                )
                db.session.add(event)
                db.session.commit()
                
                result['success'] = True
                result['message'] = f'VM {target} {action_name}. GPU may now be recoverable.'
                
                # Check GPU status
                gpu_check = run_ssh('nvidia-smi -L 2>&1')
                result['gpu_status'] = gpu_check.get('stdout', '')
            else:
                result['error'] = kill_result.get('error', kill_result.get('stderr', 'Unknown error'))
        
        elif action == 'stop_container':
            # Stop Docker container
            if not target:
                return jsonify({'error': 'target (container name) is required'}), 400
            
            stop_result = run_ssh(f'docker stop {target}')
            
            if stop_result['success']:
                event = Event(
                    server_id=server.id,
                    description=f'GPU Recovery: Container {target} stopped',
                    message=f'Container {target} was stopped to allow GPU recovery',
                    severity='warning',
                    timestamp=datetime.utcnow(),
                    event_type='RECOVERY_ACTION'
                )
                db.session.add(event)
                db.session.commit()
                
                result['success'] = True
                result['message'] = f'Container {target} stopped. GPU may now be recoverable.'
            else:
                result['error'] = stop_result.get('error', stop_result.get('stderr', 'Unknown error'))
        
        elif action == 'soft_reset_gpu':
            # nvidia-smi GPU reset
            gpu_id = target or '0'
            reset_result = run_ssh(f'nvidia-smi -r -i {gpu_id} 2>&1')
            
            result['success'] = reset_result['success']
            result['output'] = reset_result.get('stdout', '') + reset_result.get('stderr', '')
            if reset_result['success']:
                result['message'] = f'GPU {gpu_id} soft reset attempted'
        
        elif action == 'pci_reset_gpu':
            # PCI device reset
            if not target:
                return jsonify({'error': 'target (PCI address like 0000:01:00.0) is required'}), 400
            
            # WARNING: This is disruptive!
            remove_result = run_ssh(f'echo 1 > /sys/bus/pci/devices/{target}/remove && sleep 2')
            if not remove_result['success']:
                result['error'] = f'Failed to remove PCI device: {remove_result.get("stderr")}'
                return jsonify(result), 500
            
            rescan_result = run_ssh('echo 1 > /sys/bus/pci/rescan && sleep 3')
            
            event = Event(
                server_id=server.id,
                description=f'GPU Recovery: PCI {target} reset',
                message=f'PCI device {target} was removed and rescanned',
                severity='warning',
                timestamp=datetime.utcnow(),
                event_type='RECOVERY_ACTION'
            )
            db.session.add(event)
            db.session.commit()
            
            # Check if GPU came back
            gpu_check = run_ssh('nvidia-smi -L 2>&1')
            
            result['success'] = True
            result['message'] = f'PCI device {target} removed and rescanned'
            result['gpu_status'] = gpu_check.get('stdout', '')
        
        else:
            return jsonify({'error': f'Unknown action: {action}'}), 400
        
        return jsonify(result)
        
    except Exception as e:
        app.logger.error(f"Recovery action failed: {e}")
        result['error'] = str(e)
        return jsonify(result), 500


@app.route('/api/servers/<int:server_id>/xid-errors')
@login_required
def api_server_xid_errors(server_id):
    """Get Xid errors for a specific server"""
    server = Server.query.get_or_404(server_id)
    
    # Get Xid events from IPMIEvent (sensor_type = 'GPU Xid Error')
    xid_events = IPMIEvent.query.filter(
        IPMIEvent.bmc_ip == server.bmc_ip,
        IPMIEvent.sensor_type == 'GPU Xid Error'
    ).order_by(IPMIEvent.collected_at.desc()).limit(50).all()
    
    # Also check inventory for recent Xid errors from dmesg
    inventory = ServerInventory.query.filter_by(server_name=server.server_name).first()
    raw_xid = []
    if inventory and inventory.raw_inventory:
        try:
            raw = json.loads(inventory.raw_inventory)
            raw_xid = raw.get('xid_errors', [])
        except:
            pass
    
    return jsonify({
        'server_name': server.server_name,
        'bmc_ip': server.bmc_ip,
        'events': [{
            'id': e.id,
            'sel_id': e.sel_id,
            'description': e.event_description,
            'pci_address': e.sensor_id,
            'severity': e.severity,
            'raw_entry': e.raw_entry,
            'timestamp': e.collected_at.isoformat() if e.collected_at else None
        } for e in xid_events],
        'recent_xid_errors': raw_xid,
        'critical_count': len([e for e in xid_events if e.severity == 'critical'])
    })


# ============== System Settings ==============

@app.route('/api/settings', methods=['GET'])
@admin_required
def api_get_settings():
    """Get system settings"""
    settings = SystemSettings.query.all()
    return jsonify({s.key: s.value for s in settings})

@app.route('/api/settings', methods=['PUT'])
@admin_required
def api_update_settings():
    """Update system settings"""
    data = request.get_json()
    
    try:
        for key, value in data.items():
            SystemSettings.set(key, value)
        return jsonify({'status': 'success', 'message': 'Settings updated'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/system/info', methods=['GET'])
@admin_required
def api_system_info():
    """Get system information including CPU count for worker configuration"""
    return jsonify({
        'cpu_count': CPU_COUNT,
        'current_workers': get_collection_workers(),
        'configured_workers': SystemSettings.get('collection_workers', 'auto'),
        'env_workers': os.environ.get('COLLECTION_WORKERS', None),
    })

@app.route('/api/settings/anonymous', methods=['GET'])
def api_get_anonymous_setting():
    """Get anonymous access setting (public endpoint)"""
    return jsonify({
        'allow_anonymous_read': allow_anonymous_read()
    })


# ============== Credential Defaults API ==============

@app.route('/api/settings/credentials/defaults', methods=['GET', 'PUT'])
@admin_required
def api_credential_defaults():
    """
    Get or update default credentials for IPMI and SSH.
    
    These defaults are applied to new servers and can be referenced in servers.yaml.
    
    Settings stored:
    - ipmi_user: Default IPMI username
    - ipmi_pass: Default IPMI password (stored encrypted in production)
    - ssh_user: Default SSH username (usually 'root')
    - default_ssh_key_id: ID of default SSH key
    """
    if request.method == 'GET':
        # Get current defaults
        default_ssh_key = None
        default_key_id = SystemSettings.get('default_ssh_key_id')
        if default_key_id:
            key = SSHKey.query.get(int(default_key_id))
            if key:
                default_ssh_key = {'id': key.id, 'name': key.name, 'fingerprint': key.fingerprint}
        
        return jsonify({
            'ipmi_user': SystemSettings.get('ipmi_user') or os.environ.get('IPMI_USER', 'admin'),
            'ipmi_pass_set': bool(SystemSettings.get('ipmi_pass') or os.environ.get('IPMI_PASS')),
            'ssh_user': SystemSettings.get('ssh_user') or 'root',
            'ssh_port': int(SystemSettings.get('ssh_port') or 22),
            'default_ssh_key': default_ssh_key,
            'enable_ssh_inventory': SystemSettings.get('enable_ssh_inventory', 'false').lower() == 'true',
            'available_ssh_keys': [{'id': k.id, 'name': k.name, 'fingerprint': k.fingerprint} 
                                   for k in SSHKey.query.all()]
        })
    
    # PUT - update defaults
    data = request.get_json()
    
    try:
        if 'ipmi_user' in data:
            SystemSettings.set('ipmi_user', data['ipmi_user'])
        if 'ipmi_pass' in data and data['ipmi_pass']:
            SystemSettings.set('ipmi_pass', data['ipmi_pass'])
        if 'ssh_user' in data:
            SystemSettings.set('ssh_user', data['ssh_user'])
        if 'ssh_port' in data:
            SystemSettings.set('ssh_port', str(data['ssh_port']))
        if 'default_ssh_key_id' in data:
            SystemSettings.set('default_ssh_key_id', str(data['default_ssh_key_id']) if data['default_ssh_key_id'] else '')
        if 'enable_ssh_inventory' in data:
            SystemSettings.set('enable_ssh_inventory', 'true' if data['enable_ssh_inventory'] else 'false')
        
        return jsonify({
            'status': 'success',
            'message': 'Credential defaults updated'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/settings/credentials/apply', methods=['POST'])
@admin_required
def api_apply_credential_defaults():
    """
    Apply credential defaults to multiple servers.
    
    Request body:
    {
        "server_ips": ["88.0.1.0", "88.0.2.0"],  // List of BMC IPs, or "all"
        "apply_ipmi": true,      // Apply IPMI credentials
        "apply_ssh": true,       // Apply SSH credentials
        "overwrite": false       // Overwrite existing credentials
    }
    """
    data = request.get_json()
    
    server_ips = data.get('server_ips', [])
    apply_ipmi = data.get('apply_ipmi', True)
    apply_ssh = data.get('apply_ssh', True)
    overwrite = data.get('overwrite', False)
    
    # Get defaults
    default_ipmi_user = SystemSettings.get('ipmi_user') or os.environ.get('IPMI_USER', 'admin')
    default_ipmi_pass = SystemSettings.get('ipmi_pass') or os.environ.get('IPMI_PASS')
    default_ssh_user = SystemSettings.get('ssh_user') or 'root'
    default_ssh_port = int(SystemSettings.get('ssh_port') or 22)
    default_ssh_key_id = SystemSettings.get('default_ssh_key_id')
    
    # Get servers to update
    if server_ips == 'all':
        servers = Server.query.filter_by(enabled=True).all()
    else:
        servers = Server.query.filter(Server.bmc_ip.in_(server_ips)).all()
    
    updated = 0
    skipped = 0
    errors = []
    
    for server in servers:
        try:
            # Get or create config
            config = ServerConfig.query.filter_by(bmc_ip=server.bmc_ip).first()
            if not config:
                config = ServerConfig(bmc_ip=server.bmc_ip, server_name=server.server_name)
                db.session.add(config)
            
            changed = False
            
            # Apply IPMI credentials
            if apply_ipmi:
                if overwrite or not config.ipmi_user:
                    config.ipmi_user = default_ipmi_user
                    changed = True
                if overwrite or not config.ipmi_pass:
                    if default_ipmi_pass:
                        config.ipmi_pass = default_ipmi_pass
                        changed = True
            
            # Apply SSH credentials
            if apply_ssh:
                if overwrite or not config.ssh_user:
                    config.ssh_user = default_ssh_user
                    changed = True
                if overwrite or not config.ssh_port:
                    config.ssh_port = default_ssh_port
                    changed = True
                if default_ssh_key_id and (overwrite or not config.ssh_key_id):
                    config.ssh_key_id = int(default_ssh_key_id)
                    changed = True
                
                # Set server_ip if not set
                if not config.server_ip:
                    config.server_ip = server.server_ip or server.bmc_ip.replace('.0', '.1')
                    changed = True
            
            if changed:
                updated += 1
            else:
                skipped += 1
                
        except Exception as e:
            errors.append(f"{server.bmc_ip}: {str(e)}")
    
    db.session.commit()
    
    return jsonify({
        'status': 'success',
        'updated': updated,
        'skipped': skipped,
        'errors': errors,
        'message': f'Applied defaults to {updated} servers ({skipped} skipped, {len(errors)} errors)'
    })


@app.route('/api/ssh-keys', methods=['GET', 'POST'])
@admin_required
def api_ssh_keys():
    """Manage stored SSH keys"""
    if request.method == 'GET':
        keys = SSHKey.query.all()
        return jsonify({
            'keys': [{'id': k.id, 'name': k.name, 'fingerprint': k.fingerprint, 
                     'created_at': k.created_at.isoformat() if k.created_at else None}
                    for k in keys]
        })
    
    # POST - add new key
    data = request.get_json()
    name = data.get('name')
    key_content = data.get('key_content')
    
    if not name or not key_content:
        return jsonify({'error': 'name and key_content are required'}), 400
    
    # Check if name exists
    if SSHKey.query.filter_by(name=name).first():
        return jsonify({'error': f'SSH key with name "{name}" already exists'}), 400
    
    try:
        # Normalize key content
        key_content = key_content.replace('\r\n', '\n').strip() + '\n'
        fingerprint = SSHKey.get_fingerprint(key_content)
        
        key = SSHKey(name=name, key_content=key_content, fingerprint=fingerprint)
        db.session.add(key)
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'key': {'id': key.id, 'name': key.name, 'fingerprint': key.fingerprint}
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/ssh-keys/<int:key_id>', methods=['GET', 'PUT', 'DELETE'])
@admin_required
def api_ssh_key_detail(key_id):
    """Get, update, or delete an SSH key"""
    key = SSHKey.query.get_or_404(key_id)
    
    if request.method == 'GET':
        return jsonify({
            'id': key.id,
            'name': key.name,
            'fingerprint': key.fingerprint,
            'created_at': key.created_at.isoformat() if key.created_at else None,
            'key_preview': key.key_content[:50] + '...' if key.key_content else None
        })
    
    elif request.method == 'DELETE':
        # Check if key is in use
        in_use = ServerConfig.query.filter_by(ssh_key_id=key_id).count()
        if in_use > 0:
            return jsonify({'error': f'Cannot delete: key is assigned to {in_use} servers'}), 400
        
        db.session.delete(key)
        db.session.commit()
        return jsonify({'status': 'success', 'message': f'SSH key "{key.name}" deleted'})
    
    # PUT - update
    data = request.get_json()
    
    if 'name' in data and data['name'] != key.name:
        if SSHKey.query.filter_by(name=data['name']).first():
            return jsonify({'error': f'Name "{data["name"]}" already exists'}), 400
        key.name = data['name']
    
    if 'key_content' in data and data['key_content']:
        key.key_content = data['key_content'].replace('\r\n', '\n').strip() + '\n'
        key.fingerprint = SSHKey.get_fingerprint(key.key_content)
    
    db.session.commit()
    return jsonify({
        'status': 'success',
        'key': {'id': key.id, 'name': key.name, 'fingerprint': key.fingerprint}
    })


# ============== Configuration Backup/Restore ==============

@app.route('/api/config/export', methods=['GET'])
@admin_required
def api_export_config():
    """
    Export complete IPMI Monitor configuration as JSON.
    
    Includes:
    - Servers (with credentials optionally masked)
    - System settings
    - SSH keys (optionally excluded)
    - Alert rules
    - Users (passwords excluded)
    - AI configuration (API key masked)
    
    Query params:
    - include_secrets: Include passwords/keys (default: false)
    - format: json (default) or yaml
    """
    include_secrets = request.args.get('include_secrets', 'false').lower() == 'true'
    format_type = request.args.get('format', 'json')
    
    # Collect all configuration
    config_data = {
        'export_version': '1.0',
        'exported_at': datetime.utcnow().isoformat(),
        'app_name': APP_NAME,
    }
    
    # Servers
    servers = Server.query.all()
    config_data['servers'] = []
    for s in servers:
        server_data = {
            'name': s.server_name,
            'bmc_ip': s.bmc_ip,
            'server_ip': s.server_ip,
            'public_ip': s.public_ip,
            'enabled': s.enabled,
            'notes': s.notes,
        }
        # Get per-server config if exists
        server_config = ServerConfig.query.filter_by(bmc_ip=s.bmc_ip).first()
        if server_config:
            if server_config.ipmi_user:
                server_data['ipmi_user'] = server_config.ipmi_user
            if include_secrets and server_config.ipmi_pass:
                server_data['ipmi_pass'] = server_config.ipmi_pass
            if server_config.ssh_user:
                server_data['ssh_user'] = server_config.ssh_user
            if include_secrets and server_config.ssh_pass:
                server_data['ssh_pass'] = server_config.ssh_pass
            if server_config.ssh_key_id:
                ssh_key = SSHKey.query.get(server_config.ssh_key_id)
                if ssh_key:
                    server_data['ssh_key_name'] = ssh_key.name
        config_data['servers'].append(server_data)
    
    # System settings
    settings = SystemSettings.query.all()
    config_data['settings'] = {s.key: s.value for s in settings}
    
    # SSH keys
    ssh_keys = SSHKey.query.all()
    config_data['ssh_keys'] = []
    for key in ssh_keys:
        key_data = {
            'name': key.name,
            'fingerprint': key.fingerprint,
        }
        if include_secrets:
            key_data['key_content'] = key.key_content
        config_data['ssh_keys'].append(key_data)
    
    # Alert rules
    alerts = AlertRule.query.all()
    config_data['alert_rules'] = [{
        'name': a.name,
        'description': a.description,
        'event_pattern': a.event_pattern,
        'severity': a.severity,
        'enabled': a.enabled,
        'notification_channels': a.notification_channels,
    } for a in alerts]
    
    # Users (without passwords)
    users = User.query.all()
    config_data['users'] = [{
        'username': u.username,
        'role': u.role,
    } for u in users]
    
    # AI configuration
    ai_config = CloudSync.get_config()
    config_data['ai_config'] = {
        'sync_enabled': ai_config.sync_enabled,
        'subscription_tier': ai_config.subscription_tier,
        # Mask API key
        'license_key': f"{'*' * 20}...{ai_config.license_key[-8:]}" if ai_config.license_key and len(ai_config.license_key) > 8 else None,
    }
    
    # Return as JSON or downloadable file
    if request.args.get('download', 'false').lower() == 'true':
        response = make_response(json.dumps(config_data, indent=2))
        response.headers['Content-Type'] = 'application/json'
        response.headers['Content-Disposition'] = f'attachment; filename=ipmi-monitor-config-{datetime.utcnow().strftime("%Y%m%d-%H%M%S")}.json'
        return response
    
    return jsonify(config_data)


@app.route('/api/config/import', methods=['POST'])
@admin_required
def api_import_config():
    """
    Import IPMI Monitor configuration from JSON.
    
    Request body: JSON configuration (from export)
    
    Query params:
    - merge: Merge with existing config (default: true)
    - skip_servers: Don't import servers (default: false)
    - skip_settings: Don't import settings (default: false)
    - skip_ssh_keys: Don't import SSH keys (default: false)
    - skip_alerts: Don't import alert rules (default: false)
    """
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No configuration data provided'}), 400
    
    merge = request.args.get('merge', 'true').lower() == 'true'
    skip_servers = request.args.get('skip_servers', 'false').lower() == 'true'
    skip_settings = request.args.get('skip_settings', 'false').lower() == 'true'
    skip_ssh_keys = request.args.get('skip_ssh_keys', 'false').lower() == 'true'
    skip_alerts = request.args.get('skip_alerts', 'false').lower() == 'true'
    
    results = {
        'servers': {'imported': 0, 'updated': 0, 'skipped': 0},
        'settings': {'imported': 0, 'updated': 0},
        'ssh_keys': {'imported': 0, 'updated': 0, 'skipped': 0},
        'alert_rules': {'imported': 0, 'updated': 0},
        'errors': []
    }
    
    try:
        # Import SSH keys first (servers may reference them)
        if not skip_ssh_keys and 'ssh_keys' in data:
            for key_data in data['ssh_keys']:
                try:
                    existing = SSHKey.query.filter_by(name=key_data['name']).first()
                    if existing:
                        if merge and 'key_content' in key_data:
                            existing.key_content = key_data['key_content']
                            existing.fingerprint = SSHKey.get_fingerprint(key_data['key_content'])
                            results['ssh_keys']['updated'] += 1
                        else:
                            results['ssh_keys']['skipped'] += 1
                    elif 'key_content' in key_data:
                        new_key = SSHKey(
                            name=key_data['name'],
                            key_content=key_data['key_content'],
                            fingerprint=SSHKey.get_fingerprint(key_data['key_content'])
                        )
                        db.session.add(new_key)
                        results['ssh_keys']['imported'] += 1
                    else:
                        results['ssh_keys']['skipped'] += 1
                except Exception as e:
                    results['errors'].append(f"SSH key {key_data.get('name')}: {str(e)}")
        
        # Import servers
        if not skip_servers and 'servers' in data:
            for server_data in data['servers']:
                try:
                    bmc_ip = server_data.get('bmc_ip')
                    name = server_data.get('name')
                    if not bmc_ip or not name:
                        results['errors'].append(f"Server missing bmc_ip or name: {server_data}")
                        continue
                    
                    existing = Server.query.filter_by(bmc_ip=bmc_ip).first()
                    if existing:
                        if merge:
                            existing.server_name = name
                            existing.server_ip = server_data.get('server_ip')
                            existing.public_ip = server_data.get('public_ip')
                            existing.notes = server_data.get('notes')
                            existing.enabled = server_data.get('enabled', True)
                            results['servers']['updated'] += 1
                        else:
                            results['servers']['skipped'] += 1
                    else:
                        new_server = Server(
                            bmc_ip=bmc_ip,
                            server_name=name,
                            server_ip=server_data.get('server_ip'),
                            public_ip=server_data.get('public_ip'),
                            notes=server_data.get('notes'),
                            enabled=server_data.get('enabled', True)
                        )
                        db.session.add(new_server)
                        results['servers']['imported'] += 1
                    
                    # Handle per-server config
                    if any(k in server_data for k in ['ipmi_user', 'ipmi_pass', 'ssh_user', 'ssh_pass', 'ssh_key_name']):
                        config = ServerConfig.query.filter_by(bmc_ip=bmc_ip).first()
                        if not config:
                            config = ServerConfig(bmc_ip=bmc_ip)
                            db.session.add(config)
                        
                        if 'ipmi_user' in server_data:
                            config.ipmi_user = server_data['ipmi_user']
                        if 'ipmi_pass' in server_data:
                            config.ipmi_pass = server_data['ipmi_pass']
                        if 'ssh_user' in server_data:
                            config.ssh_user = server_data['ssh_user']
                        if 'ssh_pass' in server_data:
                            config.ssh_pass = server_data['ssh_pass']
                        if 'ssh_key_name' in server_data:
                            ssh_key = SSHKey.query.filter_by(name=server_data['ssh_key_name']).first()
                            if ssh_key:
                                config.ssh_key_id = ssh_key.id
                                
                except Exception as e:
                    results['errors'].append(f"Server {server_data.get('bmc_ip')}: {str(e)}")
        
        # Import settings
        if not skip_settings and 'settings' in data:
            for key, value in data['settings'].items():
                try:
                    SystemSettings.set(key, value)
                    results['settings']['imported'] += 1
                except Exception as e:
                    results['errors'].append(f"Setting {key}: {str(e)}")
        
        # Import alert rules
        if not skip_alerts and 'alert_rules' in data:
            for rule_data in data['alert_rules']:
                try:
                    existing = AlertRule.query.filter_by(name=rule_data['name']).first()
                    if existing:
                        if merge:
                            existing.description = rule_data.get('description')
                            existing.event_pattern = rule_data.get('event_pattern')
                            existing.severity = rule_data.get('severity')
                            existing.enabled = rule_data.get('enabled', True)
                            existing.notification_channels = rule_data.get('notification_channels')
                            results['alert_rules']['updated'] += 1
                    else:
                        new_rule = AlertRule(
                            name=rule_data['name'],
                            description=rule_data.get('description'),
                            event_pattern=rule_data.get('event_pattern'),
                            severity=rule_data.get('severity'),
                            enabled=rule_data.get('enabled', True),
                            notification_channels=rule_data.get('notification_channels')
                        )
                        db.session.add(new_rule)
                        results['alert_rules']['imported'] += 1
                except Exception as e:
                    results['errors'].append(f"Alert rule {rule_data.get('name')}: {str(e)}")
        
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Configuration imported successfully',
            'results': results
        })
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Config import failed: {e}")
        return jsonify({'error': str(e), 'results': results}), 500


@app.route('/api/config/backup-to-cloud', methods=['POST'])
@admin_required
def api_backup_to_cloud():
    """
    Backup configuration to cloud (requires AI subscription).
    
    Stores encrypted backup linked to WordPress account.
    """
    config = CloudSync.get_config()
    
    if not config.sync_enabled or not config.license_key:
        return jsonify({
            'error': 'Cloud backup requires an active AI subscription',
            'upgrade_url': 'https://cryptolabs.co.za/ipmi-monitor'
        }), 400
    
    try:
        # Get full config (with secrets for cloud backup)
        # We include secrets because they're encrypted in transit
        servers = Server.query.all()
        ssh_keys = SSHKey.query.all()
        settings = SystemSettings.query.all()
        alerts = AlertRule.query.all()
        
        backup_data = {
            'backup_version': '1.0',
            'backed_up_at': datetime.utcnow().isoformat(),
            'servers': [{
                'name': s.server_name,
                'bmc_ip': s.bmc_ip,
                'server_ip': s.server_ip,
                'public_ip': s.public_ip,
                'enabled': s.enabled,
                'notes': s.notes,
            } for s in servers],
            'settings': {s.key: s.value for s in settings},
            'ssh_keys': [{
                'name': k.name,
                'key_content': k.key_content,
                'fingerprint': k.fingerprint
            } for k in ssh_keys],
            'alert_rules': [{
                'name': a.name,
                'description': a.description,
                'event_pattern': a.event_pattern,
                'severity': a.severity,
                'enabled': a.enabled,
            } for a in alerts],
        }
        
        # Add per-server configs
        for server_data in backup_data['servers']:
            server_config = ServerConfig.query.filter_by(bmc_ip=server_data['bmc_ip']).first()
            if server_config:
                server_data['config'] = {
                    'ipmi_user': server_config.ipmi_user,
                    'ipmi_pass': server_config.ipmi_pass,
                    'ssh_user': server_config.ssh_user,
                    'ssh_pass': server_config.ssh_pass,
                    'ssh_key_id': server_config.ssh_key_id,
                }
        
        # Send to AI service
        response = requests.post(
            f"{config.AI_SERVICE_URL}/api/v1/backup",
            json={'backup': backup_data},
            headers={'Authorization': f'Bearer {config.license_key}'},
            timeout=30
        )
        
        if response.ok:
            result = response.json()
            return jsonify({
                'status': 'success',
                'message': 'Configuration backed up to cloud',
                'backup_id': result.get('backup_id'),
                'backed_up_at': backup_data['backed_up_at']
            })
        else:
            return jsonify({
                'error': f'Cloud backup failed: {response.text}'
            }), response.status_code
            
    except Exception as e:
        app.logger.error(f"Cloud backup failed: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/config/restore-from-cloud', methods=['POST'])
@admin_required
def api_restore_from_cloud():
    """
    Restore configuration from cloud backup.
    
    Query params:
    - backup_id: Specific backup to restore (default: latest)
    """
    config = CloudSync.get_config()
    
    if not config.sync_enabled or not config.license_key:
        return jsonify({
            'error': 'Cloud restore requires an active AI subscription',
            'upgrade_url': 'https://cryptolabs.co.za/ipmi-monitor'
        }), 400
    
    backup_id = request.args.get('backup_id', 'latest')
    
    try:
        # Fetch backup from AI service
        response = requests.get(
            f"{config.AI_SERVICE_URL}/api/v1/backup/{backup_id}",
            headers={'Authorization': f'Bearer {config.license_key}'},
            timeout=30
        )
        
        if not response.ok:
            return jsonify({
                'error': f'Failed to fetch backup: {response.text}'
            }), response.status_code
        
        backup_data = response.json().get('backup')
        if not backup_data:
            return jsonify({'error': 'No backup data returned'}), 404
        
        # Use the import function with the backup data
        # Simulate a request to our import endpoint
        with app.test_request_context(
            '/api/config/import?merge=true',
            method='POST',
            json=backup_data,
            headers={'Authorization': request.headers.get('Authorization')}
        ):
            # Re-use import logic
            pass  # This would be complex, let's just do it inline
        
        # Actually import the data
        results = {'imported': 0, 'errors': []}
        
        # Import SSH keys first
        for key_data in backup_data.get('ssh_keys', []):
            try:
                existing = SSHKey.query.filter_by(name=key_data['name']).first()
                if not existing and 'key_content' in key_data:
                    new_key = SSHKey(
                        name=key_data['name'],
                        key_content=key_data['key_content'],
                        fingerprint=key_data.get('fingerprint') or SSHKey.get_fingerprint(key_data['key_content'])
                    )
                    db.session.add(new_key)
                    results['imported'] += 1
            except Exception as e:
                results['errors'].append(f"SSH key {key_data.get('name')}: {e}")
        
        # Import servers
        for server_data in backup_data.get('servers', []):
            try:
                existing = Server.query.filter_by(bmc_ip=server_data['bmc_ip']).first()
                if not existing:
                    new_server = Server(
                        bmc_ip=server_data['bmc_ip'],
                        server_name=server_data['name'],
                        server_ip=server_data.get('server_ip'),
                        notes=server_data.get('notes'),
                        enabled=server_data.get('enabled', True)
                    )
                    db.session.add(new_server)
                    results['imported'] += 1
                
                # Import server config
                if 'config' in server_data:
                    cfg = server_data['config']
                    config_obj = ServerConfig.query.filter_by(bmc_ip=server_data['bmc_ip']).first()
                    if not config_obj:
                        config_obj = ServerConfig(bmc_ip=server_data['bmc_ip'])
                        db.session.add(config_obj)
                    config_obj.ipmi_user = cfg.get('ipmi_user')
                    config_obj.ipmi_pass = cfg.get('ipmi_pass')
                    config_obj.ssh_user = cfg.get('ssh_user')
                    config_obj.ssh_pass = cfg.get('ssh_pass')
                    if cfg.get('ssh_key_id'):
                        config_obj.ssh_key_id = cfg['ssh_key_id']
            except Exception as e:
                results['errors'].append(f"Server {server_data.get('bmc_ip')}: {e}")
        
        # Import settings
        for key, value in backup_data.get('settings', {}).items():
            try:
                SystemSettings.set(key, value)
                results['imported'] += 1
            except Exception as e:
                results['errors'].append(f"Setting {key}: {e}")
        
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'message': 'Configuration restored from cloud backup',
            'backup_id': backup_id,
            'backed_up_at': backup_data.get('backed_up_at'),
            'results': results
        })
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Cloud restore failed: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/config/cloud-backups', methods=['GET'])
@admin_required
def api_list_cloud_backups():
    """List available cloud backups"""
    config = CloudSync.get_config()
    
    if not config.sync_enabled or not config.license_key:
        return jsonify({
            'error': 'Cloud backups require an active AI subscription',
            'backups': []
        }), 400
    
    try:
        response = requests.get(
            f"{config.AI_SERVICE_URL}/api/v1/backups",
            headers={'Authorization': f'Bearer {config.license_key}'},
            timeout=30
        )
        
        if response.ok:
            return jsonify(response.json())
        else:
            return jsonify({'error': response.text, 'backups': []}), response.status_code
            
    except Exception as e:
        return jsonify({'error': str(e), 'backups': []}), 500


# Global error handlers
@app.errorhandler(404)
def not_found_error(error):
    """Handle 404 errors"""
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Resource not found'}), 404
    return render_template('login.html', error='Page not found'), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    db.session.rollback()
    app.logger.error(f"Internal server error: {error}")
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Internal server error'}), 500
    return render_template('login.html', error='Internal server error'), 500

@app.errorhandler(Exception)
def handle_exception(e):
    """Handle uncaught exceptions"""
    app.logger.exception(f"Unhandled exception: {e}")
    db.session.rollback()
    if request.path.startswith('/api/'):
        return jsonify({'error': 'An unexpected error occurred'}), 500
    return render_template('login.html', error='An unexpected error occurred'), 500

# Initialize database with lock to prevent race conditions
import fcntl

def _run_migrations(inspector):
    """Run database migrations for new columns and tables"""
    from sqlalchemy import text
    
    def execute_sql(sql):
        """Execute SQL in a way compatible with both SQLAlchemy 1.x and 2.x"""
        try:
            # SQLAlchemy 2.x style
            with db.engine.connect() as conn:
                conn.execute(text(sql))
                conn.commit()
        except Exception:
            # Fallback for older versions
            db.session.execute(text(sql))
            db.session.commit()
    
    try:
        existing_tables = inspector.get_table_names()
        
        # Migration 1: Add ssh_key table
        if 'ssh_key' not in existing_tables:
            app.logger.info("Migration: Creating ssh_key table...")
            execute_sql('''
                CREATE TABLE IF NOT EXISTS ssh_key (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name VARCHAR(50) NOT NULL UNIQUE,
                    key_content TEXT NOT NULL,
                    fingerprint VARCHAR(100),
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            app.logger.info("Migration: ssh_key table created")
        
        # Migration 2: Add ssh_key_id column to server_config
        if 'server_config' in existing_tables:
            columns = [c['name'] for c in inspector.get_columns('server_config')]
            if 'ssh_key_id' not in columns:
                app.logger.info("Migration: Adding ssh_key_id to server_config...")
                execute_sql('ALTER TABLE server_config ADD COLUMN ssh_key_id INTEGER')
                app.logger.info("Migration: ssh_key_id column added")
        
        # Migration 3: Add pcie_health columns to server_inventory
        if 'server_inventory' in existing_tables:
            columns = [c['name'] for c in inspector.get_columns('server_inventory')]
            if 'pcie_health' not in columns:
                app.logger.info("Migration: Adding pcie_health to server_inventory...")
                execute_sql('ALTER TABLE server_inventory ADD COLUMN pcie_health TEXT')
                app.logger.info("Migration: pcie_health column added")
            if 'pcie_errors_count' not in columns:
                app.logger.info("Migration: Adding pcie_errors_count to server_inventory...")
                execute_sql('ALTER TABLE server_inventory ADD COLUMN pcie_errors_count INTEGER DEFAULT 0')
                app.logger.info("Migration: pcie_errors_count column added")
        
        # Migration 4: Add public_ip column to server table
        if 'server' in existing_tables:
            columns = [c['name'] for c in inspector.get_columns('server')]
            if 'public_ip' not in columns:
                app.logger.info("Migration: Adding public_ip to server...")
                execute_sql('ALTER TABLE server ADD COLUMN public_ip VARCHAR(45)')
                app.logger.info("Migration: public_ip column added")
        
        # Migration 5: Add nic_info and nic_count columns to server_inventory
        if 'server_inventory' in existing_tables:
            columns = [c['name'] for c in inspector.get_columns('server_inventory')]
            if 'nic_info' not in columns:
                app.logger.info("Migration: Adding nic_info to server_inventory...")
                execute_sql('ALTER TABLE server_inventory ADD COLUMN nic_info TEXT')
                app.logger.info("Migration: nic_info column added")
            if 'nic_count' not in columns:
                app.logger.info("Migration: Adding nic_count to server_inventory...")
                execute_sql('ALTER TABLE server_inventory ADD COLUMN nic_count INTEGER')
                app.logger.info("Migration: nic_count column added")
        
        app.logger.info("Migrations complete")
    except Exception as e:
        app.logger.warning(f"Migration warning (may already be applied): {e}")


def init_db():
    with app.app_context():
        # Use file lock to prevent multiple workers from creating tables simultaneously
        lock_file = os.path.join(app.config.get('DATA_DIR', '/app/data'), '.db.lock')
        os.makedirs(os.path.dirname(lock_file), exist_ok=True)
        
        try:
            with open(lock_file, 'w') as f:
                fcntl.flock(f, fcntl.LOCK_EX)
                try:
                    # Check if tables exist before creating
                    inspector = db.inspect(db.engine)
                    existing_tables = inspector.get_table_names()
                    
                    if 'server' not in existing_tables:
                        db.create_all()
                        app.logger.info("Database tables created")
                    else:
                        app.logger.info("Database tables already exist")
                        # Run migrations for new columns/tables
                        _run_migrations(inspector)
                    
                    # Initialize default alert rules
                    initialize_default_alerts()
                    # Initialize default admin user (admin/admin)
                    User.initialize_default()
                    # Initialize default system settings
                    SystemSettings.initialize_defaults()
                    
                    app.logger.info("Database initialized")
                    
                    # Check if this is a fresh database (no servers)
                    server_count = Server.query.count()
                    if server_count == 0:
                        print("=" * 60, flush=True)
                        print("⚠️  WARNING: No servers configured!", flush=True)
                        print("   If you expected existing data, check your volume mounts.", flush=True)
                        print("   ", flush=True)
                        print("   Recommended: Use docker-compose with named volumes:", flush=True)
                        print("     volumes:", flush=True)
                        print("       - ipmi_data:/app/data", flush=True)
                        print("   ", flush=True)
                        print("   Or with docker run:", flush=True)
                        print("     -v ipmi_data:/app/data", flush=True)
                        print("=" * 60, flush=True)
                finally:
                    fcntl.flock(f, fcntl.LOCK_UN)
        except Exception as e:
            app.logger.warning(f"Database init (may be concurrent): {e}")
            # Tables likely already exist from another worker
            try:
                initialize_default_alerts()
                User.initialize_default()
                SystemSettings.initialize_defaults()
            except:
                pass

# Initialize on import (for gunicorn)
init_db()


def auto_load_servers_config():
    """
    Auto-load servers from config file on startup.
    
    This allows users to mount a servers.yaml/json/csv file and have
    servers automatically imported on first run.
    """
    with app.app_context():
        try:
            # Skip if we already have servers
            if Server.query.first():
                app.logger.info("📋 Servers already configured, skipping config file auto-load")
                return
            
            # Try to load from config file
            servers = load_servers_from_config_file()
            
            if servers:
                result = import_servers_to_database(servers)
                app.logger.info(f"✅ Auto-loaded servers: {result['added']} added, {result['updated']} updated")
                
                if result['errors']:
                    for err in result['errors']:
                        app.logger.warning(f"⚠️ Server import error: {err}")
            else:
                app.logger.info("📂 No servers config file found at startup")
                
        except Exception as e:
            app.logger.error(f"❌ Error auto-loading servers: {e}")


# Auto-load servers from config file
auto_load_servers_config()

# Start background collector thread
collector_thread = threading.Thread(target=background_collector, daemon=True)
collector_thread.start()

if __name__ == '__main__':
    # Run Flask app directly (for development)
    app.run(host='0.0.0.0', port=5000, debug=False)

