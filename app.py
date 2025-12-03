#!/usr/bin/env python3
"""
IPMI/BMC Event Monitor
A Flask-based dashboard for monitoring IPMI SEL logs across all servers

GitHub: https://github.com/jjziets/ipmi-monitor
License: MIT
"""

from flask import Flask, render_template, jsonify, request, Response, session, redirect, url_for
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
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ipmi_events.db'
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

def login_required(f):
    """Decorator to require any logged-in user (admin or readonly)"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            if is_api_request():
                return jsonify({'error': 'Authentication required'}), 401
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def login_required(f):
    """Decorator to require any login (admin or readonly)"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            # Check if anonymous access is allowed
            if allow_anonymous_read():
                return f(*args, **kwargs)
            if is_api_request():
                return jsonify({'error': 'Authentication required'}), 401
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def is_admin():
    """Check if current user is admin"""
    return session.get('logged_in') and session.get('user_role') == 'admin'

def is_logged_in():
    """Check if user is logged in (any role)"""
    return session.get('logged_in', False)

def can_view():
    """Check if current user/visitor can view data (logged in OR anonymous allowed)"""
    if session.get('logged_in'):
        return True
    return allow_anonymous_read()

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

def get_servers():
    """Get servers from database, fallback to defaults"""
    with app.app_context():
        try:
            servers = Server.query.filter_by(enabled=True).all()
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
    bmc_ip = db.Column(db.String(20), nullable=False, unique=True)
    server_name = db.Column(db.String(50), nullable=False)
    server_ip = db.Column(db.String(20))  # OS IP (usually .1)
    enabled = db.Column(db.Boolean, default=True)
    use_nvidia_password = db.Column(db.Boolean, default=False)  # Needs 16-char password
    protocol = db.Column(db.String(20), default='auto')  # 'auto', 'ipmi', 'redfish'
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

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

class ServerConfig(db.Model):
    """Per-server configuration (IPMI credentials, SSH keys)"""
    id = db.Column(db.Integer, primary_key=True)
    bmc_ip = db.Column(db.String(20), nullable=False, unique=True)
    server_name = db.Column(db.String(50), nullable=False)
    server_ip = db.Column(db.String(20))  # OS IP (usually .1 instead of .0)
    ipmi_user = db.Column(db.String(50))
    ipmi_pass = db.Column(db.String(100))
    ssh_user = db.Column(db.String(50), default='root')
    ssh_key = db.Column(db.Text)  # Private key content
    ssh_port = db.Column(db.Integer, default=22)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

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
    """User accounts with role-based access"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False, unique=True)
    password_hash = db.Column(db.String(64), nullable=False)  # SHA256 hash
    role = db.Column(db.String(20), nullable=False, default='readonly')  # admin, readonly
    enabled = db.Column(db.Boolean, default=True)
    password_changed = db.Column(db.Boolean, default=False)  # True after first password change
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
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
    subscription_tier = db.Column(db.String(50), nullable=True)  # 'free', 'starter', etc.
    subscription_valid = db.Column(db.Boolean, default=False)
    max_servers = db.Column(db.Integer, default=50)
    features = db.Column(db.Text, nullable=True)  # JSON array of enabled features
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # AI Service endpoint - hardcoded for now, can be made configurable later
    AI_SERVICE_URL = os.environ.get('AI_SERVICE_URL', '')  # Set to your AI service endpoint
    
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
            'last_sync': self.last_sync.isoformat() if self.last_sync else None,
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


def sync_to_cloud():
    """
    Sync data to CryptoLabs AI service.
    Called periodically by background thread.
    """
    with app.app_context():
        config = CloudSync.get_config()
        
        if not config.sync_enabled or not config.license_key:
            return {'success': False, 'message': 'Sync not enabled'}
        
        try:
            # Collect data to sync
            servers = Server.query.all()
            
            # Get recent events (last 24 hours)
            cutoff = datetime.utcnow() - timedelta(hours=24)
            events = IPMIEvent.query.filter(IPMIEvent.event_date > cutoff).all()
            
            # Get latest sensor readings
            sensors = SensorReading.query.all()
            
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
                } for s in sensors]
            }
            
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
        
        # Use ThreadPoolExecutor for parallel collection (10 workers)
        try:
            with ThreadPoolExecutor(max_workers=10) as executor:
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


def background_collector():
    """Background thread for periodic collection with graceful shutdown"""
    print(f"[IPMI Monitor] Background collector started (SEL interval: {POLL_INTERVAL}s, sensor multiplier: {SENSOR_POLL_MULTIPLIER}x)", flush=True)
    print(f"[IPMI Monitor] Data retention: {DATA_RETENTION_DAYS} days (FREE tier limit)", flush=True)
    
    # Track when to collect sensors and run cleanup
    collection_count = 0
    cleanup_counter = 0
    cleanup_interval_cycles = (CLEANUP_INTERVAL_HOURS * 3600) // POLL_INTERVAL  # How many cycles between cleanups
    
    while not _shutdown_event.is_set():
        try:
            print(f"[IPMI Monitor] Starting collection cycle...", flush=True)
            # Always collect SEL events
            collect_all_events()
            
            # Collect sensors based on multiplier (1 = every cycle, 2 = every 2nd, etc.)
            collection_count += 1
            if collection_count >= SENSOR_POLL_MULTIPLIER:
                collection_count = 0
                try:
                    print(f"[IPMI Monitor] Starting sensor collection...", flush=True)
                    collect_all_sensors_background()
                except Exception as e:
                    print(f"[IPMI Monitor] Error collecting sensors: {e}", flush=True)
            
            # Run data cleanup periodically
            cleanup_counter += 1
            if cleanup_counter >= cleanup_interval_cycles:
                cleanup_counter = 0
                try:
                    cleanup_old_data()
                except Exception as e:
                    print(f"[IPMI Monitor] Error in data cleanup: {e}", flush=True)
            
            # Auto-sync to AI service if enabled (every collection cycle)
            try:
                auto_sync_to_cloud()
            except Exception as e:
                print(f"[IPMI Monitor] Auto-sync error: {e}", flush=True)
            
            print(f"[IPMI Monitor] Collection cycle complete. Next in {POLL_INTERVAL}s", flush=True)
                    
        except Exception as e:
            print(f"[IPMI Monitor] Error in background collector: {e}", flush=True)
        
        # Wait with interruptible sleep for graceful shutdown
        _shutdown_event.wait(POLL_INTERVAL)

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
            with ThreadPoolExecutor(max_workers=10) as executor:
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
def dashboard():
    """Main dashboard"""
    return render_template('dashboard.html')

@app.route('/api/servers')
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
        query = query.filter_by(bmc_ip=server)
    
    cutoff = datetime.utcnow() - timedelta(hours=hours)
    query = query.filter(IPMIEvent.event_date >= cutoff)
    
    events = query.order_by(IPMIEvent.event_date.desc()).limit(limit).all()
    
    return jsonify([{
        'id': e.id,
        'bmc_ip': e.bmc_ip,
        'server_name': e.server_name,
        'sel_id': e.sel_id,
        'event_date': e.event_date.isoformat(),
        'sensor_type': e.sensor_type,
        'event_description': e.event_description,
        'severity': e.severity
    } for e in events])

@app.route('/api/stats')
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
@require_valid_bmc_ip
def server_detail(bmc_ip):
    """Server detail page"""
    return render_template('server_detail.html', bmc_ip=bmc_ip)

@app.route('/api/server/<bmc_ip>/events')
@require_valid_bmc_ip
def api_server_events(bmc_ip):
    """Get events for a specific server"""
    limit = request.args.get('limit', 500, type=int)
    events = IPMIEvent.query.filter_by(bmc_ip=bmc_ip)\
        .order_by(IPMIEvent.event_date.desc()).limit(limit).all()
    
    return jsonify([{
        'id': e.id,
        'sel_id': e.sel_id,
        'event_date': e.event_date.isoformat(),
        'sensor_type': e.sensor_type,
        'sensor_id': e.sensor_id,
        'event_description': e.event_description,
        'severity': e.severity,
        'raw_entry': e.raw_entry
    } for e in events])

@app.route('/api/server/<bmc_ip>/clear_sel', methods=['POST'])
@admin_required
@require_valid_bmc_ip
def api_clear_sel(bmc_ip):
    """Clear SEL log on a specific BMC - Admin only"""
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

@app.route('/api/clear_all_sel', methods=['POST'])
@admin_required
def api_clear_all_sel():
    """Clear SEL logs on all BMCs - Admin only"""
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
@admin_required
@require_valid_bmc_ip
def api_clear_db_events(bmc_ip):
    """Clear events from database only - Admin only"""
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
    """Get all managed servers from database"""
    servers = Server.query.all()
    return jsonify([{
        'id': s.id,
        'bmc_ip': s.bmc_ip,
        'server_name': s.server_name,
        'server_ip': s.server_ip,
        'enabled': s.enabled,
        'use_nvidia_password': s.use_nvidia_password,
        'notes': s.notes,
        'created_at': s.created_at.isoformat() if s.created_at else None,
        'updated_at': s.updated_at.isoformat() if s.updated_at else None
    } for s in servers])

@app.route('/api/servers/add', methods=['POST'])
@admin_required
def api_add_server():
    """Add a new server to monitor - Admin only"""
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

@app.route('/api/servers/import', methods=['POST'])
@admin_required
def api_import_servers():
    """Import servers from INI format or JSON - Admin only"""
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
                existing.enabled = server_data.get('enabled', True)
                existing.use_nvidia_password = server_data.get('use_nvidia_password', False)
                existing.notes = server_data.get('notes', '')
                updated += 1
            else:
                server = Server(
                    bmc_ip=bmc_ip,
                    server_name=server_name,
                    server_ip=server_data.get('server_ip', bmc_ip.replace('.0', '.1')),
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

@app.route('/api/servers/init-from-defaults', methods=['POST'])
@admin_required
def api_init_from_defaults():
    """Initialize database with default servers - Admin only"""
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
            return jsonify({'error': 'Server not found'}), 404
        return jsonify({
            'bmc_ip': config.bmc_ip,
            'server_name': config.server_name,
            'server_ip': config.server_ip,
            'ipmi_user': config.ipmi_user,
            'has_ipmi_pass': bool(config.ipmi_pass),
            'ssh_user': config.ssh_user,
            'has_ssh_key': bool(config.ssh_key),
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
    if 'ssh_key' in data:
        config.ssh_key = data['ssh_key']
    if 'ssh_port' in data:
        config.ssh_port = data['ssh_port']
    
    db.session.commit()
    return jsonify({'status': 'success', 'message': f'Configuration updated for {bmc_ip}'})

@app.route('/api/config/bulk', methods=['POST'])
@admin_required
def api_config_bulk():
    """Bulk update server configurations - Admin only"""
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
            with ThreadPoolExecutor(max_workers=10) as executor:
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
    
    with ThreadPoolExecutor(max_workers=10) as executor:
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
@admin_required
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
@admin_required
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
@admin_required
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
@admin_required
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
@admin_required
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
@admin_required
def api_test_notification(channel_type):
    """Test a notification channel"""
    config = NotificationConfig.query.filter_by(channel_type=channel_type).first()
    
    if not config or not config.enabled:
        return jsonify({'error': 'Channel not configured or not enabled'}), 400
    
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
@admin_required
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

# ============== Settings Page ==============

@app.route('/settings')
@admin_required
def settings_page():
    """Server configuration page - Admin only"""
    return render_template('settings.html')

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
    """Check authentication status"""
    return jsonify({
        'logged_in': is_logged_in(),
        'is_admin': is_admin(),
        'username': session.get('username'),
        'role': session.get('user_role'),
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
    if role not in ['admin', 'readonly']:
        return jsonify({'error': 'Role must be admin or readonly'}), 400
    
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
        
        if 'role' in data and data['role'] in ['admin', 'readonly']:
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
            'last_sync': config.last_sync.isoformat() if config.last_sync else None,
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
    """Get AI cloud configuration"""
    config = CloudSync.get_config()
    return jsonify(config.to_dict())


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
                config.subscription_tier = validation.get('tier', 'starter')
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
@admin_required
def api_trigger_sync():
    """Manually trigger AI cloud sync"""
    result = sync_to_cloud()
    return jsonify(result)


@app.route('/api/ai/results')
def api_get_ai_results():
    """Get cached AI results"""
    if not CloudSync.is_ai_enabled():
        return jsonify({
            'enabled': False,
            'message': 'AI features not enabled. Upgrade to Starter plan for AI insights.',
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

@app.route('/api/settings/anonymous', methods=['GET'])
def api_get_anonymous_setting():
    """Get anonymous access setting (public endpoint)"""
    return jsonify({
        'allow_anonymous_read': allow_anonymous_read()
    })

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
                    
                    # Initialize default alert rules
                    initialize_default_alerts()
                    # Initialize default admin user (admin/admin)
                    User.initialize_default()
                    # Initialize default system settings
                    SystemSettings.initialize_defaults()
                    
                    app.logger.info("Database initialized")
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

# Start background collector thread
collector_thread = threading.Thread(target=background_collector, daemon=True)
collector_thread.start()

if __name__ == '__main__':
    # Run Flask app directly (for development)
    app.run(host='0.0.0.0', port=5000, debug=False)

