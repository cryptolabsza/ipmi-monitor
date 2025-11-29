#!/usr/bin/env python3
"""
BrickBox IPMI/BMC Event Monitor
A Flask-based dashboard for monitoring IPMI SEL logs across all servers
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
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'brickbox-ipmi-monitor-secret-key-change-me')
db = SQLAlchemy(app)

# Configuration
IPMI_USER = os.environ.get('IPMI_USER', 'admin')
IPMI_PASS = os.environ.get('IPMI_PASS', 'BBccc321')
IPMI_PASS_NVIDIA = os.environ.get('IPMI_PASS_NVIDIA', 'BBccc321BBccc321')  # NVIDIA BMCs need 16 chars
POLL_INTERVAL = int(os.environ.get('POLL_INTERVAL', 300))  # 5 minutes

# Admin authentication
ADMIN_USER = os.environ.get('ADMIN_USER', 'admin')
ADMIN_PASS = os.environ.get('ADMIN_PASS', 'brickbox')  # Change this!

def admin_required(f):
    """Decorator to require admin login for a route"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            if request.is_json:
                return jsonify({'error': 'Admin authentication required'}), 401
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def is_admin():
    """Check if current user is admin"""
    return session.get('admin_logged_in', False)

# NVIDIA BMCs (require 16-char password)
NVIDIA_BMCS = {'88.0.98.0', '88.0.99.0'}

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

# Default server inventory - will be migrated to database
DEFAULT_SERVERS = {
    '88.0.1.0': 'brickbox-01',
    '88.0.2.0': 'brickbox-02',
    '88.0.3.0': 'brickbox-03',
    '88.0.5.0': 'brickbox-05',
    '88.0.6.0': 'brickbox-06',
    '88.0.7.0': 'brickbox-07',
    '88.0.8.0': 'brickbox-08',
    '88.0.9.0': 'brickbox-09',
    '88.0.10.0': 'brickbox-10',
    '88.0.11.0': 'brickbox-11',
    '88.0.25.0': 'brickbox-25',
    '88.0.26.0': 'brickbox-26',
    '88.0.27.0': 'brickbox-27',
    '88.0.28.0': 'brickbox-28',
    '88.0.30.0': 'brickbox-30',
    '88.0.31.0': 'brickbox-31',
    '88.0.32.0': 'brickbox-32',
    '88.0.33.0': 'brickbox-33',
    '88.0.34.0': 'brickbox-34',
    '88.0.35.0': 'brickbox-35',
    '88.0.36.0': 'brickbox-36',
    '88.0.37.0': 'brickbox-37',
    '88.0.38.0': 'brickbox-38',
    '88.0.39.0': 'brickbox-39',
    '88.0.40.0': 'brickbox-40',
    '88.0.41.0': 'brickbox-41',
    '88.0.42.0': 'brickbox-42',
    '88.0.43.0': 'brickbox-43',
    '88.0.44.0': 'brickbox-44',
    '88.0.45.0': 'brickbox-45',
    '88.0.46.0': 'brickbox-46',
    '88.0.47.0': 'brickbox-47',
    '88.0.48.0': 'brickbox-48',
    '88.0.96.0': 'brickbox-96',
    '88.0.97.0': 'brickbox-97',
    '88.0.98.0': 'brickbox-98',
    '88.0.99.0': 'brickbox-99',
}

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

# Thread locks for global state
import threading as _threading
_sensor_cache_lock = _threading.Lock()
_nvidia_bmcs_lock = _threading.Lock()

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
    """Validate IP address format"""
    if not ip:
        return False
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(part) <= 255 for part in parts)
    except (ValueError, TypeError):
        return False

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

def parse_sel_line(line, bmc_ip, server_name):
    """Parse a single SEL log line with extended details for ECC events"""
    # Format: "  abc | 12/12/23 | 03:21:32 SAST | Power Supply #0x9f | Presence detected | Asserted"
    # Extended format may include: "Memory #0x53 | Correctable ECC | Asserted | DIMM_A1"
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
                except (ValueError, TypeError) as e:
                    sensor_number = sensor_id
                    app.logger.debug(f"Could not parse sensor ID {sensor_id}: {e}")
            
            # For Memory/ECC events, try to extract DIMM info
            event_direction = ''
            event_data = ''
            
            for part in remaining_parts:
                part_lower = part.lower().strip()
                if 'asserted' in part_lower:
                    event_direction = 'Asserted'
                elif 'deasserted' in part_lower:
                    event_direction = 'Deasserted'
                # Look for DIMM identifiers
                if 'dimm' in part_lower or part.startswith('DIMM') or re.match(r'^[A-Z]\d+$', part.strip()):
                    event_data = part.strip()
            
            # Enhance event description - always show sensor ID for identification
            enhanced_desc = event_desc
            if sensor_id:
                # Use the actual sensor name if available (e.g., CPU1_ECC1)
                if sensor_name_lookup:
                    enhanced_desc = f"{event_desc} [{sensor_name_lookup}]"
                else:
                    enhanced_desc = f"{event_desc} [Sensor {sensor_number}]"
            
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
                event_data=event_data,
                severity=severity,
                raw_entry=line
            )
    except Exception as e:
        app.logger.error(f"Failed to parse SEL line: {line} - {e}")
    return None

def get_ipmi_credentials(bmc_ip):
    """Get IPMI credentials for a BMC (per-server config or defaults)"""
    with app.app_context():
        config = ServerConfig.query.filter_by(bmc_ip=bmc_ip).first()
        if config and config.ipmi_user and config.ipmi_pass:
            return config.ipmi_user, config.ipmi_pass
    
    # Fall back to defaults
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

def collect_ipmi_sel(bmc_ip, server_name):
    """Collect IPMI SEL from a single server using extended list for more details"""
    try:
        user, password = get_ipmi_credentials(bmc_ip)
        
        # Try elist first for more details (includes sensor numbers)
        # Allow 600 seconds (10 min) for large SEL logs - some BMCs are very slow
        result = subprocess.run(
            ['ipmitool', '-I', 'lanplus', '-H', bmc_ip, 
             '-U', user, '-P', password, 'sel', 'elist'],
            capture_output=True, text=True, timeout=600
        )
        
        # Fall back to regular list if elist fails
        if result.returncode != 0:
            result = subprocess.run(
                ['ipmitool', '-I', 'lanplus', '-H', bmc_ip, 
                 '-U', user, '-P', password, 'sel', 'list'],
                capture_output=True, text=True, timeout=600
            )
        
        if result.returncode != 0:
            app.logger.warning(f"IPMI command failed for {bmc_ip}: {result.stderr}")
            return []
        
        events = []
        for line in result.stdout.strip().split('\n'):
            if line.strip():
                event = parse_sel_line(line, bmc_ip, server_name)
                if event:
                    events.append(event)
        
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
        result = subprocess.run(
            ['ipmitool', '-I', 'lanplus', '-H', bmc_ip,
             '-U', user, '-P', password, 'sensor', 'list'],
            capture_output=True, text=True, timeout=30
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

def background_collector():
    """Background thread for periodic collection with graceful shutdown"""
    app.logger.info(f"Background collector started (interval: {POLL_INTERVAL}s)")
    while not _shutdown_event.is_set():
        try:
            collect_all_events()
        except Exception as e:
            app.logger.error(f"Error in background collector: {e}")
        
        # Wait with interruptible sleep for graceful shutdown
        _shutdown_event.wait(POLL_INTERVAL)

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
def server_detail(bmc_ip):
    """Server detail page"""
    return render_template('server_detail.html', bmc_ip=bmc_ip)

@app.route('/api/server/<bmc_ip>/events')
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
    ini_lines = ["# BrickBox IPMI Monitor - Server List", "# Format: bmc_ip = server_name", ""]
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
    """Admin login page"""
    if request.method == 'POST':
        if request.is_json:
            data = request.get_json()
            username = data.get('username')
            password = data.get('password')
        else:
            username = request.form.get('username')
            password = request.form.get('password')
        
        if username == ADMIN_USER and password == ADMIN_PASS:
            session['admin_logged_in'] = True
            session['admin_user'] = username
            
            if request.is_json:
                return jsonify({'status': 'success', 'message': 'Logged in'})
            
            next_url = request.args.get('next', url_for('dashboard'))
            return redirect(next_url)
        else:
            if request.is_json:
                return jsonify({'error': 'Invalid credentials'}), 401
            return render_template('login.html', error='Invalid username or password')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """Logout admin"""
    session.pop('admin_logged_in', None)
    session.pop('admin_user', None)
    return redirect(url_for('dashboard'))

@app.route('/api/auth/status')
def auth_status():
    """Check authentication status"""
    return jsonify({
        'is_admin': is_admin(),
        'username': session.get('admin_user')
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

# Initialize database
def init_db():
    with app.app_context():
        db.create_all()
        app.logger.info("Database initialized")

# Initialize on import (for gunicorn)
init_db()

# Start background collector thread
collector_thread = threading.Thread(target=background_collector, daemon=True)
collector_thread.start()

if __name__ == '__main__':
    # Run Flask app directly (for development)
    app.run(host='0.0.0.0', port=5000, debug=False)

