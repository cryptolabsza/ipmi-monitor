#!/usr/bin/env python3
"""
BrickBox IPMI/BMC Event Monitor
A Flask-based dashboard for monitoring IPMI SEL logs across all servers
"""

from flask import Flask, render_template, jsonify, request, Response
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from prometheus_client import Gauge, Counter, generate_latest, CONTENT_TYPE_LATEST, CollectorRegistry
import subprocess
import threading
import time
import json
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ipmi_events.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Configuration
IPMI_USER = os.environ.get('IPMI_USER', 'admin')
IPMI_PASS = os.environ.get('IPMI_PASS', 'BBccc321')
IPMI_PASS_NVIDIA = os.environ.get('IPMI_PASS_NVIDIA', 'BBccc321BBccc321')  # NVIDIA BMCs need 16 chars
POLL_INTERVAL = int(os.environ.get('POLL_INTERVAL', 300))  # 5 minutes

# NVIDIA BMCs (require 16-char password)
NVIDIA_BMCS = {'88.0.98.0', '88.0.99.0'}

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
        except:
            pass
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

# Helper functions
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
            
            # Extract sensor number from hex ID for DIMM identification
            sensor_number = ''
            if sensor_id:
                try:
                    sensor_num = int(sensor_id.replace('#', ''), 16)
                    sensor_number = f"Sensor {sensor_num}"
                except:
                    sensor_number = sensor_id
            
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
            
            # Enhance event description for Memory/ECC events
            enhanced_desc = event_desc
            if 'memory' in sensor_type.lower() or 'ecc' in event_desc.lower():
                if sensor_number and 'Sensor' in sensor_number:
                    # Try to map sensor number to DIMM slot
                    # This is vendor-specific, but we can show the sensor number
                    if not event_data:
                        event_data = sensor_number
                if event_data:
                    enhanced_desc = f"{event_desc} [{event_data}]"
            
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

def collect_ipmi_sel(bmc_ip, server_name):
    """Collect IPMI SEL from a single server using extended list for more details"""
    try:
        user, password = get_ipmi_credentials(bmc_ip)
        
        # Try elist first for more details (includes sensor numbers)
        result = subprocess.run(
            ['ipmitool', '-I', 'lanplus', '-H', bmc_ip, 
             '-U', user, '-P', password, 'sel', 'elist'],
            capture_output=True, text=True, timeout=30
        )
        
        # Fall back to regular list if elist fails
        if result.returncode != 0:
            result = subprocess.run(
                ['ipmitool', '-I', 'lanplus', '-H', bmc_ip, 
                 '-U', user, '-P', password, 'sel', 'list'],
                capture_output=True, text=True, timeout=30
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

def collect_power_status(bmc_ip):
    """Get power status from BMC"""
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
    except:
        return 'Unreachable'

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
        
        # Use ThreadPoolExecutor for parallel collection (10 workers)
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {
                executor.submit(collect_single_server, bmc_ip, server_name): (bmc_ip, server_name)
                for bmc_ip, server_name in SERVERS.items()
            }
            
            for future in as_completed(futures):
                bmc_ip, server_name, events, error = future.result()
                
                if error:
                    app.logger.error(f"Error collecting from {bmc_ip}: {error}")
                    continue
                
                try:
                    for event in events:
                        # Check if event already exists
                        existing = IPMIEvent.query.filter_by(
                            bmc_ip=event.bmc_ip, 
                            sel_id=event.sel_id
                        ).first()
                        
                        if not existing:
                            db.session.add(event)
                    
                    db.session.commit()
                    update_server_status(bmc_ip, server_name)
                    app.logger.info(f"Collected {len(events)} events from {server_name}")
                    
                except Exception as e:
                    app.logger.error(f"Error processing {bmc_ip}: {e}")
                    db.session.rollback()
        
        app.logger.info("IPMI event collection complete")

def background_collector():
    """Background thread for periodic collection"""
    while True:
        collect_all_events()
        time.sleep(POLL_INTERVAL)

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
    threading.Thread(target=collect_all_events).start()
    return jsonify({'status': 'Collection started'})

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
def api_clear_sel(bmc_ip):
    """Clear SEL log on a specific BMC"""
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
def api_clear_all_sel():
    """Clear SEL logs on all BMCs"""
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
def api_clear_db_events(bmc_ip):
    """Clear events from database only (don't touch BMC SEL)"""
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
    
    # Per-server metrics
    servers = ServerStatus.query.all()
    for s in servers:
        labels = {'bmc_ip': s.bmc_ip, 'server_name': s.server_name}
        prom_server_reachable.labels(**labels).set(1 if s.is_reachable else 0)
        prom_server_power_on.labels(**labels).set(1 if s.power_status and 'on' in s.power_status.lower() else 0)
        prom_events_total.labels(**labels).set(s.total_events or 0)
        prom_events_critical_24h.labels(**labels).set(s.critical_events_24h or 0)
        prom_events_warning_24h.labels(**labels).set(s.warning_events_24h or 0)
    
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
def api_add_server():
    """Add a new server to monitor"""
    data = request.get_json()
    
    bmc_ip = data.get('bmc_ip')
    server_name = data.get('server_name')
    
    if not bmc_ip or not server_name:
        return jsonify({'error': 'bmc_ip and server_name are required'}), 400
    
    # Check if already exists
    existing = Server.query.filter_by(bmc_ip=bmc_ip).first()
    if existing:
        return jsonify({'error': f'Server with BMC IP {bmc_ip} already exists'}), 409
    
    server = Server(
        bmc_ip=bmc_ip,
        server_name=server_name,
        server_ip=data.get('server_ip', bmc_ip.replace('.0', '.1')),
        enabled=data.get('enabled', True),
        use_nvidia_password=data.get('use_nvidia_password', False),
        notes=data.get('notes', '')
    )
    
    db.session.add(server)
    db.session.commit()
    
    # Also update NVIDIA_BMCS set if needed
    if server.use_nvidia_password:
        NVIDIA_BMCS.add(bmc_ip)
    
    return jsonify({'status': 'success', 'message': f'Added server {server_name} ({bmc_ip})', 'id': server.id})

@app.route('/api/servers/<bmc_ip>', methods=['GET', 'PUT', 'DELETE'])
def api_manage_server(bmc_ip):
    """Get, update, or delete a server"""
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
            if data['use_nvidia_password']:
                NVIDIA_BMCS.add(bmc_ip)
            else:
                NVIDIA_BMCS.discard(bmc_ip)
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
def api_import_servers():
    """Import servers from INI format or JSON"""
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
def api_init_from_defaults():
    """Initialize database with default servers"""
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
    """Get or update server configuration"""
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
def api_config_bulk():
    """Bulk update server configurations"""
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

# ============== Settings Page ==============

@app.route('/settings')
def settings_page():
    """Server configuration page"""
    return render_template('settings.html')

@app.route('/metrics')
def prometheus_metrics():
    """Prometheus metrics endpoint"""
    update_prometheus_metrics()
    return Response(generate_latest(PROM_REGISTRY), mimetype=CONTENT_TYPE_LATEST)

@app.route('/health')
def health_check():
    """Health check endpoint for container orchestration"""
    return jsonify({'status': 'healthy', 'timestamp': datetime.utcnow().isoformat()})

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

