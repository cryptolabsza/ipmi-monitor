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

# Server inventory - BMC IPs
SERVERS = {
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

# Database Models
class IPMIEvent(db.Model):
    """IPMI SEL Event"""
    id = db.Column(db.Integer, primary_key=True)
    bmc_ip = db.Column(db.String(20), nullable=False, index=True)
    server_name = db.Column(db.String(50), nullable=False, index=True)
    sel_id = db.Column(db.String(10), nullable=False)
    event_date = db.Column(db.DateTime, nullable=False, index=True)
    sensor_type = db.Column(db.String(50), nullable=False, index=True)
    sensor_id = db.Column(db.String(20))
    event_description = db.Column(db.String(200), nullable=False)
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
    critical_events_24h = db.Column(db.Integer, default=0)
    warning_events_24h = db.Column(db.Integer, default=0)

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
    """Parse a single SEL log line"""
    # Format: "  abc | 12/12/23 | 03:21:32 SAST | Power Supply #0x9f | Presence detected | Asserted"
    try:
        parts = [p.strip() for p in line.split('|')]
        if len(parts) >= 5:
            sel_id = parts[0].strip()
            date_str = parts[1].strip()
            time_str = parts[2].strip().split()[0]  # Remove timezone
            sensor_info = parts[3].strip()
            event_desc = ' | '.join(parts[4:])
            
            # Parse date - handle both MM/DD/YY and MM/DD/YYYY
            try:
                if len(date_str.split('/')[-1]) == 2:
                    event_date = datetime.strptime(f"{date_str} {time_str}", "%m/%d/%y %H:%M:%S")
                else:
                    event_date = datetime.strptime(f"{date_str} {time_str}", "%m/%d/%Y %H:%M:%S")
            except ValueError:
                event_date = datetime.utcnow()
            
            # Extract sensor type and ID
            sensor_match = re.match(r'(.+?)\s*(#0x[a-fA-F0-9]+)?$', sensor_info)
            sensor_type = sensor_match.group(1) if sensor_match else sensor_info
            sensor_id = sensor_match.group(2) if sensor_match and sensor_match.group(2) else ''
            
            severity = classify_severity(event_desc)
            
            return IPMIEvent(
                bmc_ip=bmc_ip,
                server_name=server_name,
                sel_id=sel_id,
                event_date=event_date,
                sensor_type=sensor_type,
                sensor_id=sensor_id,
                event_description=event_desc,
                severity=severity,
                raw_entry=line
            )
    except Exception as e:
        app.logger.error(f"Failed to parse SEL line: {line} - {e}")
    return None

def get_ipmi_password(bmc_ip):
    """Get the correct password for a BMC (NVIDIA uses 16-char)"""
    return IPMI_PASS_NVIDIA if bmc_ip in NVIDIA_BMCS else IPMI_PASS

def collect_ipmi_sel(bmc_ip, server_name):
    """Collect IPMI SEL from a single server"""
    try:
        password = get_ipmi_password(bmc_ip)
        result = subprocess.run(
            ['ipmitool', '-I', 'lanplus', '-H', bmc_ip, 
             '-U', IPMI_USER, '-P', password, 'sel', 'list'],
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
        password = get_ipmi_password(bmc_ip)
        result = subprocess.run(
            ['ipmitool', '-I', 'lanplus', '-H', bmc_ip,
             '-U', IPMI_USER, '-P', password, 'power', 'status'],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            return result.stdout.strip()
        return 'Unknown'
    except:
        return 'Unreachable'

def update_server_status(bmc_ip, server_name):
    """Update server status in database"""
    with app.app_context():
        status = ServerStatus.query.filter_by(bmc_ip=bmc_ip).first()
        if not status:
            status = ServerStatus(bmc_ip=bmc_ip, server_name=server_name)
            db.session.add(status)
        
        status.power_status = collect_power_status(bmc_ip)
        status.last_check = datetime.utcnow()
        status.is_reachable = status.power_status != 'Unreachable'
        
        # Count events
        cutoff = datetime.utcnow() - timedelta(hours=24)
        status.total_events = IPMIEvent.query.filter_by(bmc_ip=bmc_ip).count()
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
        
        db.session.commit()

def collect_all_events():
    """Background task to collect events from all servers"""
    with app.app_context():
        app.logger.info("Starting IPMI event collection...")
        
        for bmc_ip, server_name in SERVERS.items():
            try:
                events = collect_ipmi_sel(bmc_ip, server_name)
                
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
    """Get all server statuses"""
    servers = ServerStatus.query.all()
    return jsonify([{
        'bmc_ip': s.bmc_ip,
        'server_name': s.server_name,
        'power_status': s.power_status,
        'last_check': s.last_check.isoformat() if s.last_check else None,
        'is_reachable': s.is_reachable,
        'total_events': s.total_events,
        'critical_24h': s.critical_events_24h,
        'warning_24h': s.warning_events_24h
    } for s in servers])

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
    """Get dashboard statistics"""
    cutoff_24h = datetime.utcnow() - timedelta(hours=24)
    cutoff_7d = datetime.utcnow() - timedelta(days=7)
    
    return jsonify({
        'total_servers': ServerStatus.query.count(),
        'reachable_servers': ServerStatus.query.filter_by(is_reachable=True).count(),
        'events_24h': IPMIEvent.query.filter(IPMIEvent.event_date >= cutoff_24h).count(),
        'critical_24h': IPMIEvent.query.filter(
            IPMIEvent.severity == 'critical',
            IPMIEvent.event_date >= cutoff_24h
        ).count(),
        'warning_24h': IPMIEvent.query.filter(
            IPMIEvent.severity == 'warning',
            IPMIEvent.event_date >= cutoff_24h
        ).count(),
        'events_7d': IPMIEvent.query.filter(IPMIEvent.event_date >= cutoff_7d).count(),
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

