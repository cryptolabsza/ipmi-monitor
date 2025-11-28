# BrickBox IPMI Monitor

[![Docker Build](https://github.com/jjziets/ipmi-monitor/actions/workflows/docker-build.yml/badge.svg)](https://github.com/jjziets/ipmi-monitor/actions/workflows/docker-build.yml)

A Flask-based web dashboard for monitoring IPMI/BMC System Event Logs (SEL) across all BrickBox servers. Integrates with Prometheus and Grafana for unified monitoring.

## Features

- 🔍 **Event Collection**: Automatically collects IPMI SEL logs from all servers
- 📊 **Dashboard**: Real-time overview of all server health status
- 🚨 **Severity Classification**: Automatic classification of events (Critical/Warning/Info)
- 📈 **Prometheus Metrics**: Native `/metrics` endpoint for Grafana integration
- 📥 **Export**: CSV export of event logs
- 🐳 **Docker Ready**: Multi-arch images (amd64/arm64) via GitHub Actions

## Quick Start

### Option 1: Docker (Recommended)

```bash
# Pull and run
docker run -d \
  --name ipmi-monitor \
  -p 5000:5000 \
  -e IPMI_USER=admin \
  -e IPMI_PASS=BBccc321 \
  -v ipmi_data:/app/instance \
  ghcr.io/jjziets/ipmi-monitor:latest
```

### Option 2: Docker Compose

```bash
# Clone the repo
git clone https://github.com/jjziets/ipmi-monitor.git
cd ipmi-monitor

# Edit docker-compose.yml with your credentials
docker-compose up -d
```

### Option 3: Local Development

```bash
pip install -r requirements.txt
export IPMI_USER=admin
export IPMI_PASS=BBccc321
python app.py
```

Access the dashboard at: http://localhost:5000

## Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `IPMI_USER` | admin | IPMI/BMC username |
| `IPMI_PASS` | BBccc321 | IPMI/BMC password (8-char for most servers) |
| `IPMI_PASS_NVIDIA` | BBccc321BBccc321 | Password for NVIDIA DGX/HGX BMCs (16-char required) |
| `POLL_INTERVAL` | 300 | Seconds between automatic collections |

## Prometheus & Grafana Integration

### 1. Add to Prometheus Scrape Config

Add this to your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'ipmi-monitor'
    static_configs:
      - targets: ['ipmi-monitor:5000']
    scrape_interval: 60s
```

### 2. Import Grafana Dashboard

Import the dashboard from `grafana/dashboards/ipmi-monitor.json` or use dashboard ID from Grafana.com (coming soon).

### Available Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `ipmi_server_reachable` | Gauge | BMC reachability (1=yes, 0=no) |
| `ipmi_server_power_on` | Gauge | Server power status |
| `ipmi_events_total` | Gauge | Total events per server |
| `ipmi_events_critical_24h` | Gauge | Critical events in 24h |
| `ipmi_events_warning_24h` | Gauge | Warning events in 24h |
| `ipmi_total_servers` | Gauge | Total monitored servers |
| `ipmi_reachable_servers` | Gauge | Reachable server count |
| `ipmi_total_critical_events_24h` | Gauge | Total critical events |
| `ipmi_total_warning_events_24h` | Gauge | Total warning events |
| `ipmi_last_collection_timestamp` | Gauge | Last collection timestamp |

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Web dashboard |
| `/metrics` | GET | Prometheus metrics |
| `/health` | GET | Health check |
| `/api/servers` | GET | List all servers |
| `/api/events` | GET | Get recent events |
| `/api/stats` | GET | Dashboard statistics |
| `/api/collect` | POST | Trigger manual collection |

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    IPMI Monitor                              │
│  ┌──────────────┐   ┌────────────┐   ┌─────────────────┐   │
│  │ Flask Web UI │◄──│  SQLite    │◄──│ IPMI Collector  │   │
│  │   :5000      │   │  Database  │   │  (Background)   │   │
│  │              │   └────────────┘   └────────┬────────┘   │
│  │  /metrics ───┼──► Prometheus                │            │
│  └──────────────┘                              │            │
└────────────────────────────────────────────────┼────────────┘
                                                 │
                                                 ▼
                    ┌───────────────────────────────────┐
                    │         BMC/IPMI Network          │
                    │   88.0.X.0 (All BrickBox Servers) │
                    └───────────────────────────────────┘
```

## Deployment on BBmain (88.0.33.141)

```bash
# SSH to server
ssh root@88.0.33.141

# Create directory
mkdir -p /home/admin/ipmi-monitor
cd /home/admin/ipmi-monitor

# Download docker-compose.yml
curl -o docker-compose.yml https://raw.githubusercontent.com/jjziets/ipmi-monitor/main/docker-compose.yml

# Start the service
docker-compose up -d

# Add to existing Prometheus config
cat >> /home/admin/prometheus/prometheus.yml << 'EOF'
  - job_name: 'ipmi-monitor'
    static_configs:
      - targets: ['ipmi-monitor:5000']
EOF

# Reload Prometheus
docker exec prometheus kill -HUP 1
```

## Supported Hardware

- **ASUSTek BMCs**: Standard 8-character password
- **NVIDIA DGX/HGX**: 16-character password required (auto-detected)
- **Supermicro**: Should work with standard config
- **Dell iDRAC**: May require additional configuration

## Troubleshooting

### IPMI Connection Errors

```bash
# Test connectivity manually
ipmitool -I lanplus -H 88.0.11.0 -U admin -P BBccc321 power status
```

### Network Issues in Docker

If BMC IPs are not accessible from the container:
```yaml
# In docker-compose.yml, uncomment:
network_mode: host
```

### Database Reset

```bash
docker exec ipmi-monitor rm /app/instance/ipmi_events.db
docker restart ipmi-monitor
```

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

MIT License - see LICENSE file for details.
