# IPMI Monitor

[![Docker Build](https://github.com/jjziets/ipmi-monitor/actions/workflows/docker-build.yml/badge.svg)](https://github.com/jjziets/ipmi-monitor/actions/workflows/docker-build.yml)

A production-ready Flask web dashboard for monitoring IPMI/BMC System Event Logs (SEL) across your server fleet. Features admin authentication, sensor monitoring, ECC memory identification, alerting, and Prometheus/Grafana integration.

## Features

- 🔍 **Event Collection**: Automatically collects IPMI SEL logs from all servers (parallel, 10 workers)
- 📊 **Real-time Dashboard**: Auto-refreshing dashboard with countdown timer
- 🌡️ **Sensor Monitoring**: Temperature, fan, voltage, and power readings
- 💾 **ECC Memory Tracking**: Identifies which memory sensor (e.g., CPU1_ECC1) has errors
- 🚨 **Severity Classification**: Automatic classification (Critical/Warning/Info)
- 🔐 **Admin Authentication**: Protected settings, SEL clearing, server management
- ➕ **Server Management**: Add/edit/delete servers via UI or INI import
- 📈 **Prometheus Metrics**: Native `/metrics` endpoint for Grafana
- 📥 **Export**: CSV export of event logs
- 🐳 **Docker Ready**: Multi-arch images (amd64/arm64) via GitHub Actions
- 🏥 **Production Health Checks**: Database, thread monitoring, graceful shutdown

## Screenshots

### Dashboard
- Auto-refresh countdown with toggle
- Time range selector (1h to 30 days)
- Server status cards with event counts
- Recent events feed

### Server Detail
- Events tab with filtering
- Sensors tab with live readings (temperature, fans, voltage)

## Quick Start

### Option 1: Docker (Recommended)

```bash
docker run -d \
  --name ipmi-monitor \
  -p 5001:5000 \
  -e IPMI_USER=admin \
  -e IPMI_PASS=YourIPMIPassword \
  -e ADMIN_USER=admin \
  -e ADMIN_PASS=YourSecurePassword \
  -e SECRET_KEY=your-random-secret-key \
  -v ipmi_data:/app/instance \
  ghcr.io/jjziets/ipmi-monitor:latest
```

### Option 2: Docker Compose

```yaml
version: '3.8'
services:
  ipmi-monitor:
    image: ghcr.io/jjziets/ipmi-monitor:latest
    container_name: ipmi-monitor
    restart: unless-stopped
    ports:
      - "5001:5000"
    environment:
      - IPMI_USER=admin
      - IPMI_PASS=YourIPMIPassword
      - IPMI_PASS_NVIDIA=YourNvidia16CharPass  # For NVIDIA DGX/HGX
      - POLL_INTERVAL=300
      - ADMIN_USER=admin
      - ADMIN_PASS=YourSecurePassword
      - SECRET_KEY=your-random-secret-key
    volumes:
      - ipmi_data:/app/instance

volumes:
  ipmi_data:
```

```bash
docker-compose up -d
```

### Option 3: Local Development

```bash
pip install -r requirements.txt
export IPMI_USER=admin
export IPMI_PASS=YourIPMIPassword
export ADMIN_USER=admin
export ADMIN_PASS=YourSecurePassword
python app.py
```

Access the dashboard at: http://localhost:5000

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `IPMI_USER` | admin | IPMI/BMC username |
| `IPMI_PASS` | (required) | IPMI/BMC password (8-char for most servers) |
| `IPMI_PASS_NVIDIA` | (required) | Password for NVIDIA DGX/HGX (16-char required) |
| `POLL_INTERVAL` | 300 | Seconds between automatic collections |
| `ADMIN_USER` | admin | Dashboard admin username |
| `ADMIN_PASS` | changeme | Dashboard admin password (**CHANGE THIS!**) |
| `APP_NAME` | IPMI Monitor | Application name (customize for your org) |
| `SECRET_KEY` | (auto) | Flask session secret key (**SET THIS!**) |

### Authentication

The dashboard supports two access levels:

| Access Level | Capabilities |
|--------------|--------------|
| **Read-only** (no login) | View dashboard, events, sensors, export CSV |
| **Admin** (login required) | Settings, add/delete servers, clear SEL, credentials |

Login at `/login` with `ADMIN_USER`/`ADMIN_PASS`.

## API Endpoints

### Public Endpoints (No Auth Required)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Main dashboard |
| `/server/<bmc_ip>` | GET | Server detail page |
| `/metrics` | GET | Prometheus metrics |
| `/health` | GET | Health check (returns 503 if degraded) |
| `/api/servers` | GET | List all servers with status |
| `/api/events` | GET | Get recent events (with filters) |
| `/api/stats` | GET | Dashboard statistics |
| `/api/server/<bmc_ip>/events` | GET | Events for specific server |
| `/api/sensors/<bmc_ip>` | GET | Sensor readings for server |
| `/api/sensors/<bmc_ip>/names` | GET | Sensor ID to name mapping |
| `/api/auth/status` | GET | Check if logged in |

### Admin Endpoints (Auth Required)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/settings` | GET | Settings page |
| `/api/collect` | POST | Trigger event collection |
| `/api/collect?bmc_ip=X` | POST | Collect from single server |
| `/api/sensors/collect` | POST | Trigger sensor collection |
| `/api/servers/add` | POST | Add new server |
| `/api/servers/<bmc_ip>` | PUT/DELETE | Update/delete server |
| `/api/servers/import` | POST | Import servers from INI/JSON |
| `/api/server/<bmc_ip>/clear_sel` | POST | Clear BMC SEL log |
| `/api/server/<bmc_ip>/clear_db_events` | POST | Clear DB events only |
| `/api/clear_all_sel` | POST | Clear SEL on all BMCs |

## Health Check

The `/health` endpoint provides detailed status:

```json
{
  "status": "healthy",
  "timestamp": "2025-11-29T17:43:48.814437",
  "checks": {
    "database": "ok",
    "collector_thread": "running"
  },
  "last_collection": "2025-11-29T17:43:47.957877"
}
```

Returns:
- **200**: All systems healthy
- **503**: Degraded (DB error or collector stopped)

## Prometheus & Grafana Integration

### 1. Add to Prometheus Scrape Config

```yaml
scrape_configs:
  - job_name: 'ipmi-monitor'
    static_configs:
      - targets: ['your-server:5001']
    scrape_interval: 60s
```

### 2. Import Grafana Dashboard

Import `grafana/dashboards/ipmi-monitor.json` into Grafana.

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
| `ipmi_last_collection_timestamp` | Gauge | Last collection unix time |

## Server Management

### Add Servers via UI

1. Login as admin
2. Go to Settings → Server List
3. Click "Add Server"
4. Enter BMC IP, server name, and options

### Import from INI File

```ini
[server-01]
bmc_ip = 192.168.1.100
server_ip = 192.168.1.10
enabled = true

[server-02]
bmc_ip = 192.168.1.101
server_ip = 192.168.1.11
enabled = true
use_nvidia_password = false
```

Upload via Settings → Server List → Import.

## ECC Memory Identification

When ECC errors occur, the monitor shows which sensor detected them:

```
Correctable ECC | Asserted [CPU1_ECC1]
```

The sensor name (e.g., `CPU1_ECC1`) is looked up from the BMC's SDR (Sensor Data Repository).

To view the sensor mapping for a server:
```
GET /api/sensors/192.168.1.100/names
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                       IPMI Monitor                               │
│  ┌──────────────────┐  ┌────────────┐  ┌───────────────────┐   │
│  │   Flask Web UI   │◄─│  SQLite    │◄─│  IPMI Collector   │   │
│  │    + Admin Auth  │  │  Database  │  │  (10 parallel)    │   │
│  │                  │  └────────────┘  └─────────┬─────────┘   │
│  │  /metrics ───────┼──► Prometheus              │             │
│  │  /health ────────┼──► K8s/Docker              │             │
│  └──────────────────┘                            │             │
└──────────────────────────────────────────────────┼─────────────┘
                                                   │
                     ┌─────────────────────────────▼─────────────┐
                     │           BMC/IPMI Network                │
                     │   ipmitool -I lanplus -H 88.0.X.0 ...     │
                     │   (SEL, sensors, power status)            │
                     └───────────────────────────────────────────┘
```

## Production Deployment

### Security Checklist

- [ ] Change `ADMIN_PASS` from default
- [ ] Set a strong `SECRET_KEY`
- [ ] Use HTTPS (put behind reverse proxy)
- [ ] Restrict network access to BMC IPs
- [ ] Review firewall rules

### Docker Compose (Production)

```yaml
version: '3.8'
services:
  ipmi-monitor:
    image: ghcr.io/jjziets/ipmi-monitor:latest
    container_name: ipmi-monitor
    restart: unless-stopped
    ports:
      - "5001:5000"
    environment:
      - IPMI_USER=admin
      - IPMI_PASS=${IPMI_PASS}
      - IPMI_PASS_NVIDIA=${IPMI_PASS_NVIDIA}
      - POLL_INTERVAL=300
      - ADMIN_USER=admin
      - ADMIN_PASS=${ADMIN_PASS}
      - SECRET_KEY=${SECRET_KEY}
    volumes:
      - ipmi_data:/app/instance
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:5000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 10s

volumes:
  ipmi_data:
```

## Supported Hardware

| Vendor | Model | Password | Notes |
|--------|-------|----------|-------|
| ASUSTek | Various | 8-char | Standard config |
| NVIDIA | DGX/HGX | 16-char | Set `IPMI_PASS_NVIDIA` |
| Supermicro | Various | 8-char | Standard config |
| Dell | iDRAC | Varies | May need config changes |

## Troubleshooting

### IPMI Connection Errors

```bash
# Test connectivity manually
ipmitool -I lanplus -H 192.168.1.100 -U admin -P YourPassword power status

# Test SEL access
ipmitool -I lanplus -H 192.168.1.100 -U admin -P YourPassword sel list
```

### Slow BMC Responses

Some BMCs with large SEL logs (1000+ events) can take 5+ minutes to respond. The monitor uses 10-minute timeouts for these cases.

### Network Issues in Docker

If BMC IPs are not accessible:
```yaml
# Option 1: Host network mode
network_mode: host

# Option 2: Ensure routing to BMC network
```

### Database Issues

```bash
# Reset database
docker exec ipmi-monitor rm /app/instance/ipmi_events.db
docker restart ipmi-monitor

# Check database
docker exec ipmi-monitor sqlite3 /app/instance/ipmi_events.db ".tables"
```

### Check Logs

```bash
docker logs ipmi-monitor 2>&1 | tail -50
docker logs ipmi-monitor 2>&1 | grep -i error
```

## Development

### Local Setup

```bash
git clone https://github.com/jjziets/ipmi-monitor.git
cd ipmi-monitor
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

### Running Tests

```bash
# TODO: Add test suite
pytest tests/
```

### Building Docker Image

```bash
docker build -t ipmi-monitor:dev .
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Changelog

### v1.2.0 (2025-11-29)
- Added admin authentication
- Added sensor monitoring (temperature, fans, voltage, power)
- Added ECC memory sensor identification
- Added server management (add/edit/delete via UI)
- Added INI import/export for server lists
- Added auto-refresh countdown timer
- Production hardening (error handling, thread safety, validation)
- Enhanced health check with database and thread monitoring

### v1.1.0
- Added per-server IPMI credentials
- Added time range selector (1h to 30 days)
- Parallel event collection (10 workers)
- Fixed dashboard stats consistency

### v1.0.0
- Initial release
- Basic SEL collection and display
- Prometheus metrics integration
