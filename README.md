# IPMI Monitor

[![Docker Build](https://github.com/cryptolabsza/ipmi-monitor/actions/workflows/docker-build.yml/badge.svg)](https://github.com/cryptolabsza/ipmi-monitor/actions/workflows/docker-build.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Documentation](https://img.shields.io/badge/docs-GitHub%20Pages-blue)](https://cryptolabsza.github.io/ipmi-monitor/)

**Free, self-hosted IPMI/BMC monitoring for your server fleet.** Collect System Event Logs (SEL), monitor sensors, track hardware inventory, and get alerts - all from a beautiful web dashboard.

> 📖 **[Full Documentation](https://cryptolabsza.github.io/ipmi-monitor/)** | 🤖 **[1 Month Free AI Trial](#-ai-features-1-month-free)**

![Dashboard](docs/dashboard.png)

## 📸 Screenshots

<table>
<tr>
<td><img src="docs/server-detail-events.png" alt="Events" width="400"/><br/><em>Event Log - Track SEL events with severity filtering</em></td>
<td><img src="docs/server-detail-sensors.png" alt="Sensors" width="400"/><br/><em>Live Sensors - Temperature, fans, voltage</em></td>
</tr>
<tr>
<td><img src="docs/server-detail-inventory.png" alt="Inventory" width="400"/><br/><em>Hardware Inventory - CPU, Memory, Storage, GPU</em></td>
<td><img src="docs/login-page.png" alt="Login" width="400"/><br/><em>Secure Multi-tier Access (Admin/ReadWrite/ReadOnly)</em></td>
</tr>
</table>

## ✨ Features

### 🆓 Free Self-Hosted Features
- 🔍 **Event Collection** - Automatically collect IPMI SEL logs (parallel, 10 workers)
- 📊 **Real-time Dashboard** - Auto-refreshing with server status cards
- 🌡️ **Sensor Monitoring** - Temperature, fan, voltage, power readings
- 🔧 **Hardware Inventory** - CPU model, memory, storage via IPMI/Redfish/SSH
- ⚡ **Remote Power Control** - Power on/off/cycle/reset from the web UI
- 💾 **ECC Memory Tracking** - Identify which DIMM has errors
- 🚨 **Alert Rules** - Configurable alerts with email, Telegram, webhooks
- 📈 **Prometheus Metrics** - Native `/metrics` endpoint with pre-built Grafana dashboard
- 🔐 **3-Tier Access Control** - Admin, Read-Write, and Read-Only roles
- 🔑 **SSH Key Management** - Centralized SSH keys for detailed inventory collection
- 📥 **Import/Export** - YAML, JSON, CSV server configuration
- 🐳 **Docker Ready** - Multi-arch images (amd64/arm64)

### 🤖 AI Features (1 Month Free!)

Link your account to unlock AI-powered server intelligence:

| Feature | Description |
|---------|-------------|
| 📊 **Daily Summaries** | AI analyzes your fleet health daily |
| 🔧 **Maintenance Tasks** | Auto-generated from events with specific servers listed |
| 📈 **Predictions** | Failure warnings before they happen |
| 🔍 **Root Cause Analysis** | AI explains what went wrong |
| 💬 **AI Chat** | Ask questions about your servers in natural language |

**Start your free trial:** Settings → AI Features → Start Free Trial

---

## 🚀 Quick Start (5 minutes)

### Docker Compose (Recommended)

```yaml
# docker-compose.yml
version: '3.8'

services:
  ipmi-monitor:
    image: ghcr.io/cryptolabsza/ipmi-monitor:latest
    container_name: ipmi-monitor
    restart: unless-stopped
    ports:
      - "5000:5000"
    environment:
      - APP_NAME=My Server Fleet
      - IPMI_USER=admin
      - IPMI_PASS=YourIPMIPassword
      - ADMIN_PASS=changeme             # CHANGE THIS!
      - SECRET_KEY=change-this-to-random-string
    volumes:
      - ipmi_data:/app/data
      - ~/.ssh:/root/.ssh:ro            # Optional: for SSH inventory

volumes:
  ipmi_data:
```

```bash
docker-compose up -d
# Open http://localhost:5000
```

### Docker Run

```bash
docker run -d \
  --name ipmi-monitor \
  -p 5000:5000 \
  -e IPMI_USER=admin \
  -e IPMI_PASS=YourIPMIPassword \
  -e ADMIN_PASS=YourAdminPassword \
  -e SECRET_KEY=your-random-secret-key \
  -v ipmi_data:/app/data \
  --restart unless-stopped \
  ghcr.io/cryptolabsza/ipmi-monitor:latest
```

---

## 📖 Documentation

Full documentation is available at **[cryptolabsza.github.io/ipmi-monitor](https://cryptolabsza.github.io/ipmi-monitor/)**

Quick links:
- [User Guide](https://cryptolabsza.github.io/ipmi-monitor/user-guide)
- [Quick Start](https://cryptolabsza.github.io/ipmi-monitor/user-guide#quick-start)
- [Prometheus & Grafana](https://cryptolabsza.github.io/ipmi-monitor/user-guide#prometheus--grafana-integration)
- [Troubleshooting](https://cryptolabsza.github.io/ipmi-monitor/user-guide#troubleshooting)

Or access docs directly in the app: **Dashboard → 📖 Docs**

---

## ⚙️ Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `APP_NAME` | IPMI Monitor | Displayed in header |
| `IPMI_USER` | admin | Default BMC username |
| `IPMI_PASS` | (required) | Default BMC password |
| `IPMI_PASS_NVIDIA` | - | 16-char password for NVIDIA DGX/HGX |
| `ADMIN_USER` | admin | Dashboard admin username |
| `ADMIN_PASS` | changeme | Dashboard admin password |
| `SECRET_KEY` | (auto) | Flask session secret (**set this!**) |
| `POLL_INTERVAL` | 300 | Seconds between collections |
| `DATA_RETENTION_DAYS` | 30 | How long to keep events |
| `AI_SERVICE_URL` | - | URL to AI service (for AI features) |

### User Roles

| Role | Permissions |
|------|-------------|
| **Admin** | Full access: users, security, AI, power control |
| **Read-Write** | Manage servers, power commands, but not users |
| **Read-Only** | View only - no changes allowed |

---

## 📊 Prometheus & Grafana

### Prometheus Config

```yaml
scrape_configs:
  - job_name: 'ipmi-monitor'
    static_configs:
      - targets: ['your-server:5000']
    scrape_interval: 60s
    metrics_path: /metrics
```

### Available Metrics

| Metric | Description |
|--------|-------------|
| `ipmi_server_reachable` | BMC reachability (1=yes, 0=no) |
| `ipmi_server_power_on` | Power state |
| `ipmi_temperature_celsius` | Temperature readings per sensor |
| `ipmi_fan_speed_rpm` | Fan speed readings |
| `ipmi_voltage_volts` | Voltage readings |
| `ipmi_power_watts` | Power consumption |
| `ipmi_events_critical_24h` | Critical events in 24h |
| `ipmi_events_warning_24h` | Warning events in 24h |
| `ipmi_total_servers` | Total servers monitored |
| `ipmi_reachable_servers` | Reachable server count |

### Grafana Dashboard

Pre-built dashboard available: `grafana/dashboards/ipmi-monitor.json`

Import via Grafana → Dashboards → Import → Upload JSON

---

## 🤖 AI Features (1 Month Free!)

Upgrade your monitoring with AI-powered insights from CryptoLabs:

### Features

- **📊 Fleet Health Summaries** - Daily AI analysis of your entire server fleet
- **🔧 Maintenance Tasks** - AI identifies work items with specific server names
- **📈 Predictive Analytics** - Failure predictions before they happen
- **🔍 Root Cause Analysis** - Deep dive into specific events
- **💬 AI Chat** - Ask questions like:
  - *"Which servers have high temperatures?"*
  - *"Show me servers with ECC errors"*
  - *"What maintenance is needed this week?"*

### Getting Started

1. Go to **Settings → AI Features**
2. Click **Start Free Trial**
3. Create account at CryptoLabs (1 month free!)
4. AI features activate automatically

### Pricing

| Tier | Price | Servers | Trial |
|------|-------|---------|-------|
| Free | $0 | Unlimited | Basic monitoring only |
| Starter | $100/mo | 50 servers | **1 month free** |
| Starter+ | +$15/10 | 51+ servers | - |

---

## 🔧 SSH for Detailed Inventory

For the most accurate hardware inventory (exact CPU model, memory config, storage), enable SSH:

1. **Settings → SSH → Enable SSH to OS**
2. Add SSH keys: **Settings → SSH → Add New Key**
3. Assign keys to servers or use defaults
4. Click **Collect Inventory** on server detail page

Supports:
- SSH key authentication (recommended)
- Password authentication
- Per-server credential overrides

---

## 🔧 Troubleshooting

### Test IPMI Connectivity

```bash
docker exec ipmi-monitor ipmitool -I lanplus \
  -H 192.168.1.100 -U admin -P YourPassword power status
```

### Check Logs

```bash
docker logs ipmi-monitor --tail 100
docker logs ipmi-monitor 2>&1 | grep -i error
```

### BMC Not Reachable

1. Check network connectivity to BMC IP
2. Verify IPMI over LAN is enabled in BMC settings
3. Use **Test BMC** button in server edit dialog
4. Try `network_mode: host` in docker-compose

### Missing Inventory Data

1. Enable SSH in Settings → SSH tab
2. Configure SSH credentials for the server
3. Test with **Test SSH** button in server edit
4. Click **Collect Inventory**

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                       IPMI Monitor                               │
│  ┌──────────────────┐  ┌────────────┐  ┌───────────────────┐   │
│  │   Flask Web UI   │◄─│  SQLite    │◄─│  IPMI Collector   │   │
│  │  + Auth + Docs   │  │  Database  │  │  (10 workers)     │   │
│  └──────────────────┘  └────────────┘  └─────────┬─────────┘   │
│           │                                       │             │
│   ┌───────▼───────┐                              │             │
│   │  /metrics     │──► Prometheus/Grafana        │             │
│   │  /docs        │──► Built-in Documentation    │             │
│   │  /docs/raw    │──► Raw Markdown API          │             │
│   └───────────────┘                              │             │
└──────────────────────────────────────────────────┼─────────────┘
                                                   │
            ┌──────────────────────────────────────▼──────────────┐
            │              BMC/IPMI Network                        │
            │  • IPMI (port 623)    • Redfish (HTTPS)             │
            │  • SSH to OS (optional, for detailed inventory)     │
            └─────────────────────────────────────────────────────┘
                                                   │
            ┌──────────────────────────────────────▼──────────────┐
            │     CryptoLabs AI Service (Optional - 1 Month Free)  │
            │  • Health summaries    • Predictions                 │
            │  • Maintenance tasks   • Root cause analysis         │
            │  • AI chat assistant                                 │
            └─────────────────────────────────────────────────────┘
```

---

## 📋 API Reference

### Public Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /` | Dashboard |
| `GET /docs` | Documentation (HTML) |
| `GET /docs/raw` | Documentation (Markdown) |
| `GET /api/servers` | List servers |
| `GET /api/events` | Get events |
| `GET /api/sensors/{bmc_ip}` | Sensor readings |
| `GET /metrics` | Prometheus metrics |
| `GET /health` | Health check |

### Admin Endpoints (login required)

| Endpoint | Description |
|----------|-------------|
| `POST /api/servers/add` | Add server |
| `DELETE /api/servers/{bmc_ip}` | Delete server |
| `POST /api/servers/{bmc_ip}/inventory` | Collect inventory |
| `POST /api/server/{bmc_ip}/power` | Power control |
| `POST /api/test/bmc` | Test BMC connection |
| `POST /api/test/ssh` | Test SSH connection |

Full API docs: [User Guide - API Reference](https://cryptolabsza.github.io/ipmi-monitor/user-guide#api-reference)

---

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing`)
5. Open a Pull Request

---

## 📜 License

MIT License - see [LICENSE](LICENSE) for details.

---

## 🔗 Links

- **Documentation**: [cryptolabsza.github.io/ipmi-monitor](https://cryptolabsza.github.io/ipmi-monitor/)
- **GitHub**: [github.com/cryptolabsza/ipmi-monitor](https://github.com/cryptolabsza/ipmi-monitor)
- **Docker Image**: [ghcr.io/cryptolabsza/ipmi-monitor](https://ghcr.io/cryptolabsza/ipmi-monitor)
- **AI Features**: [cryptolabs.co.za/ipmi-monitor](https://cryptolabs.co.za/ipmi-monitor)

---

<p align="center">
  Made with ❤️ by <a href="https://cryptolabs.co.za">CryptoLabs</a>
</p>
