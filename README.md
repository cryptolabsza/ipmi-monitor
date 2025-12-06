# IPMI Monitor

[![Docker Build](https://github.com/cryptolabsza/ipmi-monitor/actions/workflows/docker-build.yml/badge.svg)](https://github.com/cryptolabsza/ipmi-monitor/actions/workflows/docker-build.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Free, self-hosted IPMI/BMC monitoring for your server fleet.** Collect System Event Logs (SEL), monitor sensors, track ECC errors, and get alerts - all from a beautiful web dashboard.

![Dashboard](docs/dashboard.png)

## 📸 Screenshots

<table>
<tr>
<td><img src="docs/server-detail-events.png" alt="Events" width="400"/><br/><em>Event Log - Track SEL events</em></td>
<td><img src="docs/server-detail-sensors.png" alt="Sensors" width="400"/><br/><em>Live Sensors - Temperature, fans, voltage</em></td>
</tr>
<tr>
<td><img src="docs/server-detail-inventory.png" alt="Inventory" width="400"/><br/><em>Hardware Inventory - CPU, Memory, Storage</em></td>
<td><img src="docs/login-page.png" alt="Login" width="400"/><br/><em>Secure Admin Login</em></td>
</tr>
</table>

## ✨ Features

### 🆓 Free Self-Hosted Features
- 🔍 **Event Collection** - Automatically collect IPMI SEL logs (parallel, 10 workers)
- 📊 **Real-time Dashboard** - Auto-refreshing with server status cards
- 🌡️ **Sensor Monitoring** - Temperature, fan, voltage, power readings
- 💾 **ECC Memory Tracking** - Identify which DIMM has errors
- 🚨 **Alert Rules** - Configurable alerts with email, Telegram, webhooks
- 📈 **Prometheus Metrics** - Native `/metrics` endpoint for Grafana
- 🔐 **User Management** - Admin and read-only access levels
- 📥 **Export** - CSV export of event logs
- 🐳 **Docker Ready** - Multi-arch images (amd64/arm64)

### 🤖 Optional AI Features (via CryptoLabs)
- 📊 Daily health summaries
- 🔧 AI-generated maintenance tasks
- 📈 Failure predictions
- 🔍 Root cause analysis
- 💬 AI chat assistant

---

## 🚀 Quick Start (5 minutes)

### Option 1: Docker Compose (Recommended)

**Step 1:** Create project directory
```bash
mkdir ipmi-monitor && cd ipmi-monitor
```

**Step 2:** Create `docker-compose.yml`:
```yaml
version: '3.8'

services:
  ipmi-monitor:
    image: ghcr.io/cryptolabsza/ipmi-monitor:latest
    container_name: ipmi-monitor
    restart: unless-stopped
    ports:
      - "5000:5000"
    environment:
      - APP_NAME=My Server Fleet        # Customize this
      - IPMI_USER=admin
      - IPMI_PASS=YourIPMIPassword      # Your BMC password
      - ADMIN_PASS=changeme             # CHANGE THIS!
      - SECRET_KEY=change-this-to-random-string
    volumes:
      - ipmi_data:/app/data             # ⚠️ IMPORTANT: Persists your data!

volumes:
  ipmi_data:
```

**Step 3:** Start the service
```bash
docker-compose up -d
```

**Step 4:** Open http://localhost:5000 and add your servers!

---

### Option 2: Docker Run

```bash
# Create a named volume for data persistence
docker volume create ipmi_data

# Run the container
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

### Option 3: Pre-configured Server List

Create `servers.yaml` with your servers:

```yaml
servers:
  - name: web-server-01
    bmc_ip: 192.168.1.100
    
  - name: database-server
    bmc_ip: 192.168.1.101
    ipmi_user: dbadmin
    ipmi_pass: custompass
    
  - name: gpu-server-01
    bmc_ip: 192.168.1.102
    nvidia: true              # Uses 16-char NVIDIA password
```

Then mount it:
```yaml
volumes:
  - ipmi_data:/app/data
  - ./servers.yaml:/app/config/servers.yaml:ro
```

Servers are auto-imported on startup!

---

## ⚠️ Important: Data Persistence

**Always use a named volume** to preserve your data across container updates:

```yaml
# ✅ CORRECT - Named volume (survives updates)
volumes:
  - ipmi_data:/app/data

# ❌ WRONG - No volume (data lost on rebuild)
# (no volume specified)

# ⚠️ CAUTION - Bind mount (works but be careful with paths)
volumes:
  - /path/on/host:/app/data
```

If you see "No servers configured" after an update, your data wasn't persisted!

---

## 🖥️ Adding Servers

### Via Web UI (Easiest)

1. Login at `/login` (default: admin / changeme)
2. Go to **Settings** → **Server List**
3. Click **Add Server**
4. Enter BMC IP and server name

### Via Import

Upload a file in Settings → Server List → Import:

**YAML** (recommended):
```yaml
servers:
  - name: server-01
    bmc_ip: 192.168.1.100
    
  - name: server-02
    bmc_ip: 192.168.1.101
    server_ip: 10.0.0.101        # OS IP for SSH inventory (optional)
    public_ip: 203.0.113.50      # External IP for documentation (optional)
    ipmi_user: admin
    ipmi_pass: secretpass
    notes: Production database
```

**CSV**:
```csv
name,bmc_ip,server_ip,public_ip,ipmi_user,ipmi_pass,notes
server-01,192.168.1.100,10.0.0.100,,,
server-02,192.168.1.101,10.0.0.101,203.0.113.50,admin,pass123,Edge server
```

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

### Authentication

| Access Level | Login Required | Can Do |
|--------------|----------------|--------|
| **Read-only** | No | View dashboard, events, sensors |
| **Admin** | Yes | Add/delete servers, clear SEL, settings |

---

## 📊 Prometheus & Grafana

### Add to Prometheus

```yaml
scrape_configs:
  - job_name: 'ipmi-monitor'
    static_configs:
      - targets: ['your-server:5000']
    scrape_interval: 60s
```

### Metrics Available

| Metric | Description |
|--------|-------------|
| `ipmi_server_reachable` | BMC reachability (1=yes) |
| `ipmi_server_power_on` | Power status |
| `ipmi_events_critical_24h` | Critical events count |
| `ipmi_events_warning_24h` | Warning events count |
| `ipmi_total_servers` | Total servers monitored |

### Grafana Dashboard

Download from: **Settings → Integrations → Download Grafana Dashboard**

---

## 🤖 AI Features (Optional)

Upgrade your monitoring with AI-powered insights from CryptoLabs:

| Feature | Description |
|---------|-------------|
| 📊 **Daily Summaries** | AI analyzes your fleet health daily |
| 🔧 **Maintenance Tasks** | Auto-generated from events |
| 📈 **Predictions** | Failure warnings before they happen |
| 🔍 **Root Cause Analysis** | AI explains what went wrong |
| 💬 **Chat** | Ask questions about your servers |

### Enable AI

1. Go to **Settings** → **AI Features**
2. Click **Start Free Trial** (1 month free!)
3. Create account or login at CryptoLabs
4. You're connected!

### Pricing

| Tier | Price | Servers | Tokens/month | Trial |
|------|-------|---------|--------------|-------|
| Free | $0 | Unlimited | - | Basic monitoring only |
| Standard | $100/mo | 50 servers | 1M tokens | 1 month free |
| Standard+ | +$15/10 servers | 51+ | +100K tokens | - |
| Professional | $500/mo | 500 servers | 10M tokens | 1 month free |

> 💡 **Tokens** are used for AI chat, summaries, and predictions. 1M tokens ≈ 2000+ AI queries/month.

---

## 🔧 Troubleshooting

### Test IPMI Connectivity

```bash
# From the container
docker exec ipmi-monitor ipmitool -I lanplus \
  -H 192.168.1.100 -U admin -P YourPassword power status
```

### Check Logs

```bash
docker logs ipmi-monitor --tail 100
docker logs ipmi-monitor 2>&1 | grep -i error
```

### Database Reset

```bash
# Backup first!
docker exec ipmi-monitor cp /app/data/ipmi_events.db /app/data/backup.db

# Then reset
docker exec ipmi-monitor rm /app/data/ipmi_events.db
docker restart ipmi-monitor
```

### BMC Not Reachable

1. Check network connectivity to BMC IP
2. Verify IPMI over LAN is enabled in BMC settings
3. Try `network_mode: host` in docker-compose

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                       IPMI Monitor                               │
│  ┌──────────────────┐  ┌────────────┐  ┌───────────────────┐   │
│  │   Flask Web UI   │◄─│  SQLite    │◄─│  IPMI Collector   │   │
│  │    + Admin Auth  │  │  Database  │  │  (10 workers)     │   │
│  └──────────────────┘  └────────────┘  └─────────┬─────────┘   │
│           │                                       │             │
│   ┌───────▼───────┐                              │             │
│   │  /metrics     │──► Prometheus/Grafana        │             │
│   │  /health      │──► Docker/K8s healthcheck    │             │
│   └───────────────┘                              │             │
└──────────────────────────────────────────────────┼─────────────┘
                                                   │
            ┌──────────────────────────────────────▼──────────────┐
            │              BMC/IPMI Network                        │
            │  ipmitool -I lanplus -H x.x.x.x sel list            │
            └─────────────────────────────────────────────────────┘
                                                   │
            ┌──────────────────────────────────────▼──────────────┐
            │          CryptoLabs AI Service (Optional)            │
            │  • Health summaries    • Predictions                 │
            │  • Maintenance tasks   • Root cause analysis         │
            └─────────────────────────────────────────────────────┘
```

---

## 📋 API Reference

### Public Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /` | Dashboard |
| `GET /api/servers` | List servers |
| `GET /api/events` | Get events |
| `GET /api/stats` | Dashboard stats |
| `GET /api/sensors/{bmc_ip}` | Sensor readings |
| `GET /metrics` | Prometheus metrics |
| `GET /health` | Health check |

### Admin Endpoints (login required)

| Endpoint | Description |
|----------|-------------|
| `POST /api/collect` | Trigger collection |
| `POST /api/servers/add` | Add server |
| `DELETE /api/servers/{bmc_ip}` | Delete server |
| `POST /api/server/{bmc_ip}/clear_sel` | Clear BMC SEL |

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

- **GitHub**: [github.com/cryptolabsza/ipmi-monitor](https://github.com/cryptolabsza/ipmi-monitor)
- **Docker Image**: [ghcr.io/cryptolabsza/ipmi-monitor](https://ghcr.io/cryptolabsza/ipmi-monitor)
- **AI Features**: [cryptolabs.co.za/ipmi-monitor](https://cryptolabs.co.za/ipmi-monitor)
- **Support**: [CryptoLabs Discord](https://discord.gg/cryptolabs)

---

<p align="center">
  Made with ❤️ by <a href="https://cryptolabs.co.za">CryptoLabs</a>
</p>
