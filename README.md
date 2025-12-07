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
- 🔍 **Event Collection** - Automatically collect IPMI SEL logs (parallel, 32 workers)
- 📊 **Real-time Dashboard** - Auto-refreshing with server status cards
- 🌡️ **Sensor Monitoring** - Temperature, fan, voltage, power readings
- 💾 **ECC Memory Tracking** - Identify which DIMM has errors
- 🎮 **GPU Health Monitoring** - Detect NVIDIA GPU errors via SSH (Xid errors)
- 🔄 **Uptime & Reboot Detection** - Track unexpected server reboots
- 🚨 **Alert Rules** - Configurable alerts with email, Telegram, webhooks
- 📈 **Prometheus Metrics** - Native `/metrics` endpoint for Grafana
- 🔐 **User Management** - Admin and read-only access levels
- 📥 **Export** - CSV export of event logs
- 🐳 **Docker Ready** - Multi-arch images (amd64/arm64)
- 🔄 **Version Display** - Shows version, git commit, and build time in header
- ⬆️ **Update Notifications** - Checks GitHub for newer releases

### 🤖 Optional AI Features (via CryptoLabs)
- 📊 Daily health summaries
- 🔧 AI-generated maintenance tasks
- 📈 Failure predictions
- 🔍 Root cause analysis
- 💬 AI chat assistant
- 🤖 **AI Recovery Agent** - Autonomous GPU recovery with escalation
- 🛠️ **Recovery Actions** - Clock limiting, soft resets, coordinated reboots

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
# Global defaults applied to all servers
defaults:
  ipmi_user: admin
  ipmi_pass: YourDefaultPassword
  ssh_user: root
  ssh_key_name: production    # References a stored SSH key by name

servers:
  - name: web-server-01
    bmc_ip: 192.168.1.100
    server_ip: 192.168.1.101  # OS IP for SSH inventory
    
  - name: database-server
    bmc_ip: 192.168.1.101
    server_ip: 192.168.1.102
    ipmi_user: dbadmin        # Override default
    ipmi_pass: custompass
    
  - name: gpu-server-01
    bmc_ip: 192.168.1.102
    server_ip: 192.168.1.103
    # Uses defaults for IPMI and SSH
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

## 🎮 GPU Health Monitoring

IPMI Monitor detects GPU errors via SSH using `dmesg` to find NVIDIA Xid errors.

### What It Detects

| Error Type | Display | Severity |
|------------|---------|----------|
| Memory errors | GPU Memory Error | Critical |
| GPU unresponsive | GPU Not Responding | Critical |
| GPU disconnected | GPU Disconnected | Critical |
| Recovery required | GPU Requires Recovery | Critical |

> 💡 **Note:** Technical Xid error codes are hidden from the UI. Events show user-friendly descriptions like "GPU Memory Error" instead of "Xid 48". Technical details are stored internally for debugging.

### Requirements

- SSH enabled in Settings
- SSH credentials configured per-server or globally
- Server has `dmesg` access (standard on Linux)

### GPU Events in Dashboard

GPU errors appear in the **Events** tab as:
- **Sensor Type:** GPU Health
- **Severity:** Critical (red)
- **Description:** User-friendly error description

---

## 🔄 Uptime & Reboot Detection

IPMI Monitor tracks server uptime via SSH and detects unexpected reboots.

### How It Works

1. Reads `/proc/uptime` via SSH each collection cycle
2. Compares with previous uptime
3. If uptime decreased → server rebooted
4. Checks if reboot was initiated by recovery action
5. Logs unexpected reboots as warning events

### Events Generated

| Event Type | Description |
|------------|-------------|
| `unexpected_reboot` | Server rebooted without recovery action |
| `recovery_action` | Reboot initiated by AI agent or admin |

### API Endpoint

```
GET /api/uptime - Get uptime for all servers
```

Response includes:
- `uptime_seconds` - Current uptime
- `uptime_days` - Uptime in days
- `last_boot_time` - When server last booted
- `reboot_count` - Total reboots detected
- `unexpected_reboot_count` - Reboots not initiated by system

---

## 🔧 Maintenance Tasks

IPMI Monitor automatically creates maintenance tasks based on error patterns.

### Auto-Generated Tasks

| Trigger | Task Created |
|---------|--------------|
| 3+ reboots in 24h | High severity maintenance |
| 2+ power cycles in 24h | High severity maintenance |
| 5+ GPU errors same device in 24h | Critical maintenance |

### API Endpoints

```
GET /api/maintenance - List maintenance tasks
PUT /api/maintenance/<id> - Update task status
GET /api/recovery-logs - View recovery action history
```

### Task Statuses

- `pending` - Needs attention
- `scheduled` - Planned for maintenance window
- `in_progress` - Being worked on
- `completed` - Task finished
- `cancelled` - No longer needed

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
| `GET /api/events` | Get events (filterable by severity, server, hours) |
| `GET /api/stats` | Dashboard stats |
| `GET /api/sensors/{bmc_ip}` | Sensor readings |
| `GET /metrics` | Prometheus metrics |
| `GET /health` | Health check |

### New Monitoring Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /api/maintenance` | List maintenance tasks |
| `GET /api/recovery-logs` | Get recovery action history |
| `GET /api/uptime` | Get server uptime information |

### Admin Endpoints (login required)

| Endpoint | Description |
|----------|-------------|
| `POST /api/collect` | Trigger collection |
| `POST /api/servers/add` | Add server |
| `DELETE /api/servers/{bmc_ip}` | Delete server |
| `POST /api/server/{bmc_ip}/clear_sel` | Clear BMC SEL |
| `PUT /api/maintenance/{id}` | Update maintenance task status |
| `PUT /api/settings/credentials/defaults` | Set global credential defaults |
| `POST /api/settings/credentials/apply` | Apply defaults to multiple servers |

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
