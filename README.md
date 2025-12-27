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
<td><img src="docs/server-detail-syslogs.png" alt="System Logs" width="400"/><br/><em>System Logs - SSH-based dmesg, syslog, journalctl</em></td>
</tr>
</table>

## ✨ Features

### 🆓 Free Self-Hosted Features
- 🔍 **Event Collection** - Automatically collect IPMI SEL logs (parallel, 32 workers)
- 📊 **Real-time Dashboard** - Auto-refreshing every second with server status cards
- 🌡️ **Sensor Monitoring** - Temperature, fan, voltage, power readings
- 💾 **ECC Memory Tracking** - Identify which DIMM has errors
- 🎮 **GPU Health Monitoring** - Detect NVIDIA GPU errors via SSH (Xid errors)
- 📜 **SSH System Logs** - Collect dmesg, journalctl, syslog, mcelog via SSH
- 🔧 **Hardware Error Detection** - AER, PCIe, ECC errors parsed automatically
- 🔄 **Uptime & Reboot Detection** - Track unexpected server reboots
- 🚨 **Alert Rules** - Configurable alerts with email, Telegram, webhooks
- ✅ **Alert Resolution** - Notifications when issues are resolved
- ⏱️ **Alert Confirmation** - Threshold checks to avoid false positives
- 📈 **Prometheus Metrics** - Native `/metrics` endpoint for Grafana
- 🔐 **User Management** - Admin and read-only access levels
- 📥 **Full Backup/Restore** - Export everything: servers, credentials, SSH keys, alerts
- 🐳 **Docker Ready** - Multi-arch images (amd64/arm64)
- 🔄 **Version Display** - Shows version, git commit, and build time in header
- ⬆️ **Update Notifications** - Checks GitHub for newer releases
- 🔧 **Bulk Credentials** - Apply SSH/IPMI credentials to multiple servers at once
- 🔃 **BMC Reset** - Cold/warm reset BMC without affecting host OS

### 🤖 Optional AI Features (via CryptoLabs)
- 📊 Daily health summaries with GPU error detection
- 🔧 AI-generated maintenance tasks
- 📈 Failure predictions
- 🔍 Root cause analysis with severity filtering
- 💬 AI chat assistant
- 🤖 **AI Recovery Agent** - Autonomous GPU recovery with escalation
- 🛠️ **Recovery Actions** - Clock limiting, soft resets, coordinated reboots
- 🏢 **Multi-Site Support** - One account, multiple datacenter locations
- 🔗 **Instance Fingerprinting** - Track all installations automatically
- 📋 **Remote Task Queue** - AI service sends tasks, Monitor executes

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

## ⚠️ Important: Data Persistence

**Always use a named volume** to preserve your data across container updates:

```yaml
# ✅ CORRECT - Named volume (survives updates)
volumes:
  - ipmi_data:/app/data

# ❌ WRONG - No volume (data lost on rebuild)
# (no volume specified)
```

---

## 🔄 Keeping Up to Date

```bash
# Pull the latest image
docker pull ghcr.io/cryptolabsza/ipmi-monitor:latest

# Recreate the container
docker-compose up -d
```

Or use [Watchtower](https://containrrr.dev/watchtower/) for automatic updates.

| Tag | Description |
|-----|-------------|
| `:latest` | Latest stable release (recommended) |
| `:dev` | Development builds (testing new features) |

---

## ⚙️ Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `APP_NAME` | IPMI Monitor | Displayed in header |
| `IPMI_USER` | admin | Default BMC username |
| `IPMI_PASS` | (required) | Default BMC password |
| `ADMIN_USER` | admin | Dashboard admin username |
| `ADMIN_PASS` | changeme | Dashboard admin password |
| `SECRET_KEY` | (auto) | Flask session secret (**set this!**) |
| `POLL_INTERVAL` | 300 | Seconds between collections |
| `DATA_RETENTION_DAYS` | 30 | How long to keep events |

---

## 🤖 AI Features (Optional)

Upgrade your monitoring with AI-powered insights from CryptoLabs:

| Feature | Description |
|---------|-------------|
| 📊 **Daily Summaries** | AI analyzes your fleet health daily with GPU focus |
| 🔧 **Maintenance Tasks** | Auto-generated from events |
| 📈 **Predictions** | Failure warnings before they happen |
| 🔍 **Root Cause Analysis** | AI explains what went wrong with severity filtering |
| 💬 **Chat** | Ask questions about your servers |
| 🏢 **Multi-Site** | Aggregate all your sites under one account |
| 🤖 **Agent Task Queue** | AI sends recovery tasks for execution |
| 🔍 **Post-Event RCA** | Investigate what happened during downtime |

### Enable AI

1. Go to **Settings** → **AI Features**
2. Click **Start Free Trial** (1 month free!)
3. Create account or login at CryptoLabs
4. Configure your **Site Name** for multi-site support
5. You're connected!

### Pricing

| Tier | Price | Servers | Tokens/month | Trial |
|------|-------|---------|--------------|-------|
| Free | $0 | Unlimited | - | Basic monitoring only |
| Standard | $100/mo | 50 servers | 1M tokens | 1 month free |
| Standard+ | +$15/10 servers | 51+ | +100K tokens | - |
| Professional | $500/mo | 500 servers | 10M tokens | 1 month free |

> 💡 **Tokens** are used for AI chat, summaries, and predictions. 1M tokens ≈ 2000+ AI queries/month.

---

## 📋 API Reference

### Public Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /` | Dashboard |
| `GET /api/servers` | List servers |
| `GET /api/events` | Get events (filterable) |
| `GET /api/stats` | Dashboard stats |
| `GET /api/sensors/{bmc_ip}` | Sensor readings |
| `GET /metrics` | Prometheus metrics |
| `GET /health` | Health check |
| `GET /api/version` | Current version info |
| `GET /api/version/check` | Check for updates |
| `POST /api/server/{bmc_ip}/investigate` | Post-event RCA investigation |
| `POST /api/server/{bmc_ip}/bmc/{action}` | BMC reset (cold/warm/info) |
| `GET /api/server/{bmc_ip}/ssh-logs` | Get SSH system logs |

### Admin Endpoints (login required)

| Endpoint | Description |
|----------|-------------|
| `POST /api/collect` | Trigger collection |
| `POST /api/servers/add` | Add server |
| `DELETE /api/servers/{bmc_ip}` | Delete server |
| `PUT /api/ai/config` | Update AI config (including site_name) |
| `GET /api/backup` | Full configuration backup |
| `POST /api/restore` | Restore from backup |

---

## 🔒 Security

IPMI Monitor is designed with security in mind for production datacenter environments:

### Credential Protection
- **No Command-Line Exposure** - IPMI passwords use environment variables (`IPMI_PASSWORD`), not `-P` flags
- **SSH Key Isolation** - SSH private keys stored in temporary files with 0600 permissions
- **Password Masking** - Passwords passed via `SSHPASS` environment variable, not command line
- **No Credential Sync** - Credentials are **never** sent to the AI cloud service

### Data Handling
- **Local-First** - All data stored locally in SQLite, cloud sync is optional
- **Minimal Cloud Data** - Only events, sensors, inventory, and logs synced (no credentials)
- **Secret Redaction** - AI responses automatically redact any detected credentials

### Access Control
- **Role-Based Access** - Admin vs read-only user levels
- **Session Management** - Secure Flask sessions with configurable secret key
- **API Authentication** - Protected endpoints require authentication

### AI Safety (Optional)
- **Input Validation** - SafetyAgent detects prompt injection and code injection
- **Threat Blocking** - Malicious queries blocked before reaching LLM
- **Output Filtering** - Secret redaction prevents accidental credential exposure

### Best Practices
```yaml
environment:
  - SECRET_KEY=your-random-32-char-key  # Always set this!
  - ADMIN_PASS=strong-unique-password   # Change from default
```

---

## 🛠️ Developer Guide

See [DEVELOPER_GUIDE.md](docs/DEVELOPER_GUIDE.md) for:

- Git workflow (develop/main branches)
- Release process
- Docker tag conventions
- CI/CD pipeline details

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
- **Documentation**: [cryptolabsza.github.io/ipmi-monitor](https://cryptolabsza.github.io/ipmi-monitor)
- **Support**: [CryptoLabs Discord](https://discord.gg/cryptolabs)

---

<p align="center">
  Made with ❤️ by <a href="https://cryptolabs.co.za">CryptoLabs</a>
</p>
