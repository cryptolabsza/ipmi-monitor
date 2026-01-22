---
layout: default
title: IPMI Monitor Documentation
---

# IPMI Monitor

**Free, self-hosted IPMI/BMC monitoring for your server fleet.**

[![GitHub](https://img.shields.io/github/stars/cryptolabsza/ipmi-monitor?style=social)](https://github.com/cryptolabsza/ipmi-monitor)
[![Docker Build](https://github.com/cryptolabsza/ipmi-monitor/actions/workflows/docker-build.yml/badge.svg)](https://github.com/cryptolabsza/ipmi-monitor/actions/workflows/docker-build.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Collect System Event Logs (SEL), monitor sensors, track ECC errors, gather SSH system logs, and get alerts — all from a beautiful web dashboard.

---

## 📖 Documentation

| Guide | Description |
|-------|-------------|
| [User Guide](user-guide.html) | Complete documentation for using IPMI Monitor |
| [IPMI SEL Reference](IPMI_SEL_REFERENCE.html) | Decode BMC event logs and troubleshoot hardware issues |
| [Developer Guide](DEVELOPER_GUIDE.html) | Git workflow, releases, CI/CD |

---

## 🚀 Quick Start

### One Command Setup (Recommended)

```bash
# Ubuntu 24.04+ / Python 3.12+
sudo apt install pipx -y
pipx install ipmi-monitor
pipx ensurepath && source ~/.bashrc
sudo ipmi-monitor quickstart

# Ubuntu 22.04 / Python 3.10
pip install ipmi-monitor
sudo ipmi-monitor quickstart
```

**That's it!** Answer a few questions and Docker containers are deployed automatically.

### Docker Run (Alternative)

```bash
docker run -d \
  --name ipmi-monitor \
  -p 5000:5000 \
  -v ipmi_data:/app/data \
  -e IPMI_USER=admin \
  -e IPMI_PASS=YourBMCPassword \
  -e ADMIN_PASS=YourAdminPassword \
  -e SECRET_KEY=your-random-secret-key \
  ghcr.io/cryptolabsza/ipmi-monitor:latest
```

Then open **http://localhost:5000** and add your servers!

See [User Guide](user-guide.md#quick-start) for Docker Compose setup.

---

## 💻 CLI Commands

After installation, use the `ipmi-monitor` CLI:

| Command | Description |
|---------|-------------|
| `sudo ipmi-monitor quickstart` | ⚡ One-command Docker deployment (recommended) |
| `ipmi-monitor status` | Show container status |
| `ipmi-monitor logs [-f]` | View container logs |
| `ipmi-monitor start` | Start containers |
| `ipmi-monitor stop` | Stop containers |
| `ipmi-monitor restart` | Restart containers |
| `ipmi-monitor upgrade` | Pull latest image & restart |
| `ipmi-monitor add-server` | Add a server interactively |
| `ipmi-monitor list-servers` | List configured servers |
| `ipmi-monitor setup-ssl` | Set up HTTPS reverse proxy |
| `ipmi-monitor uninstall` | Uninstall IPMI Monitor |
| `ipmi-monitor version` | Show detailed version info |

---

## 📸 Screenshots

![Dashboard](dashboard.png)
*Main dashboard showing 39 servers with real-time status*

<table>
<tr>
<td><img src="server-detail-events.png" alt="Events"/><br/><em>Event Log - SEL events</em></td>
<td><img src="server-detail-sensors.png" alt="Sensors"/><br/><em>Live Sensors</em></td>
</tr>
<tr>
<td><img src="server-detail-inventory.png" alt="Inventory"/><br/><em>Hardware Inventory</em></td>
<td><img src="server-detail-syslogs.png" alt="System Logs"/><br/><em>SSH System Logs</em></td>
</tr>
</table>

---

## ✨ Features

### 🆓 Free Self-Hosted

| Feature | Description |
|---------|-------------|
| 🔍 **SEL Collection** | Parallel IPMI event collection (32 workers) |
| 📊 **Real-time Dashboard** | Auto-refreshing server status cards |
| 🌡️ **Sensor Monitoring** | Temperature, fan, voltage, power readings |
| 💾 **ECC Tracking** | Identify which DIMM has memory errors |
| 🎮 **GPU Health** | Detect NVIDIA Xid errors via SSH |
| 📜 **SSH System Logs** | Collect dmesg, journalctl, syslog, mcelog |
| 🔧 **Hardware Errors** | AER, PCIe, ECC errors parsed automatically |
| 🚨 **Alerts** | Email, Telegram, webhook notifications |
| ✅ **Alert Resolution** | Notify when issues clear |
| 📈 **Prometheus** | Native `/metrics` endpoint for Grafana |
| 🔐 **User Management** | Admin and read-only access levels |
| 📥 **Backup/Restore** | Export everything for disaster recovery |
| 🔃 **BMC Reset** | Cold/warm reset without affecting host OS |
| 🐳 **Docker Ready** | Multi-arch images (amd64/arm64) |

### 🤖 AI Features (Optional)

Upgrade with AI-powered insights from [CryptoLabs](https://cryptolabs.co.za):

| Feature | Description |
|---------|-------------|
| 📊 **Daily Summaries** | AI-generated fleet health with GPU focus |
| 🔧 **Maintenance Tasks** | Auto-generated from events |
| 📈 **Predictions** | Failure warnings before they happen |
| 🔍 **Root Cause Analysis** | AI explains what went wrong |
| 💬 **AI Chat** | Ask questions about your servers |
| 🤖 **Recovery Agent** | Autonomous GPU recovery with escalation |
| 🏢 **Multi-Site** | One account, multiple datacenters |
| 📋 **Task Queue** | AI sends recovery tasks for execution |

**Start your free trial:** Settings → AI Features → Start Free Trial

---

## ⚙️ Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `APP_NAME` | IPMI Monitor | Displayed in header |
| `IPMI_USER` | admin | Default BMC username |
| `IPMI_PASS` | (required) | Default BMC password |
| `ADMIN_PASS` | changeme | Dashboard admin password |
| `SECRET_KEY` | (auto) | Flask session secret (**set this!**) |
| `POLL_INTERVAL` | 300 | Seconds between collections |
| `SSH_LOG_INTERVAL` | (disabled) | Minutes between SSH log collection |

---

## 🔒 Security

IPMI Monitor is designed for production datacenter environments:

- **No Command-Line Exposure** - Passwords via environment variables
- **SSH Key Isolation** - Private keys in temporary files with 0600 permissions
- **No Credential Sync** - Credentials **never** sent to AI cloud
- **Local-First** - All data stored locally, cloud sync optional
- **Secret Redaction** - AI responses automatically mask credentials

---

## 📋 API Reference

### Public Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /` | Dashboard |
| `GET /api/servers` | List all servers |
| `GET /api/events` | Get events (filterable) |
| `GET /api/sensors/{bmc_ip}` | Sensor readings |
| `GET /api/server/{bmc_ip}/ssh-logs` | SSH system logs |
| `GET /metrics` | Prometheus metrics |
| `GET /health` | Health check |

### Admin Endpoints

| Endpoint | Description |
|----------|-------------|
| `POST /api/collect` | Trigger collection |
| `POST /api/servers/add` | Add server |
| `POST /api/server/{bmc_ip}/bmc/{action}` | BMC reset |
| `GET /api/backup` | Full configuration backup |
| `POST /api/restore` | Restore from backup |

---

## 🔗 Links

- **GitHub**: [github.com/cryptolabsza/ipmi-monitor](https://github.com/cryptolabsza/ipmi-monitor)
- **Docker**: [ghcr.io/cryptolabsza/ipmi-monitor](https://ghcr.io/cryptolabsza/ipmi-monitor)
- **Discord**: [Join our Discord](https://discord.gg/7yeHdf5BuC)
- **AI Features**: [cryptolabs.co.za](https://cryptolabs.co.za)

---

## 🆘 Support

- 💬 [Join our Discord](https://discord.gg/7yeHdf5BuC) - Get help, chat with the community
- 🐛 [Report a Bug](https://github.com/cryptolabsza/ipmi-monitor/issues/new)
- 💡 [Request a Feature](https://github.com/cryptolabsza/ipmi-monitor/issues/new)
- 💬 [Discussions](https://github.com/cryptolabsza/ipmi-monitor/discussions)
- 📧 [support@cryptolabs.co.za](mailto:support@cryptolabs.co.za)

---

<p align="center">
  <strong>MIT License</strong> · Made with ❤️ by <a href="https://cryptolabs.co.za">CryptoLabs</a>
</p>
