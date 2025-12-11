---
layout: default
title: IPMI Monitor Documentation
---

# IPMI Monitor

**Web-based server hardware monitoring via IPMI and Redfish**

[![GitHub](https://img.shields.io/github/stars/cryptolabsza/ipmi-monitor?style=social)](https://github.com/cryptolabsza/ipmi-monitor)
[![Docker](https://img.shields.io/docker/pulls/cryptolabsza/ipmi-monitor)](https://ghcr.io/cryptolabsza/ipmi-monitor)
[![Docker Build](https://github.com/cryptolabsza/ipmi-monitor/actions/workflows/docker-build.yml/badge.svg)](https://github.com/cryptolabsza/ipmi-monitor/actions/workflows/docker-build.yml)

---

## Documentation

📖 **[User Guide](user-guide.md)** - Complete documentation for using IPMI Monitor

🛠️ **[Developer Guide](DEVELOPER_GUIDE.md)** - Git workflow, releases, CI/CD

---

## Quick Links

- [Overview](user-guide.md#overview)
- [Quick Start](user-guide.md#quick-start)
- [Dashboard](user-guide.md#dashboard)
- [Multi-Site Deployment](user-guide.md#multi-site-deployment)
- [GPU Health Monitoring](user-guide.md#gpu-health-monitoring)
- [AI Recovery Agent](user-guide.md#ai-recovery-agent)
- [Alert Configuration](user-guide.md#alert-configuration)
- [Settings](user-guide.md#settings)
- [Prometheus & Grafana](user-guide.md#prometheus--grafana-integration)
- [AI Features](user-guide.md#ai-features)
- [Troubleshooting](user-guide.md#troubleshooting)
- [API Reference](user-guide.md#api-reference)

---

## What's New in v0.7.x

### 🏢 Multi-Site Support (v0.7.0)
Deploy IPMI Monitor at multiple datacenters with a single license. Each site has its own instance but shares billing and account.

### 🔗 Instance Fingerprinting (v0.7.1)
Every IPMI Monitor installation generates a unique fingerprint for tracking and trial abuse prevention.

### 📊 All-Instance Telemetry (v0.7.2)
Even free users send basic stats, helping us understand usage patterns and improve the product.

### 👁️ Admin Instance Dashboard (v0.7.3)
View all IPMI Monitor instances across all customers with trial abuse detection.

### 🖼️ Modular AI Tabs (v0.7.4)
Embeddable AI views that can be integrated via iframes.

### 📋 Agent Task Queue (v0.7.5)
AI service can now send tasks (power cycles, BMC resets, SSH commands) to IPMI Monitor for remote execution.

### 🔍 Post-Event RCA (v0.7.6)
When a server recovers from an unreachable state, automatically investigate what happened during the downtime.

---

## Installation

### Docker (Recommended)

```bash
docker run -d \
  --name ipmi-monitor \
  -p 5000:5000 \
  -v ipmi_data:/app/data \
  -e IPMI_USER=admin \
  -e IPMI_PASS=password \
  -e SECRET_KEY=your-random-secret-key \
  ghcr.io/cryptolabsza/ipmi-monitor:latest
```

### Docker Compose

```yaml
version: '3.8'
services:
  ipmi-monitor:
    image: ghcr.io/cryptolabsza/ipmi-monitor:latest
    ports:
      - "5000:5000"
    volumes:
      - ipmi_data:/app/data
      - ./config/servers.yaml:/app/config/servers.yaml:ro  # Optional
    environment:
      - APP_NAME=My Server Fleet
      - IPMI_USER=admin
      - IPMI_PASS=password
      - ADMIN_PASS=changeme  # CHANGE THIS!
      - SECRET_KEY=your-random-secret-key
    restart: unless-stopped

volumes:
  ipmi_data:
```

---

## Features

### 🆓 Free Self-Hosted Features

✅ **Multi-server monitoring** - Monitor hundreds of servers from one dashboard  
✅ **Real-time dashboard** - Auto-refreshing every second  
✅ **Hardware alerts** - Telegram, email, webhook notifications  
✅ **Alert resolution** - Notifications when issues resolve  
✅ **Alert confirmation** - Threshold checks to prevent false positives  
✅ **Hardware inventory** - CPU, memory, storage, GPU details  
✅ **Prometheus metrics** - Built-in `/metrics` endpoint  
✅ **Remote power control** - Power on/off/cycle from web UI  
✅ **BMC Reset** - Cold/warm reset BMC without affecting host OS  
✅ **GPU Health Monitoring** - Detect NVIDIA GPU errors via SSH  
✅ **Uptime & Reboot Detection** - Track unexpected reboots  
✅ **Bulk Credentials** - Apply settings to multiple servers at once  
✅ **Full Backup/Restore** - Export everything for disaster recovery  
✅ **Version Updates** - Dashboard shows version and checks for updates  

### 🤖 AI Features (via CryptoLabs)

✅ **Fleet Health Summaries** - AI-generated overview with GPU focus  
✅ **Maintenance Tasks** - AI-identified work items with priorities  
✅ **Predictive Analytics** - Failure predictions before they happen  
✅ **Root Cause Analysis** - Deep analysis with severity filtering  
✅ **AI Chat** - Interactive assistant for questions  
✅ **AI Recovery Agent** - Autonomous GPU recovery with escalation  
✅ **Multi-Site Support** - One account for multiple datacenters  
✅ **Remote Task Execution** - AI sends tasks for IPMI Monitor to execute  
✅ **Post-Event Investigation** - AI investigates downtime causes  

---

## Multi-Site Deployment

Deploy IPMI Monitor at each datacenter location:

```
Your Company (Single Account)
├── NYC Datacenter: 50 servers
│   └── Site Name: "NYC Datacenter"
├── London Office: 30 servers
│   └── Site Name: "London Office"
└── Singapore Colo: 20 servers
    └── Site Name: "Singapore Colo"

Total: 100 servers, 1 license, 3 sites
```

### Configuration

1. Install IPMI Monitor at each location
2. Use the **same license key** everywhere
3. Settings → AI → Set unique **Site Name**
4. All sites appear in your CryptoLabs dashboard

---

## Screenshots

![Dashboard](dashboard.png)
*Main dashboard with server status cards and version display*

<table>
<tr>
<td><img src="server-detail-events.png" alt="Events"/><br/><em>Event Log</em></td>
<td><img src="server-detail-sensors.png" alt="Sensors"/><br/><em>Sensors</em></td>
</tr>
<tr>
<td><img src="server-detail-inventory.png" alt="Inventory"/><br/><em>Inventory</em></td>
<td><img src="login-page.png" alt="Login"/><br/><em>Login</em></td>
</tr>
</table>

---

## BMC Reset Feature

Reset the BMC without affecting the running OS:

- **BMC Cold Reset** - Full BMC reboot, clears all state
- **BMC Warm Reset** - Softer restart, preserves some state
- **BMC Info** - Check firmware version and status

Useful when BMC becomes unresponsive but the server is still running.

---

## Alert Features

### Confirmation Threshold
- Only fire alert after X consecutive failures
- Prevents false positives from transient issues
- Default: 3 checks for "Server Unreachable"

### Resolution Notifications
- Auto-resolve when condition clears
- "Notify on Resolve" toggle per rule
- Duration included in resolution message

---

## API Endpoints

### New in v0.7.x

```
POST /api/server/<bmc_ip>/investigate  - Post-event RCA
POST /api/server/<bmc_ip>/bmc/<action> - BMC reset (cold/warm/info)
GET  /api/recovery/permissions         - Recovery agent config
POST /api/alerts/history/<id>/resolve  - Manual alert resolution
GET  /api/backup                       - Full configuration backup
POST /api/restore                      - Restore from backup
```

### Version Endpoints

```
GET /api/version       - Get current version info
GET /api/version/check - Check for updates on GitHub
```

---

## License

MIT License - See [LICENSE](https://github.com/cryptolabsza/ipmi-monitor/blob/main/LICENSE)

---

## Support

- 🐛 [Report a Bug](https://github.com/cryptolabsza/ipmi-monitor/issues/new?template=bug_report.md)
- 💡 [Request a Feature](https://github.com/cryptolabsza/ipmi-monitor/issues/new?template=feature_request.md)
- 💬 [Discussions](https://github.com/cryptolabsza/ipmi-monitor/discussions)
- 📧 [Contact CryptoLabs](https://cryptolabs.co.za/contact)
