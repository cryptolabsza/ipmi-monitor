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

---

## Quick Links

- [Overview](user-guide.md#overview)
- [Quick Start](user-guide.md#quick-start)
- [Dashboard](user-guide.md#dashboard)
- [GPU Health Monitoring](user-guide.md#gpu-health-monitoring)
- [AI Recovery Agent](user-guide.md#ai-recovery-agent)
- [Settings](user-guide.md#settings)
- [Prometheus & Grafana](user-guide.md#prometheus--grafana-integration)
- [AI Features](user-guide.md#ai-features)
- [Troubleshooting](user-guide.md#troubleshooting)
- [API Reference](user-guide.md#api-reference)

---

## What's New in v1.6.0

🆕 **Version Display** - Dashboard shows current version with git commit and build time  
🆕 **Update Notifications** - Automatic check for new releases with one-click update info  
🆕 **GPU Error Summaries** - AI summaries now prominently feature GPU/Xid errors  
🆕 **RCA Event Filtering** - Filter Root Cause Analysis by severity (critical, warning, info)  
🆕 **Hierarchical Templates** - Per-client AI prompt customization  
🆕 **Improved Recovery Agent** - Better escalation with NVIDIA driver status checking  

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
      - ./config/servers.yaml:/app/config/servers.yaml:ro  # Optional: pre-configured servers
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
✅ **Real-time alerts** - Telegram, email, webhook notifications  
✅ **Hardware inventory** - CPU, memory, storage, GPU details via IPMI/Redfish/SSH  
✅ **Prometheus metrics** - Built-in `/metrics` endpoint for Grafana  
✅ **Remote power control** - Power on/off/cycle from the web UI  
✅ **GPU Health Monitoring** - Detect NVIDIA GPU errors via SSH (Xid errors)  
✅ **Uptime & Reboot Detection** - Track unexpected server reboots  
✅ **Maintenance Tasks** - Auto-generated from error patterns  
✅ **Global Credentials** - Set default IPMI/SSH credentials for entire fleet  
✅ **Version Updates** - Dashboard shows version and checks for updates  

### 🤖 AI Features (via CryptoLabs)

✅ **Fleet Health Summaries** - AI-generated overview with GPU issue detection  
✅ **Maintenance Tasks** - AI-identified work items with priorities  
✅ **Predictive Analytics** - Failure predictions before they happen  
✅ **Root Cause Analysis** - Deep analysis with severity filtering  
✅ **AI Chat** - Interactive assistant for questions  
✅ **AI Recovery Agent** - Autonomous GPU recovery with escalation ladder  
✅ **Per-Client Templates** - Custom AI prompts per customer  

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

## Version Display

The dashboard header shows your current version:

```
IPMI Monitor
v1.6.0 (main@8d7150c, 2025-12-07 22:41 UTC)
```

- **Click the version badge** to check for updates
- **Green badge appears** when a newer version is available
- **Update popup** shows docker pull command

### API Endpoints

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

