---
layout: default
title: IPMI Monitor Documentation
---

# IPMI Monitor

**Web-based server hardware monitoring via IPMI and Redfish**

[![GitHub](https://img.shields.io/github/stars/cryptolabsza/ipmi-monitor?style=social)](https://github.com/cryptolabsza/ipmi-monitor)
[![Docker](https://img.shields.io/docker/pulls/cryptolabsza/ipmi-monitor)](https://ghcr.io/cryptolabsza/ipmi-monitor)

---

## Documentation

📖 **[User Guide](user-guide.md)** - Complete documentation for using IPMI Monitor

---

## Quick Links

- [Overview](user-guide.md#overview)
- [Quick Start](user-guide.md#quick-start)
- [Dashboard](user-guide.md#dashboard)
- [Settings](user-guide.md#settings)
- [Prometheus & Grafana](user-guide.md#prometheus--grafana-integration)
- [AI Features](user-guide.md#ai-features)
- [Troubleshooting](user-guide.md#troubleshooting)
- [API Reference](user-guide.md#api-reference)

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
      - ~/.ssh:/root/.ssh:ro  # Optional: for SSH inventory
    environment:
      - IPMI_USER=admin
      - IPMI_PASS=password
    restart: unless-stopped

volumes:
  ipmi_data:
```

---

## Features

✅ **Multi-server monitoring** - Monitor hundreds of servers from one dashboard  
✅ **Real-time alerts** - Telegram, email, webhook notifications  
✅ **Hardware inventory** - CPU, memory, storage, GPU details  
✅ **Prometheus metrics** - Built-in exporter with Grafana dashboard  
✅ **AI-powered insights** - Predictive maintenance and root cause analysis  
✅ **Remote power control** - Power on/off/cycle from the web UI  

---

## Screenshots

*Coming soon*

---

## License

MIT License - See [LICENSE](https://github.com/cryptolabsza/ipmi-monitor/blob/main/LICENSE)

---

## Support

- 🐛 [Report a Bug](https://github.com/cryptolabsza/ipmi-monitor/issues/new?template=bug_report.md)
- 💡 [Request a Feature](https://github.com/cryptolabsza/ipmi-monitor/issues/new?template=feature_request.md)
- 💬 [Discussions](https://github.com/cryptolabsza/ipmi-monitor/discussions)

