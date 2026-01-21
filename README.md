# IPMI Monitor

[![PyPI](https://img.shields.io/pypi/v/ipmi-monitor.svg)](https://pypi.org/project/ipmi-monitor/)
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

- 🔍 **Event Collection** - Automatically collect IPMI SEL logs (parallel, 32 workers)
- 📊 **Real-time Dashboard** - Auto-refreshing every second with server status cards
- 🌡️ **Sensor Monitoring** - Temperature, fan, voltage, power readings
- 💾 **ECC Memory Tracking** - Identify which DIMM has errors
- 🎮 **GPU Health Monitoring** - Detect NVIDIA GPU errors via SSH (Xid errors)
- 📜 **SSH System Logs** - Collect dmesg, journalctl, syslog, mcelog, **Docker daemon logs** via SSH
- 🐳 **Docker Log Collection** - Monitor Docker daemon errors (storage-opt, overlay, pquota issues)
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
- 🤖 **Optional AI Features** - Enable AI-powered insights via Settings → AI Features

---

## 🚀 Quick Start

### One Command Setup ⚡

**Ubuntu 24.04+ / Python 3.12+** (uses pipx):
```bash
sudo apt install pipx -y
pipx install ipmi-monitor
pipx ensurepath && source ~/.bashrc
sudo ipmi-monitor quickstart
```

**Ubuntu 22.04 / Python 3.10** (direct pip):
```bash
pip install ipmi-monitor
sudo ipmi-monitor quickstart
```

**Alternative** (if you get "externally-managed-environment" error):
```bash
pip install ipmi-monitor --break-system-packages
sudo ipmi-monitor quickstart
```

**That's it!** Answer a few questions:

```
╭──────────────────────────────────────────────────╮
│           IPMI Monitor - Quick Setup             │
╰──────────────────────────────────────────────────╯

Detected: my-server (192.168.1.100)

Step 1: Add Server to Monitor
  Server name: gpu-server-01
  BMC IP address: 192.168.1.80
  BMC username: ADMIN
  BMC password: ******
  ✓ IPMI connection successful
  
  Add SSH access for detailed monitoring? [Y/n]: y
  Server IP (for SSH): 192.168.1.81
  SSH username: root
  SSH password: ******

Step 2: Web Interface Settings
  Web interface port: [5000]

Step 3: AI Features (Optional)
  Enable AI Insights? [y/N]: n

Step 4: Starting IPMI Monitor
  ✓ Configuration saved
  ✓ Service installed and started

╭──────────────────────────────────────────────────╮
│              ✓ Setup Complete!                   │
╰──────────────────────────────────────────────────╯
Web Interface: http://192.168.1.100:5000
```

### After Setup

```bash
# Add more servers
ipmi-monitor add-server --bmc-ip 192.168.1.82 --username admin

# Check status
ipmi-monitor status

# View logs
ipmi-monitor logs
```

### Bulk Import (Many Servers)

During quickstart, choose "Import from file" or "Paste text" to add multiple servers at once.

**Create a servers.txt file:**
```bash
# servers.txt - Example server list
# Lines starting with # are comments

# Set global credentials (applied to all servers below)
globalSSH:root,sshpassword
globalIPMI:ADMIN,ipmipassword

# Server list: serverIP,bmcIP (or just serverIP if same)
192.168.1.101,192.168.1.80
192.168.1.102,192.168.1.82
192.168.1.103,192.168.1.84
```

**Then run quickstart and select "Import from file":**
```bash
sudo ipmi-monitor quickstart
# Select: "Import from file (e.g., servers.txt)"
# Enter path: /root/servers.txt
```

**Alternative formats:**

**SSH only (no IPMI):**
```
global:root,sshpassword
192.168.1.101
192.168.1.102
```

**Per-server credentials:**
```
# serverIP,sshUser,sshPass,ipmiUser,ipmiPass,bmcIP
192.168.1.101,root,pass1,ADMIN,ipmi1,192.168.1.80
192.168.1.102,root,pass2,ADMIN,ipmi2,192.168.1.82
```

---

## 🔗 Full Datacenter Suite

For complete GPU datacenter monitoring, combine with [DC Overview](https://github.com/cryptolabsza/dc-overview):

```bash
# On master server - install both tools
pip install dc-overview ipmi-monitor

# dc-overview: Grafana + Prometheus + GPU metrics
sudo dc-overview quickstart

# ipmi-monitor: BMC/IPMI health + SEL logs + AI insights
sudo ipmi-monitor quickstart
```

| Tool | What it monitors |
|------|------------------|
| **dc-overview** | GPU utilization, temperature, power, CPU, RAM, disk |
| **ipmi-monitor** | BMC health, SEL events, ECC errors, sensors, system logs |

### CLI Commands

```bash
ipmi-monitor setup              # Interactive setup wizard
ipmi-monitor run                # Start web interface
ipmi-monitor run --port 8080    # Custom port
ipmi-monitor daemon             # Run as daemon (for systemd)
ipmi-monitor status             # Show status and config
ipmi-monitor add-server         # Add a server interactively
ipmi-monitor list-servers       # List configured servers
```

---

### Option 2: Docker Compose

For containerized deployments or if you prefer Docker:

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
    labels:
      - "com.centurylinklabs.watchtower.enable=true"  # Enable auto-updates

volumes:
  ipmi_data:
```

**Step 3:** Start the service
```bash
docker-compose up -d
```

**Step 4:** Open http://localhost:5000 and add your servers!

---

### Option 3: Docker Run

```bash
# Create a named volume for data persistence
docker volume create ipmi_data

# Run the container
docker run -d \
  --name ipmi-monitor \
  --label com.centurylinklabs.watchtower.enable=true \
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

## 📁 Configuration File Reference

### servers.yaml

```yaml
servers:
  - name: GPU-Server-01           # Display name
    bmc_ip: 192.168.1.80          # BMC/IPMI IP (required)
    username: admin               # BMC username
    password: ipmi-password       # BMC password
    protocol: auto                # auto, ipmi, or redfish
    
    # Optional: SSH for system logs
    server_ip: 192.168.1.81       # Server OS IP
    ssh_user: root
    ssh_port: 22
    ssh_password: ssh-password    # Or use ssh_key
    ssh_key: ~/.ssh/id_rsa        # Path to SSH private key
```

### config.yaml

```yaml
settings:
  web_port: 5000
  refresh_interval: 60           # Seconds between collections
  enable_prometheus: true        # /metrics endpoint

ai:
  enabled: false                 # Enable AI features
  license_key: sk-ipmi-xxxx      # CryptoLabs license key
```

---

## 🔄 Keeping Up to Date

### pip install

```bash
pip install --upgrade ipmi-monitor
sudo systemctl restart ipmi-monitor
```

### Docker Manual Update

```bash
# Pull the latest image
docker pull ghcr.io/cryptolabsza/ipmi-monitor:latest

# Recreate the container (preserves data volume)
docker-compose up -d
```

### Automatic Updates with Watchtower (Docker)

Add Watchtower to your `docker-compose.yml`:

```yaml
services:
  ipmi-monitor:
    # ... your existing config ...
    labels:
      - "com.centurylinklabs.watchtower.enable=true"

  watchtower:
    image: containrrr/watchtower
    container_name: watchtower
    restart: unless-stopped
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    environment:
      - WATCHTOWER_CLEANUP=true
      - WATCHTOWER_POLL_INTERVAL=300  # Check every 5 minutes
    command: --label-enable  # Only update labeled containers
```

| Tag | Description |
|-----|-------------|
| `:latest` | Latest stable release (recommended) |
| `:develop` | Development builds (testing new features) |
| `:v1.0.3` | Specific version (pin for stability) |

---

## 🔍 Troubleshooting

### Container won't start

```bash
# Check logs
docker logs ipmi-monitor

# Common issues:
# - Port 5000 already in use: Change port mapping to "5001:5000"
# - Permission denied: Ensure docker socket access
```

### Can't connect to BMC

```bash
# Test from the container
docker exec ipmi-monitor ipmitool -I lanplus -H 192.168.1.80 -U admin -P password power status

# Common issues:
# - Wrong IP address (use BMC IP, not server OS IP)
# - Firewall blocking port 623 (IPMI)
# - Wrong credentials
```

### SSH inventory collection fails

```bash
# Test SSH from container
docker exec ipmi-monitor ssh -o StrictHostKeyChecking=no root@192.168.1.81 hostname

# Common issues:
# - SSH key not added to container (add via Settings → SSH Keys)
# - Server IP not set (only BMC IP configured)
# - Firewall blocking port 22
```

### Data disappeared after update

Your volume name must match! Check with:
```bash
docker volume ls | grep ipmi
```

If you see multiple volumes (e.g., `ipmi_data` and `ipmi-monitor_ipmi_data`), you may have used different names. Restore by:
```bash
docker stop ipmi-monitor
docker run --rm -v OLD_VOLUME:/from -v NEW_VOLUME:/to alpine cp -av /from/. /to/
```

---

## ⚙️ Environment Variables (Docker)

| Variable | Default | Description |
|----------|---------|-------------|
| `APP_NAME` | IPMI Monitor | Displayed in header |
| `IPMI_USER` | admin | Default BMC username |
| `IPMI_PASS` | (required) | Default BMC password |
| `IPMI_PASS_NVIDIA` | - | Separate password for NVIDIA DGX BMCs (16-char requirement) |
| `ADMIN_USER` | admin | Dashboard admin username |
| `ADMIN_PASS` | changeme | Dashboard admin password (**change this!**) |
| `SECRET_KEY` | (auto) | Flask session secret (**set this for persistent sessions!**) |
| `POLL_INTERVAL` | 300 | Seconds between collections |
| `DATA_RETENTION_DAYS` | 30 | How long to keep events |
| `SSH_USER` | root | Default SSH username for system log collection |
| `SSH_PASS` | - | Default SSH password (or use SSH keys) |

---

## 🔧 Setting Up SSH for Enhanced Monitoring

SSH access enables powerful features:
- **System Logs** - dmesg, journalctl, syslog, Docker daemon logs
- **Hardware Inventory** - Detailed CPU, DIMM, GPU, NIC, storage info
- **GPU Monitoring** - NVIDIA Xid errors, driver version, CUDA version
- **Uptime Tracking** - Detect unexpected reboots

### Option 1: SSH Keys (Recommended)

1. Go to **Settings → SSH Keys**
2. Click **Add SSH Key**
3. Paste your private key content (from `~/.ssh/id_rsa` or similar)
4. Give it a name (e.g., "datacenter-key")
5. In **Settings → Servers**, assign the key to each server

### Option 2: SSH Password

1. Go to **Settings → Defaults**
2. Enter your SSH username and password
3. Click **Apply to All Servers**

### Important: Server IP vs BMC IP

- **BMC IP** (e.g., `192.168.1.80`) - IPMI/Redfish management interface
- **Server IP** (e.g., `192.168.1.81`) - The actual OS/SSH interface

When adding a server, set **both** IPs:
- BMC IP: For IPMI/Redfish event collection
- Server IP: For SSH-based inventory and logs

---

## 🎮 GPU Monitoring (NVIDIA)

IPMI Monitor can detect and monitor NVIDIA GPUs via SSH:

- **GPU Count & Models** - Detected via `nvidia-smi`
- **Driver & CUDA Version** - For compatibility tracking
- **Xid Errors** - Parsed from dmesg/syslog (GPU failures, ECC errors)
- **PCIe Health** - AER/correctable/uncorrectable errors

### Collecting GPU Inventory

1. Ensure SSH is configured for the server
2. Go to server detail page
3. Click **Collect Inventory**
4. GPU info appears under **🎮 GPU** section

---

## 📋 Detailed DIMM Inventory

For servers with Redfish or SSH access, IPMI Monitor collects per-DIMM details:

- **Slot/Locator** (e.g., A1, B2)
- **Manufacturer** (Samsung, SK Hynix, Micron, etc.)
- **Part Number**
- **Size** (32 GB, 64 GB)
- **Speed** (Configured vs Rated - highlights if running slower)

This helps identify:
- Mixed memory configurations
- Under-clocked DIMMs
- Which slot has ECC errors

---

## 🤖 AI Features (Optional)

IPMI Monitor can integrate with the CryptoLabs AI service for:
- **Fleet Summary** - AI-generated daily analysis
- **Predictive Maintenance** - Identify failing components
- **Root Cause Analysis** - Correlate events across servers
- **Task Generation** - Prioritized maintenance tasks

### Enabling AI Features

1. Go to **Settings → AI Features**
2. Get an API key from [cryptolabs.co.za/my-account](https://cryptolabs.co.za/my-account/)
3. Enter the key and click **Enable**

> 📌 AI features are **optional** - IPMI Monitor works fully offline without them.

---

## 🔌 IPMI vs Redfish

IPMI Monitor supports both protocols and auto-detects which to use:

| Feature | IPMI/ipmitool | Redfish |
|---------|---------------|---------|
| Event Collection | ✅ SEL logs | ✅ Log Service |
| Sensor Readings | ✅ SDR | ✅ Chassis/Thermal |
| Power Control | ✅ | ✅ |
| Inventory | Basic FRU | ✅ Rich metadata |
| Memory Details | - | ✅ Per-DIMM info |
| Supported BMCs | All | Dell iDRAC, HPE iLO, Supermicro, Lenovo |

### Forcing a Protocol

By default, IPMI Monitor auto-detects. To force a specific protocol:
1. Go to **Settings → Servers**
2. Click Edit on a server
3. Set **Protocol** to `ipmi` or `redfish`

---

## 🚨 Alert Configuration

IPMI Monitor can send alerts via multiple channels:

### Notification Methods

| Method | Setup |
|--------|-------|
| **Email** | Settings → Alerts → SMTP configuration |
| **Telegram** | Settings → Alerts → Bot token + Chat ID |
| **Webhook** | Settings → Alerts → Custom URL for Slack, Discord, etc. |

### Alert Rules

Create rules to trigger on specific conditions:
- **Event Type** - SEL event categories (Temperature, Memory, Fan, etc.)
- **Severity** - Critical, Warning, or both
- **Server Filter** - All servers or specific ones
- **Keyword Match** - Filter by event description

### Alert Features

- **Confirmation Period** - Wait N minutes before alerting (avoid false positives)
- **Resolution Alerts** - Get notified when issues are resolved
- **Rate Limiting** - Prevent alert floods

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
| `POST /api/server/{bmc_ip}/bmc/{action}` | BMC reset (cold/warm/info) |
| `GET /api/server/{bmc_ip}/ssh-logs` | Get SSH system logs |

### Admin Endpoints (login required)

| Endpoint | Description |
|----------|-------------|
| `POST /api/collect` | Trigger collection |
| `POST /api/servers/add` | Add server |
| `DELETE /api/servers/{bmc_ip}` | Delete server |
| `GET /api/backup` | Full configuration backup |
| `POST /api/restore` | Restore from backup |

---

## 🔒 Security

IPMI Monitor is designed with security in mind for production datacenter environments:

### Credential Protection
- **No Command-Line Exposure** - IPMI passwords use environment variables (`IPMI_PASSWORD`), not `-P` flags
- **SSH Key Isolation** - SSH private keys stored in temporary files with 0600 permissions
- **Password Masking** - Passwords passed via `SSHPASS` environment variable, not command line

### Data Handling
- **Local-First** - All data stored locally in SQLite
- **No Credential Sync** - Credentials are **never** sent externally

### Access Control
- **Role-Based Access** - Admin vs read-only user levels
- **Session Management** - Secure Flask sessions with configurable secret key
- **API Authentication** - Protected endpoints require authentication

### Best Practices
```yaml
environment:
  - SECRET_KEY=your-random-32-char-key  # Always set this!
  - ADMIN_PASS=strong-unique-password   # Change from default
```

---

## 🔑 Password Recovery

IPMI Monitor is self-hosted - there's no central server to reset your password. Since you have root access, you can reset it directly:

```bash
# Quick password reset (run on your server)
docker exec -i ipmi-monitor python3 << 'EOF'
from werkzeug.security import generate_password_hash
import sqlite3
new_password = "your_new_password"  # CHANGE THIS
conn = sqlite3.connect('/var/lib/ipmi-monitor/ipmi_events.db')
conn.execute("UPDATE user SET password_hash = ? WHERE username = 'admin'", 
             (generate_password_hash(new_password),))
conn.commit()
print(f"✅ Admin password updated!")
EOF
```

> 📖 See [User Guide - Password Recovery](docs/user-guide.md#password-recovery) for detailed instructions and a reusable script.

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

- **PyPI**: [pypi.org/project/ipmi-monitor](https://pypi.org/project/ipmi-monitor/)
- **GitHub**: [github.com/cryptolabsza/ipmi-monitor](https://github.com/cryptolabsza/ipmi-monitor)
- **Docker Image**: [ghcr.io/cryptolabsza/ipmi-monitor](https://ghcr.io/cryptolabsza/ipmi-monitor)
- **Documentation**: [github.com/cryptolabsza/ipmi-monitor/docs](https://github.com/cryptolabsza/ipmi-monitor/tree/main/docs)
- **Discord Community**: [Join our Discord](https://discord.gg/7yeHdf5BuC) - Get help, report issues, request features

---

<p align="center">
  Made with ❤️ by <a href="https://cryptolabs.co.za">CryptoLabs</a>
</p>
