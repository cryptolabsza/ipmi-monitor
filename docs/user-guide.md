# IPMI Monitor - User Guide

> Complete documentation for IPMI Monitor - a web-based server hardware monitoring tool.

---

## Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [Key Concepts](#key-concepts)
- [Dashboard](#dashboard)
- [Server Details](#server-details)
- [Settings](#settings)
  - [Manage Servers](#manage-servers)
  - [SSH Configuration](#ssh-configuration)
  - [Alerts & Rules](#alerts--rules)
  - [Notifications](#notifications)
  - [Security & Users](#security--users)
- [Prometheus & Grafana Integration](#prometheus--grafana-integration)
- [AI Features](#ai-features)
- [Troubleshooting](#troubleshooting)
- [Glossary](#glossary)
- [API Reference](#api-reference)

---

## Overview

IPMI Monitor is a web-based tool for monitoring server hardware via **IPMI** (Intelligent Platform Management Interface) and **Redfish** APIs. It provides real-time visibility into your server fleet's health.

### What It Monitors

- **System Event Log (SEL)** - Hardware events, errors, warnings
- **Sensor Readings** - Temperature, voltage, fan speed, power consumption
- **Hardware Inventory** - CPU, memory, storage, GPU information
- **Connectivity Status** - BMC and OS reachability
- **Power State** - On/off status with remote control

### Supported Hardware

IPMI Monitor works with any server that has an IPMI-compliant BMC (Baseboard Management Controller):
- Dell iDRAC
- HP iLO
- Supermicro IPMI
- ASUS ASMB
- Lenovo XClarity
- Any Redfish-compatible BMC

---

## Quick Start

### 1. Add Your First Server

1. Go to **Settings → Manage Servers**
2. Click **➕ Add New Server**
3. Enter the BMC IP address (e.g., `192.168.1.100`)
4. Give it a friendly name (e.g., `server-01`)
5. Click **Add Server**

### 2. Configure IPMI Credentials

If your servers use custom IPMI credentials:

1. Click the server in the list to edit
2. Enter the IPMI username and password
3. Click **🔗 Test BMC** to verify
4. Save changes

### 3. View Server Health

Return to the **Dashboard** to see your servers. Click any server card to view detailed events, sensors, and inventory.

---

## Key Concepts

### BMC (Baseboard Management Controller)

A dedicated processor on the server motherboard that operates independently of the main CPU. It allows remote monitoring and management even when the server is powered off or the OS has crashed.

### IPMI vs Redfish

| Feature | IPMI | Redfish |
|---------|------|---------|
| Protocol | Binary (port 623) | REST API (HTTPS 443) |
| Data Format | Binary | JSON |
| Support | Widely available | Modern BMCs |
| Detail Level | Basic | More detailed |

**Recommendation:** Use **Auto** protocol mode - IPMI Monitor will try Redfish first for more detailed data, then fall back to IPMI.

### BMC IP vs OS IP

- **BMC IP** - The management network IP (often ends in `.0`, e.g., `192.168.1.100`)
- **OS IP** - The server's main network IP where the OS runs (often `.1`, e.g., `192.168.1.101`)

---

## Dashboard

The main dashboard shows all monitored servers in a grid view.

### Server Cards

Each card displays:
- **Server Name** and BMC IP
- **Status Badge**: 🟢 Online, 🔴 Offline, 🟡 Warning
- **Event Count**: Recent events in last 24 hours
- **Temperature**: Current CPU/inlet temperature

### Status Indicators

| Status | Meaning |
|--------|---------|
| 🟢 **Online** | Server and BMC responding normally |
| 🟡 **Warning** | Warning events detected or partial connectivity |
| 🔴 **Offline** | BMC not reachable |
| ⚫ **Unknown** | Never successfully polled |

### Auto-Refresh

Data refreshes automatically every 60 seconds. Event collection runs every 5 minutes by default (configurable via `POLL_INTERVAL` environment variable).

---

## Server Details

Click any server card to view detailed information across three tabs.

### Events Tab

Shows System Event Log (SEL) entries with:
- **Timestamp** - When the event occurred
- **Severity** - Critical (🔴), Warning (🟡), Info (🔵)
- **Description** - Event message from BMC

#### Common Event Types

| Event | Meaning | Action |
|-------|---------|--------|
| Correctable ECC Error | Memory error detected and corrected | Monitor frequency; replace DIMM if recurring |
| Uncorrectable ECC Error | Memory error that couldn't be fixed | Replace DIMM immediately |
| Temperature Threshold | Component exceeded temperature limit | Check cooling, clean dust, verify airflow |
| Fan Failure | Fan stopped or below speed threshold | Replace fan ASAP |
| Power Supply Failure | PSU issue detected | Check/replace PSU |

#### Event Actions

- **Clear DB Events** - Remove from IPMI Monitor only (BMC unaffected)
- **Clear BMC SEL** - Clear actual BMC log (⚠️ Admin only, use carefully)

### Sensors Tab

Real-time sensor readings including:
- Temperature sensors (CPU, inlet, exhaust, DIMMs)
- Voltage sensors (3.3V, 5V, 12V, battery)
- Fan speeds (RPM)
- Power consumption (Watts)

#### Temperature Guidelines

| Sensor | Normal | Warning | Critical |
|--------|--------|---------|----------|
| CPU Temperature | < 70°C | 70-85°C | > 85°C |
| Inlet Temperature | < 30°C | 30-40°C | > 40°C |
| DIMM Temperature | < 60°C | 60-75°C | > 75°C |

#### Voltage Guidelines

| Rail | Normal Range |
|------|--------------|
| 3.3V | 3.1V - 3.5V |
| 5V | 4.75V - 5.25V |
| 12V | 11.4V - 12.6V |
| VBAT | 2.8V - 3.3V |

> ⚠️ **Low VBAT Warning**: If VBAT drops below 2.5V, the CMOS battery needs replacement. This can cause BIOS settings to reset.

### Inventory Tab

Hardware information collected via IPMI FRU, Redfish, and SSH:
- System manufacturer, model, serial number
- CPU model, core count
- Memory total, slots used
- Storage devices with sizes
- GPU information (if present)

#### Data Sources

| Source | Data Collected | Requirements |
|--------|----------------|--------------|
| IPMI FRU | Manufacturer, model, serial | IPMI access |
| IPMI SDR | Sensor list, CPU/DIMM counts | IPMI access |
| Redfish API | Detailed CPU, memory, storage, GPU | Redfish-enabled BMC |
| SSH to OS | Exact CPU model, memory config, drives | SSH enabled + credentials |

> 💡 **Tip**: Enable SSH in Settings → SSH tab for the most detailed inventory data.

---

## Settings

### Manage Servers

#### Adding Servers

Go to Settings → Manage Servers → Add New Server:
- **BMC IP** - The IPMI management IP
- **Server Name** - A friendly name for identification
- **OS IP** - Optional, for SSH inventory collection
- **Protocol** - Auto (recommended), IPMI only, or Redfish only

#### Editing Servers

Click any server in the list to open the edit dialog:
- Change name, IPs, protocol
- Set custom IPMI credentials
- Configure SSH credentials
- **Test BMC** - Verify IPMI connection
- **Test SSH** - Verify SSH connection
- **Check Redfish** - Test Redfish availability

#### Bulk Import

Import servers from a YAML/JSON file:

```yaml
# servers.yaml example
servers:
  - name: server-01
    bmc_ip: 192.168.1.100
    server_ip: 192.168.1.101
  - name: server-02
    bmc_ip: 192.168.1.102
    server_ip: 192.168.1.103
```

### SSH Configuration

SSH enables detailed inventory collection from the server's OS. This is **optional** and supplements data from IPMI/Redfish.

#### Data Collection Priority

IPMI Monitor collects data in this order, only filling gaps:

1. **IPMI FRU** - Manufacturer, product, serial (always tried first)
2. **Redfish API** - Detailed CPU, memory, storage, GPU info
3. **IPMI SDR** - CPU/DIMM counts from sensor names
4. **SSH to OS** - Only collects data that IPMI/Redfish didn't provide

#### Target Machine Requirements

For SSH inventory collection to work, the target server's OS needs these standard Linux tools:

| Tool | Package | Used For | Required |
|------|---------|----------|----------|
| `lspci` | `pciutils` | GPU detection, NIC detection, PCIe health | ✅ Yes |
| `lsblk` | `util-linux` | Storage devices (NVMe, SSD, HDD) | ✅ Yes |
| `lscpu` | `util-linux` | CPU model, socket count, core count | ✅ Yes |
| `/proc/cpuinfo` | (kernel) | CPU fallback if lscpu unavailable | Built-in |
| `/proc/meminfo` | (kernel) | Total memory | Built-in |
| `/sys/class/net/` | (kernel) | Network interfaces, MACs, speeds | Built-in |
| `/sys/class/dmi/id/` | (kernel) | System manufacturer, product name | Built-in |
| `/sys/class/hwmon/` | (kernel) | Temperature sensors | Built-in |
| `dmidecode` | `dmidecode` | Memory DIMM details (needs root) | Optional |
| `virsh` | `libvirt` | KVM host device passthrough info | Optional |
| `setpci` | `pciutils` | Advanced PCIe diagnostics | Optional |

**Typical installation (Debian/Ubuntu):**
```bash
sudo apt install pciutils util-linux
```

**Typical installation (RHEL/CentOS/Rocky):**
```bash
sudo dnf install pciutils util-linux
```

> ⚠️ **Note:** SSH collection does NOT require `nvidia-smi` or any vendor drivers. GPU detection uses `lspci` which sees all PCI devices including GPUs passed through to VMs.

> 💡 **Note:** No software installation is needed if you only use IPMI/Redfish for monitoring. SSH is purely supplemental.

#### PCIe Health Monitoring (AER)

When SSH is enabled, IPMI Monitor checks PCIe device health using `lspci -vvv`. This parses **AER (Advanced Error Reporting)** status registers.

**Device Status Flags:**

| Flag | Severity | Description |
|------|----------|-------------|
| `FatalError` | Critical | PCIe fatal error - device may be non-functional |
| `NonFatalError` | Warning | Recoverable PCIe error |
| `UnsupportedRequest` | Warning | Device received unsupported PCIe request |

**Uncorrectable Errors (UESta) - Critical:**

| Code | Description |
|------|-------------|
| `DLP` | Data Link Protocol Error |
| `SDES` | Surprise Down Error (device unexpectedly removed) |
| `TLP` | TLP Prefix Blocked |
| `FCP` | Flow Control Protocol Error |
| `CmpltTO` | Completion Timeout |
| `CmpltAbrt` | Completer Abort |
| `UnxCmplt` | Unexpected Completion |
| `RxOF` | Receiver Overflow |
| `MalfTLP` | Malformed TLP |
| `ECRC` | ECRC Error |
| `UnsupReq` | Unsupported Request |

**Correctable Errors (CESta) - Warning:**

| Code | Description |
|------|-------------|
| `RxErr` | Receiver Error |
| `BadTLP` | Bad TLP (recoverable) |
| `BadDLLP` | Bad DLLP (recoverable) |
| `Rollover` | Replay Number Rollover |
| `Timeout` | Replay Timer Timeout |
| `NonFatalErr` | Non-Fatal Error (Advisory) |

> 💡 **Tip:** Uncorrectable errors (UE) indicate serious hardware issues that may require replacement. Correctable errors (CE) are recovered automatically but frequent occurrences may indicate failing hardware.

The inventory page shows PCIe health status for GPUs and VGA devices. Devices with errors are highlighted and logged as warnings.

#### Enable SSH

1. Go to Settings → SSH tab
2. Toggle **Enable SSH to OS**
3. Configure default credentials

#### SSH Key Management

Store SSH keys centrally and assign them to servers:
1. Click **➕ Add New Key**
2. Give it a name (e.g., "Production Key")
3. Paste the private key content
4. Use the dropdown in server edit to assign

> 💡 Keys should be in OpenSSH format, starting with `-----BEGIN OPENSSH PRIVATE KEY-----`

#### Per-Server Overrides

Each server can have custom SSH settings:
- Custom OS IP (if different from BMC IP pattern)
- Custom username
- Different SSH key
- Custom port

### Alerts & Rules

#### Pre-configured Rules

- Temperature exceeding thresholds
- Fan speed below minimum
- ECC memory errors
- Power supply issues
- Critical BMC events

#### Creating Custom Rules

1. Go to Settings → Alerts
2. Click **Add Rule**
3. Select alert type and condition
4. Set threshold and severity
5. Enable notification channels

### Notifications

#### Telegram Setup

1. Message `@BotFather` on Telegram
2. Create a new bot with `/newbot`
3. Copy the bot token
4. Get your chat ID (message `@userinfobot`)
5. Paste both in Settings → Notifications → Telegram
6. Click **Test** to verify

#### Email Setup

Configure SMTP settings for email notifications. Works with Gmail, SendGrid, or any SMTP server.

#### Webhook

Send alerts to Slack, Discord, or custom endpoints. Webhooks receive JSON payloads with alert details.

### Security & Users

#### User Roles

| Role | Permissions |
|------|-------------|
| **Admin** | Full access: manage users, security, AI features, power control |
| **Read-Write** | Manage servers, run power commands, but not user management |
| **Read-Only** | View only - no changes allowed |

#### Anonymous Access

Enable to allow viewing the dashboard without login. Anonymous users get read-only access.

> ⚠️ **Security Note**: Only enable anonymous access on trusted networks.

---

## Prometheus & Grafana Integration

IPMI Monitor provides a built-in Prometheus exporter for integration with your existing monitoring stack.

### Metrics Endpoint

Metrics are exposed at `/metrics` in Prometheus text format:

```
http://your-ipmi-monitor:5000/metrics
```

### Available Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `ipmi_server_reachable` | Gauge | BMC reachable (1=yes, 0=no) |
| `ipmi_server_power_on` | Gauge | Power state (1=on, 0=off) |
| `ipmi_temperature_celsius` | Gauge | Temperature per sensor |
| `ipmi_fan_speed_rpm` | Gauge | Fan speed readings |
| `ipmi_voltage_volts` | Gauge | Voltage readings |
| `ipmi_power_watts` | Gauge | Power consumption |
| `ipmi_events_total` | Gauge | Total events per server |
| `ipmi_events_critical_24h` | Gauge | Critical events in 24h |
| `ipmi_events_warning_24h` | Gauge | Warning events in 24h |
| `ipmi_total_servers` | Gauge | Total monitored servers |
| `ipmi_reachable_servers` | Gauge | Reachable server count |
| `ipmi_alerts_total` | Gauge | Total fired alerts |
| `ipmi_alerts_unacknowledged` | Gauge | Unacknowledged alerts |
| `ipmi_last_collection_timestamp` | Gauge | Last collection time |

### Prometheus Configuration

Add this to your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'ipmi-monitor'
    static_configs:
      - targets: ['ipmi-monitor:5000']
    scrape_interval: 60s
    scrape_timeout: 30s
    metrics_path: /metrics
```

**Target options:**
- `ipmi-monitor:5000` - Docker network (container name)
- `localhost:5000` - Same host
- `192.168.1.50:5000` - Remote IP

### Pre-built Grafana Dashboard

We provide a ready-to-import Grafana dashboard with:
- **Fleet Overview** - Total servers, reachable count, alerts
- **Server Health** - Per-server temperature, power, events
- **Event Timeline** - Critical/warning events over time
- **Temperature Heatmap** - Temperature trends across fleet
- **Alert History** - Alert counts and status

**Import:** Download from [grafana/dashboards/ipmi-monitor.json](https://github.com/cryptolabsza/ipmi-monitor/blob/main/grafana/dashboards/ipmi-monitor.json)

### Example Grafana Alerts

```promql
# High Temperature Alert
ipmi_temperature_celsius{sensor=~"CPU.*"} > 80

# Server Unreachable
ipmi_server_reachable == 0

# Critical Events Spike
increase(ipmi_events_critical_24h[1h]) > 5

# Multiple Servers Down
count(ipmi_server_reachable == 0) > 2
```

> 💡 **Note:** Scraping `/metrics` reads cached data from the last collection cycle (default: every 5 minutes). Faster scrape intervals won't give you fresher data - they'll just read the same values repeatedly.

---

## AI Features

Premium AI features provide intelligent analysis of your server fleet.

### Features Included

- **Fleet Health Summaries** - Daily overview of all servers
- **Maintenance Tasks** - AI-identified work items with priorities
- **Predictive Analytics** - Failure predictions before they happen
- **Root Cause Analysis** - Deep analysis of specific events
- **AI Chat** - Interactive assistant for questions

### Getting Started

1. Go to Settings → AI Features
2. Click **Start Free Trial**
3. Sign up for a CryptoLabs account
4. AI features activate automatically

### AI Chat

Ask questions about your servers in natural language:

- "Which servers have high temperatures?"
- "Show me servers with ECC errors"
- "What maintenance is needed this week?"
- "Explain this error: [paste event]"
- "How do I add a new server?"

### Maintenance Tasks

AI analyzes events and sensors to generate maintenance work items.

| Priority | Meaning | Timeframe |
|----------|---------|-----------|
| 🔴 Critical | Immediate risk of outage | Today |
| 🟡 High | Component degrading | This week |
| 🔵 Medium | Needs attention | Next maintenance window |
| ⚪ Low | Monitor and plan | When convenient |

Each task includes:
- **Affected Servers** - Specific server names
- **Component** - What hardware needs attention
- **Reason** - Why this task was generated
- **Suggested Action** - What to do
- **Evidence** - Supporting data

---

## Troubleshooting

### Server Shows Offline

1. Verify BMC IP is reachable: `ping 192.168.1.100`
2. Check IPMI credentials in server edit
3. Use **Test BMC** button to diagnose
4. Verify firewall allows port 623 (IPMI)
5. Try accessing BMC web interface directly

### SSH Test Fails

| Error | Cause | Solution |
|-------|-------|----------|
| "Permission denied" | Wrong credentials | Check SSH key or password |
| "Connection refused" | SSH not running | Verify SSH service, check port |
| "No route to host" | Network issue | Check IP address, firewall |
| "error in libcrypto" | Key format issue | Re-paste the key carefully |

### Missing Inventory Data

1. Enable SSH in Settings → SSH tab
2. Configure SSH credentials for the server
3. Click **Collect Inventory**
4. Check SSH connectivity with Test SSH button

### No Events Showing

- Wait for collection cycle (default 5 minutes)
- Verify server is enabled in settings
- Some BMCs have empty SEL by default
- Check BMC firmware supports SEL

---

## Glossary

| Term | Definition |
|------|------------|
| **BMC** | Baseboard Management Controller - dedicated processor for server management |
| **IPMI** | Intelligent Platform Management Interface - protocol for BMC communication |
| **Redfish** | Modern REST API alternative to IPMI |
| **SEL** | System Event Log - BMC's record of hardware events |
| **FRU** | Field Replaceable Unit - hardware inventory data |
| **SDR** | Sensor Data Record - sensor configuration data |
| **ECC** | Error Correcting Code - memory error detection/correction |
| **DIMM** | Dual Inline Memory Module - RAM stick |
| **PSU** | Power Supply Unit |
| **VBAT** | Backup battery voltage (usually CR2032 for CMOS) |
| **iDRAC** | Dell's BMC implementation |
| **iLO** | HP's BMC implementation |

---

## API Reference

IPMI Monitor provides a REST API for integration.

### Authentication

API endpoints require session authentication. Login via POST to `/login`.

### Key Endpoints

```
GET  /api/servers           - List all servers
GET  /api/servers/managed   - List managed servers
GET  /api/server/{ip}/events - Get server events
GET  /api/server/{ip}/sensors - Get sensor readings
GET  /api/servers/{ip}/inventory - Get hardware inventory
POST /api/servers/{ip}/inventory - Collect inventory
GET  /api/auth/status       - Check auth status
POST /api/test/bmc          - Test BMC connection
POST /api/test/ssh          - Test SSH connection
GET  /metrics               - Prometheus metrics
GET  /health                - Health check
```

For complete API documentation, see the [GitHub repository](https://github.com/cryptolabsza/ipmi-monitor).

---

## Support

- **GitHub Issues**: [github.com/cryptolabsza/ipmi-monitor/issues](https://github.com/cryptolabsza/ipmi-monitor/issues)
- **Documentation**: [cryptolabsza.github.io/ipmi-monitor](https://cryptolabsza.github.io/ipmi-monitor)
- **AI Support**: Use the AI Chat feature for instant help

---

*Last updated: December 2024*

