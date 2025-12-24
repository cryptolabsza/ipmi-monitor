# IPMI Monitor - User Guide

> Complete documentation for IPMI Monitor - a web-based server hardware monitoring tool.

**Version:** v0.7.x | **Last Updated:** 2025-12-11

---

## Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [Key Concepts](#key-concepts)
- [Dashboard](#dashboard)
- [Version & Updates](#version--updates)
- [Multi-Site Deployment](#multi-site-deployment)
- [Server Details](#server-details)
- [BMC Reset](#bmc-reset)
- [GPU Health Monitoring](#gpu-health-monitoring)
- [Uptime & Reboot Detection](#uptime--reboot-detection)
- [Maintenance Tasks](#maintenance-tasks)
- [Settings](#settings)
  - [Manage Servers](#manage-servers)
  - [Bulk Credentials](#bulk-credentials)
  - [Global Credentials](#global-credentials)
  - [SSH Configuration](#ssh-configuration)
  - [Site Configuration](#site-configuration)
  - [Recovery Permissions](#recovery-permissions)
  - [Alerts & Rules](#alerts--rules)
  - [Notifications](#notifications)
  - [Security & Users](#security--users)
  - [Backup & Restore](#backup--restore)
- [Prometheus & Grafana Integration](#prometheus--grafana-integration)
- [AI Features](#ai-features)
  - [AI Recovery Agent](#ai-recovery-agent)
  - [Post-Event Investigation](#post-event-investigation)
  - [Remote Task Execution](#remote-task-execution)
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

## Version & Updates

IPMI Monitor displays version information in the dashboard header and can check for updates.

### Version Display

The header shows:
```
IPMI Monitor
v1.6.0 (main@8d7150c, 2025-12-07 22:41 UTC)   Last updated: 12:46:02 AM
```

Components:
- **Version number** - Semantic version (e.g., v1.6.0)
- **Branch** - Git branch (main)
- **Commit** - Short git commit hash
- **Build time** - When the Docker image was built

### Checking for Updates

1. **Click the version badge** in the header
2. IPMI Monitor queries GitHub for the latest commits
3. If a newer version exists:
   - A green **⬆️ Update available** badge appears
   - Click it to see update instructions

### Update Notification

When an update is available, a popup shows:
- Your current version
- The latest version on GitHub
- The docker pull command to update

### Manual Update

```bash
# Pull the latest image
docker pull ghcr.io/cryptolabsza/ipmi-monitor:latest

# Restart with docker-compose
docker-compose up -d --force-recreate ipmi-monitor

# Or with docker run
docker stop ipmi-monitor
docker rm ipmi-monitor
docker run -d ... ghcr.io/cryptolabsza/ipmi-monitor:latest
```

### API Endpoints

```
GET /api/version       - Get current version and build info
GET /api/version/check - Check GitHub for newer releases
```

**Example response from `/api/version`:**
```json
{
  "version": "1.6.0",
  "version_string": "v1.6.0 (main@8d7150c, 2025-12-07 22:41 UTC)",
  "git_branch": "main",
  "git_commit": "8d7150c",
  "build_time": "2025-12-07 22:41 UTC"
}
```

> 💡 **Note:** Update checking requires network access to api.github.com. If your server can't reach GitHub, the check will silently fail.

---

## Multi-Site Deployment

If you have servers in multiple datacenters or locations, you can deploy an IPMI Monitor instance at each site while using a single license.

### How It Works

```
Your Company (Single CryptoLabs Account)
├── NYC Datacenter
│   └── IPMI Monitor instance (50 servers)
│       Site Name: "NYC Datacenter"
├── London Office
│   └── IPMI Monitor instance (30 servers)
│       Site Name: "London Office"
└── Singapore Colo
    └── IPMI Monitor instance (20 servers)
        Site Name: "Singapore Colo"

Total: 100 servers, 1 license, 3 sites
```

### Setting Up Multi-Site

1. Install IPMI Monitor at each location
2. Use the **same license key** at all sites
3. Go to **Settings → AI** on each instance
4. Set a unique **Site Name** (e.g., "NYC Datacenter")
5. Optionally add **Location** details

### Benefits

- **Single Billing** - All sites count toward your total server limit
- **Per-Site Summaries** - AI generates summaries for each site
- **Unified Account** - View all sites from CryptoLabs dashboard
- **Instance Tracking** - Each installation has a unique fingerprint

---

## BMC Reset

Reset the BMC (Baseboard Management Controller) without affecting the running host OS. This is useful when the BMC becomes unresponsive but the server itself is still running.

### How to Reset BMC

1. Go to **Server Detail** page
2. Click **Power Control** dropdown
3. Select:
   - **BMC Cold Reset** - Full BMC reboot (recommended)
   - **BMC Warm Reset** - Softer restart
   - **BMC Info** - Check BMC status

### When to Use

| Scenario | Recommended Reset |
|----------|-------------------|
| BMC unresponsive to web/IPMI | Cold Reset |
| BMC slow but responding | Warm Reset |
| IPMI commands failing | Cold Reset |
| After firmware update | Cold Reset |

### Command Line

```bash
# Cold reset
ipmitool -I lanplus -H 192.168.1.100 -U admin -P password mc reset cold

# Warm reset
ipmitool -I lanplus -H 192.168.1.100 -U admin -P password mc reset warm

# Check BMC info
ipmitool -I lanplus -H 192.168.1.100 -U admin -P password mc info
```

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

> 📖 **See Also:** [IPMI SEL Reference Guide](IPMI_SEL_REFERENCE.md) for detailed event code interpretation including hex data decoding.

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

## GPU Health Monitoring

IPMI Monitor detects NVIDIA GPU errors via SSH by parsing `dmesg` for Xid errors.

### How It Works

1. During each collection cycle, if SSH is enabled:
2. IPMI Monitor runs `dmesg | grep "NVRM.*Xid"` on the server
3. Parses Xid error codes from the output
4. Creates events for critical errors

### User-Friendly Display

Technical Xid codes are hidden from the UI. Instead of "Xid 48", you'll see:

| What You See | Technical Code | Meaning |
|--------------|----------------|---------|
| GPU Memory Error | Xid 48, 94, 95 | ECC or memory fault |
| GPU Not Responding | Xid 43 | GPU hang |
| GPU Disconnected | Xid 79 | GPU fell off PCIe bus |
| GPU Requires Recovery | Xid 154 | Driver requests recovery |

> 💡 Technical details are stored internally for admin debugging via the API.

### Event Details

GPU events appear in the Events tab with:
- **Sensor Type:** GPU Health
- **Severity:** Critical (red)
- **Device ID:** PCI address of affected GPU

### Requirements

- SSH enabled in Settings
- SSH credentials configured
- Linux server with `dmesg` access

---

## Uptime & Reboot Detection

IPMI Monitor tracks server uptime and detects unexpected reboots.

### How It Works

1. Reads `/proc/uptime` via SSH each collection cycle
2. If uptime is less than last reading → reboot detected
3. Checks if a recovery action (reboot/power cycle) was recently initiated
4. If no recovery action → logs as "unexpected reboot"

### Events

| Event | Severity | Meaning |
|-------|----------|---------|
| Unexpected server reboot | Warning | Server rebooted without system initiation |

### Viewing Uptime

Go to the server details page or use the API:

```
GET /api/uptime?server={bmc_ip}
```

Returns:
- `uptime_days` - Days since last boot
- `last_boot_time` - When server last booted
- `reboot_count` - Total detected reboots
- `unexpected_reboot_count` - Reboots not initiated by system

---

## Maintenance Tasks

IPMI Monitor automatically creates maintenance tasks when error patterns indicate hardware issues.

### Auto-Generated Tasks

| Pattern | Task Created |
|---------|--------------|
| 3+ reboots in 24 hours | High severity maintenance required |
| 2+ power cycles in 24 hours | High severity maintenance required |
| 5+ GPU errors for same device in 24 hours | Critical maintenance required |

### Task Properties

- **Task Type:** `automated_maintenance`
- **Severity:** `medium`, `high`, or `critical`
- **Status:** `pending`, `scheduled`, `in_progress`, `completed`, `cancelled`
- **Recovery Attempts:** Count of reboots/power cycles

### Managing Tasks

View tasks at `/api/maintenance` or through the dashboard (when enabled).

Update task status via API:
```
PUT /api/maintenance/{id}
{
  "status": "completed",
  "notes": "Replaced GPU"
}
```

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

# Global defaults applied to all servers
defaults:
  ipmi_user: admin
  ipmi_pass: YourDefaultPassword
  ssh_user: root
  ssh_key_name: production      # References a stored SSH key by name

servers:
  # Minimal - just name and BMC IP (uses defaults)
  - name: server-01
    bmc_ip: 192.168.1.100
    server_ip: 192.168.1.101
    
  # Override specific credentials
  - name: server-02
    bmc_ip: 192.168.1.102       # Required: BMC/IPMI IP
    server_ip: 10.0.0.102       # Optional: OS IP for SSH inventory
    public_ip: 203.0.113.50     # Optional: External/public IP (documentation)
    ipmi_user: custom_admin     # Override default
    ipmi_pass: secretpass       # Override default
    notes: Production database  # Optional: Notes/description
```

**Available fields:**

| Field | Required | Description |
|-------|----------|-------------|
| `name` | ✅ Yes | Display name for the server |
| `bmc_ip` | ✅ Yes | BMC/IPMI management IP |
| `server_ip` | No | OS IP address (for SSH inventory) |
| `public_ip` | No | Public/external IP (for reference) |
| `ipmi_user` | No | IPMI username (uses default if not set) |
| `ipmi_pass` | No | IPMI password (uses default if not set) |
| `ssh_user` | No | SSH username (default: root) |
| `ssh_key_name` | No | Name of a stored SSH key to use |
| `ssh_pass` | No | SSH password (if not using key auth) |
| `notes` | No | Notes or description |

### Global Credentials

Set default credentials that apply to all servers unless overridden.

#### Via API

```
GET /api/settings/credentials/defaults
PUT /api/settings/credentials/defaults
```

Example:
```json
{
  "ipmi_user": "admin",
  "ipmi_pass": "DefaultPassword",
  "ssh_user": "root",
  "ssh_port": 22,
  "default_ssh_key_id": 1
}
```

#### Apply to Multiple Servers

Apply defaults to multiple servers at once:

```
POST /api/settings/credentials/apply
{
  "server_ips": ["192.168.1.100", "192.168.1.101"],
  "apply_ipmi": true,
  "apply_ssh": true,
  "overwrite": false
}
```

Set `server_ips` to `"all"` to apply to all servers.

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

### Recovery Permissions

Control what recovery actions the AI agent can perform on your servers.

#### Permission Levels

| Permission | Description | Risk Level |
|------------|-------------|------------|
| `allow_soft_reset` | PCI unbind/rebind, restart NVIDIA services | Low |
| `allow_clock_limit` | Reduce GPU clocks to stabilize | Low |
| `allow_kill_workload` | Stop containers using failed GPU | Medium |
| `allow_reboot` | Full server reboot | High |
| `allow_power_cycle` | BMC power cycle | High |
| `auto_maintenance_flag` | Auto-create maintenance tasks | Low |

#### Setting Permissions

**System-wide defaults:**
```
GET /api/recovery/permissions/default
PUT /api/recovery/permissions/default
```

**Per-server overrides:**
```
GET /api/recovery/permissions/server/{bmc_ip}
PUT /api/recovery/permissions/server/{bmc_ip}
```

**Apply to multiple servers:**
```
POST /api/recovery/permissions/apply
{
  "server_ips": ["192.168.1.100", "192.168.1.101"],
  "permissions": {
    "allow_soft_reset": true,
    "allow_reboot": false
  }
}
```

> ⚠️ **Warning:** Enabling `allow_reboot` and `allow_power_cycle` gives the AI agent permission to reboot servers automatically. Use with caution.

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
- **AI Recovery Agent** - Autonomous GPU recovery with escalation

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

### AI Recovery Agent

The AI Recovery Agent autonomously handles GPU failures with an intelligent escalation ladder.

#### How It Works

1. **Detection**: IPMI Monitor detects GPU error via SSH (Xid error)
2. **Analysis**: AI Agent analyzes error type and history
3. **Decision**: Agent decides appropriate recovery action
4. **Execution**: Action performed (if permissions allow)
5. **Verification**: Agent checks if recovery succeeded
6. **Escalation**: If failed, escalates to next level

#### Recovery Stages

| Stage | Action | Description | Cooldown |
|-------|--------|-------------|----------|
| 1 | Check Status | Verify GPU is actually failed | - |
| 2 | Soft Reset | PCI unbind/rebind, restart NVIDIA services | 5 min |
| 3 | Clock Limit | Reduce GPU clocks 20% to stabilize | 15 min |
| 4 | Kill Workload | Stop containers/VMs using the GPU | 30 min |
| 5 | Reboot | Full server reboot | 60 min |
| 6 | Power Cycle | BMC power cycle | 120 min |
| 7 | Maintenance | Flag for manual intervention | - |

#### Safety Features

- **Permission Checking**: Only performs actions you've enabled
- **Cooldown Management**: Prevents recovery storms
- **Workload Detection**: Identifies containers using GPUs before stopping them
- **NVIDIA Driver Check**: Skips soft recovery if driver reports "Node Reboot Required"
- **Persistent State**: Remembers recovery history per device

#### Agent Events

All agent actions are logged as events:

| Event | Description |
|-------|-------------|
| GPU Requires Recovery | GPU error detected |
| GPU Reset Attempted | Soft reset performed |
| GPU Clock Limited | Clock reduction applied |
| Server Rebooted | Reboot performed |
| Maintenance Required | Device flagged for manual intervention |

#### Enabling the Agent

1. Enable AI features (Settings → AI Features)
2. Configure recovery permissions (Settings → Recovery)
3. Agent automatically processes GPU errors

> 💡 **Tip:** Start with only `allow_soft_reset` and `allow_clock_limit` enabled. Enable reboot/power cycle only after testing.

### Post-Event Investigation

When a server recovers from an unreachable ("dark") state, IPMI Monitor can investigate what happened during the downtime.

#### What It Checks

1. **SSH Uptime** - Did the OS reboot during the outage?
2. **SEL Logs** - Any power/voltage events recorded?
3. **Concurrent Failures** - Did other servers go offline at the same time?

#### Likely Causes Detected

| Cause | Evidence | Confidence |
|-------|----------|------------|
| Reboot | OS boot time during outage | High |
| Power Outage | SEL shows "AC Lost" events | Very High |
| BMC Reset | SEL shows reset events | High |
| Network Issue | Multiple servers offline simultaneously | High |
| BMC Unresponsive | No other evidence found | Medium |

#### Triggering Investigation

**Automatic:** Investigation runs when alert resolves (if AI agent enabled)

**Manual:**
1. Go to Server Detail page
2. Power Control dropdown → **Investigate Recovery**
3. View investigation results

**API:**
```bash
curl -X POST http://ipmi-monitor:5000/api/server/192.168.1.100/investigate \
  -H "Content-Type: application/json" \
  -d '{"downtime_start": "2025-12-10T10:00:00Z"}'
```

### Remote Task Execution

With AI features enabled, the CryptoLabs AI service can send tasks to your IPMI Monitor for execution.

#### Supported Tasks

| Task | Description | Prerequisites |
|------|-------------|---------------|
| `power_cycle` | BMC power cycle | IPMI credentials |
| `power_reset` | Chassis reset | IPMI credentials |
| `bmc_reset` | BMC cold/warm reset | IPMI credentials |
| `collect_inventory` | SSH inventory collection | SSH credentials |
| `ssh_command` | Execute SSH command | SSH credentials |
| `check_connectivity` | Verify server reachability | - |

#### How It Works

1. AI service analyzes your fleet data
2. AI determines an action is needed (e.g., power cycle stuck server)
3. AI creates a task in the queue
4. IPMI Monitor polls for tasks during sync
5. Task is executed and result reported back

#### Task Flow

```
AI Service                    IPMI Monitor
    │                              │
    │ Create task                  │
    ├─────────────────────────────►│ Poll for tasks
    │                              │
    │◄─────────────────────────────┤ Claim task
    │                              │
    │                              │ Execute action
    │                              │
    │◄─────────────────────────────┤ Report completion
    │                              │
```

#### Viewing Task History

The agent dashboard shows:
- **Pending Tasks** - Waiting to be executed
- **Recent Actions** - Completed/failed tasks with results

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
| **Xid** | NVIDIA GPU driver error code (hidden from users in UI) |
| **PCI Unbind/Rebind** | Soft GPU reset via Linux sysfs |
| **Clock Limiting** | Reducing GPU clock speeds to improve stability |
| **Recovery Agent** | AI system that autonomously handles GPU failures |
| **Escalation Ladder** | Progressive recovery actions (soft → hard) |
| **Cooldown** | Waiting period between recovery attempts |

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

### Version & Updates

```
GET  /api/version           - Get current version and build info
GET  /api/version/check     - Check GitHub for newer releases
```

### Monitoring Endpoints

```
GET  /api/maintenance       - List maintenance tasks
PUT  /api/maintenance/{id}  - Update maintenance task
GET  /api/recovery-logs     - Get recovery action history
GET  /api/uptime            - Get server uptime information
```

### Credential Management

```
GET  /api/settings/credentials/defaults  - Get global defaults
PUT  /api/settings/credentials/defaults  - Set global defaults
POST /api/settings/credentials/apply     - Apply to multiple servers
GET  /api/ssh-keys                       - List stored SSH keys
POST /api/ssh-keys                       - Add SSH key
DELETE /api/ssh-keys/{id}                - Delete SSH key
```

### Recovery Permissions

```
GET  /api/recovery/permissions/default       - Get system defaults
PUT  /api/recovery/permissions/default       - Set system defaults
GET  /api/recovery/permissions/server/{ip}   - Get per-server overrides
PUT  /api/recovery/permissions/server/{ip}   - Set per-server overrides
POST /api/recovery/permissions/apply         - Apply to multiple servers
```

For complete API documentation, see the [GitHub repository](https://github.com/cryptolabsza/ipmi-monitor).

---

## Support

- **GitHub Issues**: [github.com/cryptolabsza/ipmi-monitor/issues](https://github.com/cryptolabsza/ipmi-monitor/issues)
- **Documentation**: [cryptolabsza.github.io/ipmi-monitor](https://cryptolabsza.github.io/ipmi-monitor)
- **AI Support**: Use the AI Chat feature for instant help

---

*Last updated: December 2025*

