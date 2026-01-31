# IPMI Monitor - User Guide

> Complete documentation for IPMI Monitor - a web-based server hardware monitoring tool.

**Version:** v1.1.0 | **Last Updated:** 2026-01-24

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
- [SSH System Logs](#ssh-system-logs)
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
- [FAQ - Frequently Asked Questions](#faq---frequently-asked-questions)

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

### Option 1: Quickstart Wizard (Recommended)

The easiest way to get started is the interactive quickstart wizard:

```bash
# Install the CLI tool
sudo apt install pipx -y
pipx install ipmi-monitor

# Run the wizard (use full path since pipx bin isn't in sudo PATH)
sudo ~/.local/bin/ipmi-monitor quickstart
```

The wizard will:
1. **Detect DC Overview** - If DC Overview is installed, import servers and SSH keys
2. **Add servers** - Link imported servers with BMC IPs, or add new ones
3. **Configure credentials** - Set up IPMI and SSH authentication
4. **SSH log collection** - Optionally enable SSH log collection (dmesg, syslog, GPU errors)
5. **Deploy containers** - Set up ipmi-monitor + cryptolabs-proxy + watchtower
6. **Configure SSL** - Let's Encrypt with auto-renewal, or self-signed
7. **Initial collection** - Fresh installs automatically collect data on first start

#### DC Overview Import

If DC Overview is already installed, the quickstart wizard automatically:
- Detects `/etc/dc-overview/` configuration
- Offers to import server IPs and SSH keys from `prometheus.yml`
- Copies SSH keys to `/etc/ipmi-monitor/ssh_keys/`
- Prompts you to link each server with its BMC IP

This makes it easy to add IPMI monitoring to an existing GPU monitoring setup.

#### Initial Data Collection

On a fresh installation, IPMI Monitor automatically performs an initial data collection:
- Collects sensors and events from all configured BMCs
- Gathers hardware inventory
- Collects SSH logs (if enabled)

A progress modal appears in the dashboard showing:
- Current phase (sensors, events, inventory, SSH logs)
- Progress (X/Y servers)
- Option to "Continue in Background" to dismiss

This ensures your dashboard has data immediately after setup.

### Option 2: Manual Setup

#### 1. Add Your First Server

1. Go to **Settings → Manage Servers**
2. Click **➕ Add New Server**
3. Enter the BMC IP address (e.g., `192.168.1.100`)
4. Give it a friendly name (e.g., `server-01`)
5. Click **Add Server**

#### 2. Configure IPMI Credentials

If your servers use custom IPMI credentials:

1. Click the server in the list to edit
2. Enter the IPMI username and password
3. Click **🔗 Test BMC** to verify
4. Save changes

#### 3. View Server Health

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

> 📖 **See Also:** [IPMI SEL Reference Guide](IPMI_SEL_REFERENCE.html) for detailed event code interpretation including hex data decoding.

#### Event Actions

- **Clear DB Events** - Remove from IPMI Monitor only (BMC unaffected)
- **SEL Management** dropdown (Admin/Read-Write only):
  - **SEL Info** - View SEL version, entries, free space, last add/erase time
  - **Enable Event Logging** - Turn on SEL event collection on BMC
  - **Disable Event Logging** - Turn off SEL event collection (use carefully!)
  - **Get SEL Time** - Check BMC's internal clock
  - **Clear SEL Log** - Clear actual BMC log (⚠️ Cannot be undone)

### Sensors Tab

Real-time sensor readings including:
- Temperature sensors (CPU, inlet, exhaust, DIMMs)
- Voltage sensors (3.3V, 5V, 12V, battery)
- Fan speeds (RPM)
- Power consumption (Watts)

#### Refresh Sensors

Click **🔄 Refresh Sensors** to collect fresh data from the BMC. After refresh:
- Values that **changed** are highlighted with a **green pulse** animation
- The highlight fades after 2 seconds
- A console at the top shows collection progress

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

### Diagnostics Tab

Admin and Read-Write users have access to the Diagnostics section for troubleshooting:

| Download | Description |
|----------|-------------|
| **Raw SEL Log** | Unparsed IPMI SEL events directly from BMC |
| **Raw Sensor Data** | All sensors with thresholds in raw format |
| **SSH Logs** | dmesg, journalctl, GPU logs collected via SSH |
| **Full Diagnostic Package** | Everything bundled in a ZIP file |

**Loading States:** All download buttons show progress (e.g., "Collecting SEL...") and are disabled during collection to prevent duplicate downloads.

**Custom Commands:** Admins can execute custom IPMI or SSH commands directly from the Diagnostics section.

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

## SSH System Logs

IPMI Monitor can collect system logs from your servers via SSH for centralized viewing and AI analysis.

### What It Collects

| Source | Command | Purpose |
|--------|---------|---------|
| **Kernel Log** | `dmesg` | Hardware errors, driver issues, boot messages |
| **Journal** | `journalctl` | Systemd service logs |
| **Syslog** | `/var/log/syslog` | System messages |
| **MCE Log** | `mcelog` | Machine check exceptions (ECC, CPU errors) |
| **Auth Log** | `/var/log/auth.log` | SSH login attempts, sudo usage |
| **Secure Log** | `/var/log/secure` | Security events (RHEL/CentOS) |
| **Docker Daemon** | `journalctl -u docker` | Docker service errors and warnings |

### Collected Error Types

- **AER Errors** - PCIe Advanced Error Reporting
- **PCIe Errors** - Bus errors, link failures
- **ECC Errors** - Memory correctable/uncorrectable errors
- **GPU Xid Errors** - NVIDIA driver faults
- **SSH Security Events** - Failed logins, brute force attempts
- **NVMe Errors** - SSD health and I/O errors
- **RAID Errors** - Controller and disk failures
- **Kernel Panics** - System crashes with stack traces
- **Docker Daemon Errors** - Container runtime issues, storage-opt, overlay, pquota errors

### Docker Daemon Log Collection

IPMI Monitor collects Docker daemon logs to help troubleshoot container issues common on GPU hosting servers.

**Detected Issues:**
- `storage-opt` errors (XFS pquota configuration)
- Overlay filesystem issues
- Container startup failures
- nvidia-docker runtime errors
- Docker daemon crashes

**How It Works:**
1. Collects logs via `journalctl -u docker` or `/var/log/docker.log`
2. Parses for errors and warnings
3. Stores in the SSH logs database
4. AI Chat can query these logs for troubleshooting

**AI Integration:**
When you ask Docker-related questions in AI Chat, it automatically:
1. Queries Docker daemon logs from your servers
2. Searches the GPU Hosting Knowledge Base for solutions
3. Provides combined answers with community-sourced fixes

### SSH Authentication Events

IPMI Monitor parses SSH authentication logs to detect:

| Event Type | Detection | Severity |
|------------|-----------|----------|
| Failed SSH Login | Multiple failed password/key attempts | Warning |
| Brute Force Attack | 5+ failed logins from same IP in 5 min | Critical |
| Successful Login | Successful authentication | Info |
| Invalid User | Login attempt with non-existent user | Warning |
| Root Login | Direct root login (if enabled) | Info |

### Enabling Collection

**During Quickstart:**
If you have servers with SSH configured, the wizard asks:
```
Step 5b: SSH Log Collection (Optional)

Collect system logs from servers via SSH (dmesg, syslog, GPU errors).
Useful for troubleshooting hardware issues.

? Enable SSH log collection? (y/N)
```

**After Installation:**
1. Go to **Settings → SSH**
2. Enable **SSH Log Collection**
3. Set collection interval (5-60 minutes)
4. Set retention period (3-30 days)

The setting is stored in the `ENABLE_SSH_LOGS` environment variable and persists across container restarts.

### Viewing Logs

1. Go to **Server Detail**
2. Click the **📜 System Logs** tab
3. Filter by severity (Critical, Error, Warning, Info)
4. Filter by log type (Kernel, Journald, Syslog, MCE, Auth)

### SSH Log Severity Mapping

| Severity | Example Entries |
|----------|-----------------|
| **Critical** | Kernel panic, OOM killer, GPU fell off bus, hardware failure |
| **Error** | I/O errors, driver failures, service crashes |
| **Warning** | Correctable ECC errors, high temperature, failed logins |
| **Info** | Service started, successful logins, normal operations |

### Requirements

- SSH access configured for the server
- Root or sudo access for dmesg/journalctl
- Read access to `/var/log/` for log file collection

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

#### Quickstart SSH Key Options

When running `ipmi-monitor quickstart`, you have multiple options for SSH authentication:

| Option | Description |
|--------|-------------|
| **Select Detected Key** | Auto-detects keys in `~/.ssh/` (id_rsa, id_ed25519, etc.) with fingerprint |
| **Enter Path Manually** | Specify a custom path to your private key |
| **Paste Key Content** | Paste the private key directly (saved to `~/.ssh/ipmi_monitor_pasted_key`) |
| **Generate New Key** | Creates ED25519 key pair and prints public key with instructions |

When generating a new key, you'll see:
```
✓ New SSH key generated!
  Private key: /root/.ssh/ipmi_monitor_key
  Fingerprint: SHA256:xxxxx... (ED25519)

━━━ PUBLIC KEY ━━━
ssh-ed25519 AAAAC3NzaC1... ipmi-monitor
━━━━━━━━━━━━━━━━━━

To allow SSH access, add this public key to your servers:
  1. Copy the public key above
  2. On each server, add it to: ~/.ssh/authorized_keys
  3. Ensure permissions: chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys
```

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

| Role | Dashboard | Settings | Server Management | User Management | AI Features |
|------|-----------|----------|-------------------|-----------------|-------------|
| **Admin** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Read-Write** | ✅ | ✅ | ✅ | ❌ | ✅ |
| **Read-Only** | ✅ | ❌ | ❌ | ❌ | View only |

- **Admin**: Full access to all features including user management and security settings
- **Read-Write**: Can manage servers, run power commands, access settings, but cannot manage users
- **Read-Only**: View-only access to dashboard and server details

#### Anonymous Access

Enable to allow viewing the dashboard without login. Anonymous users get read-only access.

> ⚠️ **Security Note**: Only enable anonymous access on trusted networks.

---

## Prometheus & Grafana Integration

IPMI Monitor provides a built-in Prometheus exporter for integration with your existing monitoring stack.

### Metrics Endpoint

Metrics are exposed at `/metrics` on the same port as the web interface (default: 5000):

```
http://ipmi-monitor:5000/metrics
```

**Common target configurations:**
- `ipmi-monitor:5000` - Docker network (using container name)
- `localhost:5000` - Same host as Prometheus
- `192.168.1.50:5000` - Remote IP address

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

Premium AI features provide intelligent analysis of your server fleet. Access AI features directly from the IPMI Monitor dashboard via the **AI Insights** panel.

### AI Insights Panel

The AI Insights panel is displayed on the right side of your dashboard and contains the following tabs:

| Tab | Description |
|-----|-------------|
| **📊 Summary** | Fleet-wide health summary with critical issues, frequent errors, and trends |
| **🔧 Tasks** | AI-generated maintenance tasks with specific component recommendations |
| **📈 Predictions** | Failure predictions based on sensor trends and event patterns |
| **🔍 RCA** | Root cause analysis for specific events or server issues |
| **💬 Chat** | Interactive AI assistant for asking questions about your fleet |
| **📈 Usage** | Token usage, subscription status, and billing information |
| **🤖 Agent** | AI Recovery Agent configuration and monitoring |

### Fleet Health Summary

The AI analyzes all your servers to generate a comprehensive health report:

- **Critical Issues**: Servers requiring immediate attention
- **Frequent Errors**: Recurring problems across your fleet
- **Recent Events**: Notable system downs, recoveries, and alerts
- **Trend Analysis**: Temperature, power, and error trends
- **SSH Security**: Failed login attempts and security events
- **SEL Analysis**: Pattern detection in System Event Logs

The summary uses **Agentic RAG** (Retrieval Augmented Generation) to:
1. Query multiple data sources (SEL, SSH logs, sensors)
2. Cross-reference findings across servers
3. Provide actionable insights with evidence

### Maintenance Tasks

AI generates specific maintenance tasks with:

- **Server Name**: Exactly which server needs attention
- **Component Name**: Specific component (e.g., "DIMM_A1", "FAN3", "PSU1")
- **Priority**: Critical, High, Medium, or Low
- **Reason**: Evidence-based explanation
- **Suggested Action**: Clear steps to resolve

Example task:
> **Replace DIMM_A1 on BrickBox-40** (Critical)  
> 47 correctable ECC errors in past 24 hours with increasing frequency.  
> Schedule memory replacement during next maintenance window.

### Failure Predictions

AI predicts potential failures based on:

- **Sensor Trends**: Temperature increasing over time
- **Error Frequency**: Correctable errors accelerating
- **Historical Patterns**: Similar failures on other servers
- **Component Age**: Expected lifetime estimates

Predictions include confidence levels and recommended preventive actions.

### Root Cause Analysis (RCA)

Deep analysis for specific events or issues:

- **Event Correlation**: Links related events across time
- **Component Mapping**: Identifies affected hardware
- **Causal Chain**: Explains sequence of failures
- **Resolution Steps**: Specific fix recommendations

Filter RCA by:
- Server (all or specific)
- Event type (SEL, SSH, System)
- Severity (Critical, Warning, Info)
- Time range

### AI Chat

Natural language interface for asking questions:

**Example Questions:**
- "Which servers have high temperatures?"
- "Show me all ECC errors from the past week"
- "What maintenance is needed for BrickBox servers?"
- "Explain the Xid 48 error on server-05"
- "Why did server-10 reboot yesterday?"
- "Are there any SSH brute force attempts?"

**Tips for Better Responses:**
- Be specific about server names when relevant
- Include time ranges ("in the last 24 hours")
- Ask follow-up questions for more detail
- Reference specific error messages if available

### Usage & Billing

The Usage tab shows:

- **Token Usage**: Current month's consumption vs allocation
- **Queries Today**: Number of AI interactions
- **Subscription Tier**: Standard, Professional, or Enterprise
- **Server Count**: Monitored servers vs subscription limit
- **Billing Link**: Direct access to your CryptoLabs account

### Getting Started with AI Features

1. Go to Settings → AI Features
2. Click **Start Free Trial**
3. Sign up for a CryptoLabs account
4. AI features activate automatically
5. Access via the AI Insights panel on dashboard

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

The AI Recovery Agent autonomously handles GPU failures and other hardware issues with an intelligent escalation ladder.

#### Agent Modes

Configure the agent's behavior via the Agent tab in AI Insights:

| Mode | Description |
|------|-------------|
| **⏸️ Disabled** | Agent does not monitor or take actions |
| **👁️ Monitoring Only** | Agent monitors and reports issues but takes no automatic actions (default) |
| **⚡ Actions Enabled** | Agent can automatically execute recovery actions on your servers |

> ⚠️ **Warning**: Actions Enabled mode allows the agent to automatically reboot servers or stop workloads. Enable with caution.

#### How It Works

1. **Detection**: IPMI Monitor detects GPU error via SSH (Xid error)
2. **Analysis**: AI Agent analyzes error type and history
3. **Decision**: Agent decides appropriate recovery action
4. **Execution**: Action performed (if permissions allow)
5. **Verification**: Agent checks if recovery succeeded
6. **Escalation**: If failed, escalates to next level

#### Recovery Actions

Recovery actions are grouped by risk level:

**Low Risk Actions (GPU Only)**
| Action | Description |
|--------|-------------|
| Stop Workload | Gracefully stop containers using the failed GPU |
| GPU Soft Reset | PCI unbind/rebind to reset GPU without rebooting |

**Medium Risk Actions**
| Action | Description |
|--------|-------------|
| Graceful Reboot | Shutdown services cleanly then reboot |
| Disk Cleanup | Clear temp files, logs, and cache if disk full |

**High Risk Actions**
| Action | Description |
|--------|-------------|
| IPMI Power Cycle | Force power cycle via BMC (data loss risk) |

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

#### Prerequisites Check

Before enabling Actions mode, the agent checks:

- **SSH Access**: Can connect to servers via SSH
- **IPMI Access**: Can send BMC commands
- **Docker Access**: Can list/stop containers (for workload management)
- **NVIDIA Driver**: nvidia-smi available for GPU operations

#### Safety Features

- **Permission Checking**: Only performs actions you've enabled
- **Cooldown Management**: Prevents recovery storms
- **Workload Detection**: Identifies containers using GPUs before stopping them
- **NVIDIA Driver Check**: Skips soft recovery if driver reports "Node Reboot Required"
- **Persistent State**: Remembers recovery history per device
- **Maintenance Escalation**: Flags for human intervention after multiple failures

#### Agent Events

All agent actions are logged as events:

| Event | Description |
|-------|-------------|
| GPU Requires Recovery | GPU error detected |
| GPU Reset Attempted | Soft reset performed |
| GPU Clock Limited | Clock reduction applied |
| Server Rebooted | Reboot performed |
| Workload Stopped | Container(s) killed to free GPU |
| Power Cycle Executed | IPMI power cycle performed |
| Maintenance Required | Device flagged for manual intervention |

#### Analyze Fleet Button

Manually trigger an Agentic RAG analysis of your entire fleet:
1. Go to AI Insights → Agent tab
2. Click **🔍 Analyze Fleet**
3. AI performs multi-round investigation across all servers
4. Results show in the main analysis section

#### Recovery History

View recent recovery actions:
- Action type and result (success/failed)
- Timestamp and duration
- Server and component affected
- Error message if failed

#### Enabling the Agent

1. Enable AI features (Settings → AI Features)
2. Go to AI Insights → Agent tab
3. Select **Monitoring Only** mode first
4. Review prerequisites
5. Configure allowed recovery actions
6. Click **Save Recovery Settings**
7. Switch to **Actions Enabled** when ready

> 💡 **Tip:** Start with only low-risk actions enabled. Enable medium/high risk actions only after testing in your environment.

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

### Password Recovery

IPMI Monitor is a **self-hosted application** - there is no central server that can reset your password. Your data and credentials are stored locally in a SQLite database inside the Docker container.

Since you have root access to your server, you can reset your password directly:

#### Option 1: Reset via Script (Recommended)

Save this script as `reset-ipmi-password.sh` and run it:

```bash
#!/bin/bash
# IPMI Monitor Password Reset Script
# Usage: ./reset-ipmi-password.sh <new_password> [username]

NEW_PASSWORD="${1:-changeme}"
USERNAME="${2:-admin}"

# Find the container
CONTAINER=$(docker ps --format '{{.Names}}' | grep -E 'ipmi-monitor|ipmi_monitor' | head -1)

if [ -z "$CONTAINER" ]; then
    echo "❌ IPMI Monitor container not found"
    echo "   Running containers: $(docker ps --format '{{.Names}}')"
    exit 1
fi

echo "🔧 Resetting password for user '$USERNAME' in container '$CONTAINER'..."

# Generate password hash and update database
docker exec -i "$CONTAINER" python3 << EOF
from werkzeug.security import generate_password_hash
import sqlite3

new_password = "$NEW_PASSWORD"
username = "$USERNAME"
password_hash = generate_password_hash(new_password)

conn = sqlite3.connect('/var/lib/ipmi-monitor/ipmi_events.db')
cursor = conn.cursor()

# Check if user exists
cursor.execute("SELECT id FROM user WHERE username = ?", (username,))
user = cursor.fetchone()

if user:
    cursor.execute("UPDATE user SET password_hash = ? WHERE username = ?", (password_hash, username))
    conn.commit()
    print(f"✅ Password updated for user '{username}'")
else:
    print(f"❌ User '{username}' not found")
    cursor.execute("SELECT username FROM user")
    users = cursor.fetchall()
    if users:
        print(f"   Available users: {', '.join([u[0] for u in users])}")

conn.close()
EOF

echo ""
echo "🔐 You can now login with:"
echo "   Username: $USERNAME"
echo "   Password: $NEW_PASSWORD"
```

**Usage:**
```bash
chmod +x reset-ipmi-password.sh

# Reset admin password to 'newpassword123'
./reset-ipmi-password.sh newpassword123 admin

# Reset a different user
./reset-ipmi-password.sh mypassword myuser
```

#### Option 2: Manual Database Update

```bash
# Enter the container
docker exec -it ipmi-monitor bash

# Use Python to update password
python3 << 'EOF'
from werkzeug.security import generate_password_hash
import sqlite3

new_password = "your_new_password"
username = "admin"

password_hash = generate_password_hash(new_password)
conn = sqlite3.connect('/var/lib/ipmi-monitor/ipmi_events.db')
cursor = conn.cursor()
cursor.execute("UPDATE user SET password_hash = ? WHERE username = ?", (password_hash, username))
conn.commit()
print(f"Password updated for {username}")
conn.close()
EOF
```

#### Option 3: Environment Variable (New Container Only)

If starting fresh, set the admin password via environment variable:

```yaml
environment:
  - ADMIN_USER=admin
  - ADMIN_PASS=your_new_password
```

> ⚠️ **Note:** The `ADMIN_PASS` environment variable only sets the password on first run when the database is created. It does not reset existing passwords.

---

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

## FAQ - Frequently Asked Questions

### Why do only some servers show power consumption?

**Short Answer:** Power readings require **DCMI (Data Center Manageability Interface)** support, which is an optional IPMI extension not all BMCs support.

**Details:**
IPMI Monitor collects power consumption using the command:
```
ipmitool dcmi power reading
```

DCMI is primarily found on enterprise/server-grade BMCs. Many motherboards, especially consumer-grade or older server boards, don't support it. Even servers of the same model can have different BMC firmware versions with varying DCMI support.

**What you can do:**
- Update BMC firmware - newer versions sometimes add DCMI support
- Check if your BMC supports Redfish power monitoring (IPMI Monitor will try Redfish first)
- Accept that power metrics are only available on supported hardware

**For comprehensive GPU and system metrics**, consider using **[DC Overview](https://github.com/cryptolabsza/dc-overview)** which installs exporters directly on servers:
- `node_exporter` - CPU, memory, disk, network metrics
- `dc-exporter-rs` - GPU temperatures, power, utilization, memory, errors
- Works regardless of BMC capabilities

### Why are temperature sensors missing for some servers?

BMC sensor support varies widely:

| BMC Type | Typical Sensors Available |
|----------|---------------------------|
| **Enterprise (Dell iDRAC, HP iLO)** | CPU, inlet, outlet, DIMM, PSU, drive temps |
| **NVIDIA DGX** | Limited via IPMI - use Redfish or dc-exporter-rs |
| **Supermicro IPMI** | CPU, system temps, some have VRM temps |
| **Consumer boards** | Often only CPU package temp |

**Solution:** Enable Redfish in Settings if your BMC supports it - Redfish often exposes more sensors than IPMI.

### Why does "No metrics collected yet" appear for dc-exporter?

This happens when `dc-exporter-rs` cannot communicate with NVIDIA's NVML (NVIDIA Management Library):

| Error | Cause | Solution |
|-------|-------|----------|
| "NVML failed to initialize" | Driver not loaded | Run `nvidia-smi`, reboot if needed |
| "Driver/library mismatch" | Kernel module ≠ userspace lib | Reinstall NVIDIA driver, reboot |
| "No NVIDIA GPU found" | No GPU or disabled | Check `lspci \| grep NVIDIA` |
| "Insufficient permissions" | Need root or nvidia group | Run exporter as root or add to nvidia group |

**Quick fix attempt:**
```bash
# Check driver status
nvidia-smi

# If mismatch, reinstall driver
sudo apt install --reinstall nvidia-driver-XXX

# Reboot to reload kernel module
sudo reboot
```

### What's the difference between IPMI Monitor and DC Overview?

| Feature | IPMI Monitor | DC Overview |
|---------|--------------|-------------|
| **Data Source** | BMC (out-of-band) | OS-level exporters (in-band) |
| **Works when OS down?** | ✅ Yes | ❌ No |
| **GPU metrics depth** | Basic (if BMC supports) | Comprehensive (NVML-based) |
| **CPU/Memory/Disk** | Limited to BMC sensors | Full via node_exporter |
| **Setup complexity** | Just need BMC IPs | Install exporters on each server |
| **Power consumption** | DCMI (if supported) | Per-GPU power via NVML |
| **Hardware events (SEL)** | ✅ Full SEL history | ❌ No |
| **Remote power control** | ✅ Yes | ❌ No |

**Recommendation:** Use both together for complete coverage:
- **IPMI Monitor** for hardware health, SEL events, and remote power control
- **DC Overview** for detailed GPU metrics, OS-level stats, and Grafana dashboards

### Why do some servers show as "unreachable" intermittently?

Common causes:

1. **Network congestion** - BMC management networks often share bandwidth
2. **BMC overload** - Too many concurrent IPMI commands
3. **Firmware bugs** - Some BMCs become unresponsive under load
4. **IPMI session limits** - Most BMCs limit concurrent sessions (typically 4-8)

**IPMI Monitor mitigations:**
- Uses parallel workers with controlled concurrency
- Implements connection pooling
- Retries on transient failures
- Prefers Redfish (faster, more reliable) when available

### How do I get GPU-specific metrics like temperature and power?

**Option 1: Via BMC (limited)**
- Some BMCs (NVIDIA DGX, Dell with GPU support) expose GPU sensors
- Enable Redfish for better GPU sensor coverage

**Option 2: DC Overview with dc-exporter-rs (recommended)**
```bash
# On each GPU server
pip install dc-overview
dc-overview quickstart
```

This installs `dc-exporter-rs` which provides 50+ GPU metrics:
- GPU temperature, hotspot, VRAM temp
- Power usage per GPU
- Utilization (SM, memory, encoder)
- Clock speeds, throttle reasons
- ECC errors, PCIe AER errors
- Fan speeds

### Why is the IPMI Monitor Grafana dashboard missing some panels?

The dashboard uses metrics that require:
- `ipmi_power_watts` - Requires DCMI support (see FAQ above)
- `ipmi_temperature_celsius{sensor_name=~"CPU.*"}` - Requires CPU temp sensors

**If panels are empty:**
1. Check if your BMC exposes those sensors (use Server Details page)
2. Wait for a collection cycle (default 5 minutes)
3. Check Prometheus is scraping IPMI Monitor correctly

### How do I monitor servers that only have Redfish (no IPMI)?

IPMI Monitor supports pure-Redfish monitoring:

1. Enable Redfish in **Settings → Server Config**
2. Set protocol to "redfish" for the server
3. Ensure BMC credentials have Redfish access

Redfish advantages:
- Faster response times
- More detailed sensor data
- Better standardization across vendors
- Works over HTTPS (more secure)

---

## Support

- 💬 **Discord**: [Join our Discord](https://discord.gg/7yeHdf5BuC) - Get help, chat with the community
- **GitHub Issues**: [github.com/cryptolabsza/ipmi-monitor/issues](https://github.com/cryptolabsza/ipmi-monitor/issues)
- **Documentation**: [CryptoLabs Support](https://www.cryptolabs.co.za/ipmi-monitor-support-documentation/)
- **AI Support**: Use the AI Chat feature for instant help

---

*Last updated: January 2026*

