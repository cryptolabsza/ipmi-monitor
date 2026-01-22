# IPMI Monitor - Complete User Guide

This document provides comprehensive information about the IPMI Monitor system. Use this knowledge to help users understand features, troubleshoot issues, and optimize their setup.

---

## Overview

IPMI Monitor is a web-based tool for monitoring server hardware via IPMI (Intelligent Platform Management Interface) and Redfish APIs. It collects BMC (Baseboard Management Controller) data including:
- System Event Log (SEL) entries
- Sensor readings (temperature, voltage, fan speed, power)
- Hardware inventory (CPU, memory, storage, GPU)
- Power status and control

---

## Dashboard

### Main View
The dashboard shows a grid of all monitored servers with:
- **Server name** and BMC IP address
- **Status indicator**: Green (online), Red (offline), Yellow (warning)
- **Event count**: Recent events in last 24 hours
- **Quick stats**: Temperature, fan status, power state

### Server Cards
Each server card displays:
- **Name**: Configurable friendly name (e.g., "brickbox-01")
- **BMC IP**: The IPMI management IP (usually ends in .0)
- **Status badge**: Online/Offline/Warning
- **Last event**: Most recent SEL entry
- **Temperature**: CPU or system inlet temperature

### Clicking a Server
Click any server card to open the **Server Detail** page with full information.

### Refresh
- Data auto-refreshes every 60 seconds
- Manual refresh available via the refresh button
- Event collection runs every 5 minutes (configurable)

---

## Server Detail Page

### Events Tab
Shows all System Event Log (SEL) entries for the server:
- **Timestamp**: When the event occurred
- **Severity**: Critical (red), Warning (yellow), Info (blue)
- **Description**: Event message from BMC
- **Sensor**: Which sensor triggered the event

**Common Event Types:**
- Memory ECC errors (correctable/uncorrectable)
- Temperature threshold crossings
- Fan speed warnings
- Power supply status changes
- System boot/shutdown events

**Actions:**
- **Clear DB Events**: Remove events from IPMI Monitor database (doesn't affect BMC)
- **Clear BMC SEL**: Clear the actual BMC System Event Log (ADMIN ONLY - use with caution!)

### Sensors Tab
Real-time sensor readings:
- **Temperature sensors**: CPU, inlet, exhaust, DIMM temperatures
- **Voltage sensors**: 3.3V, 5V, 12V, VBAT (backup battery)
- **Fan sensors**: RPM for all system fans
- **Power sensors**: Wattage consumption

**Reading the data:**
- Values shown with current reading, units, and status
- Thresholds displayed when available (warning/critical levels)
- Historical trend available for some sensors

### Inventory Tab
Hardware information collected via IPMI FRU, Redfish, and SSH:

**System Info:**
- Manufacturer (e.g., ASUS, Dell, Supermicro)
- Product name/model
- Serial number
- Part number

**CPU:**
- Model (e.g., AMD EPYC 7272 12-Core)
- Core count
- CPU count (for multi-socket)

**Memory:**
- Total installed RAM (GB)
- Slots used / total slots
- Memory type (DDR4 ECC RDIMM)

**Storage:**
- All drives detected
- Size, model, type (NVMe, SSD, HDD)

**GPU (if present):**
- GPU model (NVIDIA A100, etc.)
- VRAM
- Temperature and utilization

**Connectivity Status:**
- BMC IP reachable: Yes/No
- Primary/OS IP reachable: Yes/No
- Last check timestamp

**Collect Inventory Button:**
Manually triggers inventory collection. Useful after hardware changes.

### Power Management (Admin/Read-Write only)
Power control actions:
- **Power On**: Start the server
- **Soft Shutdown**: Graceful OS shutdown (ACPI)
- **Reset**: Warm reboot
- **Power Cycle**: Hard reboot (power off then on)
- **Force Power Off**: Immediate power cut (like pulling plug - use carefully!)

---

## Settings Page

### Manage Servers Tab
Add, edit, and remove monitored servers.

**Add New Server:**
1. Enter BMC IP address (e.g., 88.0.1.0)
2. Enter friendly server name
3. Optionally enter OS/primary IP (e.g., 88.0.1.1)
4. Select protocol: Auto, IPMI only, or Redfish only
5. Click "Add Server"

**Edit Server:**
Click any server in the list to open edit modal:
- Change name, IPs, protocol
- Configure BMC credentials (if different from default)
- Configure SSH credentials for OS inventory
- Test BMC connection
- Test SSH connection
- Check Redfish availability

**Server Status:**
- Enabled: Server is actively monitored
- Disabled: Server exists but not monitored
- Deprecated: Server archived (not monitored, kept for history)

**Initialize from Defaults:**
Bulk-add servers from a pre-configured servers.yaml file.

### SSH Tab (Optional)
Configure SSH access for detailed inventory collection.

**Why SSH?**
IPMI/Redfish provides basic inventory. SSH to the OS enables:
- Exact CPU model and specifications
- Detailed memory configuration
- Complete storage device information
- GPU information (via nvidia-smi)

**SSH Key Management:**
- Add named SSH keys (e.g., "DGX Key", "Default Key")
- Keys stored securely and can be assigned to servers
- Avoids copy-pasting same key for every server

**Default SSH Configuration:**
- Set username (default: root)
- Set port (default: 22)
- Select default SSH key or enter password

**Per-Server SSH:**
Override defaults for specific servers:
- Custom OS IP
- Custom SSH credentials
- Assign specific SSH key

**Testing Credentials:**
Use "Test BMC" and "Test SSH" buttons in edit modal to verify.

### Alerts Tab
Configure alert rules and thresholds.

**Alert Rules:**
- Temperature thresholds (warning/critical)
- Fan speed minimums
- ECC error counts
- Power events
- Custom rules based on sensor values

**Alert Actions:**
- Enable/disable individual rules
- Set cooldown periods (prevent alert spam)
- Configure notification channels

### Notifications Tab
Set up alert delivery methods.

**Telegram:**
1. Create a bot via @BotFather
2. Get the bot token
3. Get your chat ID (or group ID)
4. Enable and save

**Email:**
Configure SMTP settings for email alerts.

**Webhook:**
Send alerts to custom HTTP endpoints (Slack, Discord, etc.)

**Testing:**
Use "Test" buttons to verify each channel works.

### Security Tab (Admin only)
User management and access control.

**User Roles:**
- **Admin**: Full access, can manage users, AI features, security
- **Read-Write**: Can manage servers, run power commands, but not users
- **Read-Only**: View only, no changes allowed

**Anonymous Access:**
Enable to allow viewing without login (read-only).

**User Management:**
- Create new users with specific roles
- Enable/disable accounts
- Force password changes

**Admin Credentials:**
Change admin username and password.

### AI Features Tab (Admin only)
Connect to CryptoLabs AI service for advanced analytics.

**Features:**
- Fleet health summaries
- Predictive maintenance tasks
- Root cause analysis
- AI chat assistant

**Setup:**
1. Click "Start Free Trial" to create CryptoLabs account
2. Get API key automatically
3. Sync enabled automatically

> Visit [cryptolabs.co.za](https://cryptolabs.co.za) for current pricing and plans.

---

## AI Features (Premium)

### Summary Tab
AI-generated fleet health overview:
- Overall health score
- Servers needing attention
- Key observations
- Trend analysis

### Maintenance Tasks
AI-identified maintenance work:
- Tasks with priority (critical/high/medium/low)
- Affected servers listed explicitly
- Component identification
- Suggested actions
- Supporting evidence

### Predictions
Predictive analytics:
- Components likely to fail soon
- Recommended spare parts
- Maintenance scheduling suggestions

### RCA (Root Cause Analysis)
Deep analysis of specific events:
- Select an event to analyze
- AI explains what happened
- Identifies root cause
- Suggests prevention

### AI Chat
Interactive assistant for:
- "Which servers have high temperatures?"
- "What maintenance is needed this week?"
- "Explain this error message"
- "How do I configure X?"

---

## Troubleshooting

### Server Shows Offline
1. Check BMC IP is reachable: `ping 88.0.x.0`
2. Verify IPMI credentials are correct
3. Try "Test BMC" button in server edit
4. Check firewall allows port 623 (IPMI)

### No Events Showing
1. Check server is enabled in settings
2. Wait for next collection cycle (5 min default)
3. Some BMCs have empty SEL by default
4. Check BMC firmware supports SEL

### Inventory Missing Details
1. Enable SSH in Settings → SSH tab
2. Configure SSH credentials for server
3. Use "Collect Inventory" button
4. Check SSH connectivity with "Test SSH"

### SSH Test Fails
Common issues:
- Wrong OS IP (BMC IP vs OS IP)
- SSH key format issue (re-paste key)
- Password authentication disabled on server
- Firewall blocking port 22

### BMC Test Fails
Common issues:
- Wrong IPMI credentials
- Network not routing to BMC
- BMC firmware issue
- IPMI over LAN disabled in BIOS

### High CPU/Memory on Monitor
1. Reduce number of monitored servers
2. Increase poll interval (POLL_INTERVAL env var)
3. Use single Gunicorn worker
4. Check for network timeouts

---

## Glossary

- **BMC**: Baseboard Management Controller - dedicated processor for server management
- **IPMI**: Intelligent Platform Management Interface - protocol for BMC communication
- **Redfish**: Modern REST API alternative to IPMI
- **SEL**: System Event Log - BMC's record of hardware events
- **FRU**: Field Replaceable Unit - hardware inventory data
- **SDR**: Sensor Data Record - sensor configuration data
- **ECC**: Error Correcting Code - memory error detection/correction
- **DIMM**: Dual Inline Memory Module - RAM stick
- **PSU**: Power Supply Unit
- **VBAT**: Backup battery voltage (usually CR2032 for CMOS)

---

## Best Practices

1. **Name servers consistently** (e.g., rack-row-unit or function-number)
2. **Set up notifications** before issues occur
3. **Regular inventory collection** after hardware changes
4. **Monitor ECC errors** - they indicate failing memory
5. **Watch battery voltage** - low VBAT causes CMOS issues
6. **Keep firmware updated** on BMCs
7. **Use SSH keys** instead of passwords for automation
8. **Review AI tasks weekly** for proactive maintenance

---

## Quick Reference

| Task | Location |
|------|----------|
| Add server | Settings → Manage Servers → Add New Server |
| Edit credentials | Settings → Manage Servers → Click server → Edit |
| Test connection | Edit Server modal → Test BMC / Test SSH buttons |
| View events | Dashboard → Click server → Events tab |
| Check sensors | Dashboard → Click server → Sensors tab |
| Get inventory | Dashboard → Click server → Inventory tab → Collect |
| Power control | Dashboard → Click server → Power dropdown |
| Set up alerts | Settings → Alerts tab |
| Configure notifications | Settings → Notifications tab |
| Manage users | Settings → Security tab |
| Connect AI | Settings → AI Features tab |

