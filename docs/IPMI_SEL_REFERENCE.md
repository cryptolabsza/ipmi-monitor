# IPMI System Event Log (SEL) Reference Guide

> Complete reference for interpreting BMC System Event Log messages.

**Version:** v1.0 | **Last Updated:** December 2025

---

## Table of Contents

- [Understanding SEL Entries](#understanding-sel-entries)
- [Event Data Bytes](#event-data-bytes)
- [Memory Events](#memory-events)
- [Temperature Events](#temperature-events)
- [Fan Events](#fan-events)
- [Power Supply Events](#power-supply-events)
- [Voltage Events](#voltage-events)
- [Processor Events](#processor-events)
- [System Events](#system-events)
- [Platform-Specific Sensors](#platform-specific-sensors)
- [GPU-Related Events](#gpu-related-events)
- [Connectivity Events](#connectivity-events)
- [Vendor-Specific References](#vendor-specific-references)
- [Troubleshooting Guide](#troubleshooting-guide)
- [Quick Reference Tables](#quick-reference-tables)

---

## Understanding SEL Entries

### What is the SEL?

The **System Event Log (SEL)** is maintained by the server's BMC (Baseboard Management Controller). It records hardware events, errors, and status changes independent of the operating system. This makes it invaluable for diagnosing issues even when the OS has crashed or the server won't boot.

### SEL Record Structure

Each SEL entry contains these fields:

| Field | Description |
|-------|-------------|
| **Record ID** | Unique identifier (the SEL ID number like 15649) |
| **Timestamp** | When the event occurred (BMC time) |
| **Generator ID** | Which component generated the event |
| **Sensor Type** | Category of the sensor (Memory, Temperature, etc.) |
| **Sensor Number** | Specific sensor that triggered the event |
| **Event Direction** | Assertion (condition became true) or Deassertion (condition cleared) |
| **Event Data** | 3 bytes of event-specific data (shown as hex like 0xA0FF18) |

### Severity Levels

| Level | Color | Meaning | Action |
|-------|-------|---------|--------|
| **Critical** | 🔴 Red | Immediate risk of data loss or outage | Act immediately |
| **Warning** | 🟡 Yellow | Degraded state, potential for failure | Investigate soon |
| **Info** | 🔵 Blue | Informational, normal operation | Monitor only |

---

## Event Data Bytes

### Decoding Hex Event Data

Event data is typically shown as a 3-byte hex value like `0xA0FF18`. Here's how to decode it:

```
0xA0FF18 breaks down as:
├── 0xA0 (Byte 1): Event Data 1 - Event type/reading class
├── 0xFF (Byte 2): Event Data 2 - Sensor-specific info (0xFF = unused)
└── 0x18 (Byte 3): Event Data 3 - Additional info (e.g., DIMM slot)
```

### Byte 1 (Event Data 1) Structure

| Bits | Meaning |
|------|---------|
| Bit 7 | Event reading type class (0=threshold, 1=discrete) |
| Bits 6-4 | Event data 2/3 validity |
| Bits 3-0 | Event offset (specific event within sensor type) |

### Common Byte 1 Values

| Value | Meaning |
|-------|---------|
| 0xA0 | Correctable memory error (ECC) |
| 0xA1 | Uncorrectable memory error |
| 0xA2 | Memory parity error |
| 0x01 | Lower critical threshold |
| 0x02 | Lower non-critical threshold |
| 0x07 | Upper critical threshold |
| 0x09 | Upper non-critical threshold |

---

## Memory Events

Memory events (Sensor Type 0x0C) are among the most common and important to understand.

### Memory Event Types

| Event Code | Severity | Description | Action Required |
|------------|----------|-------------|-----------------|
| 0x00 | Info | Correctable ECC Error | Monitor frequency |
| 0x01 | Critical | Uncorrectable ECC Error | Replace DIMM |
| 0x02 | Critical | Parity Error | Replace DIMM |
| 0x03 | Warning | Memory Scrub Failed | Run diagnostics |
| 0x04 | Critical | Memory Device Disabled | Check/replace DIMM |
| 0x05 | Warning | Correctable ECC Logging Limit | Too many errors |
| 0x06 | Info | Presence Detected | Normal boot event |
| 0x07 | Warning | Configuration Error | Check DIMM seating |
| 0x08 | Info | Spare Activated | Spare DIMM in use |
| 0x09 | Warning | Memory Throttled | Check cooling |
| 0x0A | Critical | Critical Overtemperature | Check cooling |
| 0x0B | Warning | Under-temperature | Check environment |

### Interpreting Memory Error Data

For memory events like `Memory 0xA0FF18`:

```
0xA0 = Event Data 1
├── 0xA0 indicates Correctable ECC Error
└── Event offset = 0x00 (correctable)

0xFF = Event Data 2
└── Often unused (0xFF = not applicable)

0x18 = Event Data 3
└── May indicate DIMM slot (24 decimal) or memory rank
```

### Memory Event Frequency Guidelines

| Frequency | Interpretation | Action |
|-----------|----------------|--------|
| Once in months | Normal ECC operation | None |
| Weekly | Minor degradation | Monitor |
| Daily | DIMM degrading | Plan replacement |
| Hourly | DIMM failing | Replace soon |
| Multiple per hour | Imminent failure | Replace immediately |

### Recommended Actions for Memory Events

**Correctable ECC Errors (0x00):**
1. Check event frequency trend
2. Identify affected DIMM slot from event data
3. Verify operating temperatures are normal
4. Schedule memtest86+ at next maintenance
5. Plan proactive replacement if frequency increasing

**Uncorrectable ECC Errors (0x01):**
1. ⚠️ Data corruption may have occurred
2. Check system logs for crashes or hangs
3. Identify the faulty DIMM immediately
4. Schedule emergency replacement
5. Consider restoring from backup if data-sensitive

---

## Temperature Events

Temperature events (Sensor Type 0x01) indicate thermal threshold crossings.

### Temperature Event Types

| Event Code | Severity | Description | Threshold |
|------------|----------|-------------|-----------|
| 0x00 | Warning | Lower Non-Critical | Below warning low |
| 0x01 | Warning | Lower Critical | Below critical low |
| 0x02 | Critical | Lower Non-Recoverable | Extreme cold |
| 0x07 | Warning | Upper Non-Critical | Above warning high |
| 0x09 | Critical | Upper Critical | Above critical high |
| 0x0B | Critical | Upper Non-Recoverable | Extreme heat |

### Temperature Thresholds by Component

| Component | Normal | Warning | Critical |
|-----------|--------|---------|----------|
| CPU | < 70°C | 70-85°C | > 85°C |
| Inlet/Ambient | < 30°C | 30-40°C | > 40°C |
| Exhaust | < 50°C | 50-65°C | > 65°C |
| DIMM | < 60°C | 60-75°C | > 75°C |
| PCH | < 80°C | 80-95°C | > 95°C |
| VRM | < 90°C | 90-105°C | > 105°C |

### Troubleshooting High Temperatures

1. **Check ambient temperature** - Datacenter HVAC issues?
2. **Verify airflow** - Blanking panels installed?
3. **Inspect for dust** - Clean heatsinks and filters
4. **Check fan speeds** - All fans operating normally?
5. **Review workload** - Unusually high CPU/GPU usage?
6. **Thermal paste** - May need reapplication on old systems

---

## Fan Events

Fan events (Sensor Type 0x04) indicate fan speed anomalies.

### Fan Event Types

| Event Code | Severity | Description |
|------------|----------|-------------|
| 0x00 | Warning | Lower Non-Critical (slow) |
| 0x01 | Critical | Lower Critical (very slow/failing) |
| 0x02 | Critical | Lower Non-Recoverable (stopped) |
| 0x04 | Info | Presence Detected |
| 0x05 | Critical | Fault Detected |
| 0x07 | Warning | Upper Non-Critical (too fast) |

### Fan Speed Guidelines

| Status | RPM Range | Meaning |
|--------|-----------|---------|
| Normal | 2000-8000 | Healthy operation |
| Warning | 1000-2000 | Fan slowing down |
| Critical | < 1000 | Fan failing |
| Stopped | 0 | Fan dead or disconnected |

### Fan Failure Actions

1. **Verify physical fan** - Is it spinning?
2. **Check connections** - Fan cable seated properly?
3. **Listen for noise** - Grinding = bearing failure
4. **Check for obstructions** - Cables in fan path?
5. **Replace fan** - Don't delay, thermal shutdown risk

---

## Power Supply Events

Power supply events (Sensor Type 0x08) indicate PSU status changes.

### Power Supply Event Types

| Event Code | Severity | Description |
|------------|----------|-------------|
| 0x00 | Info | Presence Detected |
| 0x01 | Critical | Failure Detected |
| 0x02 | Warning | Predictive Failure |
| 0x03 | Critical | Input Lost (AC Power) |
| 0x04 | Warning | Input Out of Range |
| 0x05 | Warning | Configuration Error |
| 0x06 | Info | Standby Mode |

### Power Event Troubleshooting

| Event | Common Cause | Action |
|-------|--------------|--------|
| Input Lost | Power outage, PDU issue | Check PDU, UPS |
| Failure Detected | PSU hardware failure | Replace PSU |
| Predictive Failure | PSU degrading | Schedule replacement |
| Input Out of Range | Voltage fluctuation | Check utility power |
| Configuration Error | Mixed PSU types | Match PSU models |

---

## Voltage Events

Voltage events (Sensor Type 0x02) monitor power rail health.

### Voltage Event Types

| Event Code | Severity | Description |
|------------|----------|-------------|
| 0x00 | Warning | Lower Non-Critical |
| 0x01 | Critical | Lower Critical |
| 0x07 | Warning | Upper Non-Critical |
| 0x09 | Critical | Upper Critical |

### Normal Voltage Ranges

| Rail | Normal | Tolerance |
|------|--------|-----------|
| 3.3V | 3.135V - 3.465V | ±5% |
| 5V | 4.75V - 5.25V | ±5% |
| 12V | 11.4V - 12.6V | ±5% |
| VBAT | 2.8V - 3.3V | CMOS battery |
| CPU VCore | Varies | Per spec |

### VBAT (CMOS Battery) Warning

If VBAT drops below 2.5V:
- CMOS battery needs replacement
- BIOS settings may reset on power loss
- Time/date may be incorrect
- Replace with CR2032 at next maintenance

---

## Processor Events

Processor events (Sensor Type 0x07) indicate CPU issues.

### Processor Event Types

| Event Code | Severity | Description |
|------------|----------|-------------|
| 0x00 | Critical | IERR (Internal Error) |
| 0x01 | Critical | Thermal Trip |
| 0x02 | Critical | FRB1/BIST Failure |
| 0x03 | Critical | FRB2/Hang in POST |
| 0x04 | Critical | FRB3/Processor Init |
| 0x05 | Info | Configuration Error |
| 0x06 | Warning | SM BIOS Uncorrectable Error |
| 0x07 | Info | Processor Presence Detected |
| 0x08 | Warning | Processor Disabled |
| 0x09 | Critical | Terminator Presence |
| 0x0A | Warning | Processor Throttled |
| 0x0B | Critical | Machine Check Exception |

### Critical CPU Events

**IERR (Internal Error):**
- CPU detected internal hardware error
- May cause system crash/hang
- Check for microcode updates
- May indicate CPU failure

**Thermal Trip:**
- CPU exceeded thermal limit
- System may have shut down
- Check cooling immediately

**Machine Check Exception (MCE):**
- Serious hardware error
- Check `/var/log/mcelog` for details
- May indicate CPU, memory, or chipset issue

---

## System Events

System-wide events (Sensor Type 0x12, 0x1D, 0x21, etc.).

### Common System Events

| Event | Sensor Type | Meaning |
|-------|-------------|---------|
| System Boot | 0x1D | Server powered on/booted |
| OS Boot | 0x1F | Operating system started |
| OEM System Boot | 0x12 | Vendor-specific boot event |
| Watchdog Reset | 0x23 | Watchdog timer triggered reset |
| Platform Alert | 0x24 | Platform-specific alert |
| Entity Presence | 0x25 | Component added/removed |

### Boot Events Interpretation

Boot events are typically **informational** and indicate normal startup:
- "System Boot" - Server powered on
- "OEM System Boot Event" - BIOS POST completed
- "OS Boot" - Operating system started loading

---

## Platform-Specific Sensors

Different server manufacturers include custom sensors in their BMC implementations.

### ASUS ESC Series

| Sensor | Description |
|--------|-------------|
| PMBPower1, PMBPower2 | Power Module Bus monitoring |
| TR1 Temperature, TR3 Temperature | Thermal zone sensors |
| Memory_Train_ERR | Memory training errors during POST |
| +VCORE1, +VSOC1 | AMD EPYC CPU voltages |
| Backplane1 HDxx | Hot-swap drive bay sensors |

See [ASUS ESC4000A-E10 Reference](asus_esc4000a_e10_reference.html) for details.

### Dell PowerEdge Series

| Sensor | Description |
|--------|-------------|
| PS1-PS4 Status | Power supply health |
| DIMM Axx-Lxx | Memory slots with CPU/channel |
| Physical Disk / Virtual Disk | RAID storage events |
| GPU1-8 Temp/Status | GPU monitoring (XE9680) |
| LCD Codes (Exxx, Wxxx) | Front panel error codes |

See [Dell PowerEdge Reference](dell_poweredge_reference.html) for details.

### Lenovo ThinkSystem Series

| Sensor | Description |
|--------|-------------|
| PFA Memory/HDD/CPU/Fan | Predictive Failure Analysis |
| Lightpath Log | Diagnostic events |
| GPU1-8 Status | GPU health (SR675/680/780) |
| NVLink Status | GPU interconnect |

See [Lenovo ThinkSystem Reference](lenovo_thinksystem_reference.html) for details.

### Supermicro Series

| Sensor | Description |
|--------|-------------|
| OEM record c0/c1 | Vendor-specific OEM events |
| P1-DIMMA through P2-DIMMH | DIMM slot naming |
| FAN1-FAN8, FANA-FANF | Fan sensors |
| AOC Temp/Slot | Add-on card monitoring |

See [Supermicro Reference](supermicro_reference.html) for details.

---

## GPU-Related Events

GPU servers generate additional event types for GPU health and power management.

### GPU Power Good (PWRGD_GB_GPU)

| Event | Meaning |
|-------|---------|
| Asserted | GPU baseboard has stable power |
| Deasserted | GPU power issue detected |

### GPU Status (STATUS_GB_GPU)

| Event | Meaning |
|-------|---------|
| Asserted | GPU baseboard present and healthy |
| Deasserted | GPU baseboard not detected |

### NVIDIA-Specific Events (SEL_NV_*)

NVIDIA DGX systems use custom event types:

| Sensor | Description |
|--------|-------------|
| SEL_NV_MAXP_MAXQ | GPU power mode change (MaxP/MaxQ) |
| SEL_NV_POST_ERR | POST error during boot |
| SEL_NV_BIOS | BIOS/UEFI firmware event |
| SEL_NV_BOOT | System boot event |
| SEL_NV_AUDIT | Security audit (login/config change) |
| SEL_NV_FIRMWARE | Firmware update event |
| SEL_NV_CHASSIS | Chassis intrusion/status |

See [NVIDIA DGX A100 Reference](nvidia_dgx_a100_reference.html) for details.

---

## Connectivity Events

These are **IPMI Monitor-specific events**, not from the BMC.

| Event | Meaning | Typical Cause |
|-------|---------|---------------|
| ✅ OS/Primary IP back online | Server recovered | Issue resolved |
| ⚠️ OS/Primary IP unreachable | OS down, BMC up | OS crash, network issue |
| ❌ BMC unreachable | Can't reach BMC | Network/power failure |
| 🔄 Reboot detected | Server rebooted | Detected via uptime |

### Interpreting Connectivity Events

**OS unreachable but BMC responding:**
- OS may have crashed
- Network interface down
- Firewall blocking
- Process consuming all resources

**Both OS and BMC unreachable:**
- Network switch issue
- Power outage
- Server power failure
- BMC locked up

---

## Troubleshooting Guide

### High-Frequency Memory Errors

**Symptoms:** `Memory 0xA0xxxx` appearing frequently (every 30-60 minutes)

**Diagnosis:**
1. Extract DIMM slot from event data byte 3
2. Check if errors are from same DIMM
3. Review server temperature history
4. Check DIMM seating

**Resolution:**
1. If single DIMM: Plan replacement
2. If multiple DIMMs: Check memory controller, motherboard
3. If temperature-related: Fix cooling first

### Server Going "Dark" (Unreachable)

**Symptoms:** IPMI Monitor shows server offline, then recovers

**Investigation Steps:**
1. Check if OS rebooted (uptime decreased?)
2. Check SEL for power events during outage
3. Check if multiple servers affected (network issue?)
4. Check BMC logs for clues

**Common Causes:**
- Unplanned reboot (kernel panic, watchdog)
- Power glitch (check PDU/UPS)
- Network issue (check switches)
- BMC lockup (may need reset)

### Temperature Spikes

**Symptoms:** Sudden temperature increase events

**Immediate Actions:**
1. Check current temperatures via sensors
2. Verify all fans spinning
3. Check ambient temperature
4. Review recent workload changes

**Root Causes:**
- Fan failure
- Dust buildup
- HVAC failure
- Heavy workload
- Thermal paste degradation

---

## Quick Reference Tables

### Sensor Type Codes

| Code | Type |
|------|------|
| 0x01 | Temperature |
| 0x02 | Voltage |
| 0x03 | Current |
| 0x04 | Fan |
| 0x05 | Physical Security |
| 0x07 | Processor |
| 0x08 | Power Supply |
| 0x09 | Power Unit |
| 0x0C | Memory |
| 0x0D | Drive Slot |
| 0x0F | POST Error |
| 0x10 | Event Logging Disabled |
| 0x12 | System Event |
| 0x13 | Critical Interrupt |
| 0x14 | Button/Switch |
| 0x21 | Slot/Connector |

### Event Direction

| Value | Meaning |
|-------|---------|
| 0x00 | Assertion (condition true) |
| 0x80 | Deassertion (condition cleared) |

### Priority Action Matrix

| Event Type | Frequency | Priority | Action |
|------------|-----------|----------|--------|
| Uncorrectable ECC | Any | 🔴 Critical | Replace DIMM today |
| Correctable ECC | Hourly+ | 🟡 High | Replace this week |
| Correctable ECC | Daily | 🔵 Medium | Plan replacement |
| Correctable ECC | Weekly | ⚪ Low | Monitor |
| Temperature Critical | Any | 🔴 Critical | Fix cooling now |
| Fan Failure | Any | 🔴 Critical | Replace fan now |
| PSU Failure | Any | 🔴 Critical | Replace PSU |
| PSU Predictive | Any | 🟡 High | Order replacement |

---

## Vendor-Specific References

For platform-specific sensors and events, see these dedicated guides:

| Platform | Description |
|----------|-------------|
| [Supported Hardware List](supported_hardware.html) | Master list of all tracked hardware |
| [ASUS ESC4000A-E10](asus_esc4000a_e10_reference.html) | GPU server with AMD EPYC, PMBPower, TR temperatures |
| [Dell PowerEdge](dell_poweredge_reference.html) | PowerEdge XE9680 with iDRAC9, LCD codes |
| [ENFLECTA/ZOTAC](enflecta_zotac_reference.html) | ZRS-326V2, TIANMA GPU compute servers |
| [Lenovo ThinkSystem](lenovo_thinksystem_reference.html) | SR655/SR675/SR680/SR780 V3 with XClarity |
| [NVIDIA DGX A100](nvidia_dgx_a100_reference.html) | AI system with SEL_NV_* events, Xid errors |
| [Nutanix](nutanix_reference.html) | NX-TDT-4NL3-G7 hyperconverged (Dell-based) |
| [Supermicro](supermicro_reference.html) | AS-, SYS-, PIO- series with OEM records |

---

## See Also

- [User Guide](../docs/user-guide.html) - Complete IPMI Monitor documentation
- [AI Architecture](../docs/AI_ARCHITECTURE_V2.html) - How AI features work
- [Developer Guide](../docs/DEVELOPER_GUIDE.html) - API and integration details

---

*Last updated: December 2025*

