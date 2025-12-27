# Supermicro SEL Reference

> IPMI System Event Log reference for Supermicro servers.

**Platforms:** Various (AS-, SYS-, PIO- series) | **BMC:** IPMI 2.0 / Redfish

---

## Overview

Supermicro servers use a standard IPMI 2.0-compliant BMC with additional Supermicro-specific features. Management is available via IPMItool, IPMIView GUI, or Redfish API.

---

## Supported Models

| Model | Form Factor | CPU | Use Case |
|-------|-------------|-----|----------|
| AS-1014S-WTRT | 1U | AMD EPYC | Compute |
| AS-A126GS-TNBR | 4U | AMD | GPU Server |
| SYS-A22GA-NBRT | 4U | AMD | GPU Server |
| PIO-629BT-06408S-01-RI13 | 2U | Intel | Twin Server |
| SYS-2029TP-HC1R-G2-FS011 | 2U | Intel | TwinPro |
| GENOA2D24G-2L+ | Custom | AMD EPYC Genoa | GPU Server |
| Super Server (Generic) | Various | Various | Generic models |

---

## Model Naming Convention

| Prefix | Meaning |
|--------|---------|
| **AS-** | AMD EPYC platform |
| **SYS-** | Standard system |
| **PIO-** | Pioneer OEM series |
| **GPU-** | GPU-optimized |

| Suffix | Meaning |
|--------|---------|
| **-WTRT** | WIO (Wide I/O), Tower, Redundant PSU |
| **-TNBR** | Twin, NVMe, Redundant |
| **-HC1R** | Hot-swap, Compact, 1U, Redundant |

---

## BMC Versions

| Version | Features |
|---------|----------|
| 1.00 - 1.74 | Standard IPMI |
| 3.10+ | Enhanced Redfish |
| 6.74+ | Latest with GPU support |

---

## Temperature Sensors

Supermicro uses abbreviated sensor names:

| Sensor | Location | Warning | Critical |
|--------|----------|---------|----------|
| **CPU1 Temp** | Processor 1 | 85°C | 95°C |
| **CPU2 Temp** | Processor 2 | 85°C | 95°C |
| **System Temp** | Mainboard ambient | 75°C | 80°C |
| **Peripheral Temp** | PCIe area | 80°C | 85°C |
| **MB Temp** | Motherboard | 80°C | 85°C |
| **DIMM Temp** | Memory | 75°C | 85°C |
| **VRM Temp** | Voltage regulators | 95°C | 105°C |
| **TR1/TR2** | Thermal regions | Varies | Varies |
| **AOC Temp** | Add-on card | 80°C | 90°C |

---

## Fan Sensors

| Sensor Pattern | Description |
|----------------|-------------|
| **FAN1 - FAN8** | Chassis fans |
| **FANA - FANF** | Additional fans (hex naming) |
| **PSU Fan** | Power supply fans |

### Fan Event Types

| Event | Severity | Description |
|-------|----------|-------------|
| Lower Non-critical | 🟡 Warning | Fan slowing |
| Lower Critical | 🔴 Critical | Fan very slow |
| Lower Non-Recoverable | 🔴 Critical | Fan stopped |

---

## Power Supply Events

### PSU Sensors

| Sensor | Description |
|--------|-------------|
| **PS1 Status** | Power supply 1 |
| **PS2 Status** | Power supply 2 |
| **PSU1/PSU2** | Alternative naming |
| **PWR Status** | Overall power status |

### PSU Event Types

| Event | Severity | Description |
|-------|----------|-------------|
| Presence detected | 🟢 Info | PSU installed |
| Failure detected | 🔴 Critical | PSU failed |
| Power Supply AC lost | 🔴 Critical | AC power lost |
| Predictive failure | 🟡 Warning | PSU degrading |
| Configuration Error | 🟡 Warning | PSU mismatch |

---

## Memory Events

### DIMM Naming

Supermicro uses positional DIMM naming:

| CPU | Channels | Slots |
|-----|----------|-------|
| CPU1 | P1-DIMMA - P1-DIMMH | 1-2 per channel |
| CPU2 | P2-DIMMA - P2-DIMMH | 1-2 per channel |

### Memory Event Types

| Event | Severity | Description |
|-------|----------|-------------|
| Correctable ECC | 🔵 Info | Single-bit error |
| Uncorrectable ECC | 🔴 Critical | Multi-bit error |
| Presence Detected | 🟢 Info | DIMM found |
| Configuration Error | 🟡 Warning | DIMM config issue |

---

## OEM Records (c0, c1)

Supermicro uses OEM record types for vendor-specific events:

### OEM Record c0

```
OEM record c0 | info | 002b99 | 6a1dc0040100
```

| Field | Meaning |
|-------|---------|
| 002b99 | Event identifier |
| 6a1dc0040100 | OEM-specific data |

**Common c0 Events:**
- System configuration changes
- BIOS updates
- Hardware detection events

### OEM Record c1

```
OEM record c1 | info | 000000 | 0698c0a80202
```

**Common c1 Events:**
- Network configuration
- IP address changes (visible in hex data)

### Decoding OEM Data

The hex data often contains IP addresses:
```
0698c0a80202 = ... 192.168.2.2 (c0.a8.02.02)
0698c0a80208 = ... 192.168.2.8 (c0.a8.02.08)
```

---

## Voltage Sensors

| Sensor | Normal Range |
|--------|--------------|
| **12V** | 11.4V - 12.6V |
| **5VCC** | 4.75V - 5.25V |
| **3.3VCC** | 3.135V - 3.465V |
| **VBAT** | 2.7V - 3.3V |
| **Vcpu1/Vcpu2** | Per CPU spec |
| **VDIMM** | 1.1V - 1.3V (DDR5) |
| **5VSB** | 4.75V - 5.25V |
| **3.3VSB** | 3.135V - 3.465V |

---

## Drive Sensors

### Hot-Swap Bay Sensors

| Sensor Pattern | Description |
|----------------|-------------|
| **HDD Status** | Drive presence |
| **Slot N Status** | Individual slot status |
| **Backplane N** | Backplane health |

### Drive Events

| Event | Severity | Description |
|-------|----------|-------------|
| Drive Present | 🟢 Info | Drive installed |
| Drive Absent | 🟢 Info | Drive removed |
| Drive Fault | 🔴 Critical | Drive failure |
| Rebuild | 🟢 Info | RAID rebuilding |

---

## Processor Events

| Event | Severity | Description |
|-------|----------|-------------|
| Presence detected | 🟢 Info | CPU found |
| IERR | 🔴 Critical | Internal error |
| Thermal Trip | 🔴 Critical | CPU overheated |
| FRB1/BIST Failure | 🔴 Critical | CPU self-test failed |
| Configuration Error | 🟡 Warning | CPU mismatch |
| Throttled | 🟡 Warning | Power/thermal throttling |

---

## GPU Support (AS-A126GS, SYS-A22GA)

GPU-optimized Supermicro servers include:

| Sensor | Description |
|--------|-------------|
| **GPU1-8 Temp** | GPU temperatures |
| **GPU Power** | GPU power draw |
| **AOC Slot N** | GPU slot status |

---

## BMC Web Interface

### Access

- **URL:** `https://<bmc_ip>/`
- **Default User:** ADMIN
- **Default Pass:** ADMIN (change immediately!)

### Key Features

| Feature | Description |
|---------|-------------|
| **iKVM** | HTML5 remote console |
| **Virtual Media** | ISO/floppy mount |
| **Power Control** | Power on/off/cycle |
| **SEL Log** | Event log viewer |
| **Sensor Readings** | Real-time sensors |
| **Remote FRU** | Hardware inventory |

---

## IPMItool Commands

```bash
# Get sensor readings
ipmitool -I lanplus -H <bmc_ip> -U ADMIN -P ADMIN sdr list full

# Get SEL entries
ipmitool -I lanplus -H <bmc_ip> -U ADMIN -P ADMIN sel list

# Clear SEL (when full)
ipmitool -I lanplus -H <bmc_ip> -U ADMIN -P ADMIN sel clear

# Get FRU info
ipmitool -I lanplus -H <bmc_ip> -U ADMIN -P ADMIN fru print

# Power status
ipmitool -I lanplus -H <bmc_ip> -U ADMIN -P ADMIN power status

# Power cycle
ipmitool -I lanplus -H <bmc_ip> -U ADMIN -P ADMIN power cycle

# BMC cold reset
ipmitool -I lanplus -H <bmc_ip> -U ADMIN -P ADMIN mc reset cold

# Get BMC info
ipmitool -I lanplus -H <bmc_ip> -U ADMIN -P ADMIN mc info
```

---

## IPMIView GUI

Supermicro provides IPMIView for graphical management:

- Download from Supermicro website
- Java-based application
- Supports multiple server management
- Includes KVM, virtual media, sensor monitoring

---

## Redfish API

```bash
# Get system info
curl -k -u ADMIN:ADMIN https://<bmc_ip>/redfish/v1/Systems/1

# Get thermal
curl -k -u ADMIN:ADMIN https://<bmc_ip>/redfish/v1/Chassis/1/Thermal

# Get power
curl -k -u ADMIN:ADMIN https://<bmc_ip>/redfish/v1/Chassis/1/Power

# Get event log
curl -k -u ADMIN:ADMIN https://<bmc_ip>/redfish/v1/Managers/1/LogServices/IPMI/Entries
```

---

## Supermicro Update Manager (SUM)

SUM provides command-line firmware management:

```bash
# Get BMC firmware version
sum -i <bmc_ip> -u ADMIN -p ADMIN -c GetBmcInfo

# Update BMC firmware
sum -i <bmc_ip> -u ADMIN -p ADMIN -c UpdateBmc --file bmc_firmware.bin

# Get BIOS version
sum -i <bmc_ip> -u ADMIN -p ADMIN -c GetBiosInfo
```

---

## Troubleshooting

### BMC Not Responding

1. Check network connectivity
2. Verify BMC IP via BIOS (F2) → IPMI Config
3. Try physical BMC reset (jumper or command)
4. Check for IP conflicts

### Fan Warnings

1. Check for dust/obstructions
2. Verify fan properly seated
3. Check fan cable connection
4. Replace fan module

### High Temperatures

1. Verify datacenter cooling
2. Check all fans operational
3. Inspect for dust buildup
4. Review system load

### OEM Record Interpretation

If seeing unknown OEM records:
1. Note the record type (c0, c1, etc.)
2. Check Supermicro documentation
3. Contact Supermicro support with event data

---

## Related Documentation

- [Supermicro IPMI User Guide](https://www.supermicro.com/support/)
- [IPMIView User Guide](https://www.supermicro.com/solutions/management-software/ipmi-utilities)
- [Supermicro Update Manager (SUM)](https://www.supermicro.com/solutions/management-software/supermicro-update-manager)
- [IPMI SEL Reference](ipmi_sel_reference.md)

---

*Last updated: December 2025*

