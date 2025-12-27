# Lenovo ThinkSystem SEL Reference

> IPMI System Event Log reference for Lenovo ThinkSystem servers with XClarity Controller (XCC).

**Platforms:** ThinkSystem SR655 V3, SR675 V3, SR680a V3, SR780a V3 | **BMC:** XClarity Controller

---

## Overview

Lenovo ThinkSystem servers use the XClarity Controller (XCC) as their baseboard management controller. XCC provides IPMI 2.0 compatibility with additional Lenovo-specific features.

---

## Supported Models

| Model | Form Factor | CPU | GPU Support | Max GPUs |
|-------|-------------|-----|-------------|----------|
| SR655 V3 | 1U | AMD EPYC Genoa | Limited | 2 |
| SR675 V3 | 3U | AMD EPYC Genoa | Yes | 8 |
| SR680a V3 | 4U | AMD EPYC Genoa | Yes | 8 |
| SR780a V3 | 4U | AMD EPYC Genoa | Yes | 8 |

---

## BMC Versions

| Version | Notes |
|---------|-------|
| 5.10 | Initial V3 release |
| 8.10 - 9.20 | Stability improvements |
| 12.10 - 14.11 | Latest with enhanced GPU support |

---

## XClarity Controller Event Types

### System Events

| Sensor Type | Description |
|-------------|-------------|
| **System Event** | General system status changes |
| **Boot/POST** | Power-on self-test events |
| **OS Status** | Operating system watchdog |
| **Firmware** | Firmware update events |

### Temperature Sensors

Lenovo uses descriptive temperature sensor names:

| Sensor | Location | Warning | Critical |
|--------|----------|---------|----------|
| **Ambient Temp** | Air inlet | 35°C | 42°C |
| **CPU1 Temp** | Processor 1 | 85°C | 95°C |
| **CPU2 Temp** | Processor 2 | 85°C | 95°C |
| **GPU1-8 Temp** | GPU modules | 80°C | 90°C |
| **DIMM Temp** | Memory | 75°C | 85°C |
| **PCH Temp** | Platform Controller Hub | 85°C | 95°C |
| **VRM Temp** | Voltage Regulators | 95°C | 105°C |

### Power Supply Events

| Sensor | Description |
|--------|-------------|
| **PSU1 Status** | Power supply 1 health |
| **PSU2 Status** | Power supply 2 health |
| **PSU Redundancy** | Redundancy status |
| **Power Cap** | Power capping events |

#### PSU Event Types

| Event | Severity | Meaning |
|-------|----------|---------|
| AC Lost | 🔴 Critical | Power supply lost AC input |
| Failure Predicted | 🟡 Warning | PSU degrading |
| Failure | 🔴 Critical | PSU has failed |
| Redundancy Lost | 🟡 Warning | Single PSU mode |
| Redundancy Restored | 🟢 Info | Both PSUs online |

---

## Lenovo-Specific Sensors

### Predictive Failure Analysis (PFA)

Lenovo servers include PFA sensors that predict component failures:

| Sensor | Description | Action |
|--------|-------------|--------|
| **PFA Memory** | Memory degradation predicted | Plan DIMM replacement |
| **PFA HDD** | Drive failure predicted | Plan drive replacement |
| **PFA CPU** | Processor issue predicted | Contact support |
| **PFA Fan** | Fan degradation predicted | Replace fan |

### Light Path Diagnostics

| Sensor | Description |
|--------|-------------|
| **Lightpath Log** | System diagnostic log entries |
| **Lightpath Reminder** | Maintenance reminder |

### GPU-Specific (SR675 V3, SR680a V3)

| Sensor | Description |
|--------|-------------|
| **GPU1-8 Status** | Individual GPU health |
| **GPU Power** | GPU power draw |
| **NVLink Status** | GPU interconnect health |
| **GPU Memory ECC** | GPU memory errors |

---

## Common Event Patterns

### Normal Boot Sequence

```
System Event | Timestamp Clock Sync | Asserted
Power Unit | Power on | Asserted
Processor | Presence detected | Asserted
Memory | Presence detected | Asserted
System Event | OEM System boot | Asserted
```

### Power Failure Sequence

```
Power Supply PSU1 | AC Lost | Asserted
Power Supply | Redundancy Lost | Asserted
# If both PSUs lose power:
Power Unit | Power off/down | Asserted
```

### GPU Thermal Event

```
Temperature GPU3 | Upper Non-critical going high | Asserted
# System may throttle GPU
Temperature GPU3 | Upper Non-critical going high | Deasserted
```

---

## Memory Events

### ECC Error Reporting

Lenovo reports ECC errors with detailed location:

```
Memory DIMM A1 | Correctable ECC | Asserted
Memory DIMM A1 | Correctable ECC logging limit reached | Asserted
```

### DIMM Slot Naming

| CPU | Channel A | Channel B | Channel C | Channel D |
|-----|-----------|-----------|-----------|-----------|
| CPU1 | A1-A4 | B1-B4 | C1-C4 | D1-D4 |
| CPU2 | E1-E4 | F1-F4 | G1-G4 | H1-H4 |

---

## Voltage Sensors

| Sensor | Normal Range | Description |
|--------|--------------|-------------|
| **Planar 3.3V** | 3.135V - 3.465V | Main 3.3V rail |
| **Planar 5V** | 4.75V - 5.25V | Main 5V rail |
| **Planar 12V** | 11.4V - 12.6V | Main 12V rail |
| **VBAT** | 2.7V - 3.3V | CMOS battery |
| **CPU VCore** | Per spec | Processor core voltage |

---

## Fan Sensors

| Sensor | Description | Critical Threshold |
|--------|-------------|-------------------|
| **Fan 1-8** | System fans | < 1000 RPM |
| **PSU Fan** | Power supply fans | Reported by PSU |

### Fan Failure Actions

1. Check for obstructions
2. Verify fan is properly seated
3. Check for dust buildup
4. Replace failed fan module

---

## Firmware Events

| Event | Description | Action |
|-------|-------------|--------|
| Firmware Update Started | XCC firmware update in progress | Do not power off |
| Firmware Update Completed | XCC firmware update successful | May require BMC reset |
| Firmware Corruption | Firmware image corrupted | Recover via Lenovo tools |

---

## XCC Web Interface

The XClarity Controller provides a web interface for management:

- **URL:** `https://<bmc_ip>/`
- **Default User:** USERID
- **Default Pass:** PASSW0RD (with zero)

### Key XCC Features

| Feature | Description |
|---------|-------------|
| **Remote Console** | HTML5-based KVM |
| **Virtual Media** | ISO mounting |
| **Power Control** | Power on/off/restart |
| **SEL Viewer** | System Event Log browser |
| **Sensor Dashboard** | Real-time sensor readings |
| **Firmware Update** | In-band and out-of-band updates |

---

## Command-Line Tools

### IPMItool Commands

```bash
# Get sensor readings
ipmitool -I lanplus -H <bmc_ip> -U USERID -P <password> sensor

# Get SEL entries
ipmitool -I lanplus -H <bmc_ip> -U USERID -P <password> sel list

# Get FRU info
ipmitool -I lanplus -H <bmc_ip> -U USERID -P <password> fru

# BMC cold reset
ipmitool -I lanplus -H <bmc_ip> -U USERID -P <password> mc reset cold
```

### Redfish API

```bash
# Get system info
curl -k -u USERID:PASSW0RD https://<bmc_ip>/redfish/v1/Systems/1

# Get thermal status
curl -k -u USERID:PASSW0RD https://<bmc_ip>/redfish/v1/Chassis/1/Thermal

# Get power status
curl -k -u USERID:PASSW0RD https://<bmc_ip>/redfish/v1/Chassis/1/Power
```

---

## Troubleshooting

### XCC Not Responding

1. Verify network connectivity to BMC IP
2. Try BMC reset via physical button or OS command
3. Check for IP conflicts
4. Verify IPMI is enabled in BIOS

### High GPU Temperatures

1. Check datacenter ambient temperature
2. Verify all fans operational
3. Check GPU heatsink seating
4. Review GPU workload distribution
5. Consider GPU power limit adjustment

### Memory ECC Errors

1. Note DIMM slot from event data
2. Run Lenovo memory diagnostics
3. Check DIMM seating
4. Schedule proactive replacement if increasing

---

## Related Documentation

- [Lenovo ThinkSystem SR675 V3 Product Guide](https://lenovopress.lenovo.com/)
- [XClarity Controller User Guide](https://support.lenovo.com/)
- [IPMI SEL Reference](ipmi_sel_reference.md)

---

*Last updated: December 2025*

