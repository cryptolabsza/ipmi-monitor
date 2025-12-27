# Dell PowerEdge SEL Reference

> IPMI System Event Log reference for Dell PowerEdge servers with iDRAC.

**Platforms:** PowerEdge XE9680 | **BMC:** iDRAC9 Enterprise

---

## Overview

Dell PowerEdge servers use the Integrated Dell Remote Access Controller (iDRAC) for out-of-band management. iDRAC9 is the current generation, providing IPMI 2.0, Redfish, and Dell-specific management features.

---

## Supported Models

| Model | Form Factor | CPU | GPU Support | Max GPUs |
|-------|-------------|-----|-------------|----------|
| PowerEdge XE9680 | 4U | Intel Xeon | Yes | 8 x SXM5 |

---

## iDRAC Versions

| Version | Features |
|---------|----------|
| 7.10 | Initial XE9680 release |
| 7.20 | Bug fixes, GPU improvements |

---

## iDRAC-Specific Event Types

### System Events

| Sensor Type | Description |
|-------------|-------------|
| **System Event Log** | General system events |
| **Lifecycle Log** | Hardware changes and updates |
| **RAC Event Log** | iDRAC-specific events |

### Hardware Categories

| Category | Sensor Prefix | Description |
|----------|---------------|-------------|
| CPU | CPU | Processor status |
| Memory | DIMM | Memory modules |
| Storage | Physical Disk, Virtual Disk | RAID and drives |
| Power | PS, PWR | Power supplies |
| Thermal | Temp, Fan | Cooling system |
| GPU | GPU | Graphics processors |

---

## Temperature Sensors

Dell uses descriptive sensor names:

| Sensor | Location | Warning | Critical |
|--------|----------|---------|----------|
| **Inlet Temp** | Front air intake | 42°C | 47°C |
| **Exhaust Temp** | Rear air output | 70°C | 75°C |
| **CPU1 Temp** | Processor 1 | 80°C | 90°C |
| **CPU2 Temp** | Processor 2 | 80°C | 90°C |
| **GPU1-8 Temp** | GPU modules | 83°C | 92°C |
| **DIMM Temp** | Memory slots | 70°C | 80°C |

---

## Power Supply Events

### PSU Sensor Names

| Sensor | Description |
|--------|-------------|
| **PS1 Status** | Power supply 1 |
| **PS2 Status** | Power supply 2 |
| **PS3 Status** | Power supply 3 (if present) |
| **PS4 Status** | Power supply 4 (if present) |
| **PS Redundancy** | Overall redundancy state |

### PSU Event Types

| Event | Severity | Meaning | LCD Code |
|-------|----------|---------|----------|
| AC Lost | 🔴 Critical | Lost AC input | E1114 |
| Failed | 🔴 Critical | PSU failure | E1214 |
| Predictive Failure | 🟡 Warning | PSU degrading | W1228 |
| Input Out of Range | 🟡 Warning | Voltage issue | W1205 |
| Configuration Error | 🟡 Warning | Mismatched PSU | E1215 |
| Redundancy Lost | 🟡 Warning | Single PSU mode | W1228 |
| Redundancy Regained | 🟢 Info | Full redundancy | - |

---

## Memory Events

### DIMM Naming Convention

Dell uses a letter-number format: A1-A12, B1-B12, etc.

| CPU | Channels | DIMMs per Channel |
|-----|----------|-------------------|
| CPU1 | A-F | 2 per channel |
| CPU2 | G-L | 2 per channel |

### Memory Event Types

| Event | Severity | Description |
|-------|----------|-------------|
| Correctable ECC | 🔵 Info | Single-bit error corrected |
| Uncorrectable ECC | 🔴 Critical | Multi-bit error, data corruption |
| Memory Scrub Failed | 🟡 Warning | Background scrub error |
| DIMM Present | 🟢 Info | DIMM detected during boot |
| DIMM Failure | 🔴 Critical | DIMM hardware failure |
| Sparing Active | 🟢 Info | Spare DIMM activated |
| Memory Throttled | 🟡 Warning | Thermal throttling active |

---

## Storage Events (PERC RAID)

### Physical Disk Events

| Event | Severity | Description |
|-------|----------|-------------|
| Drive Inserted | 🟢 Info | Hot-swap drive added |
| Drive Removed | 🟡 Warning | Drive removed or failed |
| Predictive Failure | 🟡 Warning | SMART predicts failure |
| Drive Failed | 🔴 Critical | Drive has failed |
| Rebuild Started | 🟢 Info | RAID rebuild in progress |
| Rebuild Complete | 🟢 Info | RAID rebuild finished |

### Virtual Disk Events

| Event | Severity | Description |
|-------|----------|-------------|
| VD Degraded | 🟡 Warning | RAID missing drives |
| VD Failed | 🔴 Critical | RAID array offline |
| VD Optimal | 🟢 Info | RAID healthy |

---

## GPU Events (XE9680)

The PowerEdge XE9680 supports 8 NVIDIA H100 SXM5 GPUs.

### GPU Sensor Types

| Sensor | Description |
|--------|-------------|
| **GPU1-8 Status** | Individual GPU health |
| **GPU1-8 Temp** | GPU temperature |
| **GPU Power** | Total GPU power draw |
| **NVLink Status** | GPU interconnect |
| **HGX Baseboard** | GPU tray status |

### GPU Events

| Event | Severity | Description |
|-------|----------|-------------|
| GPU Present | 🟢 Info | GPU detected |
| GPU Not Present | 🟡 Warning | GPU missing |
| GPU Thermal Event | 🟡 Warning | GPU overheating |
| GPU Error | 🔴 Critical | GPU hardware error |
| NVLink Error | 🔴 Critical | GPU interconnect failure |

---

## Fan Events

### Fan Naming

| Sensor | Location |
|--------|----------|
| **Fan1-Fan8** | System cooling fans |
| **PSU Fan** | Power supply fans |

### Fan Event Types

| Event | Severity | Description |
|-------|----------|-------------|
| Fan Failed | 🔴 Critical | Fan not spinning |
| Fan Removed | 🔴 Critical | Fan module removed |
| Fan RPM Low | 🟡 Warning | Fan slowing down |
| Fan RPM Normal | 🟢 Info | Fan operating normally |

---

## LCD Panel Messages

Dell PowerEdge servers have an LCD panel displaying status codes:

| Code | Severity | Description |
|------|----------|-------------|
| E10xx | 🔴 Critical | System errors |
| E11xx | 🔴 Critical | PSU errors |
| E12xx | 🔴 Critical | Memory errors |
| E13xx | 🔴 Critical | Thermal errors |
| E14xx | 🔴 Critical | I/O errors |
| E20xx | 🔴 Critical | CPU errors |
| W1xxx | 🟡 Warning | General warnings |
| I1xxx | 🟢 Info | Informational |

---

## iDRAC Web Interface

### Access

- **URL:** `https://<idrac_ip>/`
- **Default User:** root
- **Default Pass:** calvin (change immediately!)

### Key Features

| Feature | Description |
|---------|-------------|
| **Virtual Console** | HTML5 KVM |
| **Virtual Media** | Remote ISO mount |
| **Lifecycle Controller** | Firmware updates, OS deployment |
| **Server Health** | Dashboard with sensor status |
| **System Event Log** | SEL browser |
| **Job Queue** | Pending configuration tasks |

---

## RACADM Commands

```bash
# Get system info
racadm getconfig -g cfgServerInfo

# Get sensor readings
racadm getsensorinfo

# Get SEL entries
racadm getsel

# Clear SEL
racadm clrsel

# Get power state
racadm serveraction powerstatus

# Power cycle
racadm serveraction powercycle

# Get NIC info
racadm getniccfg
```

---

## Redfish API

```bash
# Get system info
curl -k -u root:calvin https://<idrac_ip>/redfish/v1/Systems/System.Embedded.1

# Get chassis thermal
curl -k -u root:calvin https://<idrac_ip>/redfish/v1/Chassis/System.Embedded.1/Thermal

# Get power info
curl -k -u root:calvin https://<idrac_ip>/redfish/v1/Chassis/System.Embedded.1/Power

# Get SEL
curl -k -u root:calvin https://<idrac_ip>/redfish/v1/Managers/iDRAC.Embedded.1/LogServices/Sel/Entries
```

---

## Troubleshooting

### iDRAC Not Responding

1. Check network cable to dedicated iDRAC port
2. Try ping to iDRAC IP
3. Use front panel LCD to check IP
4. Physical reset via "iDRAC Reset" button
5. Reset via OS: `racadm racreset`

### GPU Thermal Issues

1. Verify datacenter cooling (18-27°C inlet)
2. Check all system fans operational
3. Verify HGX baseboard fans spinning
4. Review GPU workload distribution
5. Check NVLink bridge connections

### Memory Errors

1. Note DIMM slot from event (e.g., A1)
2. Run Dell diagnostics from Lifecycle Controller
3. Check ePPR (extended Post Package Repair)
4. Schedule proactive DIMM replacement

---

## Nutanix on Dell

Nutanix NX-TDT-4NL3-G7 is based on Dell PowerEdge hardware:

- Uses iDRAC for BMC functions
- Same event types and sensors as PowerEdge
- Nutanix adds additional OS-level monitoring

---

## Related Documentation

- [Dell PowerEdge XE9680 Technical Guide](https://www.dell.com/support/)
- [iDRAC9 User's Guide](https://www.dell.com/support/)
- [Dell OpenManage](https://www.dell.com/openmanage)
- [IPMI SEL Reference](ipmi_sel_reference.md)

---

*Last updated: December 2025*

