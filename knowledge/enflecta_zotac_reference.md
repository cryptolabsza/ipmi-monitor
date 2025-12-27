# ENFLECTA / ZOTAC SEL Reference

> IPMI System Event Log reference for ENFLECTA and ZOTAC GPU compute servers.

**Platforms:** ZRS-326V2, TIANMA | **BMC Version:** 0.33

---

## Overview

ENFLECTA and ZOTAC produce GPU compute servers targeting AI and mining workloads. These servers use custom BMC implementations with standard IPMI 2.0 support.

**Note:** ENFLECTA ZRS-326V2 and ZOTAC ZRS-326V2 are the same hardware platform.

---

## Supported Models

| Manufacturer | Model | CPU | GPU Support |
|--------------|-------|-----|-------------|
| ENFLECTA | ZRS-326V2 | AMD | Yes (8+ GPUs) |
| ENFLECTA | TIANMA | AMD | Yes |
| ZOTAC | ZRS-326V2 | AMD | Yes (8+ GPUs) |

---

## BMC Characteristics

| Feature | Status |
|---------|--------|
| IPMI Version | 2.0 |
| Redfish | Limited/None |
| Web Interface | Basic |
| Virtual KVM | Varies |
| BMC Version | 0.33 |

---

## Sensor Types

### Temperature Sensors

| Sensor | Location | Typical Threshold |
|--------|----------|-------------------|
| **CPU Temp** | Processor | 85°C warning |
| **System Temp** | Mainboard | 75°C warning |
| **GPU Temps** | Individual GPUs | 80-85°C warning |
| **Inlet Temp** | Air intake | 40°C warning |

### Fan Sensors

| Sensor | Description |
|--------|-------------|
| **FAN1-FAN8** | Chassis fans |
| **GPU Fan** | GPU cooler fans (if applicable) |

### Power Supply Sensors

| Sensor | Description |
|--------|-------------|
| **PS1/PS2** | Power supply status |
| **PWR Status** | Overall power state |

---

## Common Events

### Power Events

| Event | Severity | Description |
|-------|----------|-------------|
| Power Supply AC lost | 🔴 Critical | PSU lost AC power |
| Failure detected | 🔴 Critical | PSU failure |
| Presence detected | 🟢 Info | PSU installed |

### Thermal Events

| Event | Severity | Description |
|-------|----------|-------------|
| Upper Non-critical | 🟡 Warning | Approaching thermal limit |
| Upper Critical | 🔴 Critical | Exceeded safe temperature |
| Fan failure | 🔴 Critical | Cooling failure |

### GPU-Related Events

Due to the custom BMC, GPU events may appear as:
- Generic temperature sensors
- OEM records
- Unknown sensor types

---

## GPU Monitoring

These servers typically have 8+ GPUs. GPU health is best monitored via:

1. **SSH + nvidia-smi**
   ```bash
   nvidia-smi -q | grep -E "GPU|Temp|Power|Mem"
   ```

2. **IPMI Monitor SSH collection**
   - Enable SSH log collection
   - Xid errors captured from dmesg

---

## IPMItool Access

```bash
# Get sensor readings
ipmitool -I lanplus -H <bmc_ip> -U admin -P admin sdr list full

# Get SEL
ipmitool -I lanplus -H <bmc_ip> -U admin -P admin sel list

# Power status
ipmitool -I lanplus -H <bmc_ip> -U admin -P admin power status

# Power cycle
ipmitool -I lanplus -H <bmc_ip> -U admin -P admin power cycle
```

---

## Troubleshooting

### Limited BMC Features

These custom BMCs may have limited functionality compared to enterprise servers:

1. **No virtual KVM** - Use SSH for remote access
2. **Basic web interface** - IPMItool preferred
3. **Limited Redfish** - Use IPMI protocol

### GPU Monitoring Recommendations

Since BMC GPU monitoring is limited:

1. Enable IPMI Monitor SSH integration
2. Configure SSH credentials in Settings
3. Enable GPU error detection
4. Review Xid errors in SSH System Logs tab

### High GPU Temperatures

1. Verify all chassis fans operational
2. Check GPU thermal paste and heatsinks
3. Ensure proper airflow spacing
4. Consider underclocking for thermal headroom

---

## Related Documentation

- [IPMI SEL Reference](ipmi_sel_reference.md)
- [NVIDIA DGX A100 Reference](nvidia_dgx_a100_reference.md) (for Xid error codes)

---

*Last updated: December 2025*

