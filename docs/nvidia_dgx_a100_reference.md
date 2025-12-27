# NVIDIA DGX A100 SEL Reference

> IPMI System Event Log reference for NVIDIA DGX A100 AI systems.

**Platform:** NVIDIA DGX A100 | **BMC Version:** 0.20+

---

## Overview

The NVIDIA DGX A100 is a purpose-built AI system featuring 8x NVIDIA A100 GPUs. It uses a custom BMC firmware with NVIDIA-specific event types prefixed with `SEL_NV_`.

---

## NVIDIA-Specific Event Types

### SEL_NV_MAXP_MAXQ (Power Mode)

**Description:** Indicates GPU power mode changes.

| Mode | Meaning | Use Case |
|------|---------|----------|
| **MaxP** | Maximum Performance | Full power, maximum GPU clock speeds |
| **MaxQ** | Maximum Efficiency | Power-optimized, reduced clocks |

#### Event Format
```
Unknown SEL_NV_MAXP_MAXQ | info | | Asserted | [Power Mode Change]
```

**Interpretation:**
- These events are **informational**
- Occur when system adjusts GPU power based on workload or thermal conditions
- Frequent mode changes may indicate thermal throttling

**Troubleshooting Excessive Mode Changes:**
1. Check GPU temperatures
2. Verify cooling system operation
3. Review power supply capacity
4. Check for software forcing power limits

---

### SEL_NV_POST_ERR (POST Errors)

**Description:** Power-On Self Test errors during system boot.

```
Unknown SEL_NV_POST_ERR | info | | Asserted | [POST Error]
```

**Common POST Error Causes:**
- Memory not detected
- GPU not responding
- PCIe initialization failure
- BMC communication issue

**Troubleshooting:**
1. Check BMC console for detailed error messages
2. Verify all GPUs are properly seated
3. Check NVLink bridges
4. Review memory configuration
5. Contact NVIDIA Enterprise Support if persistent

---

### SEL_NV_BIOS (BIOS Events)

**Description:** BIOS/UEFI firmware events during system initialization.

```
Unknown SEL_NV_BIOS | info | | Asserted | [BIOS Event]
```

**Common BIOS Events:**
- Memory configuration changes
- PCI enumeration
- Boot device detection
- Security boot verification

**Note:** These are typically informational and don't require action.

---

### SEL_NV_BOOT (Boot Events)

**Description:** System boot and restart events.

```
Unknown SEL_NV_BOOT | info | | Asserted | [Boot Event]
```

**Tracked Events:**
- System power on
- System restart
- Watchdog reset
- BMC-initiated reboot

---

### SEL_NV_AUDIT (Security Audit)

**Description:** BMC security audit events.

```
Unknown SEL_NV_AUDIT | info | | Asserted | [Security Audit]
```

**Tracked Activities:**
- User login/logout
- Configuration changes
- Firmware updates
- Password changes
- Certificate updates

**Security Best Practice:** Review these events regularly for unauthorized access attempts.

---

### SEL_NV_CHASSIS

**Description:** Chassis intrusion and enclosure events.

```
Unknown SEL_NV_CHASSIS | info | | Asserted
```

**Events Include:**
- Chassis open/close
- Fan module removal
- PSU insertion/removal

---

### SEL_NV_FIRMWARE

**Description:** Firmware-related events.

```
Unknown SEL_NV_FIRMWARE | info | | Asserted
```

**Events Include:**
- Firmware update started/completed
- Firmware verification
- Firmware rollback

---

## DGX-Specific Hardware Sensors

### GPU Baseboard Status

| Sensor | Description |
|--------|-------------|
| **STATUS_GB_GPU** | GPU baseboard presence/status |
| **PWRGD_GB_GPU** | GPU baseboard power good signal |

#### GPU Baseboard Events

| Event | Meaning | Action |
|-------|---------|--------|
| Asserted | GPU baseboard detected and healthy | Normal |
| Deasserted | GPU baseboard not detected | Check GPU installation |

---

### System Power Status

| Sensor | Description |
|--------|-------------|
| **STATUS_SYS_PWR** | Overall system power status |

#### System Power Events

| Event | Severity | Meaning |
|-------|----------|---------|
| Power off/down \| Asserted | Info | System powered down |
| Power off/down \| Deasserted | Info | System powered on |
| AC lost \| Asserted | Warning | AC power lost |

---

### Multi-PSU Configuration

The DGX A100 has 4 or 6 power supplies for redundancy.

| Sensor | Description |
|--------|-------------|
| **STATUS_PSU0** | PSU 0 status |
| **STATUS_PSU1** | PSU 1 status |
| **STATUS_PSU2** | PSU 2 status |
| **STATUS_PSU3** | PSU 3 status |

#### PSU Events

| Event | Severity | Cause | Action |
|-------|----------|-------|--------|
| Power Supply AC lost \| Asserted | 🔴 Critical | PSU lost AC power | Check PDU, power cord |
| AC lost or out-of-range \| Asserted | 🟡 Warning | AC voltage issue | Verify utility power |

**Power Requirements:**
- DGX A100 requires 4x 200-240V 16A circuits
- Total system power: up to 6.5kW
- Requires PDU with sufficient capacity

---

### Dual CPU Status

| Sensor | Description |
|--------|-------------|
| **STATUS_CPU0** | CPU 0 presence and status |
| **STATUS_CPU1** | CPU 1 presence and status |

The DGX A100 uses dual AMD EPYC processors for host CPU.

---

### NVMe Drive Status

| Sensor | Description |
|--------|-------------|
| **STATUS_M.2_0** | M.2 NVMe drive 0 status |
| **STATUS_M.2_1** | M.2 NVMe drive 1 status |

The DGX A100 includes system NVMe drives for OS and caching.

---

## Common DGX A100 Issues

### High GPU Temperatures

**Symptoms:**
- SEL_NV_MAXP_MAXQ events (switching to MaxQ)
- Temperature Upper Non-critical events
- Performance degradation

**Resolution:**
1. Verify datacenter cooling (18-27°C inlet)
2. Check GPU fans via BMC
3. Ensure proper airflow (front-to-back)
4. Clean air filters monthly
5. Review workload distribution

### NVLink Errors

**Symptoms:**
- Critical Interrupt events
- Bus Fatal Error events
- GPU-to-GPU communication failures

**Resolution:**
1. Check NVLink bridge connections
2. Run NVIDIA diagnostics: `dcgmi diag -r 3`
3. Review GPU topology: `nvidia-smi topo -m`
4. Contact NVIDIA support if persistent

### Power Supply Issues

**Symptoms:**
- STATUS_PSUx AC lost events
- System shutdown or performance reduction

**Resolution:**
1. Verify all power cords connected
2. Check PDU breaker status
3. Verify 200-240V supply
4. Balance load across PDUs
5. Replace failed PSU (hot-swap capable)

---

## NVIDIA Diagnostics Commands

### GPU Health Check
```bash
nvidia-smi -q | grep -E "GPU|Temp|Power|Mem"
```

### Run DCGM Diagnostics
```bash
dcgmi diag -r 3 -j
```

### Check NVLink Status
```bash
nvidia-smi nvlink -s
```

### View GPU Errors
```bash
nvidia-smi -q | grep -A5 "Xid Errors"
```

### Check Power Mode
```bash
nvidia-smi -q | grep "Power Mode"
```

---

## Xid Error Reference

GPU errors are reported as Xid codes in the kernel log:

| Xid | Severity | Description | Action |
|-----|----------|-------------|--------|
| 13 | 🔴 Critical | Graphics Engine Exception | Check driver, may need GPU reset |
| 31 | 🔴 Critical | GPU memory page fault | Check application, may indicate HW issue |
| 43 | 🔴 Critical | GPU stopped processing | Reboot required, check thermals |
| 45 | 🔴 Critical | Preemptive cleanup | Check cooling, may be thermal |
| 48 | 🔴 Critical | Double bit ECC error | GPU memory hardware failure |
| 56 | 🟡 Warning | Display engine error | Usually recoverable |
| 57 | 🔴 Critical | TCC/TPU error | Check driver version |
| 61 | 🟡 Warning | Internal µcode error | Update driver |
| 62 | 🟡 Warning | Internal µcode breakpoint | Update driver |
| 63 | 🔴 Critical | Row remapping failure | GPU needs service |
| 64 | 🟡 Warning | Row remapping pending | Monitor, will auto-remap |
| 74 | 🔴 Critical | NVLink error | Check NVLink bridges |
| 79 | 🔴 Critical | GPU fell off bus | Check PCIe seating |
| 94 | 🟡 Warning | Memory page retired | Monitor ECC errors |
| 95 | 🟡 Warning | Memory page retirement | Monitor ECC errors |

---

## Recommended Monitoring

### Real-time Metrics
- GPU temperatures (target < 80°C)
- GPU power draw
- GPU memory usage
- NVLink bandwidth
- ECC error counts

### Daily Checks
- Review SEL for new events
- Check for Xid errors in dmesg
- Verify all GPUs visible

### Weekly
- Run DCGM diagnostics
- Review power consumption trends
- Check thermal trends

---

## Related Documentation

- [NVIDIA DGX A100 User Guide](https://docs.nvidia.com/dgx/dgxa100-user-guide/)
- [NVIDIA Data Center GPU Manager (DCGM)](https://developer.nvidia.com/dcgm)
- [NVIDIA Driver Documentation](https://docs.nvidia.com/datacenter/tesla/)
- [IPMI SEL Reference](ipmi_sel_reference.html)

---

*Last updated: December 2025*

