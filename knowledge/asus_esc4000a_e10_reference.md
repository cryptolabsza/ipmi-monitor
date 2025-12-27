# ASUS ESC4000A-E10 SEL Reference

> IPMI System Event Log reference for ASUS ESC4000A-E10 GPU servers with AMD EPYC processors.

**Platform:** ASUS ESC4000A-E10 | **BMC:** ASMB10-iKVM | **Version:** 2.0x

---

## Overview

The ASUS ESC4000A-E10 is a 4U GPU server supporting up to 8 AMD EPYC processors and multiple NVIDIA GPUs. The ASMB10-iKVM BMC provides IPMI 2.0 management capabilities.

---

## Platform-Specific Sensors

### Power Bus Monitoring

The ESC4000A-E10 has dedicated power bus sensors (PMBPower) that monitor the internal power distribution.

| Sensor | Description | Function |
|--------|-------------|----------|
| **PMBPower1** | Power Module Bus 1 | Primary power rail monitoring |
| **PMBPower2** | Power Module Bus 2 | Secondary power rail monitoring |

#### PMBPower Event Types

| Event | Severity | Meaning | Action |
|-------|----------|---------|--------|
| Upper Critical going high | 🔴 Critical | Power draw exceeds safe limit | Check GPU workload, verify PSU capacity |
| Upper Non-critical going high | 🟡 Warning | Power approaching limit | Monitor workload |
| Lower Critical going low | 🔴 Critical | Power drop detected | Check PSU connections |
| Lower Non-critical going low | 🟡 Warning | Power slightly low | Verify PSU health |
| Deasserted | 🟢 Info | Condition cleared | Normal operation |

**Note:** PMBPower events often correlate with high GPU utilization. Frequent events may indicate insufficient PSU capacity for the workload.

---

### Thermal Zones (TR1, TR3)

The ESC4000A-E10 uses thermal zone sensors to monitor component temperatures.

| Sensor | Location | Normal Range |
|--------|----------|--------------|
| **TR1 Temperature** | CPU/VRM thermal zone | < 85°C |
| **TR3 Temperature** | GPU/PCIe thermal zone | < 90°C |

#### Temperature Thresholds

| Threshold | TR1 (CPU Zone) | TR3 (GPU Zone) |
|-----------|----------------|----------------|
| Upper Non-Critical | 75°C | 80°C |
| Upper Critical | 85°C | 90°C |
| Upper Non-Recoverable | 95°C | 100°C |

#### Troubleshooting High TR Temperatures

1. **Check fan operation** - Verify all chassis and GPU fans are spinning
2. **Verify airflow** - Ensure proper cable management, no obstructions
3. **Check ambient temperature** - Datacenter HVAC within spec?
4. **Review workload** - GPU-intensive tasks will raise TR3
5. **Clean heatsinks** - Dust accumulation reduces cooling efficiency

---

### AMD EPYC Specific Voltages

These sensors monitor AMD EPYC-specific power rails.

| Sensor | Description | Normal Range |
|--------|-------------|--------------|
| **+VCORE1** | CPU Core voltage | Per processor spec (0.9V - 1.2V typical) |
| **+VSOC1** | SoC (System-on-Chip) voltage | ~0.9V |

#### Voltage Event Interpretation

| Event | Cause | Action |
|-------|-------|--------|
| Upper Critical going high | Over-voltage condition | Check VRM, may indicate failure |
| Upper Non-critical going high | Voltage slightly high | Monitor, usually transient |
| Lower Critical going low | Under-voltage condition | Check PSU, power cables |
| Lower Non-critical going low | Voltage slightly low | Monitor, check load |

**Warning:** Voltage deviations outside ±5% can cause system instability or component damage.

---

### Drive Bay Sensors

The ESC4000A-E10 has a hot-swap drive backplane with individual bay sensors.

| Sensor | Location |
|--------|----------|
| **Backplane1 HD05** | Drive bay 5 |
| **Backplane1 HD07** | Drive bay 7 |
| **Backplane1 HD08** | Drive bay 8 |

#### Drive Bay Events

| Event | Meaning | Action |
|-------|---------|--------|
| Drive Present \| Asserted | Drive inserted | Normal hot-swap |
| Drive Present \| Deasserted | Drive removed | Verify intentional |

---

### Memory Events

#### Memory Training Errors

| Sensor | Description | Severity |
|--------|-------------|----------|
| **Memory_Train_ERR** | Memory training error during POST | 🟡 Warning |

Memory training errors occur during system boot when the memory controller calibrates timing for the DIMMs.

**Common Causes:**
- DIMM not fully seated
- Incompatible DIMM
- Failed DIMM
- Memory controller issue

**Troubleshooting:**
1. Reseat the affected DIMM
2. Run memory diagnostics (memtest86+)
3. Check DIMM compatibility with server QVL
4. Try DIMM in different slot
5. Replace DIMM if errors persist

#### ECC Error DIMM Identification

The ESC4000A-E10 reports ECC errors with DIMM location:

```
Memory | Correctable ECC | Asserted | **DIMM A1 (CPU1)** | [CPU1_ECC1]
```

| Field | Meaning |
|-------|---------|
| **DIMM A1** | Physical DIMM slot |
| **(CPU1)** | Associated CPU socket |
| **[CPU1_ECC1]** | ECC controller identifier |

**DIMM Slot Layout (per CPU):**
- Slots A1-A8: CPU1 memory channels
- Slots B1-B8: CPU2 memory channels (if dual-socket)

---

### Power Supply Sensors

The ESC4000A-E10 supports redundant power supplies with individual monitoring.

| Sensor | Description |
|--------|-------------|
| **PSU1 AC Lost** | PSU 1 AC power status |
| **PSU2 AC Lost** | PSU 2 AC power status |
| **PSU2 PWR Detect** | PSU 2 presence and power detection |
| **REDUNDANCY_PSU** | Redundancy status |
| **PSU1 Over Temp** | PSU 1 thermal status |
| **PSU2 Over Temp** | PSU 2 thermal status |

#### PSU Events and Actions

| Event | Severity | Cause | Action |
|-------|----------|-------|--------|
| AC lost \| Asserted | 🔴 Critical | Power cord unplugged or PDU failure | Check PDU, power cord |
| AC lost \| Deasserted | 🟢 Info | Power restored | Normal operation |
| Failure detected \| Asserted | 🔴 Critical | PSU hardware failure | Replace PSU |
| Fully Redundant \| Asserted | 🟢 Info | Both PSUs healthy | Normal |
| Redundancy Lost \| Asserted | 🟡 Warning | Only one PSU online | Check/replace failed PSU |
| Over Temp \| Asserted | 🔴 Critical | PSU overheating | Check airflow, replace if persistent |

---

## Standard Voltage Rails

| Sensor | Normal | Warning | Critical |
|--------|--------|---------|----------|
| **+3.3V** | 3.135V - 3.465V | ±5% | ±10% |
| **+3.3VSB** | 3.135V - 3.465V | ±5% | ±10% |
| **+5VSB** | 4.75V - 5.25V | ±5% | ±10% |

---

## Critical Interrupt Events

| Event | Severity | Cause | Action |
|-------|----------|-------|--------|
| Bus Correctable error | 🔴 Critical | PCIe/memory bus error (corrected) | Monitor frequency |
| Bus Fatal Error | 🔴 Critical | Unrecoverable bus error | Check PCIe cards, reseat GPUs |
| PCI SERR | 🟢 Info | PCIe system error | Usually transient |

---

## Recommended Maintenance

### Monthly
- Clear SEL if approaching limit
- Review ECC error trends
- Check thermal zone temperatures

### Quarterly
- Clean air filters and heatsinks
- Verify fan operation
- Check PSU status

### Annually
- Firmware updates (BMC, BIOS)
- Full system diagnostics
- Thermal paste replacement if needed

---

## Related Documentation

- [ASUS ESC4000A-E10 User Manual](https://www.asus.com/support/)
- [AMD EPYC Processor Documentation](https://www.amd.com/en/products/processors/server/epyc)
- [IPMI SEL Reference](ipmi_sel_reference.md)

---

*Last updated: December 2025*

