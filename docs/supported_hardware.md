---
layout: default
title: Supported Hardware Reference
---

# Supported Hardware Reference

> Master list of all server manufacturers and models tracked by IPMI Monitor.

**Last Updated:** December 2025

---

## Overview

This document lists all server hardware platforms that have been deployed with IPMI Monitor. Each platform may have vendor-specific IPMI sensors and events that are documented in separate reference guides.

---

## Supported Manufacturers

| Manufacturer | Models | BMC Type | Reference Guide |
|--------------|--------|----------|-----------------|
| **ASUS** | ESC4000A-E10 | ASMB10-iKVM | [ASUS ESC4000A-E10](asus_esc4000a_e10_reference.html) |
| **Dell Inc.** | PowerEdge XE9680 | iDRAC9 | [Dell PowerEdge](dell_poweredge_reference.html) |
| **ENFLECTA** | ZRS-326V2, TIANMA | Custom | [ENFLECTA/ZOTAC](enflecta_zotac_reference.html) |
| **Lenovo** | ThinkSystem SR655/SR675/SR680/SR780 V3 | XClarity/BMC | [Lenovo ThinkSystem](lenovo_thinksystem_reference.html) |
| **NVIDIA** | DGX A100 | Custom BMC | [NVIDIA DGX A100](nvidia_dgx_a100_reference.html) |
| **Nutanix** | NX-TDT-4NL3-G7 | iDRAC-based | [Nutanix](nutanix_reference.html) |
| **Supermicro** | Various (see below) | IPMI/Redfish | [Supermicro](supermicro_reference.html) |
| **ZOTAC** | ZRS-326V2 | Custom | [ENFLECTA/ZOTAC](enflecta_zotac_reference.html) |
| **King Star** | ESC4000A-E10 | ASMB10-iKVM | [ASUS ESC4000A-E10](asus_esc4000a_e10_reference.html) |

---

## Detailed Model List

### ASUS / King Star Computer

| Model | BMC Version | CPU | Use Case |
|-------|-------------|-----|----------|
| ESC4000A-E10 | 2.02, 2.03 | AMD EPYC | 4U GPU Server |

**Key Sensors:** PMBPower1/2, TR1/TR3 Temperature, Memory_Train_ERR, +VCORE1, +VSOC1

---

### Dell Inc.

| Model | BMC Version | CPU | Use Case |
|-------|-------------|-----|----------|
| PowerEdge XE9680 | 7.10, 7.20 | Intel Xeon | 4U 8-GPU AI Server |

**Key Features:** iDRAC9 Enterprise, Redfish support, advanced power management

---

### ENFLECTA

| Model | BMC Version | CPU | Use Case |
|-------|-------------|-----|----------|
| ZRS-326V2 | 0.33 | AMD | GPU Compute |
| TIANMA | 0.33 | AMD | GPU Compute |

---

### Lenovo

| Model | BMC Version | CPU | Use Case |
|-------|-------------|-----|----------|
| ThinkSystem SR655 V3 | 5.40 | AMD EPYC | 1U Compute |
| ThinkSystem SR675 V3 | 5.10 - 14.11 | AMD EPYC | 3U GPU Server |
| ThinkSystem SR680a V3 | 1.11, 9.10 | AMD EPYC | 4U GPU Server |
| ThinkSystem SR780a V3 | 5.10 | AMD EPYC | 4U GPU Server |

**Key Features:** XClarity BMC, Lenovo XCC (XClarity Controller)

---

### NVIDIA

| Model | BMC Version | CPU | Use Case |
|-------|-------------|-----|----------|
| DGX A100 | 0.20 | AMD EPYC | AI Supercomputer |

**Key Sensors:** SEL_NV_MAXP_MAXQ, SEL_NV_POST_ERR, STATUS_GB_GPU, PWRGD_GB_GPU

---

### Nutanix

| Model | BMC Version | CPU | Use Case |
|-------|-------------|-----|----------|
| NX-TDT-4NL3-G7 | 7.13 | Intel Xeon | Hyperconverged |

**Base Platform:** Dell PowerEdge with Nutanix customization

---

### Supermicro

| Model | BMC Version | CPU | Use Case |
|-------|-------------|-----|----------|
| AS-1014S-WTRT | 3.10 | AMD EPYC | 1U Compute |
| AS-A126GS-TNBR | 1.02 | AMD | GPU Server |
| SYS-A22GA-NBRT | 1.00 | AMD | GPU Server |
| PIO-629BT-06408S-01-RI13 | 6.74 | Intel | 2U Twin |
| SYS-2029TP-HC1R-G2-FS011 | 1.74 | Intel | 2U TwinPro |
| Super Server (Generic) | 01.05.02, 1.01 | Various | Generic |
| GENOA2D24G-2L+ | 2.03 | AMD EPYC Genoa | GPU Server |

**Key Features:** IPMI 2.0, IPMIView, Supermicro Update Manager (SUM)

---

### ZOTAC

| Model | BMC Version | CPU | Use Case |
|-------|-------------|-----|----------|
| ZRS-326V2 | 0.33 | AMD | GPU Compute |

**Note:** ZOTAC ZRS-326V2 is similar to ENFLECTA ZRS-326V2

---

## BMC Types and Interfaces

| BMC Type | Manufacturers | Key Features |
|----------|---------------|--------------|
| **iDRAC** | Dell, Nutanix | Lifecycle Controller, Redfish, OpenManage |
| **iLO** | HPE | Active Health System, Federation |
| **XClarity/XCC** | Lenovo | XClarity Administrator, Lenovo XCC |
| **ASMB/ASWM** | ASUS | ASUS Server Management |
| **IPMI/BMC** | Supermicro | IPMIView, SUM, standard IPMI |
| **Custom** | NVIDIA, ENFLECTA | Vendor-specific implementations |

---

## Common Sensor Categories

### Universal Sensors (All Platforms)

| Category | Examples |
|----------|----------|
| Temperature | CPU, Inlet, Exhaust, DIMM, GPU |
| Voltage | +3.3V, +5V, +12V, VBAT, VCORE |
| Fan | System fans, PSU fans |
| Power Supply | Presence, failure, AC status |
| Memory | ECC errors, presence |
| Processor | Presence, thermal trip, IERR |

### Platform-Specific Sensors

| Platform | Unique Sensors |
|----------|----------------|
| ASUS | PMBPower, TR Temperature, Memory_Train_ERR |
| Dell | LCD, RAID, DRAC errors |
| Lenovo | XCC events, PFA (Predictive Failure Analysis) |
| NVIDIA | SEL_NV_*, STATUS_GB_GPU, PWRGD_GB_GPU |
| Supermicro | OEM records (c0, c1), chassis events |

---

## Adding New Hardware

When a new server model is deployed:

1. **Collect Inventory Data**
   - Run inventory collection from Settings
   - Verify manufacturer and product_name are populated

2. **Monitor Initial Events**
   - Watch SEL for vendor-specific sensor types
   - Note any "Unknown" sensor types

3. **Document New Sensors**
   - Create or update vendor reference guide
   - Add sensor descriptions and thresholds
   - Document recommended actions

4. **Update This List**
   - Add new model to appropriate manufacturer section
   - Note BMC version compatibility

---

## API: Get Hardware Summary

```bash
# Get all unique manufacturers and models
GET /api/inventory/summary

# Response
{
  "manufacturers": [
    {"name": "ASUS", "count": 35},
    {"name": "Lenovo", "count": 48},
    ...
  ],
  "models": [
    {"manufacturer": "ASUS", "product_name": "ESC4000A-E10", "count": 35},
    ...
  ]
}
```

---

## See Also

- [IPMI SEL Reference](ipmi_sel_reference.html) - Standard IPMI events
- Vendor-specific guides linked in the table above

---

*This document is auto-generated from production deployment data.*

