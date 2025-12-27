---
layout: default
title: Nutanix SEL Reference
---

# Nutanix SEL Reference

> IPMI System Event Log reference for Nutanix hyperconverged appliances.

**Platforms:** NX-TDT-4NL3-G7 | **Base Platform:** Dell PowerEdge

---

## Overview

Nutanix hyperconverged infrastructure (HCI) appliances are built on OEM server platforms. The NX-TDT-4NL3-G7 is based on Dell PowerEdge hardware and uses Dell iDRAC for BMC management.

---

## Platform Information

| Attribute | Value |
|-----------|-------|
| Model | NX-TDT-4NL3-G7 |
| Base Hardware | Dell PowerEdge |
| BMC | iDRAC (Dell) |
| BMC Version | 7.13 |

---

## BMC Access

Since Nutanix appliances use Dell iDRAC:

- **Web Interface:** `https://<bmc_ip>/`
- **Default User:** root
- **Default Pass:** Varies (check Nutanix documentation)

---

## Event Types

Nutanix appliances generate standard Dell PowerEdge events. See the [Dell PowerEdge Reference](dell_poweredge_reference.html) for complete event documentation.

### Common Categories

| Category | Description |
|----------|-------------|
| Temperature | CPU, DIMM, system temperatures |
| Fan | Cooling fan status |
| Power Supply | PSU health and redundancy |
| Memory | ECC errors, DIMM status |
| Storage | Drive health (via RAID) |
| Processor | CPU status and errors |

---

## Nutanix-Specific Monitoring

In addition to IPMI/BMC monitoring, Nutanix provides:

### Prism Central

- Cluster-wide health monitoring
- Alerts and notifications
- Performance analytics
- Predictive failure detection

### Hardware Alerts

Nutanix surfaces BMC events through Prism:
- Critical hardware alerts
- Disk failures
- Memory errors
- Fan/PSU issues

---

## IPMItool Access

```bash
# Get sensor readings
ipmitool -I lanplus -H <bmc_ip> -U root -P <password> sdr list full

# Get SEL
ipmitool -I lanplus -H <bmc_ip> -U root -P <password> sel list

# Power status
ipmitool -I lanplus -H <bmc_ip> -U root -P <password> power status
```

---

## Storage Considerations

Nutanix uses a distributed storage model:
- Local SSDs/HDDs per node
- Software-defined storage
- Drive failures handled at software layer
- IPMI may not see all storage events

---

## Troubleshooting

### BMC/iDRAC Issues

Follow Dell PowerEdge troubleshooting:
1. Network connectivity
2. iDRAC IP configuration
3. BMC reset if needed

### Nutanix-Specific

For Nutanix-layer issues:
1. Check Prism Central alerts
2. Review CVM (Controller VM) health
3. Contact Nutanix support

---

## Related Documentation

- [Dell PowerEdge Reference](dell_poweredge_reference.html) - Base platform events
- [Nutanix Hardware Replacement](https://portal.nutanix.com/) - Official Nutanix docs
- [IPMI SEL Reference](ipmi_sel_reference.html)

---

*Last updated: December 2025*

