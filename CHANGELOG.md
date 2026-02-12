# Changelog

All notable changes to IPMI Monitor will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.1] - 2026-02-12

### Added
- **SSH Log Collection** - Collect system logs (dmesg, journalctl, syslog, mcelog, GPU errors) from servers via SSH
- **AI Embed/Iframe Support** - AI-powered insights accessible via embed and iframe integration
- **Push Notifications** - Real-time browser push notifications for critical alerts and events
- **Server Manager Deployment** - Streamlined Server Manager deployment for fleet management
- **Watchtower Opt-in** - Container auto-updates via Watchtower are now opt-in with labels

### Changed
- **Quickstart renamed to Setup** - CLI command `ipmi-monitor quickstart` renamed to `ipmi-monitor setup`

### Fixed
- Various bug fixes and stability improvements

---

## [1.0.3] - 2026-01-14

### Added
- **Email Alerts via CryptoLabs** - Receive alerts to your linked CryptoLabs account email without configuring SMTP
  - New "CryptoLabs Email Alerts" section in Alert Settings tab
  - Grayed out with prompt when AI account not linked
  - Configure which alert types to receive (Server Down, Critical Events, etc.)
  - Send test emails to verify configuration
- **Real-time Inventory Collection Console** - Live progress log when collecting hardware inventory
  - Shows step-by-step progress with timestamps
  - Color-coded status (success, warning, error)
  - Displays Redfish, IPMI, and SSH collection progress
  - Console can be dismissed after completion
- **Enhanced DIMM Inventory** - Improved memory module detection and display
  - JEDEC manufacturer decoder for DIMM info
  - Support for both Redfish and dmidecode DIMM formats
  - Detailed per-DIMM information collection
- **Enhanced System Logs Filtering** - Better log search and filter capabilities
- **Vast.ai & RunPod Log Collection** - Optional service log collection from cloud GPU providers
- **Watchtower Labels in Quick Start** - README examples now include auto-update labels

### Fixed
- **System Tab Not Showing** - Fixed server_ip lookup to check Server table (not just ServerConfig)
- **Storage Display "undefined"** - Normalize Redfish storage field names (Name→name, CapacityBytes→size)
- **SSH Storage Collection** - Streaming inventory now collects storage via SSH when Redfish fails
- **AI Disconnect** - Properly clears license key and linked account info when disconnecting
- **OAuth Callback** - Redirects to settings page when opened in new tab (not popup)
- **Signup URL** - Corrected from `/ipmi-monitor/` to `/ipmi_signup/`
- **Email Test** - Test emails now bypass alert type preferences
- **AI Connection Test** - Uses stored license key if not provided
- **Redfish SensorType** - Handle list type values that were causing SQLite errors
- **Auth Inconsistencies** - Fixed authentication issues in settings page
- **Markdown Rendering** - Strip code blocks in AI content formatting
- **ServerInventory.to_dict()** - Include memory_dimms and pcie_devices fields

### Changed
- **Notifications tab renamed to "Alert Settings"** - Better describes the tab's purpose
- **CryptoLabs Email Alerts position** - Moved above SMTP settings for easier discovery

## [1.0.2] - 2025-12-XX

### Added
- Initial stable release with core features
- IPMI/BMC monitoring and event collection
- Sensor monitoring (temperature, fan, voltage, power)
- ECC memory tracking
- Alert rules and notifications (Telegram, Email, Webhook)
- Prometheus metrics endpoint
- User management with admin/read-only roles
- Full backup/restore functionality

---

## Watchtower Auto-Update

Containers with the Watchtower label will automatically update when new versions are pushed:

```yaml
labels:
  - "com.centurylinklabs.watchtower.enable=true"
```

| Tag | Updates |
|-----|---------|
| `:latest` | Stable releases only (1.0.3 → 1.1.1 → ...) |
| `:develop` | Development builds (continuous) |
| `:v1.1.1` | Never (pinned version) |
