# Traceability — scoped IPMI source integration


## Scoped IPMI authority amendment — 26 October 2026 (IPMI-SCOPED-20261026-MONITOR)

This section maps only the exact accepted IPMI delta; file-level sets describe the combined scoped role of shared modules, not every historical behavior in those files.

## Traceability Matrix

| Trace | Requirement | Implementation | Verification | Validation | Status |
| --- | --- | --- | --- | --- | --- |
| TRACE-IPMI-MON-01 | REQ-IPMI-MON-01 | `Dockerfile` | VER-IPMI-MON-01 | VAL-IPMI-MON-01; target validation held | Independently reviewed scoped source authority |
| TRACE-IPMI-MON-01, TRACE-IPMI-MON-02, TRACE-IPMI-MON-03 | REQ-IPMI-MON-01, REQ-IPMI-MON-02, REQ-IPMI-MON-03 | `src/ipmi_monitor/app.py` | VER-IPMI-MON-01, VER-IPMI-MON-02, VER-IPMI-MON-03 | VAL-IPMI-MON-01, VAL-IPMI-MON-02, VAL-IPMI-MON-03; target validation held | Independently reviewed scoped source authority |
| TRACE-IPMI-MON-01, TRACE-IPMI-MON-02 | REQ-IPMI-MON-01, REQ-IPMI-MON-02 | `src/ipmi_monitor/quickstart.py` | VER-IPMI-MON-01, VER-IPMI-MON-02 | VAL-IPMI-MON-01, VAL-IPMI-MON-02; target validation held | Independently reviewed scoped source authority |
| TRACE-IPMI-MON-01 | REQ-IPMI-MON-01 | `src/ipmi_monitor/templates/docker-compose.yml.j2` | VER-IPMI-MON-01 | VAL-IPMI-MON-01; target validation held | Independently reviewed scoped source authority |
| TRACE-IPMI-MON-02 | REQ-IPMI-MON-02 | `src/ipmi_monitor/templates/settings.html` | VER-IPMI-MON-02 | VAL-IPMI-MON-02; target validation held | Independently reviewed scoped source authority |
| TRACE-IPMI-MON-02 | REQ-IPMI-MON-02 | `tests/test_account_link_security.py` | VER-IPMI-MON-02 | VAL-IPMI-MON-02; target validation held | Independently reviewed scoped source authority |
| TRACE-IPMI-MON-02 | REQ-IPMI-MON-02 | `tests/test_auth.py` | VER-IPMI-MON-02 | VAL-IPMI-MON-02; target validation held | Independently reviewed scoped source authority |
| TRACE-IPMI-MON-03 | REQ-IPMI-MON-03 | `tests/test_cloud_inventory_payload.py` | VER-IPMI-MON-03 | VAL-IPMI-MON-03; target validation held | Independently reviewed scoped source authority |
| TRACE-IPMI-MON-01, TRACE-IPMI-MON-02 | REQ-IPMI-MON-01, REQ-IPMI-MON-02 | `tests/test_runtime_entrypoint.py` | VER-IPMI-MON-01, VER-IPMI-MON-02 | VAL-IPMI-MON-01, VAL-IPMI-MON-02; target validation held | Independently reviewed scoped source authority |
| TRACE-IPMI-MON-02 | REQ-IPMI-MON-02 | `tests/test_settings_ai_controls.py` | VER-IPMI-MON-02 | VAL-IPMI-MON-02; target validation held | Independently reviewed scoped source authority |

### Scoped verification and validation evidence

| Verification | Requirement | Test-first evidence | GREEN and independent review | Validation result / next trigger |
| --- | --- | --- | --- | --- |
| VER-IPMI-MON-01 | REQ-IPMI-MON-01 | `/Users/hanneszietsman/CrypotAI/artifacts/ipmi-readiness-20261026/implementation/monitor/persistence-red.json`; `/Users/hanneszietsman/CrypotAI/artifacts/ipmi-readiness-20261026/implementation/monitor/red.log` | `/Users/hanneszietsman/CrypotAI/artifacts/ipmi-readiness-20261026/implementation/monitor/root-final-image.json`; `/Users/hanneszietsman/CrypotAI/artifacts/ipmi-readiness-20261026/implementation/monitor/root-full-final.json`; `/Users/hanneszietsman/CrypotAI/artifacts/ipmi-readiness-20261026/implementation/review/final-monitor-backend-closure.json` | `docs/validation/ipmi-readiness-20261026-mon-01.md`; release root; Target backup, volume/DATA_DIR readback, stable site identity before and after approved recreation; exact immutable monitor artifact and rollback route required. |
| VER-IPMI-MON-02 | REQ-IPMI-MON-02 | `/Users/hanneszietsman/CrypotAI/artifacts/ipmi-readiness-20261026/implementation/monitor/red.log`; `/Users/hanneszietsman/CrypotAI/artifacts/ipmi-readiness-20261026/implementation/monitor/buttons-red.log` | `/Users/hanneszietsman/CrypotAI/artifacts/ipmi-readiness-20261026/implementation/monitor/verification-result.json`; `/Users/hanneszietsman/CrypotAI/artifacts/ipmi-readiness-20261026/implementation/monitor/status-wording-result.json`; `/Users/hanneszietsman/CrypotAI/artifacts/ipmi-readiness-20261026/implementation/review/final-monitor-backend-closure.json` | `docs/validation/ipmi-readiness-20261026-mon-02.md`; release root; Authorized real target admin SSO, identity/allowance and Test/Disconnect/Sync browser acceptance after target connectivity and approved deployment. |
| VER-IPMI-MON-03 | REQ-IPMI-MON-03 | `/Users/hanneszietsman/CrypotAI/artifacts/ipmi-readiness-20261026/implementation/monitor/red.log` | `/Users/hanneszietsman/CrypotAI/artifacts/ipmi-readiness-20261026/implementation/monitor/verification-result.json`; `/Users/hanneszietsman/CrypotAI/artifacts/ipmi-readiness-20261026/implementation/monitor/root-full-final.json`; `/Users/hanneszietsman/CrypotAI/artifacts/ipmi-readiness-20261026/implementation/review/final-monitor-backend-closure.json` | `docs/validation/ipmi-readiness-20261026-mon-03.md`; release root; Two authorized sites demonstrate stable identities, observed times, active/tombstone/history isolation after target deployment. |


## Code Anchor Evidence

| Artifact Path | Requirement | Trace | Verification | Anchor Type | Role |
| --- | --- | --- | --- | --- | --- |
| src/ipmi_monitor/app.py | REQ-IPMI-MON-01 | TRACE-IPMI-MON-01 | VER-IPMI-MON-01 | file-role | ipmi-monitor-scoped-source |
| src/ipmi_monitor/quickstart.py | REQ-IPMI-MON-01 | TRACE-IPMI-MON-01 | VER-IPMI-MON-01 | file-role | ipmi-monitor-scoped-source |
| src/ipmi_monitor/quickstart.py | REQ-IPMI-MON-01; REQ-IPMI-MON-02 | TRACE-IPMI-MON-01; TRACE-IPMI-MON-02 | VER-IPMI-MON-01; VER-IPMI-MON-02 | entrypoint | ipmi-monitor-scoped-source |
| tests/test_account_link_security.py | REQ-IPMI-MON-02 | TRACE-IPMI-MON-02 | VER-IPMI-MON-02 | verifies | ipmi-monitor-verification |
| tests/test_auth.py | REQ-IPMI-MON-02 | TRACE-IPMI-MON-02 | VER-IPMI-MON-02 | verifies | ipmi-monitor-verification |
| tests/test_cloud_inventory_payload.py | REQ-IPMI-MON-03 | TRACE-IPMI-MON-03 | VER-IPMI-MON-03 | verifies | ipmi-monitor-verification |
| tests/test_runtime_entrypoint.py | REQ-IPMI-MON-01 | TRACE-IPMI-MON-01 | VER-IPMI-MON-01 | verifies | ipmi-monitor-verification |
| tests/test_runtime_entrypoint.py | REQ-IPMI-MON-02 | TRACE-IPMI-MON-02 | VER-IPMI-MON-02 | verifies | ipmi-monitor-verification |
| tests/test_settings_ai_controls.py | REQ-IPMI-MON-02 | TRACE-IPMI-MON-02 | VER-IPMI-MON-02 | verifies | ipmi-monitor-verification |
| src/ipmi_monitor/app.py | REQ-IPMI-MON-01; REQ-IPMI-MON-02; REQ-IPMI-MON-03 | TRACE-IPMI-MON-01; TRACE-IPMI-MON-02; TRACE-IPMI-MON-03 | VER-IPMI-MON-01; VER-IPMI-MON-02; VER-IPMI-MON-03 | entrypoint | ipmi-monitor-scoped-source |
| Dockerfile | REQ-IPMI-MON-01 | TRACE-IPMI-MON-01 | VER-IPMI-MON-01 | file-role | owner-approved unsupported alternate scoped-source |
| src/ipmi_monitor/templates/docker-compose.yml.j2 | REQ-IPMI-MON-01 | TRACE-IPMI-MON-01 | VER-IPMI-MON-01 | file-role | owner-approved unsupported alternate scoped-source |
| src/ipmi_monitor/templates/settings.html | REQ-IPMI-MON-02 | TRACE-IPMI-MON-02 | VER-IPMI-MON-02 | file-role | owner-approved unsupported alternate scoped-source |


### Owner-approved unsupported-format trace route

Exact helper-route exception: `.traceweaver/ipmi-readiness-20261026/owner-alternate-acceptance.json`; approved proposal SHA256 `63e6d64c91b23a7f9e4816db1975299a5f3838a421549e4308eb3e918f4378bc`. Current source identities and exact accepted-source inverse proof: `.traceweaver/ipmi-readiness-20261026/current-source-manifest.json`. Supported-extension scanners remain scoped; PHP/Jinja/Docker/static HTML coverage uses the accepted manual proof or individually named omission, not an unsupported scanner-pass claim. All full requirement/target/provider/payment/CMS and main-deployment prerequisites remain held.
