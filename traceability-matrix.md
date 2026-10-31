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
| TRACE-PAIR-001 | REQ-PAIR-001 | src/ipmi_monitor/app.py; src/ipmi_monitor/account_link.py; src/ipmi_monitor/templates/settings.html; src/ipmi_monitor/templates/setup.html; src/ipmi_monitor/templates/dashboard.html; tests/test_account_pairing.py | VER-PAIR-001 | VAL-PAIR-001 | Owner-approved source authority; reviewed scope |
| TRACE-PAIR-002 | REQ-PAIR-002 | src/ipmi_monitor/app.py; src/ipmi_monitor/account_link.py; src/ipmi_monitor/templates/settings.html; src/ipmi_monitor/templates/setup.html; src/ipmi_monitor/templates/dashboard.html; tests/test_account_pairing.py | VER-PAIR-002 | VAL-PAIR-002 | Owner-approved source authority; reviewed scope |
| TRACE-PAIR-003 | REQ-PAIR-003 | src/ipmi_monitor/app.py; src/ipmi_monitor/account_link.py; src/ipmi_monitor/templates/settings.html; src/ipmi_monitor/templates/setup.html; src/ipmi_monitor/templates/dashboard.html; tests/test_account_pairing.py | VER-PAIR-003 | VAL-PAIR-003 | Owner-approved source authority; reviewed scope |
| TRACE-PAIR-004 | REQ-PAIR-004 | src/ipmi_monitor/app.py; src/ipmi_monitor/account_link.py; src/ipmi_monitor/templates/settings.html; src/ipmi_monitor/templates/setup.html; src/ipmi_monitor/templates/dashboard.html; tests/test_account_pairing.py | VER-PAIR-004 | VAL-PAIR-004 | Owner-approved source authority; reviewed scope |
| TRACE-PAIR-005 | REQ-PAIR-005 | src/ipmi_monitor/app.py; src/ipmi_monitor/account_link.py; src/ipmi_monitor/templates/settings.html; src/ipmi_monitor/templates/setup.html; src/ipmi_monitor/templates/dashboard.html; tests/test_account_pairing.py | VER-PAIR-005 | VAL-PAIR-005 | Owner-approved source authority; reviewed scope |
| TRACE-PAIR-006 | REQ-PAIR-006 | src/ipmi_monitor/app.py; src/ipmi_monitor/account_link.py; src/ipmi_monitor/templates/settings.html; src/ipmi_monitor/templates/setup.html; src/ipmi_monitor/templates/dashboard.html; tests/test_account_pairing.py | VER-PAIR-006 | VAL-PAIR-006 | Owner-approved source authority; reviewed scope |

### Scoped verification and validation evidence

| Verification | Requirement | Test-first evidence | GREEN and independent review | Validation result / next trigger |
| --- | --- | --- | --- | --- |
| VER-IPMI-MON-01 | REQ-IPMI-MON-01 | `/Users/hanneszietsman/CrypotAI/artifacts/ipmi-readiness-20261026/implementation/monitor/persistence-red.json`; `/Users/hanneszietsman/CrypotAI/artifacts/ipmi-readiness-20261026/implementation/monitor/red.log` | `/Users/hanneszietsman/CrypotAI/artifacts/ipmi-readiness-20261026/implementation/monitor/root-final-image.json`; `/Users/hanneszietsman/CrypotAI/artifacts/ipmi-readiness-20261026/implementation/monitor/root-full-final.json`; `/Users/hanneszietsman/CrypotAI/artifacts/ipmi-readiness-20261026/implementation/review/final-monitor-backend-closure.json` | `docs/validation/ipmi-readiness-20261026-mon-01.md`; release root; Target backup, volume/DATA_DIR readback, stable site identity before and after approved recreation; exact immutable monitor artifact and rollback route required. |
| VER-IPMI-MON-02 | REQ-IPMI-MON-02 | `/Users/hanneszietsman/CrypotAI/artifacts/ipmi-readiness-20261026/implementation/monitor/red.log`; `/Users/hanneszietsman/CrypotAI/artifacts/ipmi-readiness-20261026/implementation/monitor/buttons-red.log` | `/Users/hanneszietsman/CrypotAI/artifacts/ipmi-readiness-20261026/implementation/monitor/verification-result.json`; `/Users/hanneszietsman/CrypotAI/artifacts/ipmi-readiness-20261026/implementation/monitor/status-wording-result.json`; `/Users/hanneszietsman/CrypotAI/artifacts/ipmi-readiness-20261026/implementation/review/final-monitor-backend-closure.json` | `docs/validation/ipmi-readiness-20261026-mon-02.md`; release root; Authorized real target admin SSO, identity/allowance and Test/Disconnect/Sync browser acceptance after target connectivity and approved deployment. |
| VER-IPMI-MON-03 | REQ-IPMI-MON-03 | `/Users/hanneszietsman/CrypotAI/artifacts/ipmi-readiness-20261026/implementation/monitor/red.log` | `/Users/hanneszietsman/CrypotAI/artifacts/ipmi-readiness-20261026/implementation/monitor/verification-result.json`; `/Users/hanneszietsman/CrypotAI/artifacts/ipmi-readiness-20261026/implementation/monitor/root-full-final.json`; `/Users/hanneszietsman/CrypotAI/artifacts/ipmi-readiness-20261026/implementation/review/final-monitor-backend-closure.json` | `docs/validation/ipmi-readiness-20261026-mon-03.md`; release root; Two authorized sites demonstrate stable identities, observed times, active/tombstone/history isolation after target deployment. |


## Code Anchor Evidence

| Artifact Path | Requirement | Trace | Verification | Anchor Type | Role |
| --- | --- | --- | --- | --- | --- |
| src/ipmi_monitor/templates/settings.html | REQ-PAIR-001; REQ-PAIR-004; REQ-PAIR-005; REQ-PAIR-006 | TRACE-PAIR-001; TRACE-PAIR-004; TRACE-PAIR-005; TRACE-PAIR-006 | VER-PAIR-001; VER-PAIR-004; VER-PAIR-005; VER-PAIR-006 | file-role | owner-approved Jinja byte0 comment alternate; unsupported scanner format |
| src/ipmi_monitor/templates/setup.html | REQ-PAIR-001; REQ-PAIR-004; REQ-PAIR-005; REQ-PAIR-006 | TRACE-PAIR-001; TRACE-PAIR-004; TRACE-PAIR-005; TRACE-PAIR-006 | VER-PAIR-001; VER-PAIR-004; VER-PAIR-005; VER-PAIR-006 | file-role | owner-approved Jinja byte0 comment alternate; unsupported scanner format |
| src/ipmi_monitor/templates/dashboard.html | REQ-PAIR-001; REQ-PAIR-004; REQ-PAIR-005; REQ-PAIR-006 | TRACE-PAIR-001; TRACE-PAIR-004; TRACE-PAIR-005; TRACE-PAIR-006 | VER-PAIR-001; VER-PAIR-004; VER-PAIR-005; VER-PAIR-006 | file-role | owner-approved Jinja byte0 comment alternate; unsupported scanner format |
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
| src/ipmi_monitor/account_link.py | REQ-PAIR-004 | TRACE-PAIR-004 | VER-PAIR-004 | file-role | ipmi-account-pairing |
| src/ipmi_monitor/account_link.py | REQ-PAIR-004 | TRACE-PAIR-004 | VER-PAIR-004 | entrypoint | ipmi-account-pairing |
| tests/test_account_pairing.py | REQ-PAIR-004 | TRACE-PAIR-004 | VER-PAIR-004 | verifies | ipmi-account-pairing-verification |


### Owner-approved unsupported-format trace route

Exact helper-route exception: `.traceweaver/ipmi-readiness-20261026/owner-alternate-acceptance.json`; approved proposal SHA256 `63e6d64c91b23a7f9e4816db1975299a5f3838a421549e4308eb3e918f4378bc`. Current source identities and exact accepted-source inverse proof: `.traceweaver/ipmi-readiness-20261026/current-source-manifest.json`. Supported-extension scanners remain scoped; PHP/Jinja/Docker/static HTML coverage uses the accepted manual proof or individually named omission, not an unsupported scanner-pass claim. All full requirement/target/provider/payment/CMS and main-deployment prerequisites remain held.

## Account pairing acceptance boundary

The TRACE-PAIR rows identify owner-approved and quality-reviewed source implementation scope only. Verification is in progress. Central MariaDB/cookie/consent, required CI, independent final review and actual installed Fleet/public-service/paid acceptance remain held until their separate evidence exists. These authority labels do not close any requirement or runtime outcome.

## Generated pairing fixture provenance

These are generated raw data copies within the approved verification scope. Inline trace fields would change the canonical producer/specification artifact. The external mapping is the supported generated-file exception, not a claim of inline source coverage. Exact producer bytes are emitted by the actual WordPress handler under synthetic credentials and compared by consumer tests. No API body, assertion or scanner rule changes. Source implementation and installed acceptance remain separately gated.

| Artifact Path | Requirement | Trace | Verification | Anchor Type | Provenance / acceptance |
| --- | --- | --- | --- | --- | --- |
| tests/fixtures/pairing-producer-v1.json | REQ-PAIR-001; REQ-PAIR-003; REQ-PAIR-004; REQ-PAIR-005; REQ-PAIR-006 | TRACE-PAIR-001; TRACE-PAIR-003; TRACE-PAIR-004; TRACE-PAIR-005; TRACE-PAIR-006 | VER-PAIR-001; VER-PAIR-003; VER-PAIR-004; VER-PAIR-005; VER-PAIR-006 | Exception | Generated data approved for exact-byte provenance mapping; SHA256 d58a17f90c33e935b4307b5816e462d0445ee984b72e1d03948dfa3cd9d9404d; regenerate and drift-check from wordpress/actual-producer-fixture.json |
| tests/fixtures/pairing-wire-v1.json | REQ-PAIR-001; REQ-PAIR-003; REQ-PAIR-004; REQ-PAIR-005; REQ-PAIR-006 | TRACE-PAIR-001; TRACE-PAIR-003; TRACE-PAIR-004; TRACE-PAIR-005; TRACE-PAIR-006 | VER-PAIR-001; VER-PAIR-003; VER-PAIR-004; VER-PAIR-005; VER-PAIR-006 | Exception | Generated data approved for exact-byte provenance mapping; SHA256 8ccd5db5c28c55da4e9118c7f913e45532e3213007b8e98a4af214f4bb20d652; regenerate and drift-check from fixtures/pairing-wire-v1.json |


## Branded linking and offer repair evidence — 31 October 2026

The direct owner-approved revision3 plan and original requirement IDs are projected in `.traceweaver/link-ux-20261031/authority-projection.json`. Existing TRACE-PAIR rows remain open for installed acceptance. Precode V&V and subsequent source/release/target evidence are recorded separately; no requirement closure is asserted. Independent paid-copy/linking progress does not accept trial delivery or billing.

### Current client source evidence (31 October)

Existing TRACE-PAIR-001..006 / TRACE-IPMI-MON-02: workspace `link-ux-20261031/client/root-source-trace.json` binds exact candidate templates/tests to precode RED,97focused and258full passing cases, two existing browser batches and independent correctness repair review. The three unchanged Jinja premise anchors use the already approved exact-path alternate; the stock scanner checks only three Python tests and reports zero findings, with no HTML coverage claim. `docs/validation/branded-link-ux-20261031.md` defines intended-use acceptance. Final adversarial source review passed with no findings (97 focused tests and10independent JS race cases). Protected CI and observed central/Fleet/target acceptance remain open; this is not requirement closure.
