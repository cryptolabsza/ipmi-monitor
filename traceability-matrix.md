# Traceability — scoped IPMI source integration

## Main 1.4.2 guide correction

| Requirement | Trace | Artifacts | Verification | Validation |
| --- | --- | --- | --- | --- |
| REQ-IPMI-INSTALL-001 | TRACE-IPMI-INSTALL-001 | README.md; RELEASING.md; docker-compose.yml; docker-compose.prod.yml; examples/ipmi-config.yaml; docs/index.md; docs/user-guide.md; docs/DEVELOPER_GUIDE.md; docs/wordpress/ipmi-setup-guide.html; marketing-page.html; wordpress-content.html; wordpress-blog-post.html | VER-IPMI-INSTALL-001; .traceweaver/install-guides-20261107/checks.json; .traceweaver/install-guides-20261107/review.json | VAL-IPMI-INSTALL-001; public source/image1.4.2 and website517 readback; customer install held |



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
| TRACE-SEL-001, TRACE-SEL-002, TRACE-SEL-003, TRACE-SEL-004, TRACE-SEL-005 | REQ-SEL-001, REQ-SEL-002, REQ-SEL-003, REQ-SEL-004, REQ-SEL-005 | src/ipmi_monitor/sel_management.py | VER-SEL-001, VER-SEL-002, VER-SEL-003, VER-SEL-004, VER-SEL-005 | VAL-SEL-001, VAL-SEL-002, VAL-SEL-003, VAL-SEL-004, VAL-SEL-005; shared docs/validation/sel-health-20261103.md; hardware/intended-use validation held | Owner approved local source implementation authority |
| TRACE-SEL-001, TRACE-SEL-002, TRACE-SEL-003, TRACE-SEL-004, TRACE-SEL-005 | REQ-SEL-001, REQ-SEL-002, REQ-SEL-003, REQ-SEL-004, REQ-SEL-005 | src/ipmi_monitor/app.py | VER-SEL-001, VER-SEL-002, VER-SEL-003, VER-SEL-004, VER-SEL-005 | VAL-SEL-001, VAL-SEL-002, VAL-SEL-003, VAL-SEL-004, VAL-SEL-005; shared docs/validation/sel-health-20261103.md; hardware/intended-use validation held | Owner approved local source implementation authority |
| TRACE-SEL-001, TRACE-SEL-002, TRACE-SEL-003, TRACE-SEL-004, TRACE-SEL-005 | REQ-SEL-001, REQ-SEL-002, REQ-SEL-003, REQ-SEL-004, REQ-SEL-005 | tests/test_sel_management.py | VER-SEL-001, VER-SEL-002, VER-SEL-003, VER-SEL-004, VER-SEL-005 | VAL-SEL-001, VAL-SEL-002, VAL-SEL-003, VAL-SEL-004, VAL-SEL-005; shared docs/validation/sel-health-20261103.md; hardware/intended-use validation held | Owner approved local source implementation authority |
| TRACE-SEL-001, TRACE-SEL-002, TRACE-SEL-003, TRACE-SEL-004, TRACE-SEL-005 | REQ-SEL-001, REQ-SEL-002, REQ-SEL-003, REQ-SEL-004, REQ-SEL-005 | src/ipmi_monitor/templates/dashboard.html | VER-SEL-001, VER-SEL-002, VER-SEL-003, VER-SEL-004, VER-SEL-005 | VAL-SEL-001, VAL-SEL-002, VAL-SEL-003, VAL-SEL-004, VAL-SEL-005; shared docs/validation/sel-health-20261103.md; hardware/intended-use validation held | Owner approved local source implementation authority |
| TRACE-SEL-001, TRACE-SEL-002, TRACE-SEL-003, TRACE-SEL-004, TRACE-SEL-005 | REQ-SEL-001, REQ-SEL-002, REQ-SEL-003, REQ-SEL-004, REQ-SEL-005 | src/ipmi_monitor/templates/server_detail.html | VER-SEL-001, VER-SEL-002, VER-SEL-003, VER-SEL-004, VER-SEL-005 | VAL-SEL-001, VAL-SEL-002, VAL-SEL-003, VAL-SEL-004, VAL-SEL-005; shared docs/validation/sel-health-20261103.md; hardware/intended-use validation held | Owner approved local source implementation authority |
| TRACE-SEL-001, TRACE-SEL-002, TRACE-SEL-003, TRACE-SEL-004, TRACE-SEL-005 | REQ-SEL-001, REQ-SEL-002, REQ-SEL-003, REQ-SEL-004, REQ-SEL-005 | templates/dashboard.html | VER-SEL-001, VER-SEL-002, VER-SEL-003, VER-SEL-004, VER-SEL-005 | VAL-SEL-001, VAL-SEL-002, VAL-SEL-003, VAL-SEL-004, VAL-SEL-005; shared docs/validation/sel-health-20261103.md; hardware/intended-use validation held | Owner approved local source implementation authority |
| TRACE-SEL-001, TRACE-SEL-002, TRACE-SEL-003, TRACE-SEL-004, TRACE-SEL-005 | REQ-SEL-001, REQ-SEL-002, REQ-SEL-003, REQ-SEL-004, REQ-SEL-005 | templates/server_detail.html | VER-SEL-001, VER-SEL-002, VER-SEL-003, VER-SEL-004, VER-SEL-005 | VAL-SEL-001, VAL-SEL-002, VAL-SEL-003, VAL-SEL-004, VAL-SEL-005; shared docs/validation/sel-health-20261103.md; hardware/intended-use validation held | Owner approved local source implementation authority |
| TRACE-SEL-003 | REQ-SEL-003 | tests/test_retention_cleanup.py | VER-SEL-003 | VAL-SEL-003 | Owner approved local source implementation authority; retains batching/concurrency assertions |
| TRACE-SEL-003, TRACE-SEL-004, TRACE-SEL-005 | REQ-SEL-003, REQ-SEL-004, REQ-SEL-005 | src/ipmi_monitor/sel_qualifications.py | VER-SEL-003, VER-SEL-004, VER-SEL-005 | VAL-SEL-003, VAL-SEL-004, VAL-SEL-005; docs/validation/sel-health-20261103.md; independent source review and hardware/owner acceptance held | Owner-approved revision2 U4A source implementation authority |
| TRACE-SEL-004 | REQ-SEL-004 | src/ipmi_monitor/cli.py | VER-SEL-004 | VAL-SEL-004; docs/validation/sel-health-20261103.md | Approved fixed qualification data INSTALL/STATUS scope only |
| TRACE-SEL-003, TRACE-SEL-004, TRACE-SEL-005 | REQ-SEL-003, REQ-SEL-004, REQ-SEL-005 | tests/test_sel_qualifications.py; tests/sel_qualification_linux.py | VER-SEL-003, VER-SEL-004, VER-SEL-005 | VAL-SEL-003, VAL-SEL-004, VAL-SEL-005; docs/validation/sel-health-20261103.md | Approved executable custody/identity/SQLite verification; no hardware qualification claim |
| TRACE-SEL-002, TRACE-SEL-003, TRACE-SEL-004 | REQ-SEL-002, REQ-SEL-003, REQ-SEL-004 | tests/test_sel_persistent.py | VER-SEL-002, VER-SEL-003, VER-SEL-004 | VAL-SEL-002, VAL-SEL-003, VAL-SEL-004; docs/validation/sel-health-20261103.md | Real local child/PTY framing, cleanup and same-token verification; synthetic tool only |
| TRACE-SEL-001, TRACE-SEL-002, TRACE-SEL-003, TRACE-SEL-004 | REQ-SEL-001, REQ-SEL-002, REQ-SEL-003, REQ-SEL-004 | src/ipmi_monitor/sel_collection.py | VER-CHARLOTTESEL-001, VER-CHARLOTTESEL-002, VER-CHARLOTTESEL-003, VER-CHARLOTTESEL-004 | VAL-CHARLOTTESEL-001, VAL-CHARLOTTESEL-002, VAL-CHARLOTTESEL-003, VAL-CHARLOTTESEL-004; docs/validation/charlotte-sel-20261111.md | Owner-approved Charlotte source implementation authority; root-precode-review.json |
| TRACE-SEL-001, TRACE-SEL-002, TRACE-SEL-003, TRACE-SEL-004 | REQ-SEL-001, REQ-SEL-002, REQ-SEL-003, REQ-SEL-004 | tests/test_sel_collection_state.py | VER-CHARLOTTESEL-001, VER-CHARLOTTESEL-002, VER-CHARLOTTESEL-003, VER-CHARLOTTESEL-004 | VAL-CHARLOTTESEL-001, VAL-CHARLOTTESEL-002, VAL-CHARLOTTESEL-003, VAL-CHARLOTTESEL-004; docs/validation/charlotte-sel-20261111.md | Root-reviewed verification definition; root-precode-review.json |
| TRACE-SEL-001, TRACE-SEL-003, TRACE-SEL-004, TRACE-SEL-005 | REQ-SEL-001, REQ-SEL-003, REQ-SEL-004, REQ-SEL-005 | tests/test_sel_collection_regressions.py | VER-CHARLOTTESEL-001, VER-CHARLOTTESEL-003, VER-CHARLOTTESEL-004, VER-CHARLOTTESEL-005 | VAL-CHARLOTTESEL-001, VAL-CHARLOTTESEL-003, VAL-CHARLOTTESEL-004, VAL-CHARLOTTESEL-005; docs/validation/charlotte-sel-20261111.md | Root-reviewed verification definition; root-precode-review.json |
| TRACE-SEL-001, TRACE-SEL-002, TRACE-SEL-003 | REQ-SEL-001, REQ-SEL-002, REQ-SEL-003 | tests/fixtures/charlotte_sel_native_prefix.json | VER-CHARLOTTESEL-001, VER-CHARLOTTESEL-002, VER-CHARLOTTESEL-003 | VAL-CHARLOTTESEL-001, VAL-CHARLOTTESEL-002, VAL-CHARLOTTESEL-003; docs/validation/charlotte-sel-20261111.md | Owner-approved captured fixture verification mapping; metadata-only linkage |

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
| src/ipmi_monitor/sel_management.py | REQ-SEL-001 | TRACE-SEL-001 | VER-SEL-001 | file-role | sel-health-and-guarded-actions |
| src/ipmi_monitor/sel_management.py | REQ-SEL-001; REQ-SEL-002; REQ-SEL-003; REQ-SEL-004; REQ-SEL-005 | TRACE-SEL-001; TRACE-SEL-002; TRACE-SEL-003; TRACE-SEL-004; TRACE-SEL-005 | VER-SEL-001; VER-SEL-002; VER-SEL-003; VER-SEL-004; VER-SEL-005 | entrypoint | sel-entrypoint-001 |
| src/ipmi_monitor/sel_management.py | REQ-SEL-001; REQ-SEL-002; REQ-SEL-003; REQ-SEL-004; REQ-SEL-005 | TRACE-SEL-001; TRACE-SEL-002; TRACE-SEL-003; TRACE-SEL-004; TRACE-SEL-005 | VER-SEL-001; VER-SEL-002; VER-SEL-003; VER-SEL-004; VER-SEL-005 | entrypoint | sel-entrypoint-005 |
| src/ipmi_monitor/app.py | REQ-SEL-001; REQ-SEL-002; REQ-SEL-003; REQ-SEL-004; REQ-SEL-005 | TRACE-SEL-001; TRACE-SEL-002; TRACE-SEL-003; TRACE-SEL-004; TRACE-SEL-005 | VER-SEL-001; VER-SEL-002; VER-SEL-003; VER-SEL-004; VER-SEL-005 | entrypoint | sel-entrypoint-002 |
| src/ipmi_monitor/app.py | REQ-SEL-001; REQ-SEL-002; REQ-SEL-003; REQ-SEL-004; REQ-SEL-005 | TRACE-SEL-001; TRACE-SEL-002; TRACE-SEL-003; TRACE-SEL-004; TRACE-SEL-005 | VER-SEL-001; VER-SEL-002; VER-SEL-003; VER-SEL-004; VER-SEL-005 | entrypoint | sel-entrypoint-003 |
| tests/test_retention_cleanup.py | REQ-SEL-003 | TRACE-SEL-003 | VER-SEL-003 | verifies | sel-verification-003 |
| tests/test_sel_management.py | REQ-SEL-001 | TRACE-SEL-001 | VER-SEL-001 | verifies | sel-verification-001 |
| tests/test_sel_management.py | REQ-SEL-002 | TRACE-SEL-002 | VER-SEL-002 | verifies | sel-verification-002 |
| tests/test_sel_management.py | REQ-SEL-003 | TRACE-SEL-003 | VER-SEL-003 | verifies | sel-verification-003 |
| tests/test_sel_management.py | REQ-SEL-004 | TRACE-SEL-004 | VER-SEL-004 | verifies | sel-verification-004 |
| tests/test_sel_management.py | REQ-SEL-005 | TRACE-SEL-005 | VER-SEL-005 | verifies | sel-verification-005 |
| src/ipmi_monitor/templates/dashboard.html | REQ-SEL-001; REQ-SEL-002; REQ-SEL-003; REQ-SEL-004; REQ-SEL-005 | TRACE-SEL-001; TRACE-SEL-002; TRACE-SEL-003; TRACE-SEL-004; TRACE-SEL-005 | VER-SEL-001; VER-SEL-002; VER-SEL-003; VER-SEL-004; VER-SEL-005 | entrypoint | sel-ui |
| templates/dashboard.html | REQ-SEL-001; REQ-SEL-002; REQ-SEL-003; REQ-SEL-004; REQ-SEL-005 | TRACE-SEL-001; TRACE-SEL-002; TRACE-SEL-003; TRACE-SEL-004; TRACE-SEL-005 | VER-SEL-001; VER-SEL-002; VER-SEL-003; VER-SEL-004; VER-SEL-005 | entrypoint | sel-ui |
| src/ipmi_monitor/templates/server_detail.html | REQ-SEL-001; REQ-SEL-002; REQ-SEL-003; REQ-SEL-004; REQ-SEL-005 | TRACE-SEL-001; TRACE-SEL-002; TRACE-SEL-003; TRACE-SEL-004; TRACE-SEL-005 | VER-SEL-001; VER-SEL-002; VER-SEL-003; VER-SEL-004; VER-SEL-005 | entrypoint | sel-ui |
| templates/server_detail.html | REQ-SEL-001; REQ-SEL-002; REQ-SEL-003; REQ-SEL-004; REQ-SEL-005 | TRACE-SEL-001; TRACE-SEL-002; TRACE-SEL-003; TRACE-SEL-004; TRACE-SEL-005 | VER-SEL-001; VER-SEL-002; VER-SEL-003; VER-SEL-004; VER-SEL-005 | entrypoint | sel-ui |
| src/ipmi_monitor/sel_management.py | REQ-SEL-001; REQ-SEL-002; REQ-SEL-003; REQ-SEL-004; REQ-SEL-005 | TRACE-SEL-001; TRACE-SEL-002; TRACE-SEL-003; TRACE-SEL-004; TRACE-SEL-005 | VER-SEL-001; VER-SEL-002; VER-SEL-003; VER-SEL-004; VER-SEL-005 | entrypoint | sel-repair1-security-boundary |
| src/ipmi_monitor/templates/dashboard.html | REQ-SEL-001; REQ-SEL-002; REQ-SEL-003; REQ-SEL-004; REQ-SEL-005 | TRACE-SEL-001; TRACE-SEL-002; TRACE-SEL-003; TRACE-SEL-004; TRACE-SEL-005 | VER-SEL-001; VER-SEL-002; VER-SEL-003; VER-SEL-004; VER-SEL-005 | entrypoint | sel-repair1-security-boundary |
| templates/dashboard.html | REQ-SEL-001; REQ-SEL-002; REQ-SEL-003; REQ-SEL-004; REQ-SEL-005 | TRACE-SEL-001; TRACE-SEL-002; TRACE-SEL-003; TRACE-SEL-004; TRACE-SEL-005 | VER-SEL-001; VER-SEL-002; VER-SEL-003; VER-SEL-004; VER-SEL-005 | entrypoint | sel-repair1-security-boundary |
| src/ipmi_monitor/sel_qualifications.py | REQ-SEL-004 | TRACE-SEL-004 | VER-SEL-004 | file-role | qualification-data-custody |
| src/ipmi_monitor/sel_qualifications.py | REQ-SEL-003; REQ-SEL-004; REQ-SEL-005 | TRACE-SEL-003; TRACE-SEL-004; TRACE-SEL-005 | VER-SEL-003; VER-SEL-004; VER-SEL-005 | entrypoint | qualification-data-custody |
| src/ipmi_monitor/cli.py | REQ-SEL-004 | TRACE-SEL-004 | VER-SEL-004 | file-role | fixed-qualification-operator-cli |
| src/ipmi_monitor/cli.py | REQ-SEL-004 | TRACE-SEL-004 | VER-SEL-004 | entrypoint | fixed-qualification-operator-cli |
| tests/test_sel_qualifications.py | REQ-SEL-004 | TRACE-SEL-004 | VER-SEL-004 | verifies | qualification-custody-verification |
| tests/test_sel_persistent.py | REQ-SEL-002 | TRACE-SEL-002 | VER-SEL-002 | verifies | persistent-snapshot-verification |
| tests/sel_qualification_linux.py | REQ-SEL-004 | TRACE-SEL-004 | VER-SEL-004 | verifies | installed-linux-custody-verification |
| src/ipmi_monitor/sel_collection.py | REQ-SEL-001; REQ-SEL-002; REQ-SEL-003; REQ-SEL-004 | TRACE-SEL-001; TRACE-SEL-002; TRACE-SEL-003; TRACE-SEL-004 | VER-CHARLOTTESEL-001; VER-CHARLOTTESEL-002; VER-CHARLOTTESEL-003; VER-CHARLOTTESEL-004 | entrypoint | native-collection-boundaries |
| tests/test_sel_collection_state.py | REQ-SEL-001 | TRACE-SEL-001 | VER-CHARLOTTESEL-001 | verifies | charlotte-native-state-verification |
| tests/test_sel_collection_regressions.py | REQ-SEL-001 | TRACE-SEL-001 | VER-CHARLOTTESEL-001 | verifies | charlotte-collection-regression |
| src/ipmi_monitor/app.py | REQ-SEL-001; REQ-SEL-002; REQ-SEL-003; REQ-SEL-004; REQ-SEL-005 | TRACE-SEL-001; TRACE-SEL-002; TRACE-SEL-003; TRACE-SEL-004; TRACE-SEL-005 | VER-SEL-001; VER-SEL-002; VER-SEL-003; VER-SEL-004; VER-SEL-005 | entrypoint | manual-native-collection |
| src/ipmi_monitor/sel_management.py | REQ-SEL-001; REQ-SEL-002; REQ-SEL-003; REQ-SEL-004; REQ-SEL-005 | TRACE-SEL-001; TRACE-SEL-002; TRACE-SEL-003; TRACE-SEL-004; TRACE-SEL-005 | VER-SEL-001; VER-SEL-002; VER-SEL-003; VER-SEL-004; VER-SEL-005 | entrypoint | serialized-health-observation |
| src/ipmi_monitor/sel_management.py | REQ-SEL-001; REQ-SEL-002; REQ-SEL-003; REQ-SEL-004; REQ-SEL-005 | TRACE-SEL-001; TRACE-SEL-002; TRACE-SEL-003; TRACE-SEL-004; TRACE-SEL-005 | VER-SEL-001; VER-SEL-002; VER-SEL-003; VER-SEL-004; VER-SEL-005 | entrypoint | explicit-redfish-diagnostic-persistence |


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


## AI report CSS isolation — 2 November 2026

Direct owner authority is `.traceweaver/ai-report-css-20261102/authority.json`; earlier MON/PAIR history remains unchanged. Root owns authority review, final production GO and publication.

| Trace | Requirement | Implementation | Verification | Validation | Status |
| --- | --- | --- | --- | --- | --- |
| TRACE-AICSS-001 | REQ-AICSS-001 | `src/ipmi_monitor/templates/dashboard.html`; `.traceweaver/ai-report-css-20261102/manual-jinja-anchor-proof.json` | VER-AICSS-001; `tests/test_dashboard_ai_reports.py`; retained precode RED and `.traceweaver/ai-report-css-20261102/green-evidence.json` | VAL-AICSS-001; `docs/validation/ai-report-css-20261102.md` | Precode review/root source GO passed; 262 local tests pass; independent source review and target closure held |

Code Anchor Evidence: new Python verification has exact REQ/TRACE/VER comments. Dashboard remains under the existing exact-path alternate manual Jinja proof route; no stock HTML scanner pass or new runtime enforcement is claimed. Source GREEN, final source hash, independent source review, protected CI and actual target acceptance will be added only when observed.

Repair cycle1 evidence: `.traceweaver/ai-report-css-20261102/red-evidence-repair1.json` proves an independently found upstream HTML error still changed dashboard CSS before the one-line escape repair. `green-evidence-repair1.json` records all36browsercases and262tests passing afterward. Original32cases/RED/history remain retained. Followup independent source review remains pending; no acceptance or publication closure is inferred.

Current scoped source decision (2 November 2026): `.traceweaver/ai-report-css-20261102/root-source-acceptance.json` records two final independent reviews with no open findings after repair1, 262 passing tests and36 browser cases. Earlier pending records are retained history. Protected CI/publication, immutable image compatibility and actual per-target validation remain separate pending gates; no requirement closure or global dashboard security certification is claimed.


## SEL health/native clock additive mapping — 3 November 2026

Approved source: `.traceweaver/sel-health-20261103/owner-approval.json`; exact plan and baseline in scoped authority. The rows below are planned mappings, not implementation or closure claims. The orchestrator must accept this amendment before production edits.

| Trace | Requirement | Planned implementation | Verification | Validation | Status |
| --- | --- | --- | --- | --- | --- |
| TRACE-SEL-001 | REQ-SEL-001 | `src/ipmi_monitor/sel_management.py`; `src/ipmi_monitor/app.py`; both dashboard/server template trees as applicable | VER-SEL-001: `tests/test_sel_management.py`; scoped verification-plan.json; initial RED in scoped artifacts/red.log | VAL-SEL-001: `docs/validation/sel-health-20261103.md` | owner-approved behavior; initial RED only; root precode review/production GO pending; full GREEN, independent review, hardware and intended-use acceptance held |
| TRACE-SEL-002 | REQ-SEL-002 | `src/ipmi_monitor/sel_management.py`; `src/ipmi_monitor/app.py`; both dashboard/server template trees as applicable | VER-SEL-002: `tests/test_sel_management.py`; scoped verification-plan.json; initial RED in scoped artifacts/red.log | VAL-SEL-002: `docs/validation/sel-health-20261103.md` | owner-approved behavior; initial RED only; root precode review/production GO pending; full GREEN, independent review, hardware and intended-use acceptance held |
| TRACE-SEL-003 | REQ-SEL-003 | `src/ipmi_monitor/sel_management.py`; `src/ipmi_monitor/app.py`; both dashboard/server template trees as applicable | VER-SEL-003: `tests/test_sel_management.py`; scoped verification-plan.json; initial RED in scoped artifacts/red.log | VAL-SEL-003: `docs/validation/sel-health-20261103.md` | owner-approved behavior; initial RED only; root precode review/production GO pending; full GREEN, independent review, hardware and intended-use acceptance held |
| TRACE-SEL-004 | REQ-SEL-004 | `src/ipmi_monitor/sel_management.py`; `src/ipmi_monitor/app.py`; both dashboard/server template trees as applicable | VER-SEL-004: `tests/test_sel_management.py`; scoped verification-plan.json; initial RED in scoped artifacts/red.log | VAL-SEL-004: `docs/validation/sel-health-20261103.md` | owner-approved behavior; initial RED only; root precode review/production GO pending; full GREEN, independent review, hardware and intended-use acceptance held |
| TRACE-SEL-005 | REQ-SEL-005 | `src/ipmi_monitor/sel_management.py`; `src/ipmi_monitor/app.py`; both dashboard/server template trees as applicable | VER-SEL-005: `tests/test_sel_management.py`; scoped verification-plan.json; initial RED in scoped artifacts/red.log | VAL-SEL-005: `docs/validation/sel-health-20261103.md` | owner-approved behavior; initial RED only; root precode review/production GO pending; full GREEN, independent review, hardware and intended-use acceptance held |

Shared test artifact intentionally covers all five scoped IDs; RED is partial evidence, with exact node mapping/remaining scenarios in `.traceweaver/sel-health-20261103/verification-plan.json`. No source code anchors are claimed before implementation. Existing matrix rows and historical results above retain their meaning.


Current SEL local source result (3 November 2026): `.traceweaver/sel-health-20261103/root-local-build-result.json` supersedes historical preparation holds for local source only. Repair1 has333 passing full-suite tests,20 root targeted checks,19 Astra targeted cases,16 independent full-page cases and source-matched wheel/sdist/Linuxamd64 image smoke. Earlier rows remain preparation history. Exact hardware qualification, deployed Fleet/representative acceptance and all publication remain held; no requirement closure or runtime readiness is asserted.

Current SEL source-publication authority (3 November 2026): `.traceweaver/sel-health-20261103/publication-owner-approval.json` records the subsequent owner commit/push/test/merge request, authorizing this exact feature-to-dev integration after live gates. Earlier no-publication entries describe their recorded stage; behavioral authority and hardware/production holds are unchanged. Portable final review summaries are under scoped `reviews/`; minimum raw RED/final-suite/root-regression evidence is retained under scoped `artifacts/`.


## Current SEL release authority/status — 4 November 2026

Current owner receipt: `.traceweaver/sel-release-20261104/owner-approval.json`; bounded release projection and unchanged reviewed source hashes: `.traceweaver/sel-release-20261104/release-scope.json`. For TRACE-SEL-001 / REQ-SEL-001 / VER-SEL-001, TRACE-SEL-002 / REQ-SEL-002 / VER-SEL-002, TRACE-SEL-003 / REQ-SEL-003 / VER-SEL-003, TRACE-SEL-004 / REQ-SEL-004 / VER-SEL-004 and TRACE-SEL-005 / REQ-SEL-005 / VER-SEL-005, existing source behavior and verification mappings remain unchanged. The new approval permits the protected `1.4.0` release and gated Fleet canary; historical no-release entries above retain their stage-specific meaning.

Final release-candidate suite/build evidence, independent review, protected checks, published immutable image/tag and actual target acceptance are distinct evidence lanes owned by release root. Canary requires verified target selection/installed Fleet operation, database backup and migration-compatible rollback; wider rollout requires observed migration, retained history and warnings. Exact firmware/action qualification and BMC mutation acceptance remain held. No new behavior, requirement IDs, scanner coverage, hardware qualification, deployed acceptance or requirement closure is claimed here.

## LTX BMC repair preimplementation evidence 20261104

Owner-approved revision2 plan and frozen L3 profile: `.traceweaver/ltx-bmc-qualification-20261104/authority.json`. Independent precode tests and validation definition passed review; production GREEN, release and exact hardware/operator qualification remain pending. This append records evidence only and changes no requirement meaning.

| Trace | Requirement | Verification artifact | RED evidence | Validation definition | Precode review | Status |
| --- | --- | --- | --- | --- | --- | --- |
| TRACE-SEL-001 | REQ-SEL-001 | tests/test_sel_management.py | .traceweaver/ltx-bmc-qualification-20261104/evidence/red-strengthened.stdout | docs/validation/sel-health-20261103.md | .traceweaver/ltx-bmc-qualification-20261104/review-status.json | precode review passed; GREEN/hardware held |
| TRACE-SEL-002 | REQ-SEL-002 | tests/test_sel_management.py | .traceweaver/ltx-bmc-qualification-20261104/evidence/red-strengthened.stdout | docs/validation/sel-health-20261103.md | .traceweaver/ltx-bmc-qualification-20261104/review-status.json | precode review passed; GREEN/hardware held |
| TRACE-SEL-003 | REQ-SEL-003 | tests/test_sel_management.py | .traceweaver/ltx-bmc-qualification-20261104/evidence/red-strengthened.stdout | docs/validation/sel-health-20261103.md | .traceweaver/ltx-bmc-qualification-20261104/review-status.json | precode review passed; GREEN/hardware held |
| TRACE-SEL-004 | REQ-SEL-004 | tests/test_sel_qualifications.py | .traceweaver/ltx-bmc-qualification-20261104/evidence/red-strengthened.stdout | docs/validation/sel-health-20261103.md | .traceweaver/ltx-bmc-qualification-20261104/review-status.json | precode review passed; GREEN/hardware held |
| TRACE-SEL-005 | REQ-SEL-005 | tests/test_sel_management.py | .traceweaver/ltx-bmc-qualification-20261104/evidence/red-strengthened.stdout | docs/validation/sel-health-20261103.md | .traceweaver/ltx-bmc-qualification-20261104/review-status.json | precode review passed; GREEN/hardware held |


Current LTX source result (4 November 2026): `.traceweaver/ltx-bmc-qualification-20261104/root-source-acceptance.json` supersedes the preparation-only source holds above. Exact repair1 has382 full-suite passes (0skip),95 independent affected cases,16 independent adversarial cases plus12 retained normal checks,16 root adversarial cases and installed nonempty/fault/whole-bundle/Linux8 proofs. Both confirmed P1 families are closed. Current portable evidence and reviews are in the scoped evidence-index.json and reviews/. All REQ/TRACE/VER/VAL-SEL-001..005 retain their meaning and hardware/intended-use closure remains HELD. Revision2 U7/U8 authorizes the protected source-only M1 release/deployment route after separate current Git/CI/image/target gates; seven secure-access repairs and action qualification/opt-in remain incomplete.

## Connect enables sync — owner-approved local repair, 4 November 2026

Authority: `.traceweaver/connect-ready-20261104/approved-plan.json`; direct owner Approved after the revised automatic-sync plan. This updates only the earlier successful-connect preference-preservation choice. Failed/cancelled/expired pairing and service validation safeguards remain unchanged.

Existing `TRACE-PAIR-004` / `VER-PAIR-004` / `VAL-PAIR-004`: `src/ipmi_monitor/account_link.py`, `src/ipmi_monitor/templates/settings.html`, `src/ipmi_monitor/templates/dashboard.html`; real Flask/SQLite tests `tests/test_account_pairing.py`, rendered-handler tests `tests/test_settings_ai_controls.py`, and existing race tests `tests/test_account_link_security.py`.

Evidence: `.traceweaver/connect-ready-20261104/` contains genuine RED, precode reviewer record, checker-accepted full V&V definition and local GREEN. Validation definition: `docs/validation/connect-ready-20261104.md`. Existing approved PHP/Jinja unsupported-format manual trace route remains in force; a supported scanner pass does not claim coverage of those formats. Full requirement closure, attested model-routing compliance, installed target sync, provider inference and publication remain held.

Publication route update, 5 November 2026: owner explicitly selected the normal protected PR/CI release and LTX Fleet Manager update. `.traceweaver/connect-ready-20261104/publication-owner-authorization-20261105.json` supersedes this task’s prior local-only publication restriction and optional reviewer-model attestation gate; it does not claim that attestation passed or waive source review, tests, required CI, artifact, health or rollback checks.

## Main 1.4.2 guide correction

| Requirement | Trace | Artifacts | Verification | Validation |
| --- | --- | --- | --- | --- |
| REQ-IPMI-INSTALL-001 | TRACE-IPMI-INSTALL-001 | README.md; RELEASING.md; docker-compose.yml; docker-compose.prod.yml; examples/ipmi-config.yaml; docs/index.md; docs/user-guide.md; docs/DEVELOPER_GUIDE.md; docs/wordpress/ipmi-setup-guide.html; marketing-page.html; wordpress-content.html; wordpress-blog-post.html | VER-IPMI-INSTALL-001; .traceweaver/install-guides-20261107/checks.json; .traceweaver/install-guides-20261107/review.json | VAL-IPMI-INSTALL-001; public source/image1.4.2 and website517 readback; customer install held |

## Main/latest image alias correction — 7 November 2026

| Requirement | Trace | Implementation | Verification | Validation |
| --- | --- | --- | --- | --- |
| REQ-IPMI-LATEST-001 | TRACE-IPMI-LATEST-001 | .github/image-publisher/transport.py; .github/workflows/ci-image-publish-recipe.yml; .github/workflows/docker-build.yml | VER-IPMI-LATEST-001; .github/tests/test_image_transport.py; .github/tests/test_local_publisher.py; .github/tests/test_local_recipes.py; .traceweaver/latest-alias-20261107/red.txt; .traceweaver/latest-alias-20261107/green.txt | VAL-IPMI-LATEST-001: protected main publisher PASS and anonymous main/latest digest equality; actual registry acceptance pending until observed |

Current Charlotte source result (11 November2026): `.traceweaver/charlotte-sel-20261111/root-source-acceptance.json` supersedes preparation-only source holds for this scoped repair:474 full macOS tests,81 current independent Linux focused tests and22 final adversarial cases passed. Exact source/evidence identities are retained in that record. Protected CI, versioned compatible publication, actual Charlotte two-cycle/preservation acceptance and existing physical maintenance qualifications remain held. No requirement closure, LTX rollout or automatic-policy arming is claimed.

Current Charlotte owned-receipt correction (11 November2026): `.traceweaver/charlotte-owned-receipt-20261111/root-source-acceptance.json` links existing REQ-SEL-001/003/004 and TRACE-SEL-001/003/004 to the same `sel_management.py`/`test_sel_collection_state.py` artifacts. Only exact current-owner expired read failure completion changes; general recovery and mutation gates remain unchanged. Authentic real-SQLite/process RED→GREEN,484 full macOS tests,91 current Linux cases and independent Astra code review passed. Protected release1.4.4, corrected artifact/live two-cycle acceptance and physical maintenance qualification remain separate held gates. No requirement closure or automatic-policy arming.

Current Charlotte completion-receipt correction (11 November2026): `.traceweaver/charlotte-completion-receipt-20261111/root-source-acceptance.json` links unchanged REQ-SEL-001/003/004 and TRACE-SEL-001/003/004 to `app.py:collect_ipmi_sel` and `tests/test_sel_collection_state.py`. Only a failed reaped-child receipt hands off to unchanged common finish; full acquisition validation, actual child absence and ticket/CAS remain mandatory. Prior acquisition errors remain dominant; physical cleanup failures remain fatal. Authentic actual-PTY/SQLite RED,488 full Mac tests,95 current Linux cases and independent Astra source review passed. Compatible1.4.5 artifact/live acceptance, physical maintenance qualification and automatic arming remain held. No normative requirement closure.


## CCC90 explicit transport compatibility — 11 November 2026

Current bounded authority: `.traceweaver/ccc90-cipher3-20261111/authority.json`,
plan/profile and authentic precode acceptance in the same directory. Existing
REQ/TRACE/VER/VAL-SEL-004 meaning and all REQ-SEL-005 unknown-offset safeguards
remain unchanged. This is source compatibility evidence, not physical firmware
qualification, policy consent, target acceptance or requirement closure.

| Trace | Requirement | Implementation / verification | Evidence | Validation / held outcome |
| --- | --- | --- | --- | --- |
| TRACE-SEL-004 | REQ-SEL-004 | `src/ipmi_monitor/sel_qualifications.py`: closed supported record transport set17/3; existing full runtime/source/tool and exact fingerprint/action/evidence matching. `tests/test_sel_qualifications.py`; `tests/test_sel_management.py`: truthful/mixed admission, exact guarded transport dispatch, profile-alone/mismatch and action separation refusals. | `.traceweaver/ccc90-cipher3-20261111/evidence/red.txt`; `evidence/green.txt`; `evidence/focused.txt`; `evidence/full-tests.txt`; `evidence/trace.jsonl` (abbreviated paths relative to scoped directory). Existing source/test anchors retained; scanner passes without authoring. | VAL-SEL-004: `docs/validation/sel-health-20261103.md`; independent exact-device/action hardware and intended-use validation HELD; root owns target receipts. |
| TRACE-SEL-005 | REQ-SEL-005 | Unchanged `src/ipmi_monitor/sel_management.py`; existing unspecified-offset test now covers both clock semantics and absence of Set Time/Set Offset. | Same frozen scoped regression logs. | VAL-SEL-005 physical clock/external-writer/offset qualification remains HELD; no no-offset clock capability added. |

Runtime identity still names cipher17 as the adapter default. Each admitted record
binds its actual supported transport. Loader hash changes intentionally invalidate
old runtime-bound envelopes/records; no relabeling, pointer replacement, registry
activation, automatic fallback or policy arming is authorized by this evidence.
