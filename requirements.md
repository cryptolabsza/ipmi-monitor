# Requirements — scoped IPMI source integration


## Scoped IPMI authority amendment — 26 October 2026 (IPMI-SCOPED-20261026-MONITOR)

Owner accepted these requirement statements at `2026-10-26T17:46:07.375440+00:00`. IDs were assigned on `2026-10-26T17:50:15.911151+00:00`; CAND labels below are their prior navigation names, not backdated requirements. Authority source: `.traceweaver/ipmi-readiness-20261026/owner-scoped-acceptance.json` and `.traceweaver/ipmi-readiness-20261026/source-evidence-index.json`. Approval is for protected feature-to-dev source integration only. Mapping and comment proof require scoped document review before a publication capsule.

| Requirement | Prior label | Owner-accepted statement | Authority status | Validation |
| --- | --- | --- | --- | --- |
| REQ-IPMI-MON-01 | CAND-MON-01 | preserve persistent monitor data/site identity under image recreation while respecting explicit DATA_DIR; retain isolated image/volume proof and target backup/site identity gate. Source: repair-plan step 1. | Owner approved for source integration; target validation held | VAL-IPMI-MON-01 |
| REQ-IPMI-MON-02 | CAND-MON-02 | admin/session/target-bound one-use SSO state, verified identity/allowance and truthful settings outcomes; retain actual Flask/rendered controls/independent reproduction evidence, hold real SSO acceptance. Source: repair-plan step 1 and owner SSO preference. | Owner approved for source integration; target validation held | VAL-IPMI-MON-02 |
| REQ-IPMI-MON-03 | CAND-MON-03 | site identity, observed timestamps and tombstones preserve the active/history producer contract. Source: repair-plan step 4. | Owner approved for source integration; target validation held | VAL-IPMI-MON-03 |

Allowed claim: bounded local source verification and protected feature-to-dev preparation after exact gates. Held: full requirement closure, release readiness, target runtime/migration, real linking/provider/financial acceptance, CMS publication. Release root owns each deferred lane and its next trigger in the linked acceptance result. No version, runtime logic, CI or deployment authority is expanded.


## Owner-approved account pairing — PAIR-20261028-01

Source: latest owner approval quoted in `.traceweaver/account-pairing-20261028/authority.json`. Reviewed scope hash: `9b80ccd96837cae1dd63723fa10ce8390dc4305fcc9e65f303a4868a917dc922`. The exact shared protocol is `.traceweaver/account-pairing-20261028/contract.json`. Existing requirements remain authoritative; this appendix governs only the approved pairing increment. Delivery and paid-service acceptance remain held until observed.

### REQ-PAIR-001

A deployment administrator shall be able to link IPMI Monitor or the DC Overview/Watchdog controller to an existing or newly created CryptoLabs account using outbound HTTPS to the existing public CryptoLabs WordPress service for account pairing. Existing product service validation may use its existing approved HTTPS endpoint. Provider VPN access, an inbound deployment callback and per-deployment hostname admission shall not be prerequisites.

Verification: `VER-PAIR-001`; validation: `VAL-PAIR-001`. See scoped authority and protocol for executable acceptance boundaries.

### REQ-PAIR-002

The public linking flow shall require signed-in account consent through a nonce-protected POST for the matching displayed one-time user code. Opening a link, signing up or presenting a payment-success parameter alone shall not authorize a deployment.

Verification: `VER-PAIR-002`; validation: `VAL-PAIR-002`. See scoped authority and protocol for executable acceptance boundaries.

### REQ-PAIR-003

Pending linking attempts shall expire after 300 seconds, enforce bounded issuance, approval guesses and polling, and permit only one successful redemption through atomic persistent transitions across workers. Secret device codes shall remain backend-only and shall not be stored in plaintext by WordPress.

Verification: `VER-PAIR-003`; validation: `VAL-PAIR-003`. See scoped authority and protocol for executable acceptance boundaries.

### REQ-PAIR-004

A deployment shall accept a result only for the initiating current local administrator and session. It shall stage and verify the authoritative result before an intentional commit, consume the local attempt once, and preserve an existing working link on failure, denial, cancellation, expiry, session change or account mismatch. A first link may save verified WordPress identity with no paid grant when service validation fails; an existing different working credential/configuration shall not be replaced by a candidate that fails service validation. A same-key re-link shall not newly assert paid readiness on validation failure.

Verification: `VER-PAIR-004`; validation: `VAL-PAIR-004`. See scoped authority and protocol for executable acceptance boundaries.

### REQ-PAIR-005

The new flow shall deliver only the existing product account credential and allowlisted authoritative identity/status fields over a backend HTTPS response. It shall preserve current service entitlement/quota decisions, worker-scoped credentials and local administration/update authority. Pairing shall not grant a new paid entitlement, change retention/outage policies, or give the provider host access.

Verification: `VER-PAIR-005`; validation: `VAL-PAIR-005`. See scoped authority and protocol for executable acceptance boundaries.

### REQ-PAIR-006

The implementation shall preserve existing working links and legacy clients, keep the current pinned WordPress package/publisher boundary, and deliver installed product updates through accepted DC Overview Fleet Management. Deployment and paid-service acceptance shall remain held until observed in the intended environment.

Verification: `VER-PAIR-006`; validation: `VAL-PAIR-006`. See scoped authority and protocol for executable acceptance boundaries.


## Owner-approved branded linking and offer repair — 31 October 2026

Direct owner response: “Approve repair and rollout”. Exact reviewed revision3 plan SHA256 `38923fa994f3735f2c1c62b2cc1c0f87894892240c924ee0927128ddc4453d8f` and receipt are retained in `.traceweaver/link-ux-20261031/`. This is an approved interpretation of REQ-PAIR-001, REQ-PAIR-002, REQ-PAIR-003, REQ-PAIR-004, REQ-PAIR-005, REQ-PAIR-006, REQ-IPMI-MON-02, not a replacement for the existing contract. The plan preserves v1 transport, explicit consent/local confirmation, original expiry, bounded persistent CAS, existing account keys/entitlements and legacy clients. It authorizes safe branded continuation, readable truthful dialog states, approved paid-offer displays, protected releases, the two named CMS pages and accepted Fleet rollout after checks. Unproved trial funding/seed/expiry holds production trial changes and new or altered 1M promises; unchanged trial blocks are explicitly not reverified. No customer grants, purchases, model calls, VPN or inbound callbacks are authorized. Source verification does not imply installed, trial-delivery or billing acceptance.
