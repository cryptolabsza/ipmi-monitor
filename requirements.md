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


## Owner-approved AI report CSS repair — 2 November 2026

Direct owner intent: “Ok good we need fix thar css issue”, following the diagnosis and proposal to isolate both cached and fresh AI report HTML; subsequently “Merge and deploy”. Transcript custody remains with release root. Authority: `.traceweaver/ai-report-css-20261102/authority.json`. This appendix records only that literal approved behavior, independently of earlier MON/PAIR authority.

### REQ-AICSS-001

When displaying cached or freshly returned AI reports, IPMI Monitor shall prevent report-supplied HTML, CSS, and structured text fields from changing the existing dashboard theme, typography, or page layout, while retaining readable report text and basic formatting.

Need: NEED-AICSS-001. Trace: TRACE-AICSS-001. Verification: VER-AICSS-001. Validation: VAL-AICSS-001. Acceptance: ATP-AICSS-001 / RESULT-AICSS-001. Preserve original dashboard stylesheet/theme identity and report text/basic formatting. Protected release and ordinary Fleet deployment retain existing gates. Provider calls, credentials/credits, stored report clearing, database migrations, CI and Fleet recovery changes are outside scope. Source verification and per-target intended-use acceptance remain separate. Precode review/production GO remain held pending the root decision; no closure is asserted.

Current source evidence after root source-only GO: `.traceweaver/ai-report-css-20261102/green-evidence.json` records identical focused RED→GREEN and 262 passing tests. The preceding precode hold records the preparation state; root subsequently passed precode review and authorized source implementation only. Independent source review, protected publication and actual target acceptance remain held.

Current scoped source decision (2 November 2026): `.traceweaver/ai-report-css-20261102/root-source-acceptance.json` records two final independent reviews with no open findings after repair1, 262 passing tests and36 browser cases. Earlier pending records are retained history. Protected CI/publication, immutable image compatibility and actual per-target validation remain separate pending gates; no requirement closure or global dashboard security certification is claimed.


## Owner-approved SEL health and native clock — 3 November 2026

Authority: `.traceweaver/sel-health-20261103/owner-approval.json` records the literal approval “im lets inplement and build with [$orchestra](/Users/hanneszietsman/.agents/skills/orchestra/SKILL.md)”. The retained approved plan is `.traceweaver/sel-health-20261103/plan-v2.md`, SHA256 `0c75c22c8021534d3e360e9ebac9f7c55c6f89bb35ecac2c6a60e28a366043cc`, with carried-forward preservation/readback clarifications. Its original candidate status is historical; the subsequent owner receipt approves local implementation/build. These additive IDs record that plan, without changing prior authority or claiming source/hardware acceptance. Baseline `c0a3b83724d993ef2f806a4a12305025d72c2b88`; L3.

### REQ-SEL-001 — health

Monitor shall persist independently observed current capacity, logging state, native SEL clock, capability, identity and freshness. Dashboard and server page shall identify machine name/BMC IP and Full, Nearly Full, Logging Disabled, Clock Incorrect and Unknown/Stale states truthfully. Current controls, not historical events, determine logging. Unknown/expired/missing capacity cannot authorize writes or percentage triggers. Near-full defaults to 90%; automatic clear requires confirmed full.

Source: approved plan §1, §2. Trace: TRACE-SEL-001; verification: VER-SEL-001; validation: VAL-SEL-001, shared `docs/validation/sel-health-20261103.md`. Authority approved for local implementation/build; preparation review and production GO pending; runtime verification/validation held.

### REQ-SEL-002 — guarded backup/clear

Every manual, bulk or automatic BMC clear shall use one shared workflow: same qualified hardware reservation spans final bounded complete raw record read and clear; durable complete backup, audit intent and verifiable receipt commit before dispatch. Empty success differs from read failure; partial/malformed-without-raw/page/commit/quota/audit/guard failures prevent clear. Reservation invalidation permits bounded recollection only. Standalone fresh-reservation clear and disabling logging for a quiet window are forbidden. BMC clear shall never delete saved history; unqualified history-preserving manual and automatic clear are unavailable.

Source: approved plan §3; User scope owner selection. Trace: TRACE-SEL-002; verification: VER-SEL-002; validation: VAL-SEL-002, shared `docs/validation/sel-health-20261103.md`. Authority approved for local implementation/build; preparation review and production GO pending; runtime verification/validation held.

### REQ-SEL-003 — durable identity/retention/operation

Monitor shall serialize clear/clock using database-enforced per-server/log ownership, durable queued/archiving/mutating/verifying/complete/failed/outcome-unknown states, receipts, identity/revision, initiator and reason. Ambiguous effects reconcile before new mutations, without blind retries or exactly-once claims; attempts, deadlines and cooldown are bounded. Every insertion/dedup path shall preserve events under stable server/log identity, reconciled generation and raw evidence across ID reuse, reset, external clear and replacement. Compatible migration preserves existing rows. Trusted collected/archive time controls eligibility for the existing retention duration; raw native dates remain evidence. Pending/reconciling backups and independent action/consent audit survive ordinary SEL and explicit history clearing.

Source: approved plan §3, §4, §5. Trace: TRACE-SEL-003; verification: VER-SEL-003; validation: VAL-SEL-003, shared `docs/validation/sel-health-20261103.md`. Authority approved for local implementation/build; preparation review and production GO pending; runtime verification/validation held.

### REQ-SEL-004 — security and operator controls

Mutations and separate default-off clear/clock opt-in policies shall require current admin authority, session CSRF/request intent, exact-origin validation and POST, supporting direct/Fleet base paths. Resolve active configured stable server/log before credentials/network; bind consent to identity/revision and recheck before dispatch, revoking queued work on change. Every shared SEL sink in both template trees shall render untrusted names/events/errors as text with enum classes. Scoped transport shall use complete per-target credentials, non-argv secret channel without -P fallback, fixed allowlisted commands/configured targets and sanitized errors. IPMI is the first mutation transport; Redfish mutations stay disabled. Enable Logging changes only the qualified bit, preserves other settings and requires current readback; unsupported/ambiguous hardware stays warning-only.

Source: approved plan §1, §2, §6; clarification enable-control invariant. Trace: TRACE-SEL-004; verification: VER-SEL-004; validation: VAL-SEL-004, shared `docs/validation/sel-health-20261103.md`. Authority approved for local implementation/build; preparation review and production GO pending; runtime verification/validation held.

### REQ-SEL-005 — native clock

Monitor shall detect impossible/uninitialized dates and configurable drift (default five minutes) using verified fresh UTC, explicit qualified native/timezone/offset semantics and current external-time-management status. Healthy external NTP remains authority; unhealthy externally managed time is reported without competing writes. Admin sync/independently opted-in correction shall write only qualified hardware with unambiguous mapping and trusted reference, preserve raw dates/time quality and independently audit before/after/desired UTC. Capture intended offset, set SEL time, restore UTC offset reset by Set SEL Time and verify both offset and clock within documented tolerance; failure between writes is incomplete/unknown, never blind retry. Clock and clear share ownership; clock writes invalidate stale clear evidence. No OS/Mac/GPU clock/frequency changes.

Source: approved plan §5; implementation-clarifications.md offset restoration. Trace: TRACE-SEL-005; verification: VER-SEL-005; validation: VAL-SEL-005, shared `docs/validation/sel-health-20261103.md`. Authority approved for local implementation/build; preparation review and production GO pending; runtime verification/validation held.

Boundaries: isolated feature worktree; no dependency/infrastructure/CI/version change; no live BMC actions, credentials, publication, merge, release or deployment. Exact firmware/transport mutation qualification and representative owner acceptance remain separate held gates. Unsupported devices retain useful read warnings. Lossy clear override, generic Redfish mutations and unrelated credential refactors are excluded.


## Current SEL release approval projection — 4 November 2026

The latest direct owner response “Approve and deploy” is retained byte-for-byte in `.traceweaver/sel-release-20261104/owner-approval.json`. Its bounded mechanical release projection is `.traceweaver/sel-release-20261104/release-scope.json`: dev `e6c63ef25aecdfcc856f3bff73cd19b31259e9d7`, main `cf79b1258e9b6c0daed8c9c998218e4fb48cc0db`, and release version `1.4.0`. Existing REQ-SEL-001, REQ-SEL-002, REQ-SEL-003, REQ-SEL-004 and REQ-SEL-005 and their reviewed behavior remain unchanged. This adds no normative requirement or workflow profile.

This approval authorizes the protected dev-to-main release, required checks, verified image publication/tagging and one Fleet canary after verified database backup with migration-compatible rollback ready. Actual migration, retained history and warning UI must be observed before wider rollout. Earlier local-only/no-release statements record historical approval stages; they do not override this later scoped release approval. Required publication, artifact identity and target prerequisites remain gates. Automatic clearing and native-clock correction remain off/unqualified unless the exact BMC firmware/action is qualified; no hardware write or unobserved acceptance is authorized by this projection. Source verification does not close requirements or establish installed/runtime acceptance.
