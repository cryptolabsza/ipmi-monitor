# Charlotte SEL repair validation definition — 11 November 2026

Status: target validation held. Source verification and independent source review
passed on the exact R4 candidate; see
`.traceweaver/charlotte-sel-20261111/root-source-acceptance.json`. No installed
source or hardware acceptance is claimed. Authority remains the approved
nine-step plan and owner receipt in `.traceweaver/charlotte-sel-20261111/`.

Need: reliable, retained native hardware evidence for Charlotte RCA, while
preserving history, credentials, accounts and production services. The operator
must be able to distinguish a fresh complete SEL collection, a confirmed empty
log, and an inaccessible/partial collection across CCC89–99.

Rater: Charlotte owner/operator Hannes Zietsman or an explicitly approved
operational proxy. Root supplies retained evidence; the source implementer does
not self-approve acceptance. This rater operates the affected equipment and is
representative of the intended user. Proxy approval is not assumed.

| Validation | Existing requirement | Representative scenario and acceptance signal |
| --- | --- | --- |
| VAL-CHARLOTTESEL-001 | REQ-SEL-001 | After compatible deployment, two ordinary collector cycles on all ten accessible BMCs show persisted fresh complete native per-host successes, including confirmed empty CCC97. An accessible host remaining incomplete is a held host result and cannot count as successful complete-cycle acceptance. Honest degraded reporting remains necessary but does not satisfy complete collection. CCC94 stays explicitly degraded; reachability alone cannot pass. |
| VAL-CHARLOTTESEL-002 | REQ-SEL-002 | Before each approved manual CCC93/95/96 clear, fresh identity and complete exact dual raw archives reconcile with current records, including six CCC96 prefix IDs; qualification, ownership and reservation/audit guards pass. Readback proves actual outcome without replay; existing history and backups survive. |
| VAL-CHARLOTTESEL-003 | REQ-SEL-003 | Operator inspects saved native evidence across backfill and two cycles: native bytes/dates/quality preserved, repeated bytes deduplicate, corrected clocks do not manufacture generations, and historical warnings do not trigger an alert flood. |
| VAL-CHARLOTTESEL-004 | REQ-SEL-004 | CCC90 uses only its explicitly validated scoped cipher3 transport; secret-free argv/diagnostics and unchanged accounts/permissions/policies are evidenced. No generic fallback or unqualified writes. |
| VAL-CHARLOTTESEL-005 | REQ-SEL-005 | Approved manual CCC90/91 corrections occur only with trusted UTC, exact native convention and archive/identity guards, preserve raw historical dates and verify native clock plus offset. Unknown/ambiguous state remains held and reconciled without blind retry. |

Evidence destination: root run
`/Users/hanneszietsman/CrypotAI/artifacts/charlotte-sel-repair-20261111/`,
future `acceptance/` per-host JSON, immutable artifact identity, DB/config backup
references, before/after native records, two-cycle persistence/freshness and
operator judgment. Root owns collection after source review, required CI,
compatible immutable release and fresh target prerequisites. No unavailable
native evidence may be substituted with mocked tests or Redfish reachability.

Verification input: `verification-plan.json`, `artifacts/red-collection-final.txt`
and future exact-candidate GREEN/reviews. These are verification, not validation.
Open gap GAP-CHARLOTTESEL-TARGET-20261111: owner root; trigger accepted immutable
compatible deployment and fresh identity/backup/qualification gates; expected
evidence the records above. Actual target acceptance remains held until observed.
CCC94 restoration is not promised by source tests and must remain explicit.

Rollback: retain a consistent DB/WAL/config backup and previous immutable artifact.
Do not discard acknowledged post-backup evidence during rollback; reconcile it.
BMC clear cannot be reversed by software rollback; preserve raw archives/audit.
Ambiguous clock/clear effects require state readback, never blind replay. Automatic
policies stay OFF; no LTX, power/reset, firmware or credential changes.

## Candidate operator configuration (source only)

The read-only special transport file defaults to
`DATA_DIR/sel-read-profiles.json` (`/app/data/sel-read-profiles.json` in the
existing container). The existing persistent data mount is sufficient. A native
clone uses its configured `DATA_DIR`; no new mount or environment variable is
required. `SEL_READ_PROFILES_FILE` optionally selects a different absolute file.
A missing default file uses cipher17. A missing explicitly selected file,
unsafe file, stale matching binding or mismatched identity fails closed.
There is no retry-driven cipher downgrade.

The file is strict UTF-8 JSON, maximum64KiB/256entries, with duplicate keys and
unknown fields rejected. Use a regular file with one hard link, mode0600,
owned by root or the actual application UID. Files and every ancestor are opened
without following symlinks; group/world writable files are rejected. Provision
with the normal persistent-volume owner, write a temporary file of mode0600 in
the same directory, then rename it atomically. This config contains device
identity, not passwords. Keep credentials in the existing managed credential
source; this repair creates no new credential store.

Example structure (replace every placeholder with current exact values):

```json
{
  "schema_version": "sel-read-profiles/1",
  "profiles": [{
    "server_id": 123,
    "binding": "CURRENT_64_CHARACTER_LOWERCASE_SHA256",
    "bmc_ip": "CURRENT_CONFIGURED_ADDRESS",
    "cipher": 3,
    "device_id_reply": "CURRENT_COMPLETE_11_OR_15_BYTE_LOWERCASE_HEX",
    "guid": "CURRENT_16_BYTE_LOWERCASE_HEX"
  }]
}
```

Read `server_id`, `binding`, and `bmc_ip` from `sel_target` in the current database
using a read-only SQLite connection under the native image/volume owner. For
example, execute the following Python in the same runtime/data directory; it
reads only public target identifiers, never credential tables:

```python
import os, pathlib, sqlite3
path = pathlib.Path(os.environ.get('DATA_DIR', '/app/data')) / 'ipmi_events.db'
with sqlite3.connect(path.as_uri() + '?mode=ro', uri=True) as db:
    print(db.execute('SELECT server_id,bmc_ip,binding FROM sel_target').fetchall())
```

The target row is established by an ordinary first collection attempt. Obtain
Device ID and GUID through the approved fixed read-only identity probe, or use
fresh retained exact identity evidence after root verifies the current binding.
The whole Device ID reply includes firmware identity. The cipher3 adapter issues
only Get Device ID/Get System GUID before verifying those exact bytes; other
reads are refused on mismatch. Both one-shot and persistent-shell argv use the
selected cipher. Installing this file does not grant clear, clock or logging
mutation authority. The independent, existing exact-action qualification loader
and admin/CSRF/ownership/archive guards remain required. Do not use an old audit
identity as a substitute for a current check.

## Candidate collection semantics and recovery

The durable `sel_target.collection_state` column is additive and nullable. Its
migration preserves existing target/event rows, does not rewrite historical
records, and can run repeatedly. An old runtime ignores this extra column; an
image rollback does not undo records acknowledged by the candidate. Keep the
consistent database/config checkpoint and post-checkpoint evidence described
above.

One ordinary read has one180s monotonic budget, including a maximum of one fresh
reservation retry. Existing mutation deadlines remain60s. A short native chain
can use at most128 live direct candidate reads per snapshot, nearest predecessors
and observed gaps only; unknown incompleteness remains failed. No archive bytes
are used for native recovery. The child is closed/reaped on every source path;
termination uses short bounded waits, within the30s reconciliation grace.

`begin_collection`, clear and clock claims serialize through SQLite
`BEGIN IMMEDIATE`; no network reads hold the write transaction. A collection
lease stores attempt, target/binding/revision/fingerprint/generation/epoch,
process-instance UUID, real boot/PID-start identity and owned child PID/start
identity. Linux also records the PID namespace and namespace-init start to avoid
mistaking an invisible old container for a dead local owner. Darwin uses kernel
microsecond start identity. No heartbeat/time-only reclaim is performed.

`recover_collection` can release only the exact old attempt after210s and local
proof that its exact owner is gone and its exact child is absent/reaped. A live
owner, unreaped/live child, foreign boot/namespace or unknown spawn window holds
ownership. A normal finish also retains ownership while a live/unknown child
exists. A late old ticket cannot release a replacement or acknowledge records.
These are read-lease rules; mutation outcome-unknown ownership is unchanged and
must be reconciled independently. Operators must inspect an explicit held
collection; they must not clear a lease solely because it is old.

Success is committed only with a complete native snapshot, exact unique16-byte
record count and current acquisition identity. Confirmed zero records is fresh
success. Failures preserve the prior complete-success receipt/time, expose the
latest failure/counts separately and break notification continuity. Staleness is
based only on committed complete success (`max(120,2*POLL_INTERVAL+180)` seconds),
never generic reachability or probe time. Individual capacity/logging/clock facts
are retained even while the collection state is degraded.

Raw record identity is a domain-separated SHA256 over the16bytes, independent
of decoder text. Type02 and timestamped OEMc0–df preserve the native four-byte
counter and label it unverified/uninitialized; OEMe0–ff have no timestamp and do
not acquire an invented native date. Collection UTC is independent. Decoder
names follow the [upstream ipmitool field/event definitions](https://github.com/ipmitool/ipmitool/blob/master/include/ipmitool/ipmi_sel.h);
notification severity is the existing project convention for known threshold,
power, processor, ECC, OS-stop and watchdog faults. Unknown OEM payloads remain
raw, with informational severity. Deassertions do not trigger prospective alerts.

First baseline, process restart, generation change, failed/stale interval and
explicit raw imports suppress historical incident notifications. After a fresh
baseline, newly asserted known warning/critical records can alert after commit.
Collector degradation uses the existing warning-event configuration/cooldowns;
no settings or global mute are changed. Both worker and bulk use the same finish
transaction, including empty and failed results. The worker retries native
collection despite stale generic reachability, and the scheduler waits for
in-flight work instead of queuing overlapping cycles.

## Source verification scope

Builder checks are local synthetic verification only, including real OS child
processes, PTYs, SQLite and Chromium pages. No builder BMC/SSH/deployment occurred.
Exact commands, outcomes and candidate hashes are in scoped `artifacts/source-*`
and the root run `findings/source-builder.json`. Root retains fresh Linux/package
verification, independent Sol/Astra review, official CI/publication and intended-use
acceptance. Source checks do not establish firmware qualification, current archive
CAS, native latency or successful physical clock/clear operations.

Final source controls also compare every immutable ticket field against its
durable captured value; the in-memory producer cannot relabel evidence after a
generation/epoch change. The one-second SQLite lock wait applies only during
collection transactions and is restored to the connection's exact original
setting on pool return. Real writer-contention tests verify that child receipts
do not consume the original60s timeout and that later mutation callers still
receive that60s setting. Child-terminal proof is repeated on the failure-receipt
retry path as well as the normal finish path.

## Verified source result and remaining target boundary

The root full macOS run passed474 tests in158.07s. Current independent Linux
validation passed81 focused cases and the original Redfish-only data-loss
reproduction on the official1.4.1 dependencies with the candidate source mounted
read-only. The final adversarial review passed22 targeted cases with no open
findings. Exact evidence and frozen hashes are retained beside the source result.
Earlier13,882-record replay, additive migration and old/candidate/old/candidate
startup checks apply only to the unchanged paths identified by the Linux report.
These source checks authorize the protected publication route; they do not close
the validation scenarios above.

Explicit Redfish-only targets retain diagnostic events and independent diagnostic
progress. Their native completeness stays unverified and native action
capabilities unavailable. Auto/IPMI targets keep complete native acquisition as
the authority. Restart across an unprovable old container namespace leaves an
interrupted read lease held; operators may not reclaim it by age alone. A slow
blocked Redfish chunk remains a soft-deadline limitation. Automatic policies
remain OFF and physical maintenance requires existing exact qualification.
