# Branded account linking validation definition

Authority: `.traceweaver/link-ux-20261031/owner-approval.json`, exact revision3 plan38923fa9. Scope: REQ-PAIR-001..006 and REQ-IPMI-MON-02; existing IDs retained.

Intended use: a deployment administrator signs in or signs up through the existing branded central flow, reviews matching code, explicitly consents centrally and intentionally saves locally. The dialog must be readable at desktop/mobile/200% zoom, visibly distinguish waiting/saving/error and display linked identity separately from paid service.

Verification: existing Flask/v1/security regressions plus actual extracted JavaScript with only DOM/HTTP/time substitutes. Precode RED94cases/12 expected failures and original81cases passing are in the workspace artifact client/definition/red.log. Postfix raw logs, source hash and two batched browser QA rounds must identify the exact candidate. Mocked success does not prove central/target acceptance.

Validation actor: owner or independent authorized release operator; implementer evidence is verification only. Scenarios and observable signals: (1) desktop/mobile, long identity, keyboard/Escape, light/dark and200% readable no overlap; (2) isolated synthetic account/installation signup and signin preserve code via fixed POST, explicit central consent/local confirmation, single saved identity, lost response qualified without replay; (3) accepted Fleet update version/digest healthy with stored identity/config preserved. Evidence: link-ux-20261031/client/validation/{browser-operator-result,end-to-end-result}.json and release/fleet-result.json in the workspace artifact.

Deferred validation owned by release root: trigger reviewed candidate and central-first installation then accepted Fleet artifact. LTX remains linked and only read-only before/after checks occur. Trial funding/provisioning, model calls and billing are not accepted by this work. Rollback uses last healthy exact Fleet image, retaining volume/config/link, with no DB restore or unlink.
