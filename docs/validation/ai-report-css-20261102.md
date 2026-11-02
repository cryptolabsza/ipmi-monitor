# VAL-AICSS-001 — AI report readability and dashboard preservation

Need: NEED-AICSS-001. Requirement: REQ-AICSS-001. Procedure: ATP-AICSS-001. Result: RESULT-AICSS-001. Source authority: `.traceweaver/ai-report-css-20261102/authority.json`.

Validation question: When an administrator opens an existing AI report after the normal approved deployment, does the dashboard retain its original theme, font and page width while the report remains readable with headings, bold text, lists, safe links and tables?

Intended use: deployment administrators reviewing saved fleet reports in the actual dashboard, including dark/light and narrow/wide views. Rater: Hannes Zietsman, owner and representative administrator; independent of the builder implementation. Root may collect observations as an explicitly identified operator, but builder self-assessment is not acceptance.

| Scenario | Need | Acceptance signal | Evidence path | Status |
| --- | --- | --- | --- | --- |
| Existing Charlotte report at normal dashboard route | NEED-AICSS-001 | Original body typography/max-width/theme preserved before and after report display; report text/basic formatting visibly readable; no new inference | Root external repair folder target-acceptance receipt | Planned; held until ordinary verified deployment |
| Existing LTX report if native selection permits | NEED-AICSS-001 | Same signal under ordinary deployment/selection; native unresolved recovery guard respected | Root external repair folder target-acceptance receipt | Held if native guard refuses |

Record template: candidate/release SHA and immutable image; target; route; timestamp; rater and relationship; viewport/theme; before/after computed style and screenshot references; report content readability; observed result (`pass`, `fail`, `partial`, `blocked`); acceptance statement and remaining holds. No customer report text or credentials belong in the source fixture.

Decision: held. Actual target observations and representative judgment have not happened. Root owns collection after protected release and normal Fleet deployment. Missing/blocked target evidence retains that target's acceptance hold; no Fleet repair, provider calls, key grants or cache reset is authorized.

Verification is separate: `tests/test_dashboard_ai_reports.py` uses actual Flask-rendered DOM/CSS and extracted production report handlers in isolated headless Chromium, with only HTTP response boundaries and unrelated startup replaced. External fonts are omitted, so comparisons use the same local fallback before/after; this proves CSS isolation rather than live installed-font or target deployment acceptance. CSP and DNS blocking prevent external requests. Harmless image, frame and stylesheet probes may contact only the owned loopback fixture server; the server records those actual requests, independently of DOM node checks. The regression requires zero report probe requests after repair. It proves these tested resource paths rather than every possible browser resource type.

Repair cycle1 source verification also covers a backend-shaped fresh-summary failure response containing the observed body stylesheet. The error remains readable literal text and cannot alter dashboard CSS. This adds verification evidence only; actual target validation remains held.
