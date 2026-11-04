# Implementation clarifications to the reviewed plan

These make existing preservation/readback obligations explicit; they do not claim code or hardware acceptance.

- From Astra SEL-V2-01: Enable Event Logging modifies only the qualified logging control, preserves unrelated settings and reports success only after current-state readback. An accepted command with disabled/unknown readback is not success. Unsupported or ambiguous controls remain unavailable. Include this in the focused preservation/readback test.
- From independent primary-spec inspection: Set SEL Time resets the SEL UTC Offset to unspecified (Intel IPMI v2.0 sections 31.11a/b). On qualified offset-capable hardware, capture the intended native offset, set time with the correct native interpretation, then restore and verify that offset along with clock readback. A failure between writes remains an incomplete/unknown correction; do not blindly repeat either write or report a successful sync. If timezone/offset capability cannot establish safe interpretation, warn without writing. Test positive/negative offsets and failure between time and offset updates.

Source: https://www.intel.la/content/dam/www/public/us/en/documents/specification-updates/ipmi-intelligent-platform-mgt-interface-spec-2nd-gen-v2-0-spec-update.pdf

Reviewed design remains plan-v2.md, SHA256 0c75c22c8021534d3e360e9ebac9f7c55c6f89bb35ecac2c6a60e28a366043cc. These notes are carried-forward implementation invariants; no fresh security acceptance is asserted for code or firmware.
