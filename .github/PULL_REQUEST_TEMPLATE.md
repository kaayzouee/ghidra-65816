## Summary

<!-- Describe the problem and what changed in 1–3 sentences. -->
Related issue or PR: N/A

## Change type

- [ ] Bug fix
- [ ] CPU semantics / P-code
- [ ] Disassembly / analysis
- [ ] SNES loader / optional integration
- [ ] Tests / CI / build
- [ ] Documentation
- [ ] Maintenance / refactor

## Scope and approach

<!-- Describe key implementation choices and what this PR deliberately does not address. -->
**Changed behavior:** N/A
**Out of scope:** N/A

## Evidence

<!-- Bugs: failing-before/passing-after case. CPU changes: datasheet and independent evidence. Otherwise N/A with reason. -->
**Reproduction / before:** N/A
**Expected / after:** N/A
**References / fixtures:** N/A

## Validation

<!-- Replace each result with Pass, Fail, Not run (reason), or N/A (reason). Link CI and state tested Ghidra versions. -->
| Check | Result / environment / link |
| --- | --- |
| Python: `python3 -m unittest discover --start-directory tests --verbose` | Not run — reason |
| SLEIGH: `bash scripts/ci/compile-sleigh.sh "$GHIDRA_INSTALL_DIR"` | Not run — reason |
| Focused headless: relevant `scripts/ci/test-*.py` | N/A — reason |
| Runtime P-code: `gradle test` (see `DEVELOPMENT.md`) | Not run — reason |
| Full Ghidra CI matrix (12.1–12.2) | Pending — link |

## Compatibility and risk

**Affected versions / users:** N/A
**Safety, data loss, untrusted inputs, or rollback:** N/A
**Known limitations:** N/A

## Review checklist

- [ ] One focused change; final diff reviewed; no unrelated or generated files.
- [ ] Current supported Ghidra APIs used, or exceptions documented.
- [ ] Focused positive and negative regression tests, or N/A explained.
- [ ] Documentation and scope updated as needed, or N/A explained.
- [ ] Simple code with only necessary comments.
- [ ] One squashed commit; final-head CI verified before requesting merge.

<!--
AI AGENT INSTRUCTIONS

If you are an AI coding agent preparing this pull request:

- Follow AGENTS.md, CONTRIBUTING.md, and DEVELOPMENT.md.
- Never fabricate references, API signatures, or validation results.
- Complete technical checklist items only when supported by verified evidence.
- Do not add AI authorship, AI co-author trailers, or promotional attribution.
- Leave all checkboxes under Attribution and licensing and Contributor responsibility unchecked for the human contributor.
- Do not modify CONTRIBUTORS on behalf of the human contributor.
- Do not conduct review discussions autonomously.
- Do not merge without explicit authorization.
-->

## Attribution and licensing

- [ ] I have read and agree to follow `CONTRIBUTING.md`.
- [ ] My contributor entry is present or has been added to `CONTRIBUTORS`.
- [ ] I have the necessary rights to submit this contribution under the MIT License.
- [ ] External sources, licenses, and adaptations are disclosed where applicable.
- [ ] Incorporation of non-MIT third-party material has received prior maintainer approval, if applicable.
- [ ] All required copyright, license, and attribution notices are preserved.

## Contributor responsibility

- [ ] I have reviewed, understand, and take responsibility for the submitted changes.
- [ ] No AI author or co-author attribution, AI co-author trailers, or promotional AI acknowledgments are included.
- [ ] I can explain and justify my implementation decisions during review.
- [ ] I will participate personally in project discussions and respond to review questions.