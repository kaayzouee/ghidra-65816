# PR #28 scope work roadmap

**Updated:** 2026-10-29 · Execution checklist aligned with [Limitations and roadmap](limitations-roadmap.md).

| Priority | Work item | Exit criterion | Status |
| --- | --- | --- | --- |
| P0 | Program-bank instruction fetch and fall-through at `$xx:FFFF`. | Characterize 1-, 2-, and 3-byte instructions at bank boundaries, then identify the required Ghidra-level fetch/address extension. Do not ship a partial SLEIGH-only workaround. | The 1-, 2-, and 3-byte characterization, the strict-vs-diagnostic result classifier, and its four unit tests pass CI [40803385130](https://github.com/kaayzouee/ghidra-65816/actions/runs/40803385130). Manual Actions input `require_bank_wrap` rejects the current limitation when validating a fix. Source review of `MemoryBufferImpl` and `CodeUnitDB` shows both byte-fetch and contiguous instruction-range constraints. I evaluated a padded virtual code-space/duplicate-bank-start layout; it would require a new address encoding, import transformation, separate physical data memory, target conversions, and non-linear fall-through handling, so it is not a safe local SLEIGH fix. The next step is an upstream-supported fetch/extent extension; the permission-blocked issue draft is at [ghidra-bank-fetch-support-request.md](ghidra-bank-fetch-support-request.md). Related [discussion #9349](https://github.com/NationalSecurityAgency/ghidra/discussions/9349) addresses target resolution only. |
| P1 | Uncertain M/X/E and XCE state recovery. | Review the existing context model, document what is and is not inferable, and make only state-safe changes backed by a regression. | Audited and guarded by a source regression: stack pulls update runtime status/index effects, but static M/X decode context cannot be inferred from unknown stack bytes. README now documents manual context overrides. |
| P2 | Broaden independent CPU-correctness evidence. | Identify coverage gaps in the bounded test set and add a small reproducible test where the expected hardware behavior has an independent oracle. | Expanded the pinned SingleStepTests subset from 120 to 160 cases with CMP-immediate and BNE-relative coverage in emulation/native modes; the expanded headless and P-code emulator tests passed in CI run 40629110625. |
| P3 | Compatibility with a real compiler ABI. | Model the published stack ABI accurately without affecting the default or the illustrative register conventions; validate argument order, stack effects, and return values against real compiler output. | Published OpenSNES ABI is now reviewed and the checker validates source-order pushes. Its left-to-right stack layout needs Ghidra's proposed `stackltr` support (upstream PR #9921 is still open); 32-bit results also use `tcc__retval_hi`. Candidate and blockers documented in [the ABI gap note](opensnes-cc65816-abi-gap.md); no unsupported model enabled. |

## Working rules

- Do not treat P0 as solved by masking branch targets or PC p-code: the parser must fetch bank-wrapped bytes before semantics can run.
- Use the manual `require_bank_wrap` workflow input to verify any candidate fix in strict mode.
- Prefer focused headless tests and independent expected results over source-text assertions.
- Do not enable a compiler-spec attribute that the repository's pinned Ghidra version does not support.
- Record architectural blockers and evidence here, in [the limitations roadmap](limitations-roadmap.md), and in the [program-bank boundary design note](program-bank-boundary-design.md).
- 65802 support, SNES loading, automatic vector discovery, and cycle timing remain out of scope.
