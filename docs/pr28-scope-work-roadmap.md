# PR #28 scope work roadmap

**Updated:** 2026-10-28 · Execution checklist aligned with [Limitations and roadmap](limitations-roadmap.md).

| Priority | Work item | Exit criterion | Status |
| --- | --- | --- | --- |
| P0 | Program-bank instruction fetch and fall-through at `$xx:FFFF`. | Characterize 1-, 2-, and 3-byte instructions at bank boundaries, then identify the required Ghidra-level fetch/address extension. Do not ship a partial SLEIGH-only workaround. | Expanded characterization covers 1-, 2-, and 3-byte instructions; all three cases passed pinned Ghidra CI run 40629110625. The runner now compares against both hardware-correct and known-current outputs and has a strict `GHIDRA_BANK_WRAP_REQUIRED=1` mode for future fix validation. Source review of Ghidra 12.1.4 shows `MemoryBufferImpl` advances with `Address.addNoWrap`; no SLEIGH-only fix found. A complete fix is blocked on a supported bank-aware fetch/address integration point; see [design findings](program-bank-boundary-design.md). |
| P1 | Uncertain M/X/E and XCE state recovery. | Review the existing context model, document what is and is not inferable, and make only state-safe changes backed by a regression. | Audited and guarded by a source regression: stack pulls update runtime status/index effects, but static M/X decode context cannot be inferred from unknown stack bytes. README now documents manual context overrides. |
| P2 | Broaden independent CPU-correctness evidence. | Identify coverage gaps in the bounded test set and add a small reproducible test where the expected hardware behavior has an independent oracle. | Expanded the pinned SingleStepTests subset from 120 to 160 cases with CMP-immediate and BNE-relative coverage in emulation/native modes; the expanded headless and P-code emulator tests passed in CI run 40629110625. |
| P3 | Compatibility with a real compiler ABI. | Model the published stack ABI accurately without affecting the default or the illustrative register conventions; validate argument order, stack effects, and return values against real compiler output. | Published OpenSNES ABI is now reviewed and the checker validates source-order pushes. Its left-to-right stack layout needs Ghidra's proposed `stackltr` support (upstream PR #9921 is still open); 32-bit results also use `tcc__retval_hi`. Candidate and blockers documented in [the ABI gap note](opensnes-cc65816-abi-gap.md); no unsupported model enabled. |

## Working rules

- Do not treat P0 as solved by masking branch targets or PC p-code: the parser must fetch bank-wrapped bytes before semantics can run.
- Prefer focused headless tests and independent expected results over source-text assertions.
- Do not enable a compiler-spec attribute that the repository's pinned Ghidra version does not support.
- Record architectural blockers and evidence here, in [the limitations roadmap](limitations-roadmap.md), and in the [program-bank boundary design note](program-bank-boundary-design.md).
- 65802 support, SNES loading, automatic vector discovery, and cycle timing remain out of scope.
