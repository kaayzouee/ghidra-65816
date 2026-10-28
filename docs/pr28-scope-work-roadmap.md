# PR #28 scope work roadmap

**Updated:** 2026-10-28 · Execution checklist aligned with [Limitations and roadmap](limitations-roadmap.md).

| Priority | Work item | Exit criterion | Status |
| --- | --- | --- | --- |
| P0 | Program-bank instruction fetch and fall-through at `$xx:FFFF`. | Characterize wrapped fetch and next-PC behavior; identify whether Ghidra exposes a supported bank-aware byte-fetch/address hook, and do not ship a partial SLEIGH-only workaround. | Characterization passes. Source review of Ghidra 12.1.4 shows `MemoryBufferImpl` advances with `Address.addNoWrap`; no SLEIGH-only fix found. A complete fix is blocked on a supported bank-aware fetch/address integration point; see [design findings](program-bank-boundary-design.md). |
| P1 | Uncertain M/X/E and XCE state recovery. | Review the existing context model, document what is and is not inferable, and make only state-safe changes backed by a regression. | Audited and guarded by a source regression: stack pulls update runtime status/index effects, but static M/X decode context cannot be inferred from unknown stack bytes. README now documents manual context overrides. |
| P2 | Broaden independent CPU-correctness evidence. | Identify coverage gaps in the bounded test set and add a small reproducible test where the expected hardware behavior has an independent oracle. | Expanded the pinned SingleStepTests subset from 120 to 160 cases with CMP-immediate and BNE-relative coverage in emulation/native modes; the pinned fetch and P-code emulator tests passed in CI run 40627076792. |
| P3 | Compatibility with a real compiler ABI. | Keep illustrative `__near`/`__far` conventions separate from any compiler-specific ABI; only add a compiler model when its published ABI and test artifacts are available. | Scope clarified in the limitations roadmap; compiler-specific ABI support deferred until there is a concrete target and oracle. |

## Working rules

- Do not treat P0 as solved by masking branch targets or PC p-code: the parser must fetch bank-wrapped bytes before semantics can run.
- Prefer focused headless tests and independent expected results over source-text assertions.
- Record architectural blockers and evidence here, in [the limitations roadmap](limitations-roadmap.md), and in the [program-bank boundary design note](program-bank-boundary-design.md).
- 65802 support, SNES loading, automatic vector discovery, and cycle timing remain out of scope.
