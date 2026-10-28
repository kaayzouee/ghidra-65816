# PR #28 scope work roadmap

**Updated:** 2026-10-28 · Execution checklist aligned with [Limitations and roadmap](limitations-roadmap.md).

| Priority | Work item | Exit criterion | Status |
| --- | --- | --- | --- |
| P0 | Program-bank instruction fetch and fall-through at `$xx:FFFF`. | A minimal headless fixture distinguishes bank-wrapped bytes/PC from linear 24-bit decoding; identify the Ghidra address-space constraint before changing SLEIGH. | Fixture and CI step added; pinned Ghidra CI run 40627076792 passed the characterization. It confirms the current linear decoding behavior; [the design investigation](program-bank-boundary-design.md) shows the required change is below SLEIGH's semantic layer. |
| P1 | Uncertain M/X/E and XCE state recovery. | Review the existing context model, document what is and is not inferable, and make only state-safe changes backed by a regression. | Audited: stack pulls update runtime flags, but static M/X context cannot be inferred from unknown stack bytes; no safe automatic inference change identified. |
| P2 | Broaden independent CPU-correctness evidence. | Identify coverage gaps in the bounded test set and add a small reproducible test where the expected hardware behavior has an independent oracle. | Expanded the pinned SingleStepTests subset from 120 to 160 cases with CMP-immediate and BNE-relative coverage in emulation/native modes; the pinned fetch and P-code emulator tests passed in CI run 40627076792. |
| P3 | Compatibility with a real compiler ABI. | Keep illustrative `__near`/`__far` conventions separate from any compiler-specific ABI; only add a compiler model when its published ABI and test artifacts are available. | Scope clarified in the limitations roadmap; compiler-specific ABI support deferred until there is a concrete target and oracle. |

## Working rules

- Follow the priority order; do not alter SLEIGH semantics until P0's behavior is characterized.
- Prefer focused headless tests and independent expected results over source-text assertions.
- Record architectural blockers and evidence here, in [the limitations roadmap](limitations-roadmap.md), and in the [program-bank boundary design note](program-bank-boundary-design.md).
- 65802 support, SNES loading, automatic vector discovery, and cycle timing remain out of scope.
