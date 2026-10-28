# PR #28 scope work roadmap

**Updated:** 2026-10-28 · Execution checklist aligned with [Limitations and roadmap](limitations-roadmap.md).

| Priority | Work item | Exit criterion | Status |
| --- | --- | --- | --- |
| P0 | Program-bank instruction fetch and fall-through at `$xx:FFFF`. | A minimal headless fixture distinguishes bank-wrapped bytes/PC from linear 24-bit decoding; identify the Ghidra address-space constraint before changing SLEIGH. | In progress |
| P1 | Uncertain M/X/E and XCE state recovery. | Review the existing context model, document what is and is not inferable, and make only state-safe changes backed by a regression. | Pending |
| P2 | Broaden independent CPU-correctness evidence. | Identify coverage gaps in the bounded test set and add a small reproducible test where the expected hardware behavior has an independent oracle. | Pending |
| P3 | Compatibility with a real compiler ABI. | Keep illustrative `__near`/`__far` conventions separate from any compiler-specific ABI; only add a compiler model when its published ABI and test artifacts are available. | Pending |

## Working rules

- Follow the priority order; do not alter SLEIGH semantics until P0's behavior is characterized.
- Prefer focused headless tests and independent expected results over source-text assertions.
- Record architectural blockers and evidence here and in [the limitations roadmap](limitations-roadmap.md).
- 65802 support, SNES loading, automatic vector discovery, and cycle timing remain out of scope.
