# Limitations and roadmap

**Updated:** 2026-10-29 · Based on merged PRs, current source, and the bank-boundary characterization work.

## Recently completed

- **Immediate constants:** immediate operands no longer reference their own instruction bytes ([PR #18](https://github.com/kaayzouee/ghidra-65816/pull/18)).
- **P-code stack/context fixes:** corrected 16-bit pulls and native status-stack semantics ([PR #20](https://github.com/kaayzouee/ghidra-65816/pull/20)).
- **Disassembly regressions:** added focused headless checks for instruction lengths, self-references, and decompiler constants ([PR #21](https://github.com/kaayzouee/ghidra-65816/pull/21)).
- **SingleStepTests:** PR #22 added a deterministic 120-case CI subset and an optional 25,600-case workflow; this roadmap branch expands the pinned subset to 160 cases with immediate-compare and relative-branch coverage.
- **WAI/STP:** removed unresolved p-code operations; WAI falls through and STP self-loops ([PR #23](https://github.com/kaayzouee/ghidra-65816/pull/23)).
- **Bank boundaries:** tests cover selected data accesses, branches, and near/far calls ([PR #13](https://github.com/kaayzouee/ghidra-65816/pull/13), [PR #14](https://github.com/kaayzouee/ghidra-65816/pull/14)).
- **Optional call conventions:** PR #28 adds manually selected `__near` and `__far` register models. These are illustrative conventions, not a claim of compatibility with a particular compiler ABI.
- **Compiler ABI review:** the OpenSNES `cc65816` ABI uses left-to-right stack arguments and caller cleanup. A proposed upstream Ghidra `stackltr` attribute is not yet merged; the candidate model and 32-bit return limitation are documented separately in [the ABI gap note](opensnes-cc65816-abi-gap.md).

## Remaining priorities

| Priority | Gap | Next step |
| --- | --- | --- |
| 1 | Instruction bytes and fall-through can cross the end of a program bank incorrectly. | Pinned Ghidra CI confirms the current linear behavior; the bank-boundary runner also records the hardware-correct expectations and exposes a strict `GHIDRA_BANK_WRAP_REQUIRED=1` mode. Source review of Ghidra 12.1.4 shows standard instruction-byte reads use non-wrapping address addition; a complete fix needs a supported bank-aware fetch/address integration point, not just SLEIGH masking. See [design findings](program-bank-boundary-design.md). |
| 2 | Static analysis cannot always infer M/X/E from unknown stack values, computed Carry at XCE, or conflicting paths. | A source regression now guards against treating unknown stacked M/X bits as static decode context. Keep uncertain paths manual; see CPU-state guidance in [README](../README.md). |
| 3 | Test coverage is not proof of complete CPU correctness. | The 160-case pinned subset, including immediate compare and relative branch cases in both modes, passed CI run [40629110625](https://github.com/kaayzouee/ghidra-65816/actions/runs/40629110625); investigate any mismatch against the WDC reference and another emulator. |
| Out of scope | 65802, SNES loader, automatic vector analyzer, cycle timing. | Keep separate unless project scope changes. |

## Validation

Normal CI runs source tests, pinned SLEIGH compilation, headless disassembly, runtime P-code checks, and the bounded SingleStepTests subset. The optional full-corpus workflow is documented in [DEVELOPMENT.md](../DEVELOPMENT.md).

Useful references: [W65C816S datasheet](https://www.westerndesigncenter.com/wdc/documentation/w65c816s.pdf) · [SingleStepTests/65816](https://github.com/SingleStepTests/65816) · [MAME 65816 implementation](https://github.com/mamedev/mame/tree/master/src/devices/cpu/g65816) · [Ghidra SLEIGH context](https://ghidra.re/ghidra_docs/languages/html/sleigh_context.html)
