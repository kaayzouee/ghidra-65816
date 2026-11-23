# Limitations and roadmap

**Updated:** 2026-11-23

## Current status

- **Compatibility:** CI covers Ghidra 12.1, 12.1.2, 12.1.3, 12.1.4, and 12.2 ([PR #34](https://github.com/kaayzouee/ghidra-65816/pull/34)).
- **Instruction regressions:** native RTI index behavior ([PR #35](https://github.com/kaayzouee/ghidra-65816/pull/35)) and PER/WDM display ([PR #36](https://github.com/kaayzouee/ghidra-65816/pull/36)).
- **XCE:** known Carry improves local decoding ([PR #37](https://github.com/kaayzouee/ghidra-65816/pull/37)); branch conflicts are tested ([PR #38](https://github.com/kaayzouee/ghidra-65816/pull/38)) and can be flagged by a [warning script](../scripts/Flag65816XceCarryJoins.java) ([PR #39](https://github.com/kaayzouee/ghidra-65816/pull/39)).
- **Bank boundaries:** a [repair script](../scripts/Repair65816BankFallthrough.java) fixes safe fall-through edges ([PR #32](https://github.com/kaayzouee/ghidra-65816/pull/32)), but not instruction fetch across a bank boundary.
- **Tests:** CI runs source checks, SLEIGH compilation, headless disassembly, P-code tests, and a bounded 160-case SingleStepTests subset. See [DEVELOPMENT.md](../DEVELOPMENT.md).

## Remaining priorities

1. **Bank-wrapped instruction fetch:** Ghidra can read instruction bytes from the next bank instead of wrapping within the current bank. This needs a Ghidra-level solution for fetching bytes, instruction extents, and flow; a SLEIGH-only fix is insufficient. See [design findings](program-bank-boundary-design.md) and [upstream issue #10060](https://github.com/NationalSecurityAgency/ghidra/issues/10060).
2. **CPU context recovery:** unknown stack status, computed Carry, and conflicting control-flow paths can leave M/X/E uncertain. The XCE warning script detects only a specific branch-join pattern; manual context correction is still needed.
3. **Compiler ABIs:** `__near` and `__far` are example conventions, not OpenSNES-compatible. Stack argument ordering depends on [upstream PR #9921](https://github.com/NationalSecurityAgency/ghidra/pull/9921); 32-bit returns need separate handling. See the [ABI gap](opensnes-cc65816-abi-gap.md).
4. **Coverage:** add focused regressions for verified CPU bugs; use the optional full SingleStepTests workflow when appropriate.

SNES loading, automatic vector discovery, 65802 support, and cycle accuracy are outside the current processor-module scope.
