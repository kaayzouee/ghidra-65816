# Supported scope

This repository implements the WDC W65C816S language and instruction-level P-code for Ghidra. It is a static-analysis module, not a cycle-accurate CPU emulator.

## In scope

- Instruction decoding, registers, flags, addressing, stack effects, and control flow.
- Explicit handling of accumulator/index widths and emulation mode where analysis has enough context.
- Regression tests for P-code behavior, disassembly, immediate constants, and selected bank-boundary cases.
- Clear documentation of known gaps.

## Not included

- **65802:** no variant support in this repository.
- **SNES loader or automatic vector analyzer:** these are platform integrations, not part of the CPU module.
- **Cycle-accurate timing, bus behavior, or interrupt wake-up:** these are not modeled by the P-code.
- **Perfect automatic context recovery:** unknown stack status, computed Carry at `XCE`, and conflicting paths can require manual context.

Instruction-byte and fall-through wrapping at the end of a program bank also remain limitations; see the [roadmap](limitations-roadmap.md).

## Optional calling conventions

The default call model remains `__unknowncall`. The optional `__near` and `__far` models are not selected automatically by `JSR` or `JSL`; users must assign them to functions that follow this example register convention.

These models assume `C`, `X`, and `Y` can carry inputs, `C` carries a result, `SP` is preserved, and `X`, `Y`, `DP`, `DBR`, and status flags may be clobbered. This is a selectable convention, not a universal 65816 ABI. It does not describe stack-passed arguments.

The global return-address annotation remains two bytes. The far model's three-byte stack shift therefore still needs a headless `JSL`/`RTL` decompilation regression before its stack effects can be considered verified.

## When is a limitation fixed?

Require a regression or repeatable fixture that fails before the change, a relevant CPU reference, and validation with the Ghidra version pinned in CI. Compilation alone is not sufficient.
