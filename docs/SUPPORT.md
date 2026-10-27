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

## When is a limitation fixed?

Require a regression or repeatable fixture that fails before the change, a relevant CPU reference, and validation with the Ghidra version pinned in CI. Compilation alone is not sufficient.
