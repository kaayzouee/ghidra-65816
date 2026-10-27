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

These models assume `C`, `X`, and `Y` can carry inputs, `C` carries a result, `SP` and `PBR` are preserved, and `X`, `Y`, `DP`, `DBR`, and status flags may be clobbered. This is a selectable example convention, not a universal 65816 ABI. It does not describe stack-passed arguments.

The models declare 2-byte and 3-byte return-address layouts for near and far calls respectively. Regression coverage checks the declared preserved/clobbered register sets, DP/DBR/ZF effects after calls, the stack byte layout, and nested native/emulation call cases. These tests establish consistency of this model with the synthetic test fixtures; they do not establish compatibility with an arbitrary compiler or ROM.

### ABI compatibility review

The optional models have been compared with two concrete ABI references, and neither should be treated as interchangeable with them.

**OpenSNES `cc65816` (compiler-generated reference).** The checked-in fixture at `tests/fixtures/abi/opensnes-cc65816-reference.asm` captures examples published in [OpenSNES `compiler/ABI.md`](https://github.com/k0b3n4irb/opensnes/blob/main/compiler/ABI.md). That document says its assembly examples are actual output from `bin/cc65816 input.c -o output.asm`; its compiler toolchain pins are recorded in [`compiler/PINS.md`](https://github.com/k0b3n4irb/opensnes/blob/main/compiler/PINS.md). The fixture's ABI examples pass parameters on the stack, use `JSL`/`RTL`, return values up to 16 bits in A, and clean arguments in the caller. The optional `__near`/`__far` models instead pass inputs in C/X/Y and model near and far return addresses as 2 and 3 bytes. **They are not compatible with OpenSNES cc65816.** CI checks the checked-in reference snapshot and preserves this explicit incompatibility; it does not build or execute the external compiler.

**SNES-Dev w65 ABI v1 (proposed ABI).** The published [w65 ABI v1 specification](https://snes-dev.github.io/abi/v1.html) uses X/Y for the first two small scalar parameters, A/C for small scalar return values, extended in-memory argument registers, and stack-passed remaining arguments. It also defines mode-flag requirements. The optional models do not implement that ABI either.

The register-effects regression verifies the assumptions internal to these example models: C/X/Y argument and result recovery; X/Y and A clobbering; DP and DBR effects on effective addresses; status-flag effects after calls; PBR restoration across a cross-bank JSL/RTL; and SP/return-address stack restoration in nested native and emulation-mode calls. These synthetic tests do not establish compatibility with an arbitrary compiler or ROM.

Do not assign `__near` or `__far` merely because a function runs on a 65816. Identify the actual compiler and ABI first. If OpenSNES compatibility is needed, add a separate prototype model and headless regression based on its stack-argument/caller-cleanup convention; do not repurpose these illustrative register models. The checked-in assembly is a pinned reference snapshot, not a substitute for compiling a conformance fixture with the target toolchain.
 
## When is a limitation fixed?

Require a regression or repeatable fixture that fails before the change, a relevant CPU reference, and validation with the Ghidra version pinned in CI. Compilation alone is not sufficient.
