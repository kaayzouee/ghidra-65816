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

The `__near` and `__far` models have been compared with the published [SNES-Dev w65 ABI v1](https://snes-dev.github.io/abi/v1.html), a proposed ABI for modern w65 toolchains. They are **not compatible** with that ABI: w65 places the first two small scalar parameters in `X` and `Y`, uses `A`/`C` for small scalar return values, and requires `JSL`/`RTL` for externally linked or address-taken functions. It also specifies extended in-memory argument registers, stack-passed remaining arguments, and mode-flag requirements that these example models do not represent.

This is an ABI-level incompatibility finding, not a compiler-generated conformance test. No particular compiler output is currently used as the reference fixture. Do not assign `__near` or `__far` to functions merely because they run on a 65816; first identify the compiler/ABI used by the target. Supporting w65 ABI v1 should be implemented as a separate convention and verified against a pinned compiler-generated fixture, rather than changing these illustrative models in place.

## When is a limitation fixed?

Require a regression or repeatable fixture that fails before the change, a relevant CPU reference, and validation with the Ghidra version pinned in CI. Compilation alone is not sufficient.
