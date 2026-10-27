# Ghidra 65816

A processor module for the WDC W65C816S in Ghidra.

This is an experimental community continuation of [achan1989/ghidra-65816](https://github.com/achan1989/ghidra-65816). It supports static disassembly and instruction-level P-code; it is **not cycle-accurate**.

## Install

1. Copy this repository to Ghidra's `Ghidra/Processors/65816` directory.
2. Restart Ghidra.
3. Import the binary, select **65816**, and configure its memory map and initial CPU state.

## CPU state

Set context and registers for each entry point:

| Setting | Meaning |
| --- | --- |
| `MF` | Accumulator width: 1 = 8-bit, 0 = 16-bit |
| `XF` | Index width: 1 = 8-bit, 0 = 16-bit |
| `EF` | Emulation mode |
| `PBR` / `DBR` | Program / data bank |
| `DP` / `SP` | Direct page / stack pointer |
| `DF` | Decimal mode flag |

Use **Processor Options...** for `MF`, `XF`, and `EF`; use **Set Register Values...** for the other registers.

## Status

- **Decoding:** broad opcode coverage. Branch, data-access, and near/far-call bank-boundary cases have regression tests.
- **P-code:** regression-tested stack, status, arithmetic, control-flow, and context behavior.
- **Immediate operands:** represented as constants for decompiler propagation.
- **Tests:** source checks, pinned SLEIGH compilation, headless disassembly, runtime P-code tests, and a bounded 120-case SingleStepTests subset.

## Limitations

- Instruction bytes and fall-through can still cross a program-bank boundary incorrectly. See the [roadmap](docs/limitations-roadmap.md).
- Static analysis cannot always infer `MF`/`XF`/`EF` from unknown stack contents, computed Carry, or conflicting paths.
- `WAI` is modelled as fall-through; `STP` as a self-loop. Wait-state, interrupt wake-up, and hardware reset are not emulated.
- This repository does not include a SNES ROM loader, automatic vector analyzer, or 65802 variant.
- Passing tests does not prove full hardware correctness.

See [supported scope](docs/SUPPORT.md) and [development/testing](DEVELOPMENT.md).
