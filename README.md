# Ghidra 65816

A processor module for the WDC 65816 CPU in Ghidra.

This is an experimental community continuation of the original
[ghidra-65816 project](https://github.com/achan1989/ghidra-65816). It is useful for
disassembly and early analysis, but it is **not a cycle-accurate CPU emulator**. Verify important
results against known-good 65816 documentation or test programs.

## Install

1. Copy this repository into your Ghidra `Processors` directory.
2. Name the folder `65816`.
3. Restart Ghidra.
4. Import your ROM or binary and choose **65816** as the language.
5. Set up the memory map before disassembling.

## Set the initial CPU state

For each code entry point, set the processor context and registers to match the program.

| Setting | Meaning |
| --- | --- |
| `MF` | Accumulator width: 1 = 8-bit, 0 = 16-bit |
| `XF` | Index-register width: 1 = 8-bit, 0 = 16-bit |
| `EF` | Emulation mode |
| `PBR` | Program bank |
| `DBR` | Data bank |
| `DP` | Direct-page base |
| `SP` | Stack pointer |
| `DF` | Decimal mode flag |

In the CodeBrowser, right-click the first instruction and use **Processor Options...** for
`MF`, `XF`, and `EF`. Use **Set Register Values...** for registers such as `PBR`, `DBR`,
`DP`, and `SP`.

## Current status

| Area | Status |
| --- | --- |
| Instruction decoding | Broad coverage; verify unusual bank-boundary cases |
| P-code semantics | Improving; not fully validated against a CPU emulator |
| Automatic mode tracking | Limited; changes to `MF`, `XF`, and `EF` may need manual context |
| Interrupt entry points | Vector symbols exist, but entry points may need to be added manually |
| 65802 variant | Not supported |

## Known limitations

- Instructions and operands that cross the end of a program bank may be analysed incorrectly.
- Immediate operands are modelled through references to instruction bytes, which can limit constant propagation in analysis.
- `PLP` and `RTI` restore status bits at runtime, but Ghidra cannot automatically use the restored
  `MF` and `XF` bits to select the correct decode context.
- `XCE` changes emulation/native mode at runtime. Static disassembly context cannot always follow
  a mode change that depends on the carry flag.
- Interrupt vectors are not automatically created as code entry points.
- Passing the test suite and compiling SLEIGH do not prove that every instruction behaves exactly
  like real hardware.

## Development

See [DEVELOPMENT.md](DEVELOPMENT.md) for the small local test suite and SLEIGH compiler check.
