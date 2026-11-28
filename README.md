# Ghidra 65816

A processor module for the WDC W65C816S in Ghidra.

This is an experimental community continuation of [achan1989/ghidra-65816](https://github.com/achan1989/ghidra-65816). It supports static disassembly and instruction-level P-code; it is **not cycle-accurate**.

## Install

1. Copy this repository to Ghidra's `Ghidra/Processors/65816` directory.
2. Restart Ghidra.
3. Import the binary, select **65816**, and configure its memory map and initial CPU state.

### SNES cartridge import

For cartridge import, install the extension ZIP built for your Ghidra release through
**File → Install Extensions**, then restart Ghidra. Install one copy of the processor
language: move any manually installed 65816 module outside Ghidra before enabling
the ZIP. Import a cartridge and select **SNES ROM**. The loader maps ROM and WRAM
and disassembles the instruction at `RESET`. **Raw Binary** remains available.

The loader accepts ROM-only LoROM (32 KiB–4 MiB) and HiROM (64 KiB–4 MiB)
with power-of-two payloads, optionally preceded by a 512-byte copier header.
Detection requires a matching size code, ordinary slow/fast map mode, zero
cartridge type and RAM size, and a reset vector in an upper ROM window.
A printable nonblank 21-byte title or complementary checksum words supply
additional evidence. Ambiguous headers are rejected. Checksum-word consistency
does not verify the payload checksum.

LoROM maps upper 32 KiB windows. Board-dependent lower-half LoROM windows
are left unmapped. HiROM maps full cartridge banks and upper system-bank
windows. Both use uninitialized WRAM with low 8 KiB mirrors. MMIO, SRAM,
enhancement chips, extended maps and interleaved layouts are outside this release.
Only reset receives an entry point from this loader.

To build, set `GHIDRA_INSTALL_DIR` to the target release and run
`gradle buildExtension`. The ZIP is written to `dist/`.

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
- **Calling conventions:** optional `__near`/`__far` are illustrative register-only models, not the OpenSNES `cc65816` stack ABI. See the [ABI modelling gap](docs/opensnes-cc65816-abi-gap.md).
- **Immediate operands:** represented as constants for decompiler propagation.
- **Tests:** source checks, pinned SLEIGH compilation, headless disassembly, runtime P-code tests, and a bounded 160-case SingleStepTests subset.

## Limitations

- Instruction bytes and fall-through can still cross a program-bank boundary incorrectly. The current SLEIGH model cannot wrap parser byte reads at `$xx:FFFF`. The optional [fall-through repair script](DEVELOPMENT.md#safe-bank-local-fall-through-repair) fixes **only** flow edges for instructions whose final byte is at `$xx:FFFF`; it cannot fix instructions that straddle the boundary. See the [design findings](docs/program-bank-boundary-design.md) and [roadmap](docs/limitations-roadmap.md).
- Static analysis cannot always infer `MF`/`XF`/`EF` from unknown stack contents, computed Carry, or conflicting paths. After disassembly, run [Flag65816XceCarryJoins.java](scripts/Flag65816XceCarryJoins.java) from Ghidra's Script Manager to mark conditional branches that bypass a Carry setter before `XCE` with Warning bookmarks. This is a diagnostic, not path-sensitive decoding; inspect flagged paths and set context manually. See the [limitations roadmap](docs/limitations-roadmap.md).
- **Callee M/X propagation is partial.** After analysis, the optional [Repair65816CalleeWidths.java](scripts/Repair65816CalleeWidths.java) script handles direct calls to leaves with one or two adjacent `SEP/REP #$10/#$20/#$30` instructions before `RTS/RTL`, followed by short isolated immediate-only code. It skips ambiguous flows, analyst-defined references, labels, and code it cannot safely replace; other cases require manual context correction.
- `WAI` is modelled as fall-through; `STP` as a self-loop. Wait-state, interrupt wake-up, and hardware reset are not emulated.
- Automatic interrupt-vector analysis and a 65802 variant are outside the CPU module's scope.
- Passing tests does not prove full hardware correctness.

See [supported scope](docs/SUPPORT.md) and [development/testing](DEVELOPMENT.md).
