# Supported scope

## Primary target

The processor module models the WDC W65C816S (65816) CPU in Ghidra. It is a **static processor language with P-code semantics**, not a cycle-accurate hardware emulator. Its acceptance criteria are reliable instruction decoding and useful, evidence-backed data-flow/decompiler analysis for code whose initial processor state and memory map are supplied correctly.

## In scope

- W65C816 instructions, addressing modes, register and flag behavior.
- Emulation/native mode and accumulator/index width behavior, including explicit unknown-state limitations.
- Program-bank and data-bank address semantics, stack effects, interrupts, and return flow.
- Ghidra language metadata, P-code runtime tests, independently sourced single-step tests, and focused disassembly/decompiler fixtures.
- Documentation of known gaps and reproducible validation.

## Separate integrations

- **SNES ROM loader and memory maps:** platform-specific. Keep LoROM/HiROM mapping, mirrors, RAM/MMIO regions, ROM header handling, and SNES-specific symbols in a loader or companion script/extension rather than baking those assumptions into the generic CPU language.
- **Other 65816-based systems:** use platform profiles or loaders for their memory maps and entry points; do not assume every binary is a SNES ROM.

## Explicitly not supported yet

- **65802:** not supported until a separate compatibility matrix and variant-specific regression tests exist. Do not label it supported just because it shares instructions with the 65816.
- **Cycle-exact timing or bus emulation:** the Ghidra P-code semantics are instruction-level and do not promise cycle accuracy or full bus-cycle fidelity.
- **Automatic certainty for unknown runtime state:** stack contents, unknown Carry values at XCE, and conflicting control-flow paths may prevent static MF/XF/EF resolution. The analyzer must not force a decode mode when the evidence is ambiguous.

## Definition of improvement

A limitation should only be marked resolved when the PR includes a failing-before/fixed-after regression or a repeatable analysis fixture, cites the relevant processor rule, and demonstrates the behavior on the pinned Ghidra version. Compilation and source-pattern tests are necessary but not sufficient. External CPU tests are an independent reference, not an unquestionable oracle; disputed cases must be cross-checked and documented.
