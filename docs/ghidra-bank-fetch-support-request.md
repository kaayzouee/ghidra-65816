# Upstream Ghidra support request: bank-wrapped instruction fetch

This file is a copy-ready issue draft for the Ghidra repository. It is not an upstream issue: the connected GitHub integration was not permitted to create issues in `NationalSecurityAgency/ghidra`.

## Suggested title

Support bank-wrapped instruction-byte fetch and instruction extent for banked program counters

## Problem

The WDC 65816 fetches each instruction byte using a 16-bit PC within the current program bank (PBR). If an instruction crosses offset `$FFFF`, subsequent bytes come from the same bank at `$0000`, and sequential PC flow wraps without incrementing PBR.

The Ghidra 12.1.4 SLEIGH model currently encodes PBR:PC as a flat 24-bit address. As a result, standard disassembly reads sequentially into the next linear bank. This cannot be fixed just by masking `inst_next`, branch targets, or PC p-code: the instruction parser has already consumed the wrong bytes and selected an instruction length before semantics run.

## Reproduction

A headless regression in [kaayzouee/ghidra-65816 PR #29](https://github.com/kaayzouee/ghidra-65816/pull/29) covers three boundary cases. The test code is in [G65816BankBoundaryCheck.java](https://github.com/kaayzouee/ghidra-65816/blob/work/scope-limitations-roadmap/tests/G65816BankBoundaryCheck.java); it is run by [test-bank-boundary.py](https://github.com/kaayzouee/ghidra-65816/blob/work/scope-limitations-roadmap/scripts/ci/test-bank-boundary.py).

1. A three-byte `LDA absolute` at `$00:FFFE`: byte three should be read from `$00:0000`, not `$01:0000`.
2. A two-byte `LDA immediate` at `$02:FFFF`: byte two should be read from `$02:0000`, not `$03:0000`.
3. A one-byte `NOP` at `$04:FFFF`: fall-through should be `$04:0000`, not `$05:0000`.

The regression passes in normal CI when the output matches either the hardware-correct behavior or the known current limitation; it has a strict `GHIDRA_BANK_WRAP_REQUIRED=1` mode that only accepts hardware-correct output.

## Code-path evidence

In the pinned Ghidra 12.1.4 source:

- `Disassembler.disassembleInstructionBlock` makes a `WrappedMemBuffer` for the candidate instruction and passes it to the language parser.
- `WrappedMemBuffer` documents that it does not wrap when the end of the memory space is encountered; its underlying buffer fetches linearly.
- `MemoryBufferImpl.getByte()` and `getBytes()` use non-wrapping address addition for bytes outside their current cache.
- `SleighParserContext` obtains operand bytes through the supplied buffer and computes `nextInstrAddr` by adding the parsed instruction length to the current address.
- `CodeUnitDB.getMaxAddress()` derives a code unit's maximum address by adding `length - 1` to its start; the listing model assumes a contiguous ordered range, so a custom fetch buffer alone would still overlap bytes belonging to the following bank.

See the version-pinned Ghidra sources: [Disassembler.java](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.4_build/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/disassemble/Disassembler.java), [WrappedMemBuffer.java](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.4_build/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/mem/WrappedMemBuffer.java), [MemoryBufferImpl.java](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.4_build/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/mem/MemoryBufferImpl.java), and [SleighParserContext.java](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.4_build/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/app/plugin/processors/sleigh/SleighParserContext.java), and [CodeUnitDB.java](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.4_build/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/database/code/CodeUnitDB.java).

## Requested capability

Could Ghidra provide a supported processor-language extension point for bank-aware instruction fetch and wrapped instruction extent/flow? At minimum it would need to support:

- Fetching byte `n` for a decoded instruction from `(PBR, (PC + n) & 0xffff)`.
- Keeping different physical banks distinct at stable analysis addresses.
- Representing an instruction whose logical bytes wrap to a lower offset without reserving the corresponding linear address in the next bank.
- Computing sequential flow with 16-bit PC wrap and unchanged PBR, while keeping listing, cross-references, re-disassembly, and decompiler behavior coherent.

A language-level instruction-buffer factory may solve byte selection, but the listing/instruction model also needs to represent the instruction extent correctly when its bytes are not a contiguous range in the physical address map. Is there an existing supported extension point or preferred architecture for this?

## Related but distinct work

[Discussion #9349, “Context-aware address resolution for banked memory (extending overlays)”](https://github.com/NationalSecurityAgency/ghidra/discussions/9349) proposes making *operand/reference target resolution* depend on processor context. That is related to banked processors, but P0 is earlier in the pipeline: instruction bytes must be correct before constructor selection and instruction-length determination. The two capabilities are complementary, not interchangeable.
