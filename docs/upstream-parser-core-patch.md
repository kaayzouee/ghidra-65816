# Proposed upstream patch: opt-in instruction-address mapping

**Status:** proof-of-concept API patch, **not** a fix for full 65816 bank-boundary disassembly.
**Target:** NationalSecurityAgency/ghidra `Ghidra_12.1.4_build` (the version pinned in this repository).

The source patch is [0001-banked-instruction-parser-address-mapping.patch](../patches/ghidra-12.1.4/0001-banked-instruction-parser-address-mapping.patch).

## Confirmed upstream source paths

- `MemoryBufferImpl.getByte/getBytes` uses `startAddr.addNoWrap(offset)`: it cannot fetch an instruction operand from the original bank after the 16-bit PC wraps.
- `SleighParserContext` currently calculates `inst_next` by adding the parsed length to the start address; supplying a custom wrapped `MemBuffer` fixes byte reads but not `inst_next`.
- `SleighInstructionPrototype.getFallThrough` computes a linear address from the instruction context.
- `Disassembler.parseInstructionPrototype` receives a normal `WrappedMemBuffer` built from a standard memory buffer; it does **not** automatically use the new buffer class in this proposal.
- `Disassembler.processInstruction` advances with `block.getMaxAddress().next()`. The `CodeUnitDB` implementation uses a contiguous range `address .. address + length - 1`, and its byte access also assumes linear backing. That model cannot store an instruction with bytes at `$00:FFFE`, `$00:FFFF`, `$00:0000` while leaving `$01:0000` independently available.

These observations are grounded in the tagged Ghidra Java sources, not speculative SLEIGH behavior.

## What this patch changes

1. Adds `InstructionAddressMapper`, an opt-in `MemBuffer` contract exposing the physical byte address for an instruction-relative offset.
2. Adds `BankedInstructionMemBuffer`, a generic implementation with a configurable bank-local PC width (16 for 65816). Reads follow `(start & ~mask) | ((start + offset) & mask)`.
3. Updates `SleighParserContext` so `inst_next` respects the mapping when a caller supplies this buffer; ordinary buffer behavior is unchanged.
4. Updates `SleighInstructionPrototype.getFallThrough` to consult the same mapping for an opt-in instruction context; the existing `addNoWrap` path remains for other buffers.

**Explicit non-goals:** this patch does not enable the mapper in the normal Ghidra disassembler, alter `MemoryBufferImpl` globally, extend the database to store non-contiguous instruction bytes, modify the normal `InstructionDB`, or satisfy `GHIDRA_BANK_WRAP_REQUIRED=1`. The existing parser prototype in `G65816BankBoundaryCheck.java` remains valuable validation of this approach; it is not full listing integration.

The opt-in design also avoids changing semantics for the other architectures using Ghidra.

## How to test

With the pinned Ghidra release installed:

```sh
bash scripts/ci/check-upstream-core-patch.sh "$GHIDRA_INSTALL_DIR"
```

The script fetches **only two tagged upstream source files** (it does not clone or rebuild Ghidra), verifies that the patch applies cleanly, compiles both modified Java sources and both added Java sources against the pinned Ghidra libraries, and runs a Java smoke test covering wrapped 1/2/3-byte fetches, little-endian word and BigInteger reads, incorrect next-bank decoy bytes, partial reads, and PC-width validation. The normal repository CI also runs this test.

To apply the patch to a separate local checkout of the exact upstream tag:

```sh
cd /path/to/ghidra-source
git checkout Ghidra_12.1.4_build
git apply --check /path/to/ghidra-65816/patches/ghidra-12.1.4/0001-banked-instruction-parser-address-mapping.patch
git apply /path/to/ghidra-65816/patches/ghidra-12.1.4/0001-banked-instruction-parser-address-mapping.patch
```

Do not copy just the patched classes into a production Ghidra installation: the design is still experimental and depends on a Ghidra build integrating all associated core changes.

## What is still needed for a complete fix

An upstream-quality design must satisfy **all** of these before we can claim bank-boundary correctness:

1. A processor-selected instruction-byte address mapper in the normal disassembler, including its instruction cache and `WrappedMemBuffer` interaction.
2. Correct `inst_next`, `inst_next2`, delay slots, computed/explicit targets, and disassembler block progression. This proposal covers only the basic parser-next and prototype fall-through pathways when the caller opts in.
3. **An instruction-storage and listing representation** for discontinuous instruction-byte addresses, including overlap detection, byte lookup, instruction extents, program database persistence, reference ownership, re-disassembly, and independent instructions in adjacent banks. The current `CodeUnitDB` contiguous range is the blocking issue.
4. Runtime tests in a rebuilt Ghidra that pass the strict `GHIDRA_BANK_WRAP_REQUIRED=1` gate while correctly decoding an independent instruction at `$01:0000`.

Until the third requirement is designed, making normal disassembly use the wrapped parser would introduce an inconsistency between decoded operands and recorded code-unit bytes. **Do not enable it in normal disassembly yet.** The safe user-script fix from [PR #32](https://github.com/kaayzouee/ghidra-65816/pull/32) remains available for instructions that *end* at a bank boundary without crossing it.

Related: [upstream feature request #10060](https://github.com/NationalSecurityAgency/ghidra/issues/10060), [original design investigation](program-bank-boundary-design.md).
