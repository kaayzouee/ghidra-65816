# Program-bank instruction fetch: design findings

**Updated:** 2026-10-29 · Investigation for P0 in [the scope work roadmap](pr28-scope-work-roadmap.md).

## Finding

This limitation is at the instruction-byte acquisition layer. It is not just a bad branch-target calculation.

For Ghidra 12.1.4, the relevant implementation paths are:

- [`MemoryBufferImpl.java`](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.4_build/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/mem/MemoryBufferImpl.java): both `getByte(offset)` and `getBytes(..., offset)` advance from the instruction address with `startAddr.addNoWrap(offset)`.
- [`SleighParserContext.java`](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.4_build/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/app/plugin/processors/sleigh/SleighParserContext.java): instruction fields are read from that memory buffer; `nextInstrAddr` is derived by adding the parsed instruction length to the current instruction address.
- [`SleighInstructionPrototype.java`](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.4_build/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/app/plugin/processors/sleigh/SleighInstructionPrototype.java): the SLEIGH parser first identifies the instruction and its length; operand/p-code address calculation happens after that parse.
- [`CodeUnitDB.java`](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.4_build/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/database/code/CodeUnitDB.java): an instruction's `getMaxAddress()` is calculated as `address.add(length - 1)`, and code-unit containment assumes the instruction is a contiguous ordered address range. A wrapping byte buffer alone would therefore still leave the instruction range overlapping the next bank in a flat address map.

The present 3-byte default space therefore lets a byte at `$00:FFFF` be followed by linear `$01:0000`. Making the default space 2 bytes would not, by itself, solve this: `addNoWrap` would hit the address-space limit rather than remap that next byte to `$00:0000`. In addition, a flat 16-bit program space cannot distinguish the same PC offset in different PBR banks without a separate address-space/overlay mapping strategy.

## Approaches evaluated

| Approach | Result |
| --- | --- |
| Mask `inst_next`, branch targets, or PC updates in SLEIGH | Insufficient. These expressions can correct semantic targets, but they cannot change which bytes the parser consumed to decide an instruction's encoding and length. |
| Change only the default bus space from 3-byte to 2-byte addressing | Insufficient and potentially regressive. It loses the flat unique address for PBR:PC, and Ghidra's standard memory buffer does not wrap `addNoWrap` at a program-bank boundary. |
| Add 256 ordinary overlays | Not sufficient alone. Overlay address translation does not override the byte-buffer's address stepping or provide bank-aware instruction-byte reads. The upstream discussion on [context-aware banked-memory resolution](https://github.com/NationalSecurityAgency/ghidra/discussions/9349) describes related limitations of static overlay resolution; instruction-byte wrapping is an additional requirement. |
| Use Ghidra's `SegmentedAddressSpace` as a 16-bit segment:offset PC | Not sufficient as-is. In Ghidra 12.1.4, [`SegmentedAddressSpace.add()`](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.4_build/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/address/SegmentedAddressSpace.java) advances a flat encoded offset and attempts to preserve the segment; it can fall back to a default segment when the offset no longer fits. It does not implement the 65816 rule “wrap the 16-bit PC and preserve PBR,” and the standard memory buffer still needs a bank-aware byte source. |
| Use a padded virtual code space with duplicate bank-start bytes | Theoretically possible without changing Ghidra core: allocate a wider code space with a per-bank stride larger than 64 KiB, copy each bank's first maximum-instruction-length bytes into a trailer, and keep data memory in a separate 24-bit bus space. However, the address encoding would change, a loader/import transformation would be required, PC/PBR and every code target would need conversion between logical and virtual addresses, and sequential flow would need to be redirected from trailer aliases to canonical bank offsets. It would also affect headless tests, loaders, symbols, and user expectations about addresses. This is a separate, high-risk architecture fork rather than a local fix; no prototype has been claimed or shipped. |
| Add a bank-aware fetch/address layer in Ghidra or a supported processor integration point | The plausible full solution. It must supply each instruction byte from `(PBR, (PC + byteOffset) & 0xffff)`, and compute the next code location with the same bank-local wrap while still giving each physical bank a distinct, stable analysis address. This needs an API/core design and end-to-end proof, not just a SLEIGH expression. |

Ghidra's [SLEIGH address-space documentation](https://ghidra.re/ghidra_docs/languages/html/sleigh_definitions.html) defines address spaces by their address width, but does not describe a per-instruction bank-wrapped memory-buffer mode. A p-code macro runs after parsing and cannot supply that missing behavior.

## Existing behavior and regression

The headless test [`G65816BankBoundaryCheck.java`](../tests/G65816BankBoundaryCheck.java), invoked by [`test-bank-boundary.py`](../scripts/ci/test-bank-boundary.py), now checks one-, two-, and three-byte instructions at `$xx:FFFF` / `$xx:FFFE`, places different bytes at the wrapped same-bank addresses, and records decoded bytes plus fall-through. All three characterization cases passed pinned Ghidra CI run [40629110625](https://github.com/kaayzouee/ghidra-65816/actions/runs/40629110625).

The runner records both the hardware-correct expected output and the known current output. By default, CI succeeds only when the observed result matches one of those two states: it prints either `PASS` for hardware conformance or `KNOWN LIMITATION` with the observed-vs-expected bytes and fall-through. Setting `GHIDRA_BANK_WRAP_REQUIRED=1` turns the current limitation into a hard failure, so the same fixture can be run as a strict conformance gate when validating a proposed fix.

## Upstream path

Ghidra [Discussion #9349](https://github.com/NationalSecurityAgency/ghidra/discussions/9349) addresses context-aware resolution of *operand/reference targets* for banked memory. It does not provide instruction-byte wrapping or a discontiguous instruction extent, so it is relevant but not sufficient for P0. A separate upstream request has been prepared in [ghidra-bank-fetch-support-request.md](ghidra-bank-fetch-support-request.md). The repository connection could not create a new issue in `NationalSecurityAgency/ghidra` due to an HTTP 403 permission denial; no upstream issue is being claimed as filed.

The validation workflow now exposes a manual `require_bank_wrap` input. Run **Actions → SLEIGH validation → Run workflow** with that input checked to require hardware-correct output; the current implementation is expected to fail this strict gate until P0 is actually fixed. Normal push/PR CI remains diagnostic and passes only for either the known current behavior or the correct hardware behavior.

## Parser-only prototype

A headless probe passes a test-only `MemBuffer` to `Language.parse` that wraps byte offsets within the instruction's starting bank. The expanded regression covers a three-byte `LDA absolute` at `$00:FFFE` (third byte from `$00:0000`), a two-byte `LDA immediate` at `$02:FFFF` (operand `$42` from `$02:0000` rather than the linear byte at `$03:0000`), and a one-byte `NOP` at `$04:FFFF` (next byte sampled at `$04:0000`). It also checks little-endian 16-bit reads across those boundaries (`$5634`, `$42A9`, and `$18EA`). These tests validate byte selection with a caller-supplied buffer, not the normal disassembler. The initial parser prototype passed [CI run 40804944764](https://github.com/kaayzouee/ghidra-65816/actions/runs/40804944764); the expanded regression passed the full pinned workflow in [CI run 40806375370](https://github.com/kaayzouee/ghidra-65816/actions/runs/40806375370). The standard buffer, instruction extent, and fall-through behavior still require a supported integration point.

## Custom disassembler extension check

Ghidra 12.1.4's public [Disassembler API](https://ghidra.re/ghidra_docs/api/ghidra/program/disassemble/Disassembler.html) has protected constructors plus overridable `parseInstructionPrototype` and `processInstruction` hooks. A separate Java extension could explore a bank-aware parser buffer for a custom disassembly command, but the normal language/disassembler factory does not make this a processor-spec-only override. More importantly, changing the parse buffer would still leave `CodeUnitDB` requiring each instruction to occupy a contiguous address range; custom flow handling alone cannot make the wrapped bytes coexist with the next bank's canonical address. This is a possible experiment for a separate extension, not a safe standalone fix to this processor module.

## Decision

Do not change `658xx.sinc`, the default address space, or the PC register layout in isolation. The correct next step for a complete fix is to prototype or request a supported Ghidra-level bank-aware instruction-fetch/address mechanism, then validate instruction decoding at both `$xx:FFFE` and `$xx:FFFF` for one-, two-, and three-byte instructions. Keep the current model until that mechanism is available; partial masking would make some branch flows appear correct while leaving decoded operands incorrect.
