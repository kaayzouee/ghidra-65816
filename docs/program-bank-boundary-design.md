# Program-bank instruction fetch: design findings

**Updated:** 2026-10-28 · Investigation for P0 in [the scope work roadmap](pr28-scope-work-roadmap.md).

## Finding

This limitation is at the instruction-byte acquisition layer. It is not just a bad branch-target calculation.

For Ghidra 12.1.4, the relevant implementation paths are:

- [`MemoryBufferImpl.java`](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.4_build/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/mem/MemoryBufferImpl.java): both `getByte(offset)` and `getBytes(..., offset)` advance from the instruction address with `startAddr.addNoWrap(offset)`.
- [`SleighParserContext.java`](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.4_build/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/app/plugin/processors/sleigh/SleighParserContext.java): instruction fields are read from that memory buffer; `nextInstrAddr` is derived by adding the parsed instruction length to the current instruction address.
- [`SleighInstructionPrototype.java`](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.4_build/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/app/plugin/processors/sleigh/SleighInstructionPrototype.java): the SLEIGH parser first identifies the instruction and its length; operand/p-code address calculation happens after that parse.

The present 3-byte default space therefore lets a byte at `$00:FFFF` be followed by linear `$01:0000`. Making the default space 2 bytes would not, by itself, solve this: `addNoWrap` would hit the address-space limit rather than remap that next byte to `$00:0000`. In addition, a flat 16-bit program space cannot distinguish the same PC offset in different PBR banks without a separate address-space/overlay mapping strategy.

## Approaches evaluated

| Approach | Result |
| --- | --- |
| Mask `inst_next`, branch targets, or PC updates in SLEIGH | Insufficient. These expressions can correct semantic targets, but they cannot change which bytes the parser consumed to decide an instruction's encoding and length. |
| Change only the default bus space from 3-byte to 2-byte addressing | Insufficient and potentially regressive. It loses the flat unique address for PBR:PC, and Ghidra's standard memory buffer does not wrap `addNoWrap` at a program-bank boundary. |
| Add 256 ordinary overlays | Not sufficient alone. Overlay address translation does not override the byte-buffer's address stepping or provide bank-aware instruction-byte reads. The upstream discussion on [context-aware banked-memory resolution](https://github.com/NationalSecurityAgency/ghidra/discussions/9349) describes related limitations of static overlay resolution; instruction-byte wrapping is an additional requirement. |
| Use Ghidra's `SegmentedAddressSpace` as a 16-bit segment:offset PC | Not sufficient as-is. In Ghidra 12.1.4, [`SegmentedAddressSpace.add()`](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.4_build/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/address/SegmentedAddressSpace.java) advances a flat encoded offset and attempts to preserve the segment; it can fall back to a default segment when the offset no longer fits. It does not implement the 65816 rule “wrap the 16-bit PC and preserve PBR,” and the standard memory buffer still needs a bank-aware byte source. |
| Add a bank-aware fetch/address layer in Ghidra or a supported processor integration point | The plausible full solution. It must supply each instruction byte from `(PBR, (PC + byteOffset) & 0xffff)`, and compute the next code location with the same bank-local wrap while still giving each physical bank a distinct, stable analysis address. This needs an API/core design and end-to-end proof, not just a SLEIGH expression. |

Ghidra's [SLEIGH address-space documentation](https://ghidra.re/ghidra_docs/languages/html/sleigh_definitions.html) defines address spaces by their address width, but does not describe a per-instruction bank-wrapped memory-buffer mode. A p-code macro runs after parsing and cannot supply that missing behavior.

## Existing behavior and regression

The headless test [`G65816BankBoundaryCheck.java`](../tests/G65816BankBoundaryCheck.java), invoked by [`test-bank-boundary.py`](../scripts/ci/test-bank-boundary.py), now checks one-, two-, and three-byte instructions at `$xx:FFFF` / `$xx:FFFE`, places different bytes at the wrapped same-bank addresses, and records decoded bytes plus fall-through. All three characterization cases passed pinned Ghidra CI run [40629110625](https://github.com/kaayzouee/ghidra-65816/actions/runs/40629110625).

This is a characterization test, not a passing hardware-conformance test. It protects the current, documented limitation from silently changing; once the fetch model is fixed, replace its expected-current-limitation assertions with hardware-correct expectations.

## Decision

Do not change `658xx.sinc`, the default address space, or the PC register layout in isolation. The correct next step for a complete fix is to prototype or request a supported Ghidra-level bank-aware instruction-fetch/address mechanism, then validate instruction decoding at both `$xx:FFFE` and `$xx:FFFF` for one-, two-, and three-byte instructions. Keep the current model until that mechanism is available; partial masking would make some branch flows appear correct while leaving decoded operands incorrect.
