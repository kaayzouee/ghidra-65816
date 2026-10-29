# Ghidra feature request: bank-wrapped instruction fetch

This is a draft for an upstream feature request. It has not been filed.

## Problem

The WDC 65816 uses a 16-bit program counter within the current program bank. When an instruction crosses offset `$FFFF`, the following instruction bytes and sequential PC wrap to offset `$0000` in the same bank.

In Ghidra 12.1.4, the 65816 language maps the bank and PC to a flat 24-bit address. Disassembly can therefore read bytes from the next linear bank and set fall-through to that bank. Masking the PC in SLEIGH semantics is too late because the parser has already read the instruction bytes.

## Reproduction

The headless regression in [ghidra-65816 PR #29](https://github.com/kaayzouee/ghidra-65816/pull/29) tests:

- A three-byte `LDA absolute` at `$00:FFFE`: the last byte should come from `$00:0000`.
- A two-byte `LDA immediate` at `$02:FFFF`: the operand should come from `$02:0000`.
- A one-byte `NOP` at `$04:FFFF`: fall-through should be `$04:0000`.

The current disassembly reads linearly into the next bank instead. The test and its runner are in [G65816BankBoundaryCheck.java](https://github.com/kaayzouee/ghidra-65816/blob/work/scope-limitations-roadmap/tests/G65816BankBoundaryCheck.java) and [test-bank-boundary.py](https://github.com/kaayzouee/ghidra-65816/blob/work/scope-limitations-roadmap/scripts/ci/test-bank-boundary.py).

## Request

Is there an existing supported way for a processor language to define bank-aware instruction fetch and wrapped instruction flow? If not, could Ghidra provide one?

A solution needs to:
- Read instruction byte `n` from `(PBR, (PC + n) & 0xffff)`.
- Represent an instruction that wraps within a bank without occupying the next bank's address range.
- Set sequential flow to the wrapped PC while keeping banks at distinct analysis addresses.

A test-only `MemBuffer` passed to the public `Language.parse` API can supply wrapped bytes, but normal disassembly does not use that buffer and the parser's next address remains linear. The test documents this limitation.

Guidance on the appropriate extension point or design would help before implementation begins.
