# Ghidra feature request: 65816 bank-wrapped instruction fetch

The 65816 wraps instruction fetch and sequential flow at offset `$FFFF` within the current program bank. Ghidra 12.1.4 reads linearly into the next bank instead.

A source check of Ghidra 12.2 shows the relevant buffer, parser, and disassembler code is unchanged. Runtime testing against 12.2 has not been done.

The regression cases in [PR #29](https://github.com/kaayzouee/ghidra-65816/pull/29) cover 1-, 2-, and 3-byte instructions at the bank boundary.

Does Ghidra provide a supported way to implement bank-aware instruction fetch, instruction extent, and wrapped sequential flow? If not, what extension point would be appropriate?
