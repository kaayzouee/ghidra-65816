**Is your feature request related to a problem? Please describe.**
The 65816 wraps instruction fetch and sequential flow at offset `$FFFF` within the current program bank. Ghidra 12.1.4 reads linearly into the next bank.

**Describe the solution you'd like**
A supported way to implement bank-aware instruction fetch, instruction extent, and wrapped sequential flow.

**Describe alternatives you've considered**
If no direct support exists, guidance on the appropriate extension point.

**Additional context**
A source check shows the relevant code is unchanged in Ghidra 12.2; runtime testing has not been done. [PR #29](https://github.com/kaayzouee/ghidra-65816/pull/29) contains 1-, 2-, and 3-byte boundary regression cases.