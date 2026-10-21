# SingleStepTests fixture

`3d.e.json` is the compact state/memory sample named `3d e 1` published in the README of [SingleStepTests/65816](https://github.com/SingleStepTests/65816#sample-test). It is retained as a small CI smoke sample; it is not representative of the full corpus. The upstream project uses the MIT License. See [LICENCE](LICENCE) and the [upstream README](https://github.com/SingleStepTests/65816#readme).

The adapter compares processor registers and reported RAM state; it does not claim cycle-level bus validation.

The adapter also runs three **locally authored supplemental fixtures**:
- `local-lda-immediate-emulation.json`: immediate load in emulation mode.
- `local-cmp-immediate-native.json`: 16-bit immediate compare in native mode.
- `local-xba-native.json`: accumulator byte exchange in native mode.

These fixtures exercise adapter setup, mode selection, status mapping, PC advancement, and named failure messages. They are not upstream SingleStepTests vectors and do not count as independent hardware-oracle coverage.
