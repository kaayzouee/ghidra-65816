# SingleStepTests fixture

`3d.e.json` is the small state/memory sample from [SingleStepTests/65816](https://github.com/SingleStepTests/65816#sample-test). It is a CI smoke test, not full-corpus coverage. See [LICENCE](LICENCE) for the upstream MIT licence.

CI also fetches a pinned 120-case subset from commit `307c63f5673c8c6b861c52f71ddb89212a227480`: 10 cases each for opcodes `69`, `a9`, `48`, `68`, `8d`, and `b7`, in emulation and native modes.

The adapter compares processor registers and reported RAM state; it does not claim cycle-level bus validation.

The adapter also runs three **locally authored supplemental fixtures**:
- `local-lda-immediate-emulation.json`: immediate load in emulation mode.
- `local-cmp-immediate-native.json`: 16-bit immediate compare in native mode.
- `local-xba-native.json`: accumulator byte exchange in native mode.

These fixtures exercise adapter setup, mode selection, status mapping, PC advancement, and named failure messages. They are not upstream SingleStepTests vectors and do not count as independent hardware-oracle coverage.
