# SingleStepTests fixture

`3d.e.json` is the compact state/memory sample named `3d e 1` published in the README of [SingleStepTests/65816](https://github.com/SingleStepTests/65816). It is retained as a small CI smoke sample; it is not representative of the full corpus. The full upstream corpus contains large per-opcode files and must not be downloaded during every regular PR run.

The upstream project is licensed under MIT. See [LICENSE](LICENSE) and the [upstream README](https://github.com/SingleStepTests/65816#readme). The adapter intentionally compares processor registers and reported RAM state; it does not claim cycle-level bus validation.
