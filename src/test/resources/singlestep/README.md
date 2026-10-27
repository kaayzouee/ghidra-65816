# SingleStepTests fixture

`3d.e.json` is the compact state/memory sample named `3d e 1` published in the README of [SingleStepTests/65816](https://github.com/SingleStepTests/65816#sample-test). It is retained as a small CI smoke sample; it is not representative of the full corpus. The upstream project uses the MIT License. See [LICENCE](LICENCE) and the [upstream README](https://github.com/SingleStepTests/65816#readme).

The adapter compares processor registers and reported RAM state; it does not claim cycle-level bus validation.

The CI runtime suite also fetches a bounded subset from upstream commit
`307c63f5673c8c6b861c52f71ddb89212a227480` using
`scripts/ci/fetch-singlestep-subset.py`. It selects the first 10 cases for opcodes `69`, `a9`,
`48`, `68`, `8d`, and `b7`, in both emulation and native modes (120 cases total). The source
corpus is fetched at test time rather than copied into the repository; the subset is deterministic
because the upstream commit and selection are pinned. These cases check state after one instruction,
not cycle-level bus behavior.
