# SingleStepTests fixture

`3d.e.json` is the small state/memory sample from [SingleStepTests/65816](https://github.com/SingleStepTests/65816#sample-test). It is a CI smoke test, not full-corpus coverage. See [LICENCE](LICENCE) for the upstream MIT licence.

CI also fetches a pinned 120-case subset from commit `307c63f5673c8c6b861c52f71ddb89212a227480`: 10 cases each for opcodes `69`, `a9`, `48`, `68`, `8d`, and `b7`, in emulation and native modes.

The adapter compares selected final registers, flags, and RAM. It does not validate cycle timing or bus behavior.
