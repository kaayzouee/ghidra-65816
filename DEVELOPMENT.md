# Development

## Checks

Run the source-level regression tests:

```sh
python3 -m unittest discover --start-directory tests --verbose
```

Compile SLEIGH with any Ghidra release covered by CI (12.1, 12.1.2, 12.1.3, 12.1.4, or 12.2):

```sh
bash scripts/ci/compile-sleigh.sh /path/to/ghidra_12.1.4_PUBLIC
```

The script compiles a temporary copy twice and checks that the output matches. It does not prove CPU correctness.

## Packaged SNES loader check

Run `gradle buildExtension` with `GHIDRA_INSTALL_DIR` pointing to the target release.
Extract the resulting ZIP into that installation's `Ghidra/Extensions` directory
in a clean test installation with no other 65816 module. Run
`python scripts/ci/test-snes-loader.py` to exercise automatic format selection,
the imported memory map, reset disassembly, and an explicit Raw Binary import.

## Runtime P-code tests

CI tests Ghidra 12.1, 12.1.2, 12.1.3, and 12.1.4 with Java 21 and Gradle 8.5,
and Ghidra 12.2 with Java 25 and Gradle 9.1.0. There is no published 12.1.1 release.
The optional full SingleStepTests workflow remains pinned to 12.1.4.

For a Ghidra 12.1.4 installation:

```sh
export GHIDRA_INSTALL_DIR=/path/to/ghidra_12.1.4_PUBLIC
export GHIDRA_EXTERNAL_MODULES="$PWD/build/harness-modules/ghidra-65816"
mkdir -p "$GHIDRA_EXTERNAL_MODULES"
cp Module.manifest "$GHIDRA_EXTERNAL_MODULES/Module.manifest"
bash scripts/ci/compile-sleigh.sh "$GHIDRA_INSTALL_DIR" "$GHIDRA_EXTERNAL_MODULES/data/languages"
gradle test
```

Runtime regressions cover arithmetic and flags, status stack behavior, P-code stack operations, near/far control flow, selected bank-boundary cases, and `WAI`/`STP`. CI also runs headless disassembly checks and a deterministic 160-case subset of [SingleStepTests/65816](https://github.com/SingleStepTests/65816).

## Safe bank-local fall-through repair

Ghidra's default linear fall-through is wrong when an instruction ends exactly at
`$xx:FFFF`: its next PC should be `$xx:0000`, preserving the program bank. For
instructions that **fit entirely within the bank** (for example, a one-byte NOP
at `$04:FFFF`, a two-byte instruction at `$06:FFFE`, or a three-byte
instruction at `$08:FFFD`), this can be corrected using the supported
`Instruction.setFallThrough(Address)` API without changing instruction bytes
or code-unit extents.

Run [`scripts/Repair65816BankFallthrough.java`](scripts/Repair65816BankFallthrough.java)
as a Ghidra Java script against an imported 65816 program, preferably after
disassembly has completed. It edits fall-through references in the current
program; save a project backup first. To get a machine-readable report in a
headless invocation, pass one argument (the report output path).

The script only visits instructions in the default address space, skips
instructions whose bytes actually straddle the bank end, respects manual
fall-through overrides and nonstandard flow, and can be run repeatedly. It
does **not** correct parser byte fetch, repair straddling instruction extents,
undo already incorrect disassembly in the next bank, or turn the strict
`GHIDRA_BANK_WRAP_REQUIRED=1` conformance gate green. The headless
bank-boundary regression tests cover safe lengths 1/2/3, the two unsafe
straddling cases, an existing user override, and idempotence.

## Strict program-bank fetch conformance

Normal CI runs `scripts/ci/test-bank-boundary.py` diagnostically: it accepts either the currently reproduced limitation or true hardware-correct behavior, while rejecting unexpected results. To require the real fix, open **Actions → SLEIGH validation → Run workflow**, enable `require_bank_wrap`, and run it. That input sets `GHIDRA_BANK_WRAP_REQUIRED=1`; the workflow must fail until instruction bytes and fall-through match the hardware expectations for the 1-, 2-, and 3-byte boundary cases.

This strict gate is only a test gate, not a workaround. The current SLEIGH module still cannot make Ghidra's standard memory buffer fetch bytes from a wrapped program-bank address or represent a discontinuous instruction extent. See [the design findings](docs/program-bank-boundary-design.md). An upstream feature request has now been filed.

The optional `.github/workflows/singlestep-full.yml` workflow runs 25,600 cases. It is not access-controlled by YAML alone: configure GitHub Actions workflow execution protection under **Settings → Actions → Policies** for this workflow, allowing only `workflow_dispatch` and maintainers/admins.

## Submitting pull requests

1. Start from current `master`; keep a PR to one reviewable issue or feature slice. Avoid bundling unrelated fixes, formatting, or generated files.
2. Use [the PR template](.github/PULL_REQUEST_TEMPLATE.md) unchanged. Fill its existing fields in the **PR description**, including when creating a PR through an API or agent. Keep all headings and validation rows; use `N/A — reason` for irrelevant checks. Do not edit the template file to describe individual PRs.
3. Include the relevant before/after regression or a reason tests do not apply. Identify versions, CPU references, untrusted inputs, and analyst-data preservation where relevant. Prefer supported non-deprecated Ghidra APIs, small methods, and minimal comments.
4. Run focused checks, then review the full CI matrix. Report actual results and links, not assumed success. See the test setup above.
5. Squash into **one commit** before declaring the PR ready, review the final diff, and check CI on the final commit. Merge only with explicit approval.

## Before changing CPU semantics

1. Add a focused regression that fails before the fix.
2. Compile SLEIGH and run the relevant tests.
3. Cross-check surprising behavior against the [W65C816S datasheet](https://www.westerndesigncenter.com/wdc/documentation/w65c816s.pdf) and an independent implementation such as [MAME](https://github.com/mamedev/mame/tree/master/src/devices/cpu/g65816).

A passing test suite is evidence, not proof of complete hardware behavior. Immediate operands are constants; `WAI` is modelled as fall-through and `STP` as a self-loop.

## Updating the Ghidra versions

Add or update the version, release date, SHA-256, Java version, and Gradle version
together in the matrix in `.github/workflows/sleigh.yml`, using the
[official Ghidra releases](https://github.com/NationalSecurityAgency/ghidra/releases).
Run the full SingleStepTests workflow separately when changing its pinned version.
