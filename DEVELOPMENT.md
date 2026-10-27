# Development

## Checks

Run the source-level regression tests:

```sh
python3 -m unittest discover --start-directory tests --verbose
```

Compile SLEIGH with the Ghidra version pinned in CI (currently 12.1.4):

```sh
bash scripts/ci/compile-sleigh.sh /path/to/ghidra_12.1.4_PUBLIC
```

The script compiles a temporary copy twice and checks that the output matches. It does not prove CPU correctness.

## Runtime P-code tests

Use Java 21, Gradle 8.5, and Ghidra 12.1.4:

```sh
export GHIDRA_INSTALL_DIR=/path/to/ghidra_12.1.4_PUBLIC
export GHIDRA_EXTERNAL_MODULES="$PWD/build/harness-modules/ghidra-65816"
mkdir -p "$GHIDRA_EXTERNAL_MODULES"
cp Module.manifest "$GHIDRA_EXTERNAL_MODULES/Module.manifest"
bash scripts/ci/compile-sleigh.sh "$GHIDRA_INSTALL_DIR" "$GHIDRA_EXTERNAL_MODULES/data/languages"
gradle test
```

Runtime regressions cover arithmetic and flags, status stack behavior, P-code stack operations, near/far control flow, selected bank-boundary cases, and `WAI`/`STP`. CI also runs headless disassembly checks and a deterministic 120-case subset of [SingleStepTests/65816](https://github.com/SingleStepTests/65816).

The optional `.github/workflows/singlestep-full.yml` workflow runs 25,600 cases. It is not access-controlled by YAML alone: configure GitHub Actions workflow execution protection under **Settings → Actions → Policies** for this workflow, allowing only `workflow_dispatch` and maintainers/admins.

## Before changing CPU semantics

1. Add a focused regression that fails before the fix.
2. Compile SLEIGH and run the relevant tests.
3. Cross-check surprising behavior against the [W65C816S datasheet](https://www.westerndesigncenter.com/wdc/documentation/w65c816s.pdf) and an independent implementation such as [MAME](https://github.com/mamedev/mame/tree/master/src/devices/cpu/g65816).

A passing test suite is evidence, not proof of complete hardware behavior. Immediate operands are constants; `WAI` is modelled as fall-through and `STP` as a self-loop.

## Updating the Ghidra version

Update `GHIDRA_VERSION`, `GHIDRA_RELEASE_DATE`, and `GHIDRA_SHA256` together in `.github/workflows/sleigh.yml`, using the [official releases](https://github.com/NationalSecurityAgency/ghidra/releases) page.
