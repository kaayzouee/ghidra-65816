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

## Proposed upstream Ghidra parser patch (experimental)

A version-specific proof-of-concept source patch for Ghidra 12.1.4 lives under
[`patches/ghidra-12.1.4/`](patches/ghidra-12.1.4/). It introduces an opt-in
bank-aware parser buffer and address mapper, **but does not fix normal
disassembly or discontinuous code-unit storage**. See
[`docs/upstream-parser-core-patch.md`](docs/upstream-parser-core-patch.md)
for scope, limitations, and the independent instruction-extents requirement.

To verify the patch against the pinned tagged Ghidra sources and installed
binary APIs, run:

```sh
bash scripts/ci/check-upstream-core-patch.sh "$GHIDRA_INSTALL_DIR"
```

This verifies patch application, Java compilation, and a standalone buffer
smoke test. It does not claim strict bank-boundary disassembly conformance.

## Strict program-bank fetch conformance

Normal CI runs `scripts/ci/test-bank-boundary.py` diagnostically: it accepts either the currently reproduced limitation or true hardware-correct behavior, while rejecting unexpected results. To require the real fix, open **Actions → SLEIGH validation → Run workflow**, enable `require_bank_wrap`, and run it. That input sets `GHIDRA_BANK_WRAP_REQUIRED=1`; the workflow must fail until instruction bytes and fall-through match the hardware expectations for the 1-, 2-, and 3-byte boundary cases.

This strict gate is only a test gate, not a workaround. The current SLEIGH module still cannot make Ghidra's standard memory buffer fetch bytes from a wrapped program-bank address or represent a discontinuous instruction extent. See [the design findings](docs/program-bank-boundary-design.md). An upstream feature request has now been filed.

The optional `.github/workflows/singlestep-full.yml` workflow runs 25,600 cases. It is not access-controlled by YAML alone: configure GitHub Actions workflow execution protection under **Settings → Actions → Policies** for this workflow, allowing only `workflow_dispatch` and maintainers/admins.

## Before changing CPU semantics

1. Add a focused regression that fails before the fix.
2. Compile SLEIGH and run the relevant tests.
3. Cross-check surprising behavior against the [W65C816S datasheet](https://www.westerndesigncenter.com/wdc/documentation/w65c816s.pdf) and an independent implementation such as [MAME](https://github.com/mamedev/mame/tree/master/src/devices/cpu/g65816).

A passing test suite is evidence, not proof of complete hardware behavior. Immediate operands are constants; `WAI` is modelled as fall-through and `STP` as a self-loop.

## Updating the Ghidra version

Update `GHIDRA_VERSION`, `GHIDRA_RELEASE_DATE`, and `GHIDRA_SHA256` together in `.github/workflows/sleigh.yml`, using the [official releases](https://github.com/NationalSecurityAgency/ghidra/releases) page.
