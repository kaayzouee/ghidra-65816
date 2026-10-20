# Development

## Run tests

Run the source-level regression tests:

```sh
python3 -m unittest discover --start-directory tests --verbose
```

Compile the processor definition with the same Ghidra release used by CI (currently Ghidra
12.1.4):

```sh
bash scripts/ci/compile-sleigh.sh /path/to/ghidra_12.1.4_PUBLIC
```

The script compiles a temporary copy of `data/languages` twice and checks that the generated
`65816.sla` files match. It does not add generated files to the repository.

## What the checks mean

| Check | Confirms | Does not confirm |
| --- | --- | --- |
| Python tests | Selected source patterns and XML metadata stay as expected | Full instruction correctness |
| SLEIGH compile | The language compiles with the pinned Ghidra version | Runtime CPU behaviour |
| Repeat compile | Identical inputs produce identical output | Correctness of the output |
| P-code emulator tests | Selected instructions produce expected register, flag, stack, and vector results | Complete processor correctness |

## Runtime P-code tests

CI also compiles the language into a temporary external Ghidra module and runs JUnit tests against
Ghidra's `PcodeEmulator`. The current suite executes twenty-four instruction sequences:

| Instruction | Cases |
| --- | --- |
| `XBA` | Byte exchange; negative and zero flags |
| `CMP abs` | Unsigned carry for less-than and equality |
| `ADC` / `SBC` | Decimal-mode BCD results, carry/borrow, zero, negative, and overflow flags |
| `CPY abs` | Correct comparison width in 8-bit and 16-bit index modes |
| `XCE` | Native-to-native index preservation and native/emulation transitions |
| `PHP` / `PLP` | Emulation-mode status image bits, live flag restore, and ignored B bit |
| `RTI` | Emulation-mode status/PC restoration and stack pointer movement |
| `BRK` / `COP` | Emulation-mode status push ordering, program-bank clearing, and vector transfer |
| `MVN` / `MVP` | Block-copy direction, count, bank selection, and index-width behavior |

Use Java 21 and Gradle 8.5 for the runtime tests. With the official Ghidra 12.1.4 distribution
already extracted, run:

```sh
export GHIDRA_INSTALL_DIR=/path/to/ghidra_12.1.4_PUBLIC
export GHIDRA_EXTERNAL_MODULES="$PWD/build/harness-modules/ghidra-65816"
mkdir -p "$GHIDRA_EXTERNAL_MODULES"
cp Module.manifest "$GHIDRA_EXTERNAL_MODULES/Module.manifest"
bash scripts/ci/compile-sleigh.sh "$GHIDRA_INSTALL_DIR" "$GHIDRA_EXTERNAL_MODULES/data/languages"
gradle test
```

The compiler helper also accepts only the Ghidra installation path; in that mode, it compiles a
temporary copy and verifies reproducibility without setting up the runtime test module.

## Update the Ghidra version

The CI workflow pins the official Ghidra download and its SHA-256 hash. To update it, change
`GHIDRA_VERSION`, `GHIDRA_RELEASE_DATE`, and `GHIDRA_SHA256` together in
`.github/workflows/sleigh.yml`. Use the official
[Ghidra releases](https://github.com/NationalSecurityAgency/ghidra/releases) page and check
which Java version the release requires.

## Before changing CPU semantics

1. Check the 65816 reference documentation.
2. Add a focused regression test.
3. Compile the language and run the tests.
4. For behaviour that depends on runtime state, validate against trusted test vectors or an
   independent emulator before claiming it is correct.

Keep changes small. A passing build is necessary, but it is not proof of correct emulation. Also,
immediate operands are modelled through references to instruction bytes, which can limit constant
propagation in analysis.


## SingleStepTests adapter

The runtime suite contains the compact `3d e 1` state/memory fixture published in the [SingleStepTests/65816 README](https://github.com/SingleStepTests/65816#sample-test). `PcodeEmulatorRegressionTest` loads the fixture's initial RAM and CPU state, executes one instruction, then compares architecturally relevant final registers, flags, and listed memory bytes. This is a smoke test of the adapter, not full corpus coverage or bus-cycle validation. The fixture attribution and upstream MIT licence are included in `src/test/resources/singlestep/README.md` and `src/test/resources/singlestep/LICENCE`. Keep PR CI bounded; broader upstream corpus runs should be an opt-in or scheduled job.
