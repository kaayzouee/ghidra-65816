# Development

## Run checks

| Check | What it covers |
| --- | --- |
| Python tests | Known source-level regressions and XML metadata |
| SLEIGH compile | Syntax and constructor consistency with Ghidra 12.1.4 |
| Repeat compile | Same inputs produce identical `.sla` files |
| P-code tests | Selected instructions execute in Ghidra's emulator |

## Runtime tests

CI builds a temporary external processor module and runs these tests with Ghidra's
`PcodeEmulator`.

| Instructions | Cases |
| --- | --- |
| `XBA` | Byte exchange; negative and zero flags |
| `CMP abs` | Carry on unsigned less-than and equality |
| `CPY abs` | 8-bit and 16-bit index-width behavior |
| `XCE` | Native-to-native preservation; native/emulation transitions |

## Run locally

Use Java 21, Gradle 8.5, and an extracted Ghidra 12.1.4 distribution.

```sh
export GHIDRA_INSTALL_DIR=/path/to/ghidra_12.1.4_PUBLIC
export GHIDRA_EXTERNAL_MODULES="$PWD/build/harness-modules/ghidra-65816"
mkdir -p "$GHIDRA_EXTERNAL_MODULES"
cp Module.manifest "$GHIDRA_EXTERNAL_MODULES/Module.manifest"
bash scripts/ci/compile-sleigh.sh "$GHIDRA_INSTALL_DIR" "$GHIDRA_EXTERNAL_MODULES/data/languages"
gradle test
```

The compiler helper also accepts only `GHIDRA_INSTALL_DIR`; in that form it compiles in a
temporary directory and checks reproducible output without setting up runtime tests.

A passing SLEIGH compile proves the language compiles, not that the whole CPU is emulated
correctly. Add small instruction tests and compare disputed behavior with trusted reference vectors.
