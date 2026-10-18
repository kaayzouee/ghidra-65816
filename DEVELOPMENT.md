# Development checks

The repository's GitHub Actions workflow validates the language definitions with a pinned
public Ghidra release and repeats a clean SLEIGH compilation to detect nondeterministic output.

## Run the checks locally

Run the standard-library Python regression tests:

\`\`\`sh
python3 -m unittest discover --start-directory tests --verbose
\`\`\`

Download and extract the same official Ghidra release used by CI (Ghidra 12.1.4), then pass
the extracted installation directory to the compiler helper:

\`\`\`sh
bash scripts/ci/compile-sleigh.sh /path/to/ghidra_12.1.4_PUBLIC
\`\`\`

The helper compiles a temporary copy of \`data/languages\` using Ghidra's own
\`ghidra.pcodeCPort.slgh_compile.SleighCompile\` class. It compiles twice from clean generated
outputs, checks that \`65816.sla\` was produced, and compares output hashes. It does not put
generated \`.sla\` files into the working tree.

## Keeping the CI compiler version current

The workflow pins the official archive URL and SHA-256 digest rather than following a floating
download. When upgrading the Ghidra release, update \`GHIDRA_VERSION\`, \`GHIDRA_RELEASE_DATE\`,
and \`GHIDRA_SHA256\` together using metadata from the official
[Ghidra releases](https://github.com/NationalSecurityAgency/ghidra/releases). Check the
release's required Java version before changing the workflow's JDK.

The Python tests are source-level regression tests for known semantic mistakes and XML metadata;
they do not replace execution tests in Ghidra's emulator. A clean SLEIGH compile verifies syntax
and constructor consistency, not full CPU correctness.
