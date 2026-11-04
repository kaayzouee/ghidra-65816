#!/usr/bin/env bash
# Validate proposed upstream patch against the source tag and Ghidra binary APIs.
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 /path/to/ghidra_12.1.4_PUBLIC" >&2
  exit 2
fi

ghidra_home="$(cd "$1" && pwd)"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
patch="$repo_root/patches/ghidra-12.1.4/0001-banked-instruction-parser-address-mapping.patch"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

src='Ghidra/Framework/SoftwareModeling/src/main/java/ghidra'
tag='Ghidra_12.1.4_build'
for path in \
  "$src/app/plugin/processors/sleigh/SleighParserContext.java" \
  "$src/app/plugin/processors/sleigh/SleighInstructionPrototype.java"; do
  mkdir -p "$work/$(dirname "$path")"
  curl --fail --location --retry 3 --silent --show-error \
    "https://raw.githubusercontent.com/NationalSecurityAgency/ghidra/$tag/$path" \
    --output "$work/$path"
done

(
  cd "$work"
  git apply --check "$patch"
  git apply "$patch"
)
echo 'UPSTREAM PATCH: applies cleanly to Ghidra_12.1.4_build'

classpath="$(find "$ghidra_home" -type f -name '*.jar' -print | LC_ALL=C sort | paste -sd ':' -)"
if [[ -z "$classpath" ]]; then
  echo 'No Ghidra JARs found for compilation' >&2
  exit 2
fi

out="$work/compiled"
mkdir -p "$out"
javac --release 21 -classpath "$classpath" -d "$out" \
  "$work/$src/program/model/mem/InstructionAddressMapper.java" \
  "$work/$src/program/model/mem/BankedInstructionMemBuffer.java" \
  "$work/$src/app/plugin/processors/sleigh/SleighParserContext.java" \
  "$work/$src/app/plugin/processors/sleigh/SleighInstructionPrototype.java" \
  "$repo_root/scripts/ci/BankedInstructionMemBufferSmoke.java"

java -classpath "$out:$classpath" BankedInstructionMemBufferSmoke

echo 'UPSTREAM PATCH: Java compilation and mapped-buffer runtime checks passed'
