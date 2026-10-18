#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 /path/to/ghidra-install" >&2
  exit 2
fi

ghidra_home="$(cd "$1" && pwd)"
framework="$ghidra_home/Ghidra/Framework"
for module in SoftwareModeling Generic Utility; do
  if [[ ! -d "$framework/$module/lib" ]]; then
    echo "Missing Ghidra framework libraries: $framework/$module/lib" >&2
    exit 2
  fi
done

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
work_root="$(mktemp -d)"
trap 'rm -rf "$work_root"' EXIT

language_dir="$work_root/languages"
cp -a "$repo_root/data/languages" "$language_dir"
: > "$work_root/sleighArgs.txt"

shopt -s nullglob
jars=()
for module in SoftwareModeling Generic Utility; do
  module_jars=("$framework/$module/lib/"*.jar)
  if [[ ${#module_jars[@]} -eq 0 ]]; then
    echo "No JARs found under $framework/$module/lib" >&2
    exit 2
  fi
  jars+=("${module_jars[@]}")
done
classpath="$(IFS=:; printf '%s' "${jars[*]}")"

compile_language() {
  (
    cd "$work_root"
    java -Xmx2048M -cp "$classpath" \
      ghidra.pcodeCPort.slgh_compile.SleighCompile \
      "-DBaseDir=$ghidra_home/Ghidra/" \
      -i "$work_root/sleighArgs.txt" \
      -a ./languages
  )
}

hash_sla_outputs() {
  (
    cd "$language_dir"
    find . -maxdepth 1 -type f -name '*.sla' -printf '%P\n' |
      LC_ALL=C sort |
      while IFS= read -r file; do
        [[ -n "$file" ]] && sha256sum "$file"
      done
  )
}

echo "First SLEIGH compilation using Ghidra at: $ghidra_home"
rm -f "$language_dir"/*.sla "$language_dir"/*.sla.lock
compile_language
test -s "$language_dir/65816.sla"
hash_sla_outputs > "$work_root/first.sha256"

echo "Second SLEIGH compilation using identical inputs"
rm -f "$language_dir"/*.sla "$language_dir"/*.sla.lock
compile_language
test -s "$language_dir/65816.sla"
hash_sla_outputs > "$work_root/second.sha256"

if ! diff -u "$work_root/first.sha256" "$work_root/second.sha256"; then
  echo "SLEIGH output changed between identical clean builds." >&2
  exit 1
fi

echo "SLEIGH compilation succeeded; generated SLA output is reproducible."
