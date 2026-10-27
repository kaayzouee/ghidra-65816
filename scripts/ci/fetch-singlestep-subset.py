#!/usr/bin/env python3
"""Fetch a small, deterministic SingleStepTests/65816 subset for runtime regression tests.

Only selected opcode/mode files are downloaded. Each source file is reduced in memory to its
first N state-transition cases, with cycle traces omitted. The corpus is pinned to a commit so
CI results do not change when the upstream repository advances.

Usage: fetch-singlestep-subset.py <output.json> [cases-per-opcode-mode]
"""
import json
import pathlib
import sys
import time
import urllib.error
import urllib.request

COMMIT = "307c63f5673c8c6b861c52f71ddb89212a227480"
BASE_URL = (
    "https://raw.githubusercontent.com/SingleStepTests/65816/"
    f"{COMMIT}/v1/{{opcode:02x}}.{{mode}}.json"
)
# Arithmetic/flags, immediate-width decoding, stack transfers, memory writes, and indirect-long
# indexed reads. Avoid STP because the current p-code model intentionally represents it as a halt.
OPCODES = (0x69, 0xA9, 0x48, 0x68, 0x8D, 0xB7)
MODES = ("e", "n")


def fetch_json(url: str) -> list[dict]:
    request = urllib.request.Request(
        url, headers={"User-Agent": "ghidra-65816-singlestep-ci"}
    )
    last_error = None
    for attempt in range(3):
        try:
            with urllib.request.urlopen(request, timeout=45) as response:
                return json.load(response)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            last_error = exc
            if attempt < 2:
                time.sleep(attempt + 1)
    raise RuntimeError(f"failed to fetch valid JSON from {url}: {last_error}")


def main() -> None:
    if len(sys.argv) not in (2, 3):
        raise SystemExit(__doc__)
    output = pathlib.Path(sys.argv[1])
    count = int(sys.argv[2]) if len(sys.argv) == 3 else 10
    if count < 1:
        raise SystemExit("cases-per-opcode-mode must be positive")

    cases = []
    for opcode in OPCODES:
        for mode in MODES:
            url = BASE_URL.format(opcode=opcode, mode=mode)
            source_cases = fetch_json(url)
            if len(source_cases) < count:
                raise RuntimeError(
                    f"{url} contains only {len(source_cases)} cases; requested {count}"
                )
            cases.extend(
                {
                    "name": case["name"],
                    "initial": case["initial"],
                    "final": case["final"],
                }
                for case in source_cases[:count]
            )
            print(f"{opcode:02x}.{mode}: selected {count} cases", file=sys.stderr)

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(cases, separators=(",", ":")) + "\n", encoding="utf-8")
    print(f"wrote {len(cases)} cases to {output}", file=sys.stderr)


if __name__ == "__main__":
    main()
