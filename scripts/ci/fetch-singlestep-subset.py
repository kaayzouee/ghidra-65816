#!/usr/bin/env python3
"""Fetch deterministic SingleStepTests/65816 state-transition fixtures.

By default, fetch the small selected subset used by pull-request CI. Pass --all to fetch
all 256 opcodes in both emulation/native modes. Cycle traces are omitted and the source corpus
is pinned to a commit so results do not change when upstream advances.

Usage: fetch-singlestep-subset.py <output.json> [cases-per-opcode-mode] [--all]
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
# indexed reads. Avoid STP in the fast subset because the current p-code model represents it as a halt.
SUBSET_OPCODES = (0x69, 0xA9, 0x48, 0x68, 0x8D, 0xB7)
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
    args = sys.argv[1:]
    if not args or len(args) > 3:
        raise SystemExit(__doc__)
    output = pathlib.Path(args.pop(0))
    all_opcodes = "--all" in args
    args = [arg for arg in args if arg != "--all"]
    if len(args) > 1:
        raise SystemExit(__doc__)
    count = int(args[0]) if args else (50 if all_opcodes else 10)
    if count < 1:
        raise SystemExit("cases-per-opcode-mode must be positive")

    opcodes = range(256) if all_opcodes else SUBSET_OPCODES
    cases = []
    for opcode in opcodes:
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
        if opcode % 16 == 15 or not all_opcodes:
            print(f"fetched opcode range ending at {opcode:02x}", file=sys.stderr)

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(cases, separators=(",", ":")) + "\n", encoding="utf-8")
    expected = len(opcodes) * len(MODES) * count
    if len(cases) != expected:
        raise RuntimeError(f"expected {expected} cases, generated {len(cases)}")
    print(f"wrote {len(cases)} cases to {output}", file=sys.stderr)


if __name__ == "__main__":
    main()
