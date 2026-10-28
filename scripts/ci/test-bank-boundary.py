#!/usr/bin/env python3
"""Reproduce the known 65816 fetch/fall-through limitation at bank boundaries."""

import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
GHIDRA = Path(os.environ["GHIDRA_INSTALL_DIR"])

# Three-byte LDA absolute starts at $00:FFFE. Its third byte is at linear $01:0000.
ROM = bytes.fromhex("ad 34 12")
ENTRY = 0x00FFFE

EXPECTED = {
    "absolute3": {
        "entry": 0x00FFFE,
        "mnemonic": "LDA",
        "length": 3,
        "bytes": "ad3412",
        "wrapped": 0x56,
        "fallthrough": 0x010001,
    },
    "immediate2": {
        "entry": 0x02FFFF,
        "mnemonic": "LDA",
        "length": 2,
        "bytes": "a999",
        "wrapped": 0x42,
        "fallthrough": 0x030001,
    },
    "single1": {
        "entry": 0x04FFFF,
        "mnemonic": "NOP",
        "length": 1,
        "bytes": "ea",
        "wrapped": 0x18,
        "fallthrough": 0x050000,
    },
}


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="65816-bank-boundary-") as temporary:
        work = Path(temporary)
        rom_path = work / "bank-boundary.bin"
        rom_path.write_bytes(ROM)
        output = work / "result.txt"
        project = work / "project"
        project.mkdir()

        command = [
            str(GHIDRA / "support" / "analyzeHeadless"),
            str(project),
            "bank-boundary",
            "-import",
            str(rom_path),
            "-loader",
            "BinaryLoader",
            "-loader-baseAddr",
            hex(ENTRY),
            "-processor",
            "65816:LE:16:default",
            "-noanalysis",
            "-scriptPath",
            str(ROOT / "tests"),
            "-postScript",
            "G65816BankBoundaryCheck.java",
            str(output),
            "-deleteProject",
        ]
        completed = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        if completed.returncode:
            raise RuntimeError(
                f"analyzeHeadless failed with exit code {completed.returncode}:\n"
                f"{completed.stdout}"
            )
        if not output.is_file():
            raise AssertionError(
                "Headless bank-boundary script produced no output:\n" + completed.stdout
            )

        actual = {}
        for line in output.read_text(encoding="utf-8").splitlines():
            fields = dict(field.split("=", 1) for field in line.split("|"))
            case = fields.pop("case")
            actual[case] = {
                "entry": int(fields["entry"], 16),
                "mnemonic": fields["mnemonic"],
                "length": int(fields["length"]),
                "bytes": fields["bytes"],
                "wrapped": int(fields["wrapped"], 16),
                "fallthrough": int(fields["fallthrough"], 16),
            }

        if actual != EXPECTED:
            raise AssertionError(
                "Bank-boundary characterization changed. Replace the expected-current-limitation "
                "checks with hardware-conformance assertions if bank-wrapped instruction fetch "
                f"becomes supported.\nExpected: {EXPECTED}\nObserved: {actual}\n"
                f"Headless output:\n{completed.stdout}"
            )

        print(
            "Known bank-boundary limitation reproduced for 3-, 2-, and 1-byte instructions: "
            "instruction bytes and fall-through advance linearly into the next bank."
        )


if __name__ == "__main__":
    main()
