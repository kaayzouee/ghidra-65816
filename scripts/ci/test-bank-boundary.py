#!/usr/bin/env python3
"""Reproduce the known 65816 fetch/fall-through limitation at $xx:FFFF."""

import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
GHIDRA = Path(os.environ["GHIDRA_INSTALL_DIR"])

# LDA immediate starts at $00:FFFF. On the 65816 its operand is fetched from
# $00:0000 (= 0x42), while this linear 24-bit model sees $01:0000 (= 0x99).
ROM = bytes.fromhex("a9 99")
ENTRY = 0x00FFFF
LINEAR_OPERAND = 0x99
WRAPPED_OPERAND = 0x42
LINEAR_FALLTHROUGH = 0x010001


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
                f"analyzeHeadless failed with exit code {completed.returncode}:\\n"
                f"{completed.stdout}"
            )
        if not output.is_file():
            raise AssertionError(
                "Headless bank-boundary script produced no output:\\n" + completed.stdout
            )

        result = output.read_text(encoding="utf-8").strip()
        fields = dict(field.split("=", 1) for field in result.split("|"))
        observed = {
            "entry": int(fields["entry"], 16),
            "mnemonic": fields["mnemonic"],
            "length": int(fields["length"]),
            "opcode": int(fields["opcode"], 16),
            "operand": int(fields["operand"], 16),
            "wrapped": int(fields["wrapped"], 16),
            "fallthrough": int(fields["fallthrough"], 16),
        }
        expected_limitation = {
            "entry": ENTRY,
            "mnemonic": "LDA",
            "length": 2,
            "opcode": 0xA9,
            "operand": LINEAR_OPERAND,
            "wrapped": WRAPPED_OPERAND,
            "fallthrough": LINEAR_FALLTHROUGH,
        }
        if observed != expected_limitation:
            raise AssertionError(
                "Bank-boundary characterization changed. If the language now supports "
                "wrapped instruction fetch, replace this limitation check with conformance "
                f"assertions.\\nExpected current limitation: {expected_limitation}\\n"
                f"Observed: {observed}\\nHeadless output:\\n{completed.stdout}"
            )

        print(
            "Known bank-boundary limitation reproduced: "
            f"LDA at $00:FFFF reads $${LINEAR_OPERAND:02X} from $01:0000 "
            f"instead of wrapped $${WRAPPED_OPERAND:02X} from $00:0000; "
            f"fall-through is $${LINEAR_FALLTHROUGH:06X} instead of $00:0001."
        )


if __name__ == "__main__":
    main()
