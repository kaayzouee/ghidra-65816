#!/usr/bin/env python3
"""Characterize and watch for a fix to 65816 program-bank instruction wrapping."""

import os
from pathlib import Path
import subprocess
import tempfile

from bank_boundary_contract import classify_observation

ROOT = Path(__file__).resolve().parents[2]
GHIDRA = Path(os.environ["GHIDRA_INSTALL_DIR"])
REQUIRE_HARDWARE = os.environ.get("GHIDRA_BANK_WRAP_REQUIRED") == "1"

ROM = bytes.fromhex("ad 34 ea")
ENTRY = 0x00FFFE


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
        coexistence_diagnostics = {}
        parser_probe = None
        for line in output.read_text(encoding="utf-8").splitlines():
            fields = dict(field.split("=", 1) for field in line.split("|"))
            case = fields.pop("case")
            if case == "parserprobe":
                parser_probe = fields
            elif case == "coexist":
                actual[case] = {"coexists": fields["coexists"] == "1"}
                coexistence_diagnostics = fields
            else:
                actual[case] = {
                    "entry": int(fields["entry"], 16),
                    "mnemonic": fields["mnemonic"],
                    "length": int(fields["length"]),
                    "bytes": fields["bytes"],
                    "wrapped": int(fields["wrapped"], 16),
                    "fallthrough": int(fields["fallthrough"], 16),
                }

        if parser_probe is None:
            raise AssertionError("Bank-wrapped Language.parse prototype produced no result")
        if (
            int(parser_probe["length"]) != 2
            or int(parser_probe["operand"], 16) != 0x42
            or int(parser_probe["wrapped_byte"], 16) != 0x42
        ):
            raise AssertionError(
                "Custom bank-wrapped MemBuffer did not parse LDA #$42: "
                f"{parser_probe}"
            )
        print(
            "PARSER PROTOTYPE: custom bank-wrapped MemBuffer parses LDA #$42 "
            "correctly; normal disassembly still uses Ghidra's standard buffer."
        )

        status, message = classify_observation(
            actual, require_hardware=REQUIRE_HARDWARE
        )
        print(f"{status}: {message}")
        if coexistence_diagnostics:
            print(f"Bank-start coexistence details: {coexistence_diagnostics}")


if __name__ == "__main__":
    main()
