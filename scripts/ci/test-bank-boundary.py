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
        parser_probes = {}
        for line in output.read_text(encoding="utf-8").splitlines():
            fields = dict(field.split("=", 1) for field in line.split("|"))
            case = fields.pop("case")
            if case == "parserprobe":
                label = fields.pop("label")
                parser_probes[label] = fields
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

        expected_parser_probes = {
            "absolute3": {
                "entry": 0x00FFFE,
                "length": 3,
                "bytes": "ad3456",
                "wrapped_offset": 2,
                "wrapped_byte": 0x56,
                "word_offset": 1,
                "word": 0x5634,
            },
            "immediate2": {
                "entry": 0x02FFFF,
                "length": 2,
                "bytes": "a942",
                "wrapped_offset": 1,
                "wrapped_byte": 0x42,
                "word_offset": 0,
                "word": 0x42A9,
                "operand": 0x42,
            },
            "single1": {
                "entry": 0x04FFFF,
                "length": 1,
                "bytes": "ea",
                "wrapped_offset": 1,
                "wrapped_byte": 0x18,
                "word_offset": 0,
                "word": 0x18EA,
            },
        }
        if set(parser_probes) != set(expected_parser_probes):
            raise AssertionError(
                "Expected wrapped parser probes for all instruction lengths; "
                f"got {sorted(parser_probes)}"
            )
        for label, expected in expected_parser_probes.items():
            observed = parser_probes[label]
            for key in ("length", "wrapped_offset", "word_offset"):
                if int(observed[key]) != expected[key]:
                    raise AssertionError(
                        f"Parser probe {label} has unexpected {key}: "
                        f"{observed[key]} (expected {expected[key]})"
                    )
            if (
                int(observed["entry"], 16) != expected["entry"]
                or observed["bytes"] != expected["bytes"]
                or int(observed["wrapped_byte"], 16) != expected["wrapped_byte"]
                or int(observed["word"], 16) != expected["word"]
            ):
                raise AssertionError(
                    f"Parser probe {label} mismatched expected wrapped bytes: "
                    f"{observed} versus {expected}"
                )
            if "operand" in expected and (
                observed["operand"] == "none"
                or int(observed["operand"], 16) != expected["operand"]
            ):
                raise AssertionError(
                    f"Parser probe {label} decoded the wrong wrapped operand: "
                    f"{observed}"
                )
        print(
            "PARSER PROTOTYPE: custom bank-wrapped MemBuffer parsed one-, two-, "
            "and three-byte boundary instructions with the expected wrapped bytes; "
            "LDA #$42 consumed its operand from the wrapped address. Normal "
            "disassembly still uses Ghidra's standard buffer."
        )

        status, message = classify_observation(
            actual, require_hardware=REQUIRE_HARDWARE
        )
        print(f"{status}: {message}")
        if coexistence_diagnostics:
            print(f"Bank-start coexistence details: {coexistence_diagnostics}")


if __name__ == "__main__":
    main()
