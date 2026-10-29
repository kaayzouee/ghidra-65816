#!/usr/bin/env python3
"""Characterize and watch for a fix to 65816 program-bank instruction wrapping."""

import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
GHIDRA = Path(os.environ["GHIDRA_INSTALL_DIR"])
REQUIRE_HARDWARE = os.environ.get("GHIDRA_BANK_WRAP_REQUIRED") == "1"

ROM = bytes.fromhex("ad 34 12")
ENTRY = 0x00FFFE

# Hardware expectation: instruction bytes wrap within PBR and fall-through
# wraps the 16-bit PC without incrementing PBR.
EXPECTED_HARDWARE = {
    "absolute3": {
        "entry": 0x00FFFE, "mnemonic": "LDA", "length": 3,
        "bytes": "ad3456", "wrapped": 0x56, "fallthrough": 0x000001,
    },
    "immediate2": {
        "entry": 0x02FFFF, "mnemonic": "LDA", "length": 2,
        "bytes": "a942", "wrapped": 0x42, "fallthrough": 0x020001,
    },
    "single1": {
        "entry": 0x04FFFF, "mnemonic": "NOP", "length": 1,
        "bytes": "ea", "wrapped": 0x18, "fallthrough": 0x040000,
    },
}

# Current known behavior before bank-aware fetch/address support. Accept both
# this observation and the true hardware result so CI will keep passing once a
# real fix is implemented rather than locking the old bug in as expected.
KNOWN_CURRENT_LIMITATION = {
    "absolute3": {
        "entry": 0x00FFFE, "mnemonic": "LDA", "length": 3,
        "bytes": "ad3412", "wrapped": 0x56, "fallthrough": 0x010001,
    },
    "immediate2": {
        "entry": 0x02FFFF, "mnemonic": "LDA", "length": 2,
        "bytes": "a999", "wrapped": 0x42, "fallthrough": 0x030001,
    },
    "single1": {
        "entry": 0x04FFFF, "mnemonic": "NOP", "length": 1,
        "bytes": "ea", "wrapped": 0x18, "fallthrough": 0x050000,
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

        if actual == EXPECTED_HARDWARE:
            print(
                "PASS: bank-wrapped instruction bytes and fall-through conform "
                "for one-, two-, and three-byte instructions."
            )
        elif actual == KNOWN_CURRENT_LIMITATION:
            details = []
            for name in EXPECTED_HARDWARE:
                observed = actual[name]
                expected = EXPECTED_HARDWARE[name]
                details.append(
                    f"  {name}: observed bytes={observed['bytes']} "
                    f"fallthrough=0x{observed['fallthrough']:06X}; "
                    f"expected bytes={expected['bytes']} "
                    f"fallthrough=0x{expected['fallthrough']:06X}"
                )
            message = (
                "Instruction bytes and fall-through still advance linearly across the "
                "PBR boundary. Hardware expects:\n" + "\n".join(details)
            )
            if REQUIRE_HARDWARE:
                raise AssertionError(
                    "GHIDRA_BANK_WRAP_REQUIRED=1, but bank-wrapped fetch is unsupported.\n"
                    + message
                )
            print("KNOWN LIMITATION: " + message)
        else:
            raise AssertionError(
                "Bank-boundary behavior matches neither the known limitation nor the "
                f"hardware expectations.\nExpected hardware: {EXPECTED_HARDWARE}\n"
                f"Known limitation: {KNOWN_CURRENT_LIMITATION}\nObserved: {actual}\n"
                f"Headless output:\n{completed.stdout}"
            )


if __name__ == "__main__":
    main()
