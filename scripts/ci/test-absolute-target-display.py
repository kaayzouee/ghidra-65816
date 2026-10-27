#!/usr/bin/env python3
"""Verify full 24-bit target display and static flow references in headless Ghidra."""

import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
GHIDRA = Path(os.environ["GHIDRA_INSTALL_DIR"])
CODE_BASE = 0x128000
ROM = bytes.fromhex("4c 34 12 20 78 56 5c 78 56 34 22 bc 9a 78")
EXPECTED = {
    CODE_BASE: ("JMP", 0x121234),
    CODE_BASE + 3: ("JSR", 0x125678),
    CODE_BASE + 6: ("JML", 0x345678),
    CODE_BASE + 10: ("JSL", 0x789ABC),
}


def normalized_operand(text: str) -> str:
    return re.sub(r"[^0-9a-fA-F]", "", re.sub(r"(?i)0x", "", text)).lower()


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="65816-absolute-target-") as temporary:
        work = Path(temporary)
        rom_path = work / "absolute-targets.bin"
        rom_path.write_bytes(ROM)
        output = work / "result.txt"
        project = work / "project"
        project.mkdir()

        command = [
            str(GHIDRA / "support" / "analyzeHeadless"), str(project), "absolute-targets",
            "-import", str(rom_path), "-loader", "BinaryLoader",
            "-loader-baseAddr", hex(CODE_BASE), "-processor", "65816:LE:16:default",
            "-noanalysis", "-scriptPath", str(ROOT / "tests"),
            "-postScript", "G65816AbsoluteTargetCheck.java", str(output), f"{CODE_BASE:x}",
            "-deleteProject",
        ]
        completed = subprocess.run(
            command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
        )
        if completed.returncode:
            raise RuntimeError(
                "analyzeHeadless failed with exit code "
                f"{completed.returncode}:\n{completed.stdout}"
            )
        if not output.is_file():
            raise AssertionError("Headless target-check script did not produce output:\n"
                                 + completed.stdout)

        actual = {}
        for line in output.read_text(encoding="utf-8").splitlines():
            fields = line.split("|", maxsplit=3)
            if len(fields) == 4:
                address, mnemonic, operand, target = fields
                actual[int(address, 16)] = (mnemonic, operand, int(target, 16))

        if set(actual) != set(EXPECTED):
            raise AssertionError(
                f"Expected checks at {sorted(EXPECTED)}, got {sorted(actual)}"
            )
        for address, (expected_mnemonic, expected_target) in EXPECTED.items():
            mnemonic, operand, target = actual[address]
            full_target = f"{expected_target:06x}"
            if mnemonic != expected_mnemonic or target != expected_target:
                raise AssertionError(
                    f"{address:06x}: expected {expected_mnemonic}->{full_target}, "
                    f"got {mnemonic}->{target:06x}"
                )
            if full_target not in normalized_operand(operand):
                raise AssertionError(
                    f"{address:06x}: operand '{operand}' does not show full target {full_target}"
                )

        print("Absolute target display regressions: 4 instructions, full targets and flow references verified")


if __name__ == "__main__":
    main()
