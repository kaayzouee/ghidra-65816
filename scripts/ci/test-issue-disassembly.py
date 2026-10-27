#!/usr/bin/env python3
"""Run a focused headless disassembly regression against the installed Ghidra."""

import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
GHIDRA = Path(os.environ["GHIDRA_INSTALL_DIR"])
ROM = bytes.fromhex("""
    78 18 fb a2 03 9e 40 21 a9 80 8d 00 21 c9 c1 f0 03
    ce 30 0f 89 20 d0 02 8b ab 20 32 80 c2 30 a2 cd 9b
    a0 ff 1f c0 e5 3d 29 ff 7f 89 00 40 a9 78 22 40 c2
    20 a9 34 12 18 69 01 01 8d 00 03 e2 20 60
""")

EXPECTED = {
    0x8000: ("SEI", 1), 0x8001: ("CLC", 1), 0x8002: ("XCE", 1),
    0x8003: ("LDX", 2), 0x8005: ("STZ", 3), 0x8008: ("LDA", 2),
    0x800A: ("STA", 3), 0x800D: ("CMP", 2), 0x800F: ("BEQ", 2),
    0x8011: ("DEC", 3), 0x8014: ("BIT", 2), 0x8016: ("BNE", 2),
    0x8018: ("PHB", 1), 0x8019: ("PLB", 1), 0x801A: ("JSR", 3),
    0x801D: ("REP", 2), 0x801F: ("LDX", 3), 0x8022: ("LDY", 3),
    0x8025: ("CPY", 3), 0x8028: ("AND", 3), 0x802B: ("BIT", 3),
    0x802E: ("LDA", 3), 0x8031: ("RTI", 1), 0x8032: ("REP", 2),
    0x8034: ("LDA", 3), 0x8037: ("CLC", 1), 0x8038: ("ADC", 3),
    0x803B: ("STA", 3), 0x803E: ("SEP", 2), 0x8040: ("RTS", 1),
}


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="65816-issue-test-") as temporary:
        work = Path(temporary)
        rom_path = work / "issues.bin"
        rom_path.write_bytes(ROM)
        output = work / "result.txt"
        project = work / "project"
        project.mkdir()
        command = [
            str(GHIDRA / "support" / "analyzeHeadless"), str(project), "issues",
            "-import", str(rom_path), "-loader", "BinaryLoader",
            "-loader-baseAddr", "0x8000", "-processor", "65816:LE:16:default",
            "-noanalysis", "-scriptPath", str(ROOT / "tests"),
            "-postScript", "G65816IssueCheck.java", str(output), "8000", "8032",
            "-deleteProject",
        ]
        completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   text=True)
        if completed.returncode:
            raise RuntimeError(
                "analyzeHeadless failed with exit code "
                f"{completed.returncode}:\\n{completed.stdout}"
            )
        listing, separator, decompiled = output.read_text(encoding="utf-8").partition(
            "=== decompile"
        )
        if not separator:
            raise AssertionError("Headless test did not produce decompiler output")

        actual = {}
        for line in listing.splitlines():
            fields = line.split("|")
            if len(fields) != 4:
                continue
            address, selfrefs, length, mnemonic = fields
            actual[int(address, 16)] = (mnemonic, int(length), int(selfrefs))

        for address, (mnemonic, length) in EXPECTED.items():
            got = actual.get(address)
            if got is None or got[:2] != (mnemonic, length):
                raise AssertionError(
                    f"{address:06x}: expected {mnemonic}/{length}, got {got}"
                )
        bad_references = [
            f"{address:06x}" for address, (_, _, selfrefs) in actual.items()
            if selfrefs != 0
        ]
        if bad_references:
            raise AssertionError("Instruction references its own bytes: " + ", ".join(bad_references))
        if "FAILED " in decompiled or "0x35" not in decompiled or "0x13" not in decompiled:
            raise AssertionError("Decompiler did not preserve the immediate constants:\\n" + decompiled)
        print(f"Issue disassembly regressions: {len(EXPECTED)} instructions, no self references, constants preserved")


if __name__ == "__main__":
    main()
