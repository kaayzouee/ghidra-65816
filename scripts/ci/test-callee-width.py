#!/usr/bin/env python3
"""Characterize M/X decoding after subroutine calls without implementing propagation."""

import os
from pathlib import Path
import subprocess
import tempfile
import shutil

from ghidra_paths import analyze_headless

ROOT = Path(__file__).resolve().parents[2]
GHIDRA = Path(os.environ["GHIDRA_INSTALL_DIR"])


def main() -> None:
    rom = bytearray(0x500)
    cases = {
        0x8200: "c2 30 20 10 82 a9 12 a2 34 db",
        0x8210: "e2 30 60",
        0x8240: "c2 30 20 50 82 a9 34 12 a2 78 56 db",
        0x8250: "ea 60",
        0x8280: "c2 30 20 90 82 a9 34 12 a2 78 56 db",
        0x8290: "d0 02 e2 30 60",
        0x82c0: "e2 30 20 d0 82 a9 34 12 a2 78 56 db",
        0x82d0: "c2 30 60",
        0x8300: "c2 30 20 10 83 a9 12 a2 34 db",
        0x8310: "e2 30 60",
        0x8340: "c2 30 22 50 83 00 a9 12 a2 34 db",
        0x8350: "e2 30 6b",
        0x8380: "c2 30 20 90 83 a9 12 a2 34 12 db",
        0x8390: "e2 20 60",
        0x83c0: "e2 30 20 d0 83 a9 12 a2 34 12 db",
        0x83d0: "c2 10 60",
        0x8400: "c2 30 20 10 84 a9 34 12 a2 78 56 db",
        0x8410: "e2 31 60",
        0x8440: "c2 30 20 50 84 a9 34 12 a2 78 db",
        0x8450: "e2 10 60",
        0x8480: "e2 30 20 90 84 a9 34 12 a2 78 db",
        0x8490: "c2 20 60",
    }
    for address, contents in cases.items():
        data = bytes.fromhex(contents)
        offset = address - 0x8000
        rom[offset:offset + len(data)] = data

    with tempfile.TemporaryDirectory(prefix="65816-callee-width-") as temp:
        work = Path(temp)
        binary = work / "callee-width.bin"
        binary.write_bytes(rom)
        report = work / "widths.txt"
        project = work / "project"
        project.mkdir()
        scripts = work / "scripts"
        scripts.mkdir()
        shutil.copy2(ROOT / "tests" / "G65816CalleeWidthCheck.java", scripts)
        shutil.copy2(ROOT / "scripts" / "Repair65816CalleeWidths.java", scripts)
        repair_report = work / "repair.txt"
        command = [
            analyze_headless(GHIDRA), str(project), "callee-width",
            "-import", str(binary), "-loader", "BinaryLoader",
            "-loader-baseAddr", "0x8000", "-processor", "65816:LE:16:default",
            "-noanalysis", "-scriptPath", str(scripts),
            "-postScript", "G65816CalleeWidthCheck.java", str(report), str(repair_report),
            "-deleteProject",
        ]
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True)
        if result.returncode:
            raise RuntimeError(f"Headless callee test failed: {result.stdout}")

        found = {}
        for line in report.read_text(encoding="utf-8").splitlines():
            address, lda, ldx = line.split("|")
            found[int(address, 16)] = (int(lda), int(ldx))

        expected = {
            0x8200: (2, 2),
            0x8240: (3, 3),
            0x8280: (3, 3),
            0x82c0: (3, 3),
            0x8300: (3, 0),
            0x8340: (2, 2),
            0x8380: (2, 3),  # SEP M; X remains 16-bit
            0x83c0: (2, 3),  # REP X; M remains 8-bit
            0x8400: (3, 3),  # SEP #$31 is not a supported repair
            0x8440: (3, 2),  # SEP X; M remains 16-bit
            0x8480: (3, 2),  # REP M; X remains 8-bit
        }
        if found != expected:
            raise AssertionError(f"Callee widths: expected {expected}, got {found}")
        if repair_report.read_text(encoding="utf-8").strip() != "REPAIRED|7":
            raise AssertionError("Expected exactly seven isolated leaf-call repairs")
        print("Callee widths: seven leaf-call repairs, including independent M/X changes; "
              "preserving, ambiguous, unsupported-mask, and user-labeled cases unchanged")


if __name__ == "__main__":
    main()
