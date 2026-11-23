#!/usr/bin/env python3
"""Characterize M/X decoding after subroutine calls without implementing propagation."""

import os
from pathlib import Path
import subprocess
import tempfile

from ghidra_paths import analyze_headless

ROOT = Path(__file__).resolve().parents[2]
GHIDRA = Path(os.environ["GHIDRA_INSTALL_DIR"])


def main() -> None:
    rom = bytearray(0x300)
    cases = {
        0x8200: "c2 30 20 10 82 a9 12 a2 34 db",
        0x8210: "e2 30 60",
        0x8240: "c2 30 20 50 82 a9 34 12 a2 78 56 db",
        0x8250: "ea 60",
        0x8280: "c2 30 20 90 82 a9 34 12 a2 78 56 db",
        0x8290: "d0 02 e2 30 60",
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
        command = [
            analyze_headless(GHIDRA), str(project), "callee-width",
            "-import", str(binary), "-loader", "BinaryLoader",
            "-loader-baseAddr", "0x8000", "-processor", "65816:LE:16:default",
            "-noanalysis", "-scriptPath", str(ROOT / "tests"),
            "-postScript", "G65816CalleeWidthCheck.java", str(report),
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

        if set(found) != set((0x8200, 0x8240, 0x8280)):
            raise AssertionError(f"Unexpected callee cases: {found}")
        if found[0x8200] not in ((3, 0), (2, 2)):
            raise AssertionError(f"Unexpected post-SEP decode: {found[0x8200]}")
        if found[0x8240] != (3, 3):
            raise AssertionError(f"Preserving callee changed widths: {found[0x8240]}")
        if found[0x8280] not in ((3, 3), (2, 2)):
            raise AssertionError(f"Unexpected ambiguous-return decode: {found[0x8280]}")

        print(f"Callee width: unconditional SEP gives LDA/LDX {found[0x8200]} "
              "(desired 2/2); preserving callee gives 3/3; "
              f"conflicting returns give {found[0x8280]} (path-dependent)")


if __name__ == "__main__":
    main()
