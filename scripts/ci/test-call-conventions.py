#!/usr/bin/env python3
"""Exercise near and far 65816 calling conventions in Ghidra's decompiler."""

import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
GHIDRA = Path(os.environ["GHIDRA_INSTALL_DIR"])

# Base address is 0x8000. The caller invokes $8100 with JSR and $008200 with JSL.
ROM = bytearray([0xEA] * 0x300)
ROM[0x0000:0x0010] = bytes.fromhex(
    "a9 11 20 00 81 8d 00 03 22 00 82 00 8d 01 03 60"
)
ROM[0x0100:0x0103] = bytes.fromhex("a9 22 60")  # near: LDA #$22; RTS
ROM[0x0200:0x0203] = bytes.fromhex("a9 33 6b")  # far: LDA #$33; RTL


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="65816-call-convention-") as temporary:
        work = Path(temporary)
        rom_path = work / "calls.bin"
        rom_path.write_bytes(ROM)
        output = work / "result.txt"
        project = work / "project"
        project.mkdir()
        command = [
            str(GHIDRA / "support" / "analyzeHeadless"),
            str(project),
            "call-conventions",
            "-import", str(rom_path),
            "-loader", "BinaryLoader",
            "-loader-baseAddr", "0x8000",
            "-processor", "65816:LE:16:default",
            "-noanalysis",
            "-scriptPath", str(ROOT / "tests"),
            "-postScript", "G65816CallConventionCheck.java", str(output),
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
        if not output.exists():
            raise AssertionError(
                f"Headless test produced no result file. Output:\n{completed.stdout}"
            )
        result = output.read_text(encoding="utf-8")
        if "near=__near" not in result or "far=__far" not in result:
            raise AssertionError("Functions did not retain selected conventions:\n" + result)
        if "FAILED " in result:
            raise AssertionError("Decompiler failure:\n" + result)
        decompiled = result.partition("=== caller decompile ===\n")[2]
        if not decompiled:
            raise AssertionError("Caller decompilation was not included:\n" + result)
        for name in ("near_fn(", "far_fn("):
            if name not in decompiled:
                raise AssertionError(
                    f"Caller decompilation did not contain {name}:\n{decompiled}"
                )
        print("Near/far calling-convention regression passed.")
        print(decompiled)


if __name__ == "__main__":
    main()
