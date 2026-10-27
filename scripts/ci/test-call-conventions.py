#!/usr/bin/env python3
"""Exercise near and far 65816 calling conventions in Ghidra's decompiler."""

import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
GHIDRA = Path(os.environ["GHIDRA_INSTALL_DIR"])

# Base address is 0x8000. The caller passes values in A/C, X, and Y,
# calls $8100 with JSR and $008200 with JSL, then stores each return value.
ROM = bytearray([0xEA] * 0x300)
ROM[0x0000:0x001A] = bytes.fromhex(
    "a9 11 a2 03 a0 04 20 00 81 8d 00 03 "
    "a9 42 a2 05 a0 06 22 00 82 00 8d 01 03 60"
)
# Both callees use all three input registers and return an 8-bit accumulator value.
ROM[0x0100:0x010C] = bytes.fromhex(
    "8d 02 03 8e 03 03 8c 04 03 a9 44 60"
)
ROM[0x0200:0x020C] = bytes.fromhex(
    "8d 05 03 8e 06 03 8c 07 03 a9 55 6b"
)


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

        caller = result.partition("=== caller decompile ===\n")[2].partition(
            "=== near decompile ===\n"
        )[0]
        near = result.partition("=== near decompile ===\n")[2].partition(
            "=== far decompile ===\n"
        )[0]
        far = result.partition("=== far decompile ===\n")[2]
        if not caller or not near or not far:
            raise AssertionError("Headless test omitted one or more decompilations:\n" + result)

        for name in ("near_fn(", "far_fn("):
            if name not in caller:
                raise AssertionError(
                    f"Caller decompilation did not contain {name}:\n{caller}"
                )
        # Ghidra renders 8-bit integer arguments as C character constants.
        for marker in (r"'\x11'", r"'\x03'", r"'\x04'"):
            if marker not in caller:
                raise AssertionError(
                    f"Near call did not preserve input {marker}:\n{caller}"
                )
        for marker in ("'B'", r"'\x05'", r"'\x06'"):
            if marker not in caller:
                raise AssertionError(
                    f"Far call did not preserve input {marker}:\n{caller}"
                )
        if "return 'D'" not in near:
            raise AssertionError("Near function return value was not recovered:\n" + near)
        if "return 'U'" not in far:
            raise AssertionError("Far function return value was not recovered:\n" + far)

        print("Near/far calling-convention regression passed.")
        print("=== caller ===")
        print(caller)
        print("=== near ===")
        print(near)
        print("=== far ===")
        print(far)


if __name__ == "__main__":
    main()
