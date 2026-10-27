#!/usr/bin/env python3
"""Exercise near and far 65816 calling conventions in Ghidra's decompiler."""

import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
GHIDRA = Path(os.environ["GHIDRA_INSTALL_DIR"])

# Base address is 0x808000 (bank $80). The caller passes values in A/C, X, and Y,
# calls $8100 with JSR and $808200 with JSL, then stores each return value.
ROM = bytearray([0xEA] * 0x500)
ROM[0x0000:0x001A] = bytes.fromhex(
    "a9 11 a2 03 a0 04 20 00 81 8d 00 03 "
    "a9 42 a2 05 a0 06 22 00 82 80 8d 01 03 60"
)
# Both callees use all three input registers and return an 8-bit accumulator value.
ROM[0x0100:0x010C] = bytes.fromhex(
    "8d 02 03 8e 03 03 8c 04 03 a9 44 60"
)
ROM[0x0200:0x020C] = bytes.fromhex(
    "8d 05 03 8e 06 03 8c 07 03 a9 55 6b"
)

# A second caller switches to 16-bit accumulator/index widths with REP #$30.
# This exercises the two-byte pentry paths as well as the one-byte paths above.
ROM[0x0020:0x0042] = bytes.fromhex(
    "c2 30 a9 34 12 a2 45 23 a0 56 34 20 00 83 8d 10 03 "
    "a9 67 45 a2 78 56 a0 89 67 22 00 84 80 8d 12 03 60"
)
ROM[0x0300:0x030D] = bytes.fromhex(
    "8d 20 03 8e 22 03 8c 24 03 a9 9a 78 60"
)
ROM[0x0400:0x040D] = bytes.fromhex(
    "8d 26 03 8e 28 03 8c 2a 03 a9 de bc 6b"
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
            "-loader-baseAddr", "0x808000",
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
        for marker in ("near=__near", "far=__far", "near16=__near", "far16=__far"):
            if marker not in result:
                raise AssertionError("Functions did not retain selected conventions:\n" + result)
        if "FAILED " in result:
            raise AssertionError("Decompiler failure:\n" + result)

        caller = result.partition("=== caller decompile ===\n")[2].partition(
            "=== near decompile ===\n"
        )[0]
        near = result.partition("=== near decompile ===\n")[2].partition(
            "=== far decompile ===\n"
        )[0]
        far = result.partition("=== far decompile ===\n")[2].partition(
            "=== caller16 decompile ===\n"
        )[0]
        caller16 = result.partition("=== caller16 decompile ===\n")[2].partition(
            "=== near16 decompile ===\n"
        )[0]
        near16 = result.partition("=== near16 decompile ===\n")[2].partition(
            "=== far16 decompile ===\n"
        )[0]
        far16 = result.partition("=== far16 decompile ===\n")[2]
        if not all((caller, near, far, caller16, near16, far16)):
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

        for name in ("near16_fn(", "far16_fn("):
            if name not in caller16:
                raise AssertionError(
                    f"16-bit caller decompilation did not contain {name}:\n{caller16}"
                )
        for marker in ("0x1234", "0x2345", "0x3456", "0x4567", "0x5678", "0x6789"):
            if marker not in caller16:
                raise AssertionError(
                    f"16-bit caller did not preserve input {marker}:\n{caller16}"
                )
        if "return 0x789a" not in near16:
            raise AssertionError("16-bit near return value was not recovered:\n" + near16)
        if "return 0xbcde" not in far16:
            raise AssertionError("16-bit far return value was not recovered:\n" + far16)

        # JSR pushes high/low return bytes; JSL pushes bank/high/low bytes.
        # The next call must reuse the caller's stack baseline after the first
        # callee returns. The stack variable names expose an unexpected residual
        # stack shift even when Ghidra's output still contains BADSPACEBASE.
        stack_writes = []
        stack_locations = []
        for line in caller.splitlines():
            if ("&stack0x" in line or "&uStack_" in line) and " = " in line:
                stack_writes.append(line.rsplit(" = ", 1)[1].rstrip(";").strip())
                stack_locations.append(line.split("&", 1)[1].split(")", 1)[0])
        expected_values = ["0x80", "8", "0x80", "0x80", "0x15"]
        expected_locations = [
            "stack0x0000", "uStack_1", "stack0x0000", "uStack_1", "uStack_2"
        ]
        if stack_writes != expected_values or stack_locations != expected_locations:
            raise AssertionError(
                "Unexpected call return-address stack effects. "
                f"writes={stack_writes}, locations={stack_locations}:\n{caller}"
            )

        print("Near/far calling-convention regression passed.")
        print("=== caller ===")
        print(caller)
        print("=== near ===")
        print(near)
        print("=== far ===")
        print(far)
        print("=== caller16 ===")
        print(caller16)
        print("=== near16 ===")
        print(near16)
        print("=== far16 ===")
        print(far16)


if __name__ == "__main__":
    main()
