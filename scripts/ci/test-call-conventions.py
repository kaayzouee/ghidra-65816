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
ROM = bytearray([0xEA] * 0xC00)
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

# Void callees deliberately overwrite A/X/Y. The caller must not keep the
# pre-call accumulator or index-register values live across either call.
ROM[0x0060:0x0086] = bytes.fromhex(
    "a9 11 a2 22 a0 33 20 00 85 "
    "8d 08 03 8e 0a 03 8c 0b 03 "
    "a9 55 a2 66 a0 77 22 00 86 80 "
    "8d 09 03 8e 0c 03 8c 0d 03 60"
)
ROM[0x0500:0x0507] = bytes.fromhex("a9 44 a2 88 a0 99 60")
ROM[0x0600:0x0607] = bytes.fromhex("a9 aa a2 bb a0 cc 6b")

# Emulation-mode versions of the basic near/far call pair. The native/emulation
# context is assigned explicitly by the headless script, rather than inferred.
ROM[0x0700:0x071A] = bytes.fromhex(
    "a9 11 a2 03 a0 04 20 00 88 8d 14 03 "
    "a9 42 a2 05 a0 06 22 00 89 80 8d 15 03 60"
)
ROM[0x0800:0x080C] = bytes.fromhex(
    "8d 16 03 8e 17 03 8c 18 03 a9 44 60"
)
ROM[0x0900:0x090C] = bytes.fromhex(
    "8d 19 03 8e 1a 03 8c 1b 03 a9 55 6b"
)

# A native-mode root calls a far wrapper, then calls a near function itself.
# The wrapper in turn calls near and far callees. This exercises nested mixed
# calls and checks that every later call reuses its function's stack baseline.
ROM[0x00A0:0x00B2] = bytes.fromhex(
    "a9 11 22 00 8a 80 8d 20 03 a9 22 20 00 81 8d 21 03 60"
)
ROM[0x0A00:0x0A12] = bytes.fromhex(
    "a9 33 20 00 81 8d 22 03 a9 44 22 00 82 80 8d 23 03 6b"
)

# PHA data must survive JSL/RTL and JSR/RTS, with PLA restoring the original
# byte after each call. These values are not stack-passed function arguments.
ROM[0x0B00:0x0B16] = bytes.fromhex(
    "a9 11 48 22 00 8a 80 68 8d 24 03 "
    "a9 22 48 20 00 81 68 8d 25 03 60"
)


def extract_stack_writes(source: str) -> tuple[list[int], list[str]]:
    values: list[int] = []
    locations: list[str] = []
    for line in source.splitlines():
        if " = " not in line:
            continue
        left, right = line.split(" = ", 1)
        # Only count stores whose destination is a stack slot. A normal
        # memory store that reads stack0x0000 on its right side is not a push.
        if "&stack0x" not in left and "&uStack_" not in left:
            continue
        value = right.rstrip(";").strip()
        # Ghidra may print small values in decimal and others in hex.
        values.append(int(value, 0))
        locations.append(left.split("&", 1)[1].split(")", 1)[0])
    return values, locations


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
        for marker in (
            "near=__near", "far=__far", "near16=__near", "far16=__far",
            "nearVoid=__near", "farVoid=__far",
            "nearEmu=__near", "farEmu=__far", "nestedWrapper=__far",
        ):
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
        far16 = result.partition("=== far16 decompile ===\n")[2].partition(
            "=== callerVoid decompile ===\n"
        )[0]
        caller_void = result.partition("=== callerVoid decompile ===\n")[2].partition(
            "=== nearVoid decompile ===\n"
        )[0]
        near_void = result.partition("=== nearVoid decompile ===\n")[2].partition(
            "=== farVoid decompile ===\n"
        )[0]
        far_void = result.partition("=== farVoid decompile ===\n")[2].partition(
            "=== nestedCaller decompile ===\n"
        )[0]
        nested_caller = result.partition("=== nestedCaller decompile ===\n")[2].partition(
            "=== nestedWrapper decompile ===\n"
        )[0]
        nested_wrapper = result.partition("=== nestedWrapper decompile ===\n")[2].partition(
            "=== stackDataCaller decompile ===\n"
        )[0]
        stack_data_caller = result.partition("=== stackDataCaller decompile ===\n")[2].partition(
            "=== emulationCaller decompile ===\n"
        )[0]
        emulation_caller = result.partition("=== emulationCaller decompile ===\n")[2].partition(
            "=== nearEmu decompile ===\n"
        )[0]
        near_emu = result.partition("=== nearEmu decompile ===\n")[2].partition(
            "=== farEmu decompile ===\n"
        )[0]
        far_emu = result.partition("=== farEmu decompile ===\n")[2]
        if not all((
            caller, near, far, caller16, near16, far16, caller_void, near_void, far_void,
            nested_caller, nested_wrapper, stack_data_caller, emulation_caller, near_emu, far_emu
        )):
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

        if "near_void(" not in caller_void or "far_void(" not in caller_void:
            raise AssertionError("Void callees missing from caller decompilation:\n" + caller_void)
        # Verify that every post-call store uses the value returned by the
        # clobber model, rather than merely checking that the calls are present.
        expected_clobbers = (
            "0x308) = extraout_A",
            "0x30a) = extraout_XLow",
            "0x30b) = extraout_YLow",
            "0x309) = extraout_A_00",
            "0x30c) = extraout_XLow_00",
            "0x30d) = extraout_YLow_00",
        )
        for fragment in expected_clobbers:
            if fragment not in caller_void:
                raise AssertionError(
                    f"Expected post-call clobbered value {fragment!r}:\n{caller_void}"
                )

        # Void callees overwrite A/X/Y; stale pre-call values must not survive.
        stale_stores = (
            ("0x308)", "0x11"), ("0x30a)", "0x22"), ("0x30b)", "0x33"),
            ("0x309)", "0x55"), ("0x30c)", "0x66"), ("0x30d)", "0x77"),
        )
        for location, stale_value in stale_stores:
            for line in caller_void.splitlines():
                if location in line and stale_value in line:
                    raise AssertionError(
                        f"Register value {stale_value} incorrectly survives void call "
                        f"at {location}:\n{caller_void}"
                    )

        # JSR pushes high/low return bytes; JSL pushes bank/high/low bytes.
        # The next call must reuse the caller's stack baseline after the first
        # callee returns. Check values and variable locations, not just metadata.
        expected_locations_near_then_far = [
            "stack0x0000", "uStack_1", "stack0x0000", "uStack_1", "uStack_2"
        ]

        stack_writes, stack_locations = extract_stack_writes(caller)
        expected_values = [0x80, 8, 0x80, 0x80, 0x15]
        if stack_writes != expected_values or stack_locations != expected_locations_near_then_far:
            raise AssertionError(
                "Unexpected native near/far return-address stack effects. "
                f"writes={stack_writes}, locations={stack_locations}:\n{caller}"
            )

        # The root's JSL to a far wrapper and the following JSR must reuse the
        # same baseline after the wrapper's nested near/far calls have returned.
        nested_values, nested_locations = extract_stack_writes(nested_caller)
        expected_nested_values = [0x80, 0x80, 0xa5, 0x80, 0xad]
        expected_root_locations = [
            "stack0x0000", "uStack_1", "uStack_2", "stack0x0000", "uStack_1"
        ]
        if "nested_wrapper(" not in nested_caller or "near_fn(" not in nested_caller:
            raise AssertionError("Nested caller omitted its mixed calls:\n" + nested_caller)
        if nested_values != expected_nested_values or nested_locations != expected_root_locations:
            raise AssertionError(
                "Nested mixed calls did not restore the root stack baseline. "
                f"writes={nested_values}, locations={nested_locations}:\n{nested_caller}"
            )

        # Inside the wrapper, a near call followed by a far call must also reuse
        # the wrapper's baseline. The $8A PC high byte distinguishes these
        # nested return addresses from the root caller's $80 bank.
        wrapper_values, wrapper_locations = extract_stack_writes(nested_wrapper)
        expected_wrapper_values = [0x8a, 4, 0x80, 0x8a, 13]
        if "near_fn(" not in nested_wrapper or "far_fn(" not in nested_wrapper:
            raise AssertionError("Wrapper omitted a nested near/far call:\n" + nested_wrapper)
        if wrapper_values != expected_wrapper_values or wrapper_locations != expected_locations_near_then_far:
            raise AssertionError(
                "Nested wrapper near/far stack effects mismatch. "
                f"writes={wrapper_values}, locations={wrapper_locations}:\n{nested_wrapper}"
            )

        # PHA data must survive both call types. Return-address bytes should
        # occupy higher stack slots, and the post-call store should still read
        # the saved stack0x0000 byte rather than a return-address byte.
        if "nested_wrapper()" not in stack_data_caller or "near_fn(" not in stack_data_caller:
            raise AssertionError(
                "Stack-data caller omitted calls or treated the wrapper as parameterized:\\n"
                + stack_data_caller
            )
        stack_data_values, stack_data_locations = extract_stack_writes(stack_data_caller)
        expected_stack_data_values = [0x11, 0x80, 0x8b, 6, 0x22, 0x8b, 0x10]
        expected_stack_data_locations = [
            "stack0x0000", "uStack_1", "uStack_2", "uStack_3",
            "stack0x0000", "uStack_1", "uStack_2"
        ]
        if (stack_data_values != expected_stack_data_values
                or stack_data_locations != expected_stack_data_locations):
            raise AssertionError(
                "Saved data or return addresses occupied unexpected stack slots. "
                f"writes={stack_data_values}, locations={stack_data_locations}:\\n"
                + stack_data_caller
            )
        for address in ("0x324", "0x325"):
            if not any(
                    address in line and "&stack0x0000" in line
                    for line in stack_data_caller.splitlines()):
                raise AssertionError(
                    f"Store to {address} did not read back the saved stack0x0000 byte:\\n"
                    + stack_data_caller
                )

        # Emulation mode is a separate context, not just another native-mode
        # caller. Verify argument/return recovery and the JSR/JSL stack bytes.
        for name in ("near_emu_fn(", "far_emu_fn("):
            if name not in emulation_caller:
                raise AssertionError(
                    f"Emulation caller decompilation did not contain {name}:\n{emulation_caller}"
                )
        for marker in (r"'\x11'", r"'\x03'", r"'\x04'", "'B'", r"'\x05'", r"'\x06'"):
            if marker not in emulation_caller:
                raise AssertionError(
                    f"Emulation caller did not preserve input {marker}:\n{emulation_caller}"
                )
        if "return 'D'" not in near_emu:
            raise AssertionError("Emulation near return value was not recovered:\n" + near_emu)
        if "return 'U'" not in far_emu:
            raise AssertionError("Emulation far return value was not recovered:\n" + far_emu)
        emu_values, emu_locations = extract_stack_writes(emulation_caller)
        expected_emu_values = [0x87, 8, 0x80, 0x87, 0x15]
        if emu_values != expected_emu_values or emu_locations != expected_locations_near_then_far:
            raise AssertionError(
                "Unexpected emulation-mode near/far stack effects. "
                f"writes={emu_values}, locations={emu_locations}:\n{emulation_caller}"
            )

        print("Native/emulation near/far and nested stack regression passed.")
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
        print("=== callerVoid ===")
        print(caller_void)
        print("=== nearVoid ===")
        print(near_void)
        print("=== farVoid ===")
        print(far_void)
        print("=== nestedCaller ===")
        print(nested_caller)
        print("=== nestedWrapper ===")
        print(nested_wrapper)
        print("=== stackDataCaller ===")
        print(stack_data_caller)
        print("=== emulationCaller ===")
        print(emulation_caller)
        print("=== nearEmu ===")
        print(near_emu)
        print("=== farEmu ===")
        print(far_emu)


if __name__ == "__main__":
    main()
