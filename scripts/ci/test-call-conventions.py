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
ROM = bytearray([0xEA] * 0x10200)
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

# A void far callee deliberately changes DP, DBR, and status flags. Its caller
# uses direct-page and DBR-relative addressing, then branches on ZF after JSL.
ROM[0x0C00:0x0C1A] = bytes.fromhex(
    "a9 11 22 80 8c 80 85 10 8d 34 12 d0 07 "
    "a9 11 8d 40 03 80 05 a9 22 8d 41 03 6b"
)
ROM[0x0C80:0x0C91] = bytes.fromhex(
    "c2 20 a9 34 12 5b e2 20 4b ab 38 f8 78 b8 a9 00 6b"
)

# Test volatile branch flags after a far call. STZ does not modify flags, so
# subsequent branches still observe the call's outgoing status values. ADC then
# consumes DF/CF, and PHP makes the remaining status bits observable as a byte.
ROM[0x0D00:0x0D23] = bytes.fromhex(
    "22 80 8c 80 "
    "d0 03 9c 50 03 "
    "b0 03 9c 51 03 "
    "30 03 9c 52 03 "
    "70 03 9c 53 03 "
    "69 01 8d 54 03 08 68 8d 55 03 60"
)

# The caller is in bank $80 and calls a far callee in bank $81. PHK/PLA after
# RTL records the caller's PBR, testing that the call restores the program bank.
ROM[0x0D80:0x0D8A] = bytes.fromhex(
    "22 00 81 81 4b 68 8d 44 03 60"
)
ROM[0x10100:0x10103] = bytes.fromhex("a9 33 6b")


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


def require_fragments(source: str, fragments: tuple[str, ...], context: str) -> None:
    missing = [fragment for fragment in fragments if fragment not in source]
    if missing:
        raise AssertionError(f"{context}: missing {missing!r}\n{source}")


def assert_stack_effects(
    source: str,
    expected_values: list[int],
    expected_locations: tuple[str, ...] | list[str],
    context: str,
) -> None:
    values, locations = extract_stack_writes(source)
    if values != expected_values or locations != list(expected_locations):
        raise AssertionError(
            f"{context}: writes={values}, locations={locations}\n{source}"
        )


def extract_decompilations(source: str) -> dict[str, str]:
    """Return decompiler output keyed by the labels emitted by the Java script."""
    sections: dict[str, list[str]] = {}
    current: str | None = None

    for line in source.splitlines():
        if line.startswith("=== ") and line.endswith(" decompile ==="):
            current = line.removeprefix("=== ").removesuffix(" decompile ===")
            sections[current] = []
        elif current is not None:
            sections[current].append(line)

    return {name: "\n".join(lines).strip() for name, lines in sections.items()}


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
        require_fragments(
            result,
            (
                "near=__near", "far=__far", "near16=__near", "far16=__far",
                "nearVoid=__near", "farVoid=__far", "nearEmu=__near", "farEmu=__far",
                "nestedWrapper=__far", "registerEffectsCallee=__far", "crossBankCallee=__far",
            ),
            "Functions did not retain selected conventions",
        )
        if "FAILED " in result:
            raise AssertionError("Decompiler failure:\n" + result)

        decompilations = extract_decompilations(result)
        section_names = (
            "caller", "near", "far", "caller16", "near16", "far16",
            "callerVoid", "nearVoid", "farVoid", "nestedCaller", "nestedWrapper",
            "stackDataCaller", "registerEffectsCaller", "registerEffectsCallee",
            "statusEffectsCaller", "crossBankCaller", "crossBankCallee",
            "emulationCaller", "nearEmu", "farEmu",
        )
        missing = [name for name in section_names if not decompilations.get(name)]
        if missing:
            raise AssertionError(
                f"Headless test omitted decompilations {missing}:\n{result}"
            )

        (
            caller, near, far, caller16, near16, far16,
            caller_void, near_void, far_void, nested_caller, nested_wrapper,
            stack_data_caller, register_effects_caller, register_effects_callee,
            status_effects_caller, cross_bank_caller, cross_bank_callee,
            emulation_caller, near_emu, far_emu,
        ) = (decompilations[name] for name in section_names)

        # Ghidra renders 8-bit integer arguments as C character constants.
        require_fragments(
            caller,
            ("near_fn(", "far_fn(", r"'\x11'", r"'\x03'", r"'\x04'", "'B'", r"'\x05'", r"'\x06'"),
            "8-bit calls or register arguments were not recovered",
        )
        require_fragments(near, ("return 'D'",), "Near return value was not recovered")
        require_fragments(far, ("return 'U'",), "Far return value was not recovered")

        require_fragments(
            caller16,
            ("near16_fn(", "far16_fn(", "0x1234", "0x2345", "0x3456",
             "0x4567", "0x5678", "0x6789"),
            "16-bit calls or register arguments were not recovered",
        )
        require_fragments(near16, ("return 0x789a",), "16-bit near return was not recovered")
        require_fragments(far16, ("return 0xbcde",), "16-bit far return was not recovered")

        # Verify that post-call stores use clobbered outputs, not stale values.
        require_fragments(
            caller_void,
            (
                "near_void(", "far_void(", "0x308) = extraout_A",
                "0x30a) = extraout_XLow", "0x30b) = extraout_YLow",
                "0x309) = extraout_A_00", "0x30c) = extraout_XLow_00",
                "0x30d) = extraout_YLow_00",
            ),
            "Void-call clobbers were not propagated",
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

        assert_stack_effects(
            caller, [0x80, 8, 0x80, 0x80, 0x15],
            expected_locations_near_then_far, "Native near/far return-address effects",
        )

        # The root's JSL to a far wrapper and the following JSR must reuse the
        # same baseline after the wrapper's nested near/far calls have returned.
        require_fragments(
            nested_caller, ("nested_wrapper(", "near_fn("),
            "Nested caller omitted its mixed calls",
        )
        assert_stack_effects(
            nested_caller, [0x80, 0x80, 0xa5, 0x80, 0xad],
            ("stack0x0000", "uStack_1", "uStack_2", "stack0x0000", "uStack_1"),
            "Nested calls did not restore the root stack baseline",
        )

        # Inside the wrapper, a near call followed by a far call must also reuse
        # the wrapper's baseline. The $8A PC high byte distinguishes these
        # nested return addresses from the root caller's $80 bank.
        require_fragments(
            nested_wrapper, ("near_fn(", "far_fn("),
            "Wrapper omitted a nested near/far call",
        )
        assert_stack_effects(
            nested_wrapper, [0x8a, 4, 0x80, 0x8a, 13],
            expected_locations_near_then_far, "Nested wrapper stack effects",
        )

        # PHA data must survive both call types. Return-address bytes should
        # occupy higher stack slots, and the post-call store should still read
        # the saved stack0x0000 byte rather than a return-address byte.
        require_fragments(
            stack_data_caller, ("nested_wrapper()", "near_fn("),
            "Stack-data caller omitted calls or treated the wrapper as parameterized",
        )
        assert_stack_effects(
            stack_data_caller, [0x11, 0x80, 0x8b, 6, 0x22, 0x8b, 0x10],
            ("stack0x0000", "uStack_1", "uStack_2", "uStack_3",
             "stack0x0000", "uStack_1", "uStack_2"),
            "Saved data and return-address stack slots",
        )
        for address in ("0x324", "0x325"):
            if not any(
                    address in line and "&stack0x0000" in line
                    for line in stack_data_caller.splitlines()):
                raise AssertionError(
                    f"Store to {address} did not read back the saved stack0x0000 byte:\n"
                    + stack_data_caller
                )

        # The far void callee's convention promises that DP, DBR, and all
        # modeled status flags may be clobbered. Ghidra must not reuse their
        # pre-call values when deriving the caller's effective addresses/branch.
        require_fragments(
            register_effects_caller, ("extraout_DP", "extraout_ZF"),
            "DP or ZF caller-clobber was not propagated",
        )
        if not any(
            "extraout_DBR" in line and "0x1234" in line
            for line in register_effects_caller.splitlines()
        ):
            raise AssertionError(
                "Absolute store did not use the caller-clobbered DBR value:\n"
                + register_effects_caller
            )
        if "void __far registerEffectsCallee(void)" not in register_effects_callee:
            raise AssertionError(
                "Register-effect callee did not decompile as a void function:\n"
                + register_effects_callee
            )

        # These tests exercise flags through actual post-call instructions.
        # STZ does not modify flags, so each branch consumes the outgoing flag
        # value from the far call. ADC consumes DF, and PHP exposes IF.
        require_fragments(
            status_effects_caller,
            ("extraout_ZF", "extraout_CF", "extraout_NF", "extraout_VF",
             "extraout_DF", "extraout_IF"),
            "Caller-clobbered status flags were not propagated after JSL",
        )

        # Cross-bank JSL/RTL must restore PBR to the caller's bank. The metadata
        # test covers the declaration; PHK/PLA makes the restored PBR observable.
        if "crossBankCallee();" not in cross_bank_caller or "0x344" not in cross_bank_caller:
            raise AssertionError(
                "Cross-bank caller did not call the callee and store the observed PBR:\n"
                + cross_bank_caller
            )
        if "extraout_PBR" in cross_bank_caller:
            raise AssertionError(
                "PBR is modeled as caller-clobbered after RTL:\n" + cross_bank_caller
            )
        if not any(
            line.strip().endswith("= in_PBR;")
            for line in cross_bank_caller.splitlines()
        ):
            raise AssertionError(
                "PHK/PLA after cross-bank RTL did not read the preserved caller PBR:\n"
                + cross_bank_caller
            )

        # Emulation mode is a separate context, not just another native-mode
        # caller. Verify argument/return recovery and the JSR/JSL stack bytes.
        require_fragments(
            emulation_caller,
            ("near_emu_fn(", "far_emu_fn(", r"'\x11'", r"'\x03'", r"'\x04'",
             "'B'", r"'\x05'", r"'\x06'"),
            "Emulation calls or register arguments were not recovered",
        )
        require_fragments(near_emu, ("return 'D'",), "Emulation near return was not recovered")
        require_fragments(far_emu, ("return 'U'",), "Emulation far return was not recovered")
        # In emulation mode, S is constrained to page one. Unlike native
        # mode, the decompiler represents the wrapped SP addresses as computed
        # bus addresses rather than a sequence of uStack_N locals. Check the
        # actual return bytes and the page-one address expressions instead.
        emulation_stack_fragments = (
            "ZEXT23(&stack0x0000) = 0x87",
            "CONCAT11(uVar3,0xff) = 8",
            "uVar2 = CONCAT11(uVar3,0xfe)",
            "(uVar2 + 2) = 0x80",
            "(uVar2 + 1) = 0x87",
            "(uint3)uVar2 = 0x15",
        )
        require_fragments(
            emulation_caller, emulation_stack_fragments,
            "Missing emulation-mode stack effects",
        )
        if not (
            emulation_caller.index("CONCAT11(uVar3,0xff) = 8")
            < emulation_caller.index("near_emu_fn(")
            < emulation_caller.index("(uVar2 + 2) = 0x80")
            < emulation_caller.index("far_emu_fn(")
        ):
            raise AssertionError(
                "Emulation-mode return-address writes were not ordered around calls:\n"
                + emulation_caller
            )

        print("Native/emulation near/far and nested stack regression passed.")
        for label, body in decompilations.items():
            print(f"=== {label} ===")
            print(body)


if __name__ == "__main__":
    main()
