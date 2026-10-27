#!/usr/bin/env python3
"""Check the illustrative prototypes against a pinned real compiler ABI snapshot.

This is a compatibility guard, not a claim that the OpenSNES ABI is universal.
The reference assembly is copied from OpenSNES's published cc65816 ABI examples.
"""

from pathlib import Path
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
CSPEC = ROOT / "data/languages/65816.cspec"
REFERENCE = ROOT / "tests/fixtures/abi/opensnes-cc65816-reference.asm"


def main() -> None:
    assembly = REFERENCE.read_text(encoding="utf-8")
    required_assembly = (
        "lda 6,s",
        "sbc 4,s",
        "rtl",
        "jsl oamSet",
        "adc.w #14",
        "tas",
    )
    for fragment in required_assembly:
        if fragment not in assembly:
            raise AssertionError(
                f"OpenSNES ABI reference lost expected assembly {fragment!r}"
            )

    pushes = [line for line in assembly.splitlines() if line.strip().startswith("pea.w ")]
    if len(pushes) != 7:
        raise AssertionError(
            f"Expected seven stack-passed arguments in the compiler snapshot; got {len(pushes)}"
        )

    root = ET.parse(CSPEC).getroot()
    global_return_address = root.find("./returnaddress")
    if global_return_address is None:
        raise AssertionError("Compiler spec is missing the default return-address layout")

    for name, expected_return_size in (("__near", 2), ("__far", 3)):
        model = next(
            (node for node in root.findall("./prototype") if node.get("name") == name),
            None,
        )
        if model is None:
            raise AssertionError(f"Missing optional prototype {name}")
        if model.get("strategy") != "register":
            raise AssertionError(f"{name} should remain explicitly register-based")

        input_registers = [
            node.get("name") for node in model.findall("./input/pentry/register")
        ]
        if input_registers != ["C", "X", "Y"]:
            raise AssertionError(
                f"{name} input contract changed: expected C/X/Y, got {input_registers}"
            )

        return_address = model.find("./returnaddress")
        if return_address is None:
            return_address = global_return_address
        varnode = return_address.find("./varnode")
        if varnode is None or int(varnode.get("size", "0")) != expected_return_size:
            raise AssertionError(
                f"{name} return-address size no longer matches its documented model"
            )

    # The comparison is intentionally negative: this repo's optional models
    # are register-only and use JSR/RTS-like 2-byte near or JSL/RTL-like 3-byte
    # far return addresses. OpenSNES cc65816 passes these parameters on the
    # stack, calls with JSL, returns with RTL, and cleans arguments in the caller.
    print(
        "ABI reference check passed: OpenSNES cc65816 uses stack arguments and "
        "caller cleanup; __near/__far remain separate illustrative register models."
    )


if __name__ == "__main__":
    main()
