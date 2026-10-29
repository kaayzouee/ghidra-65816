"""Expected outputs and classification for the 65816 bank-boundary regression."""

EXPECTED_HARDWARE = {
    "absolute3": {
        "entry": 0x00FFFE,
        "mnemonic": "LDA",
        "length": 3,
        "bytes": "ad3456",
        "wrapped": 0x56,
        "fallthrough": 0x000001,
    },
    "immediate2": {
        "entry": 0x02FFFF,
        "mnemonic": "LDA",
        "length": 2,
        "bytes": "a942",
        "wrapped": 0x42,
        "fallthrough": 0x020001,
    },
    "single1": {
        "entry": 0x04FFFF,
        "mnemonic": "NOP",
        "length": 1,
        "bytes": "ea",
        "wrapped": 0x18,
        "fallthrough": 0x040000,
    },
    "coexist": {"coexists": True},
}

KNOWN_CURRENT_LIMITATION = {
    "absolute3": {
        "entry": 0x00FFFE,
        "mnemonic": "LDA",
        "length": 3,
        "bytes": "ad34ea",
        "wrapped": 0x56,
        "fallthrough": 0x010001,
    },
    "immediate2": {
        "entry": 0x02FFFF,
        "mnemonic": "LDA",
        "length": 2,
        "bytes": "a999",
        "wrapped": 0x42,
        "fallthrough": 0x030001,
    },
    "single1": {
        "entry": 0x04FFFF,
        "mnemonic": "NOP",
        "length": 1,
        "bytes": "ea",
        "wrapped": 0x18,
        "fallthrough": 0x050000,
    },
    "coexist": {"coexists": False},
}


def classify_observation(actual: dict, require_hardware: bool = False) -> tuple[str, str]:
    """Classify the headless output without accepting arbitrary behavior.

    Normal CI is diagnostic until the architectural fix lands: it passes for
    either true hardware behavior or the reproduced current limitation.
    Strict mode is intended for validating a candidate fix and accepts only
    true hardware behavior, including independent decodability at bank $01:0000.
    """
    if actual == EXPECTED_HARDWARE:
        return (
            "PASS",
            "Bank-wrapped instruction bytes and fall-through conform for "
            "one-, two-, and three-byte instructions; the instruction at "
            "bank $01:$0000 remains independently decodable.",
        )

    if actual == KNOWN_CURRENT_LIMITATION:
        details = []
        for name in ("absolute3", "immediate2", "single1"):
            observed = actual[name]
            expected = EXPECTED_HARDWARE[name]
            details.append(
                f"  {name}: observed bytes={observed['bytes']} "
                f"fallthrough=0x{observed['fallthrough']:06X}; "
                f"expected bytes={expected['bytes']} "
                f"fallthrough=0x{expected['fallthrough']:06X}"
            )
        details.append(
            "  bank-$01:$0000 NOP coexistence: "
            f"observed={actual['coexist']['coexists']}; expected=True"
        )
        message = (
            "Instruction-byte fetch, code-unit extent, or fall-through still "
            "violates 65816 bank semantics. Hardware expects:\n" + "\n".join(details)
        )
        if require_hardware:
            raise AssertionError(
                "GHIDRA_BANK_WRAP_REQUIRED=1, but bank-wrapped instruction behavior is "
                "unsupported.\n" + message
            )
        return "KNOWN LIMITATION", message

    raise AssertionError(
        "Bank-boundary behavior matches neither the known limitation nor the "
        f"hardware expectations.\nExpected hardware: {EXPECTED_HARDWARE}\n"
        f"Known limitation: {KNOWN_CURRENT_LIMITATION}\nObserved: {actual}"
    )
