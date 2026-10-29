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
}

KNOWN_CURRENT_LIMITATION = {
    "absolute3": {
        "entry": 0x00FFFE,
        "mnemonic": "LDA",
        "length": 3,
        "bytes": "ad3412",
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
}


def classify_observation(actual: dict, require_hardware: bool = False) -> tuple[str, str]:
    """Classify the headless output without accepting arbitrary behavior.

    Normal CI is diagnostic until the architectural fix lands: it passes for
    either true hardware behavior or the one reproduced current limitation.
    Strict mode is intended for validating a candidate fix and accepts only
    true hardware behavior.
    """
    if actual == EXPECTED_HARDWARE:
        return (
            "PASS",
            "Bank-wrapped instruction bytes and fall-through conform for "
            "one-, two-, and three-byte instructions.",
        )

    if actual == KNOWN_CURRENT_LIMITATION:
        details = []
        for name in EXPECTED_HARDWARE:
            observed = actual[name]
            expected = EXPECTED_HARDWARE[name]
            details.append(
                f"  {name}: observed bytes={observed['bytes']} "
                f"fallthrough=0x{observed['fallthrough']:06X}; "
                f"expected bytes={expected['bytes']} "
                f"fallthrough=0x{expected['fallthrough']:06X}"
            )
        message = (
            "Instruction bytes and fall-through still advance linearly across the "
            "PBR boundary. Hardware expects:\n" + "\n".join(details)
        )
        if require_hardware:
            raise AssertionError(
                "GHIDRA_BANK_WRAP_REQUIRED=1, but bank-wrapped fetch is unsupported.\n"
                + message
            )
        return "KNOWN LIMITATION", message

    raise AssertionError(
        "Bank-boundary behavior matches neither the known limitation nor the "
        f"hardware expectations.\nExpected hardware: {EXPECTED_HARDWARE}\n"
        f"Known limitation: {KNOWN_CURRENT_LIMITATION}\nObserved: {actual}"
    )
