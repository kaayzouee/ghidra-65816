"""Unit tests for the bank-boundary test's acceptance contract."""

import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts" / "ci"))

from bank_boundary_contract import (  # noqa: E402
    EXPECTED_HARDWARE,
    KNOWN_CURRENT_LIMITATION,
    classify_observation,
)


class BankBoundaryContractTests(unittest.TestCase):
    def test_true_hardware_result_passes_normal_and_strict_modes(self) -> None:
        self.assertEqual(classify_observation(EXPECTED_HARDWARE)[0], "PASS")
        self.assertEqual(
            classify_observation(EXPECTED_HARDWARE, require_hardware=True)[0],
            "PASS",
        )

    def test_known_bug_is_diagnostic_in_normal_ci(self) -> None:
        status, message = classify_observation(KNOWN_CURRENT_LIMITATION)
        self.assertEqual(status, "KNOWN LIMITATION")
        self.assertIn("fallthrough=0x010001", message)
        self.assertIn("expected bytes=ad3456", message)

    def test_known_bug_fails_strict_conformance_mode(self) -> None:
        with self.assertRaisesRegex(AssertionError, "GHIDRA_BANK_WRAP_REQUIRED=1"):
            classify_observation(KNOWN_CURRENT_LIMITATION, require_hardware=True)

    def test_unexpected_behavior_always_fails(self) -> None:
        mutated = {name: dict(case) for name, case in KNOWN_CURRENT_LIMITATION.items()}
        mutated["absolute3"]["bytes"] = "ad34ff"
        with self.assertRaisesRegex(AssertionError, "matches neither"):
            classify_observation(mutated)


if __name__ == "__main__":
    unittest.main()
