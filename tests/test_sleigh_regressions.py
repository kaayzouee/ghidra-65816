"""Source-level regression tests for known 65816 SLEIGH semantic bugs.

These tests complement (but do not replace) compiling and executing the language in Ghidra.
They intentionally cover high-impact instruction semantics that previously regressed.
"""

from pathlib import Path
import re
import unittest
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
LANGUAGES = ROOT / "data" / "languages"
SINC = (LANGUAGES / "658xx.sinc").read_text(encoding="utf-8")


def instruction_blocks(mnemonic: str) -> list[tuple[str, str]]:
    """Return (constructor header, semantic body) pairs for an instruction."""
    starts = list(re.finditer(rf"(?m)^:{re.escape(mnemonic)}\b", SINC))
    blocks = []
    for match in starts:
        brace = SINC.find("{", match.start())
        if brace < 0:
            continue
        close = SINC.find("\n}", brace)
        if close < 0:
            continue
        blocks.append((SINC[match.start():brace], SINC[brace + 1:close]))
    return blocks


class LanguageMetadataTests(unittest.TestCase):
    def test_xml_metadata_is_well_formed(self) -> None:
        for filename in ("65816.ldefs", "65816.cspec", "65816.pspec"):
            with self.subTest(filename=filename):
                ET.parse(LANGUAGES / filename)

    def test_language_definition_references_existing_files(self) -> None:
        definitions = ET.parse(LANGUAGES / "65816.ldefs").getroot()
        entries = definitions.findall("language")
        self.assertTrue(entries, "65816.ldefs must define at least one language")
        for entry in entries:
            with self.subTest(language=entry.get("id")):
                sla = entry.attrib["slafile"]
                self.assertTrue(sla.endswith(".sla"))
                self.assertTrue((LANGUAGES / sla.replace(".sla", ".slaspec")).is_file())
                processor_spec = entry.attrib["processorspec"]
                self.assertTrue((LANGUAGES / processor_spec).is_file())
                compiler = entry.find("compiler")
                self.assertIsNotNone(compiler)
                self.assertTrue((LANGUAGES / compiler.attrib["spec"]).is_file())


class InstructionSemanticRegressionTests(unittest.TestCase):
    def test_cpy_uses_index_register_width_context(self) -> None:
        blocks = instruction_blocks("CPY")
        eight_bit = [header for header, _ in blocks if "ctx_XF=1" in header]
        sixteen_bit = [header for header, _ in blocks if "ctx_XF=0" in header]
        self.assertEqual(len(eight_bit), 1)
        self.assertEqual(len(sixteen_bit), 1)
        bodies = [body for _, body in blocks]
        self.assertTrue(any("deref_read8(data" in body and "YLow" in body for body in bodies))
        self.assertTrue(any("deref_read16(data" in body and "sext(Y)" in body for body in bodies))

    def test_compare_carry_is_unsigned_no_borrow(self) -> None:
        expected = {
            "CMP": {
                "ctx_MF=1": "CF = A >= data;",
                "ctx_MF=0": "CF = C >= data;",
            },
            "CPX": {
                "ctx_XF=1": "CF = XLow >= data;",
                "ctx_XF=0": "CF = X >= data;",
            },
            "CPY": {
                "ctx_XF=1": "CF = YLow >= data;",
                "ctx_XF=0": "CF = Y >= data;",
            },
        }
        for mnemonic, cases in expected.items():
            blocks = instruction_blocks(mnemonic)
            for context, carry_assignment in cases.items():
                with self.subTest(mnemonic=mnemonic, context=context):
                    matching_bodies = [
                        body for header, body in blocks if context in header
                    ]
                    self.assertTrue(matching_bodies)
                    self.assertTrue(
                        all(carry_assignment in body for body in matching_bodies),
                        f"{mnemonic} {context} must use {carry_assignment}",
                    )

    def test_xba_exchanges_accumulator_bytes_and_sets_flags_from_new_a(self) -> None:
        blocks = instruction_blocks("XBA")
        self.assertEqual(len(blocks), 1)
        _, body = blocks[0]
        self.assertRegex(
            body,
            r"local old_a:1 = A;\s*A = B;\s*B = old_a;\s*flag8_NZ\(A\);",
        )

    def test_wide_accumulator_transfers_set_sixteen_bit_flags(self) -> None:
        for mnemonic, source in (("TXA", "XLow"), ("TYA", "YLow")):
            with self.subTest(mnemonic=mnemonic):
                matches = [
                    body
                    for header, body in instruction_blocks(mnemonic)
                    if "ctx_XF=1" in header and "ctx_MF=0" in header
                ]
                self.assertEqual(len(matches), 1)
                self.assertIn(f"C = zext({source});", matches[0])
                self.assertIn("flag16_NZ(C);", matches[0])
                self.assertNotIn(f"flag8_NZ({source});", matches[0])


if __name__ == "__main__":
    unittest.main()
