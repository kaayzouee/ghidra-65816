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
MEMACCESS = (LANGUAGES / "658xx_memaccess.sinc").read_text(encoding="utf-8")


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


    def test_emulation_status_stack_image_forces_reserved_and_break_bits(self) -> None:
        push_macro = re.search(
            r"macro push_status_emulation\(([^)]*)\)\s*\{(.*?)\n\}",
            MEMACCESS,
            re.DOTALL,
        )
        self.assertIsNotNone(push_macro)
        push_body = push_macro.group(2)
        self.assertIn("status[5,1] = 1;", push_body)
        self.assertIn("status[4,1] = _break;", push_body)

        pull_macro = re.search(
            r"macro pull_status_emulation\(\)\s*\{(.*?)\n\}",
            MEMACCESS,
            re.DOTALL,
        )
        self.assertIsNotNone(pull_macro)
        self.assertNotRegex(pull_macro.group(1), r"\bBF\s*=")

        for mnemonic in ("BRK", "COP", "PHP"):
            with self.subTest(mnemonic=mnemonic):
                emulation_bodies = [
                    body for header, body in instruction_blocks(mnemonic)
                    if "ctx_EF=1" in header
                ]
                self.assertTrue(emulation_bodies)
                self.assertTrue(
                    all("push_status_emulation(1:1);" in body for body in emulation_bodies),
                    f"{mnemonic} must push an emulation-mode status image with B=1",
                )


    def test_emulation_software_interrupts_clear_program_bank(self) -> None:
        for mnemonic in ("BRK", "COP"):
            with self.subTest(mnemonic=mnemonic):
                emulation_bodies = [
                    body for header, body in instruction_blocks(mnemonic)
                    if "ctx_EF=1" in header
                ]
                self.assertEqual(len(emulation_bodies), 1)
                body = emulation_bodies[0]
                self.assertIn("PBR = 0;", body)
                self.assertLess(body.index("PBR = 0;"), body.index("goto [target];"))

    def test_plp_and_rti_use_mode_specific_status_pull(self) -> None:
        for mnemonic in ("PLP", "RTI"):
            with self.subTest(mnemonic=mnemonic, mode="emulation"):
                blocks = [
                    body for header, body in instruction_blocks(mnemonic)
                    if "ctx_EF=1" in header
                ]
                self.assertEqual(len(blocks), 1)
                self.assertIn("pull_status_emulation();", blocks[0])
                self.assertNotIn("pull_status_native();", blocks[0])

            with self.subTest(mnemonic=mnemonic, mode="native"):
                blocks = [
                    body for header, body in instruction_blocks(mnemonic)
                    if "ctx_EF=0" in header
                ]
                self.assertEqual(len(blocks), 1)
                self.assertIn("pull_status_native(status);", blocks[0])
                self.assertNotIn("pull_status_emulation();", blocks[0])

    def test_native_status_pull_uses_stacked_x_bit_for_index_cleanup(self) -> None:
        self.assertIn("macro pull_status_native(_status) {", MEMACCESS)
        pull_body = MEMACCESS.split("macro pull_status_native(_status) {", 1)[1].split("\\n}", 1)[0]
        self.assertIn("pull8_native(_status);", pull_body)
        self.assertIn("NF = _status[7,1];", pull_body)
        self.assertIn("CF = _status[0,1];", pull_body)

        self.assertNotIn("unknown_native_status_pull", SINC)
        for mnemonic in ("PLP", "RTI"):
            with self.subTest(mnemonic=mnemonic):
                native_bodies = [
                    body for header, body in instruction_blocks(mnemonic)
                    if "ctx_EF=0" in header
                ]
                self.assertEqual(len(native_bodies), 1)
                body = native_bodies[0]
                self.assertIn("pull_status_native(status);", body)
                self.assertIn("status[4,1] == 0", body)
                self.assertIn("XHigh = 0;", body)
                self.assertIn("YHigh = 0;", body)

    def test_interrupt_entry_stacks_state_before_changing_live_flags(self) -> None:
        for mnemonic in ("BRK", "COP"):
            for mode, context in (("native", "ctx_EF=0"), ("emulation", "ctx_EF=1")):
                with self.subTest(mnemonic=mnemonic, mode=mode):
                    bodies = [
                        body for header, body in instruction_blocks(mnemonic)
                        if context in header
                    ]
                    self.assertEqual(len(bodies), 1)
                    body = bodies[0]
                    status_push = (
                        "push_status_native();"
                        if mode == "native"
                        else "push_status_emulation(1:1);"
                    )
                    self.assertLess(body.index("push"), body.index(status_push))
                    self.assertLess(body.index(status_push), body.index("IF = 1;"))
                    self.assertLess(body.index("IF = 1;"), body.index("DF = 0;"))
                    self.assertLess(body.index("DF = 0;"), body.index("PBR = 0;"))

    def test_rti_restores_pc_with_mode_appropriate_bank_handling(self) -> None:
        emulation = [
            body for header, body in instruction_blocks("RTI")
            if "ctx_EF=1" in header
        ]
        native = [
            body for header, body in instruction_blocks("RTI")
            if "ctx_EF=0" in header
        ]
        self.assertEqual(len(emulation), 1)
        self.assertIn("pull16_emulation(pc);", emulation[0])
        self.assertIn("(zext(PBR) << 16) | zext(pc)", emulation[0])
        self.assertNotIn("pull8_emulation(pbr)", emulation[0])

        self.assertEqual(len(native), 1)
        self.assertIn("pull16_native(pc);", native[0])
        self.assertIn("pull8_native(pbr);", native[0])
        self.assertIn("(zext(pbr) << 16) | zext(pc)", native[0])

    def test_software_interrupts_clear_pbr_before_vector_transfer(self) -> None:
        vectors = {"BRK": ("0x00FFE6", "0x00FFFE"),
                   "COP": ("0x00FFE4", "0x00FFF4")}
        for mnemonic, (native_vector, emulation_vector) in vectors.items():
            blocks = instruction_blocks(mnemonic)
            for mode, vector in (("native", native_vector), ("emulation", emulation_vector)):
                with self.subTest(mnemonic=mnemonic, mode=mode):
                    matches = [
                        body for header, body in blocks
                        if f"ctx_EF={'0' if mode == 'native' else '1'}" in header
                    ]
                    self.assertEqual(len(matches), 1)
                    body = matches[0]
                    self.assertIn("PBR = 0;", body)
                    self.assertLess(body.index("PBR = 0;"), body.index("goto [target];"))
                    self.assertIn(vector, body)

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


    def test_stp_does_not_synthesize_an_immediate_reset(self) -> None:
        blocks = instruction_blocks("STP")
        self.assertEqual(len(blocks), 1)
        _, body = blocks[0]
        self.assertIn("stop();", body)
        self.assertIn("goto inst_start;", body)
        self.assertNotIn("0x00FFFC", body)
        self.assertNotRegex(body, r"\bgoto\s+\[")

    def test_native_xce_preserves_width_context_and_index_high_bytes(self) -> None:
        blocks = instruction_blocks("XCE")
        native = [ (header, body) for header, body in blocks if "ctx_EF=0" in header ]
        self.assertEqual(len(native), 1)
        header, body = native[0]

        self.assertIn("ctx_MF=ctx_MF | CF", header)
        self.assertIn("ctx_XF=ctx_XF | CF", header)

        native_to_native = body.split("\n    <to_native>", 1)[1].split("\n    <end>", 1)[0]
        self.assertNotRegex(native_to_native, r"\bXHigh\s*=\s*0")
        self.assertNotRegex(native_to_native, r"\bYHigh\s*=\s*0")

    def test_xce_applies_register_cleanup_only_on_mode_transitions(self) -> None:
        blocks = instruction_blocks("XCE")
        native = [body for header, body in blocks if "ctx_EF=0" in header]
        emulation = [body for header, body in blocks if "ctx_EF=1" in header]
        self.assertEqual(len(native), 1)
        self.assertEqual(len(emulation), 1)

        native_body = native[0]
        to_emulation = native_body.split("\n#    <to_emulation>", 1)[1].split("\n    <to_native>", 1)[0]
        self.assertIn("XHigh = 0;", to_emulation)
        self.assertIn("YHigh = 0;", to_emulation)
        self.assertIn("SPHigh = 1;", to_emulation)
        self.assertIn("CF = 0;", native_body)

        emulation_body = emulation[0]
        to_native = emulation_body.split("\n    <to_native>", 1)[1].split("\n    <end>", 1)[0]
        self.assertIn("XHigh = 0;", to_native)
        self.assertIn("YHigh = 0;", to_native)
        self.assertIn("CF = 1;", emulation_body)

if __name__ == "__main__":
    unittest.main()
