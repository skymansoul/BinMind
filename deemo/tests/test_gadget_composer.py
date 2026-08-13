# ROP/JOP/COP/SROP -- most of the real logic has been rewritten in binary_analyzer
import os
import unittest
import pytest

from modules.gadget_composer import (
    ComposeResult,
    GadgetChain,
    GadgetComposer,
    GadgetDatabase,
    GadgetTemplate,
    GadgetType,
    TemplateEngine,
    create_gadget_composer,
)


class TestGadgetType(unittest.TestCase):
    """GadgetType enum: ROP / JOP / COP / SROP"""

    def test_gadget_type_values(self):
        self.assertEqual(GadgetType.ROP.value, "rop")
        self.assertEqual(GadgetType.JOP.value, "jop")
        self.assertEqual(GadgetType.COP.value, "cop")
        self.assertEqual(GadgetType.SROP.value, "srop")


class TestGadgetTemplate(unittest.TestCase):
    def test_template_creation(self):
        """Template object -- preconditions + effect"""
        template = GadgetTemplate(
            gadget_type=GadgetType.ROP,
            preconditions=["pop rdi", "ret"],
            effect="set rdi to controlled value",
        )
        if template is None:
            self.fail("GadgetTemplate creation returned None")
        self.assertEqual(template.gadget_type, GadgetType.ROP)
        self.assertEqual(len(template.preconditions), 2)
        self.assertEqual(template.effect, "set rdi to controlled value")


class TestGadgetChain(unittest.TestCase):
    def test_chain_creation(self):
        """Chain with two gadgets, 0.85 success probability"""
        chain = GadgetChain(
            gadgets=[0x1000, 0x1002],
            gadget_type=GadgetType.ROP,
            effects=["set rdi"],
            success_probability=0.85,
        )
        self.assertEqual(len(chain.gadgets), 2)
        self.assertEqual(chain.gadget_type, GadgetType.ROP)
        self.assertEqual(chain.success_probability, 0.85)


class TestComposeResult(unittest.TestCase):
    """ComposeResult: success and failure variants"""

    def test_success_result(self):
        chain = GadgetChain(
            gadgets=[0x1000],
            gadget_type=GadgetType.ROP,
            effects=["test"],
            success_probability=0.5,
        )
        result = ComposeResult(success=True, chain=chain)
        self.assertTrue(result.success)
        self.assertIsNotNone(result.chain)

    def test_failure_result(self):
        """Failure result -- chain should be None"""
        result = ComposeResult(success=False, chain=None)
        self.assertFalse(result.success)
        self.assertIsNone(result.chain)


class TestGadgetComposer(unittest.TestCase):
    """GadgetComposer -- needs a real binary on disk, so skip for now"""

    def test_composer_init(self):
        pytest.skip("GadgetComposer requires a real binary file on disk")

    def test_create_gadget_composer(self):
        pytest.skip("create_gadget_composer requires a real binary file on disk")


class TestGadgetScanner(unittest.TestCase):
    """Old GadgetScanner, replaced by GadgetDatabase"""

    def test_scanner_init(self):
        pytest.skip("GadgetScanner removed -- replaced by GadgetDatabase")

    def test_scan_memory_empty(self):
        pytest.skip(
            "GadgetScanner.scan_memory removed -- replaced by GadgetDatabase.scan"
        )

    def test_scan_memory_with_ret(self):
        pytest.skip(
            "GadgetScanner.scan_memory removed -- replaced by GadgetDatabase.scan"
        )

    def test_scan_memory_pop_rdi_ret(self):
        pytest.skip(
            "GadgetScanner.scan_memory removed -- replaced by GadgetDatabase.scan"
        )


class TestLegacyGadgetComposer(unittest.TestCase):
    """Legacy GadgetComposer -- most APIs removed"""

    def test_composer_init_legacy(self):
        pytest.skip(
            "Legacy GadgetComposer(list) removed -- constructor now takes binary_path"
        )

    def test_find_gadget_by_type(self):
        pytest.skip("find_gadget removed -- replaced by TemplateEngine.match_gadgets")

    def test_find_gadget_by_description(self):
        pytest.skip("find_gadget removed -- replaced by TemplateEngine.match_gadgets")

    def test_compose_chain_simple(self):
        pytest.skip(
            "compose_chain removed -- replaced by GadgetComposer.run with GadgetTemplate"
        )

    def test_compose_chain_complex(self):
        pytest.skip(
            "compose_chain removed -- replaced by GadgetComposer.run with GadgetTemplate"
        )

    def test_find_srop_chain(self):
        pytest.skip(
            "find_srop_chain removed -- SROP now handled via GadgetType.SROP template"
        )

    def test_generate_shellcode_chain(self):
        pytest.skip("generate_shellcode_chain removed")

    def test_calculate_probability(self):
        pytest.skip(
            "calculate_probability removed -- now computed internally in ComposeResult"
        )


class TestConvenienceFunctions(unittest.TestCase):
    """Convenience functions -- old API, all removed"""

    def test_scan_gadgets(self):
        pytest.skip("scan_gadgets removed -- use GadgetDatabase(binary_path).scan()")

    def test_create_gadget_chain(self):
        pytest.skip(
            "create_gadget_chain removed -- use GadgetComposer(binary_path).run(template)"
        )


if __name__ == "__main__":
    unittest.main()
