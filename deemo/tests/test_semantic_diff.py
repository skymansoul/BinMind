
"""
Cross-version binary semantic diff analysis engine unit tests
"""

import os
_MOD_DEBUG = False
import sys
import unittest
import tempfile
import shutil

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.semantic_diff import (
    SemanticDiffer, SymbolicSignatureExtractor,
    SemanticSignature, FunctionSemantics,
    PatchDelta, VersionComparison, SignatureType, CrossVersionAnalyzer,
)
from modules.ir_lifter import FunctionIR, BasicBlock, IRType


class TestSignatureTypeEnum(unittest.TestCase):
    """Signature type enum test"""

    def test_signature_type_values(self):
        self.assertEqual(SignatureType.FUNCTION_ENTRY.value, "function_entry")
        self.assertEqual(SignatureType.FUNCTION_EXIT.value, "function_exit")
        self.assertEqual(SignatureType.BASIC_BLOCK.value, "basic_block")
        self.assertEqual(SignatureType.CALL_SITE.value, "call_site")
        self.assertEqual(SignatureType.MEMORY_ACCESS.value, "memory_access")
        self.assertEqual(SignatureType.REGISTER_USE.value, "register_use")
        self.assertEqual(SignatureType.DATA_FLOW.value, "data_flow")


class TestSemanticSignatureDataclass(unittest.TestCase):
    """SemanticSignature dataclass test"""

    def test_semantic_signature_creation(self):
        signature = SemanticSignature(
            signature_type=SignatureType.BASIC_BLOCK,
            address=0x401000,
            features={"instruction_count": 5},
        )

        self.assertEqual(signature.signature_type, SignatureType.BASIC_BLOCK)
        self.assertEqual(signature.address, 0x401000)
        self.assertEqual(signature.features, {"instruction_count": 5})
        self.assertTrue(len(signature.hash) > 0)

    def test_semantic_signature_hash_uniqueness(self):
        sig1 = SemanticSignature(
            signature_type=SignatureType.BASIC_BLOCK,
            address=0x401000,
            features={"test": 1},
        )
        sig2 = SemanticSignature(
            signature_type=SignatureType.BASIC_BLOCK,
            address=0x402000,
            features={"test": 2},
        )
        self.assertNotEqual(sig1.hash, sig2.hash)

    def test_semantic_signature_hash_same(self):
        sig1 = SemanticSignature(
            signature_type=SignatureType.BASIC_BLOCK,
            address=0x401000,
            features={"test": 1},
        )
        sig2 = SemanticSignature(
            signature_type=SignatureType.BASIC_BLOCK,
            address=0x401000,
            features={"test": 1},
        )
        self.assertEqual(sig1.hash, sig2.hash)


class TestFunctionSemanticsDataclass(unittest.TestCase):
    """FunctionSemantics dataclass test"""

    def test_function_semantics_creation(self):
        sig = SemanticSignature(
            signature_type=SignatureType.BASIC_BLOCK,
            address=0x401000,
            features={},
        )
        func_sem = FunctionSemantics(
            function_name="main",
            address=0x401000,
            signatures=[sig],
            control_flow_graph={},
            data_dependencies={},
            side_effects=set(),
        )

        self.assertEqual(func_sem.function_name, "main")
        self.assertEqual(func_sem.address, 0x401000)
        self.assertEqual(len(func_sem.signatures), 1)

    def test_get_unique_signature(self):
        sig = SemanticSignature(
            signature_type=SignatureType.BASIC_BLOCK,
            address=0x401000,
            features={},
        )
        func_sem = FunctionSemantics(
            function_name="main",
            address=0x401000,
            signatures=[sig],
            control_flow_graph={},
            data_dependencies={},
            side_effects=set(),
        )
        unique = func_sem.get_unique_signature()
        self.assertIsInstance(unique, str)
        self.assertTrue(len(unique) > 0)


class TestPatchDeltaDataclass(unittest.TestCase):
    """PatchDelta dataclass test"""

    def test_patch_delta_creation(self):
        delta = PatchDelta(
            type="security_fix",
            old_address=0x401000,
            new_address=0x402000,
            description="Fixed buffer overflow",
            severity="critical",
            trigger_condition="Large input > 256 bytes",
        )

        self.assertEqual(delta.type, "security_fix")
        self.assertEqual(delta.old_address, 0x401000)
        self.assertEqual(delta.severity, "critical")

    def test_patch_delta_no_change(self):
        delta = PatchDelta(
            type="no_change",
            old_address=0x401000,
            new_address=0x402000,
            description="Function semantics unchanged",
            severity="none",
            trigger_condition=None,
        )

        self.assertEqual(delta.type, "no_change")
        self.assertEqual(delta.severity, "none")


class TestVersionComparisonDataclass(unittest.TestCase):
    """VersionComparison dataclass test"""

    def test_version_comparison_creation(self):
        comp = VersionComparison(
            version_old="1.0",
            version_new="2.0",
            functions_added=[],
            functions_removed=[],
            functions_changed=[],
            patches=[],
            one_day_candidates=[],
        )

        self.assertEqual(comp.version_old, "1.0")
        self.assertEqual(comp.version_new, "2.0")
        self.assertEqual(len(comp.patches), 0)


class TestSemanticDiffer(unittest.TestCase):
    """SemanticDiffer test"""

    def test_compare_functions_no_change(self):
        differ = SemanticDiffer()

        sig = SemanticSignature(
            signature_type=SignatureType.BASIC_BLOCK,
            address=0x401000,
            features={"test": 1},
        )
        old_func = FunctionSemantics(
            function_name="test_func",
            address=0x401000,
            signatures=[sig],
            control_flow_graph={0x401000: []},
            data_dependencies={},
            side_effects=set(),
        )
        new_func = FunctionSemantics(
            function_name="test_func",
            address=0x402000,
            signatures=[sig],
            control_flow_graph={0x402000: []},
            data_dependencies={},
            side_effects=set(),
        )

        delta = differ.compare_functions(old_func, new_func)
        self.assertIsInstance(delta, PatchDelta)
        self.assertEqual(delta.type, "no_change")
        self.assertEqual(delta.severity, "none")


class TestSymbolicSignatureExtractor(unittest.TestCase):
    """SymbolicSignatureExtractor test"""

    def test_extractor_creation(self):
        # SymbolicSignatureExtractor requires a binary_analyzer argument
        # Create a simple mock
        class MockAnalyzer:
            def get_function(self, addr):
                return None

        extractor = SymbolicSignatureExtractor(MockAnalyzer())
        self.assertIsNotNone(extractor)

    def test_extract_function_signature_not_found(self):
        class MockAnalyzer:
            def get_function(self, addr):
                return None

        extractor = SymbolicSignatureExtractor(MockAnalyzer())

        with self.assertRaises(ValueError):
            extractor.extract_function_signature(0x401000)


class TestCrossVersionAnalyzer(unittest.TestCase):
    """CrossVersionAnalyzer test"""

    def test_analyzer_creation(self):
        analyzer = CrossVersionAnalyzer(
            old_binary_path="/nonexistent/old.bin",
            new_binary_path="/nonexistent/new.bin",
        )
        self.assertIsNotNone(analyzer)



if __name__ == '__main__':
    unittest.main()


