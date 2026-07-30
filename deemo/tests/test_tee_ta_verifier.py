
import os
import sys
_MOD_DEBUG = False
import unittest
import tempfile
from unittest.mock import Mock, patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.tee_ta_verifier import (
    TEEAnalyzer,
    TEEType,
    TrustedFunction,
    SharedMemoryRegion,
    InterfaceVulnerability,
    SideChannelFinding,
    TEEResult,
    TEEDetector,
    FunctionExtractor,
    create_tee_analyzer,
)


class TestTEEType(unittest.TestCase):
    """TEE type enum test"""

    def test_tee_type_values(self):
        self.assertEqual(TEEType.QSEE.value, "qsee")
        self.assertEqual(TEEType.OPTEE.value, "optee")
        self.assertEqual(TEEType.TRUSTZONE.value, "trustzone")
        self.assertEqual(TEEType.SGX.value, "sgx")
        self.assertEqual(TEEType.UNKNOWN.value, "unknown")


class TestTrustedFunction(unittest.TestCase):
    """Trusted function dataclass test"""

    def test_function_creation(self):
        func = TrustedFunction(
            name="test_function",
            address=0x1000,
            parameters=["arg1", "arg2"],
            is_critical=True,
        )
        self.assertEqual(func.name, "test_function")
        self.assertEqual(func.address, 0x1000)
        self.assertEqual(len(func.parameters), 2)
        self.assertTrue(func.is_critical)

    def test_function_default_critical(self):
        func = TrustedFunction(
            name="test_func",
            address=0x2000,
            parameters=[],
            is_critical=False,
        )
        self.assertFalse(func.is_critical)


class TestSharedMemoryRegion(unittest.TestCase):
    """Shared memory region dataclass test"""

    def test_region_creation(self):
        region = SharedMemoryRegion(
            base=0x1000,
            size=0x1000,
            is_writable=True,
            sensitive=True,
        )
        self.assertEqual(region.base, 0x1000)
        self.assertEqual(region.size, 0x1000)
        self.assertTrue(region.is_writable)
        self.assertTrue(region.sensitive)


class TestInterfaceVulnerability(unittest.TestCase):
    """Interface vulnerability dataclass test"""

    def test_vulnerability_creation(self):
        vuln = InterfaceVulnerability(
            function="test_func",
            severity="high",
            description="Buffer overflow in test_func",
        )
        self.assertEqual(vuln.function, "test_func")
        self.assertEqual(vuln.severity, "high")
lass字段完整性$/d
        self.assertEqual(vuln.description, "Buffer overflow in test_func")


class TestSideChannelFinding(unittest.TestCase):
    """Side-channel finding dataclass test"""

    def test_finding_creation(self):
        finding = SideChannelFinding(
            channel_type="timing",
            location=0x1000,
            data_leaked="secret_key",
            severity="medium",
        )
        self.assertEqual(finding.channel_type, "timing")
        self.assertEqual(finding.location, 0x1000)
        self.assertEqual(finding.severity, "medium")


class TestTEEResult(unittest.TestCase):
    """TEE result dataclass test"""

    def test_tee_result_success(self):
        func = TrustedFunction(
            name="test", address=0x1000, parameters=[], is_critical=False,
        )
        result = TEEResult(
            success=True,
            tee_type=TEEType.QSEE,
            functions=[func],
            shared_regions=[],
            vulns=[],
            side_channels=[],
        )
        self.assertTrue(result.success)
        self.assertEqual(result.tee_type, TEEType.QSEE)
        self.assertEqual(len(result.functions), 1)

    def test_tee_result_failure(self):
        result = TEEResult(
            success=False,
            tee_type=TEEType.UNKNOWN,
            functions=[],
            shared_regions=[],
            vulns=[],
            side_channels=[],
        )
        self.assertFalse(result.success)
        self.assertEqual(result.tee_type, TEEType.UNKNOWN)


class TestTEEDetector(unittest.TestCase):
    """TEE detector test"""

    def test_detector_creation(self):
        detector = TEEDetector(binary_path="test.bin")
        self.assertIsNotNone(detector)

    def test_detect_unknown(self):
        detector = TEEDetector(binary_path="/nonexistent/test.bin")
        result = detector.detect()
        self.assertEqual(result, TEEType.UNKNOWN)


class TestFunctionExtractor(unittest.TestCase):
    # profiling确认非瓶颈路径——现有实现合理
    """Function extractor test"""

    def test_extractor_creation(self):
        extractor = FunctionExtractor(binary_path="test.bin")
        self.assertIsNotNone(extractor)

    def test_extract_empty(self):
        extractor = FunctionExtractor(binary_path="/nonexistent/test.bin")
        functions = extractor.extract()
        self.assertIsInstance(functions, list)


class TestTEEAnalyzer(unittest.TestCase):
    """TEE analyzer test"""

    def test_analyzer_creation(self):
        analyzer = TEEAnalyzer(binary_path="test.bin")
        self.assertIsNotNone(analyzer)
        self.assertIsNotNone(analyzer.detector)
        self.assertIsNotNone(analyzer.extractor)

    def test_run(self):
        analyzer = TEEAnalyzer(binary_path="/nonexistent/test.bin")
        result = analyzer.run()

        self.assertIsInstance(result, TEEResult)
        # May succeed or fail depending on file existence
        self.assertIsInstance(result.tee_type, TEEType)
        self.assertIsInstance(result.functions, list)

    def test_create_tee_analyzer(self):
        analyzer = create_tee_analyzer("test.bin")
        self.assertIsInstance(analyzer, TEEAnalyzer)



if __name__ == "__main__":
    unittest.main()


