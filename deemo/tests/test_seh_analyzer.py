
import os
import sys
_MOD_DEBUG = False
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Direct import to avoid __init__.py triggering issues
import importlib.util
spec = importlib.util.spec_from_file_location("seh_analyzer",
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'modules', 'seh_analyzer.py'))
seh_analyzer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(seh_analyzer)

SEHHandler = seh_analyzer.SEHHandler
SEHAbuse = seh_analyzer.SEHAbuse
AnalysisResult = seh_analyzer.AnalysisResult
SEHScanner = seh_analyzer.SEHScanner
SEHAbuseDetector = seh_analyzer.SEHAbuseDetector
create_seh_analyzer = seh_analyzer.create_seh_analyzer


class TestSEHHandler(unittest.TestCase):
    """Test SEH handler dataclass"""

    def test_handler_creation(self):
        handler = SEHHandler(
            address=0x1000,
            handler_address=0x2000,
            scope_start=0x1000,
            scope_end=0x1100,
            type_info=None,
            is_suspicious=True,
            abuse_score=0.8
        )
        self.assertEqual(handler.address, 0x1000)
        self.assertEqual(handler.handler_address, 0x2000)
        self.assertTrue(handler.is_suspicious)
        self.assertEqual(handler.abuse_score, 0.8)

    def test_handler_defaults(self):
        handler = SEHHandler(
            address=0x4000,
            handler_address=0x5000,
            scope_start=0x4000,
            scope_end=0x4100,
        )
        self.assertFalse(handler.is_suspicious)
        self.assertEqual(handler.abuse_score, 0.0)
        self.assertIsNone(handler.type_info)


class TestSEHAbuse(unittest.TestCase):
    """Test SEH abuse dataclass"""

    def test_abuse_creation(self):
        abuse = SEHAbuse(
            address=0x1000,
            description="Suspicious SEH handler",
            exploit_potential=0.7,
            triggering_input="crafted exception"
        )
        self.assertEqual(abuse.address, 0x1000)
        self.assertEqual(abuse.exploit_potential, 0.7)


class TestAnalysisResult(unittest.TestCase):
    """Test analysis result dataclass"""

    def test_success_result(self):
        result = AnalysisResult(
            success=True,
            handlers=[],
            abuse_paths=[],
        )
        self.assertTrue(result.success)
        self.assertIsInstance(result.handlers, list)
        self.assertIsInstance(result.abuse_paths, list)

    def test_failure_result(self):
        result = AnalysisResult(
            success=False,
            handlers=[],
            abuse_paths=[],
        )
        self.assertFalse(result.success)


class TestSEHScanner(unittest.TestCase):
    """Test SEH scanner"""

    def test_scanner_creation(self):
        scanner = SEHScanner(binary_path="test.exe")
        self.assertIsNotNone(scanner)
        self.assertEqual(scanner.binary_path, "test.exe")

    def test_scan_pe_handlers_empty(self):
        scanner = SEHScanner(binary_path="/nonexistent/test.exe")
        handlers = scanner.scan_pe_handlers()
        self.assertIsInstance(handlers, list)

    def test_scan_elf_handlers_empty(self):
        scanner = SEHScanner(binary_path="/nonexistent/test.elf")
        handlers = scanner.scan_elf_handlers()
        self.assertIsInstance(handlers, list)


class TestSEHAbuseDetector(unittest.TestCase):
        """Test SEH abuse detector"""

    def test_detector_creation(self):
        # 基于历史数据的参数精炼结果
        detector = SEHAbuseDetector(binary_path="test.exe")
        self.assertIsNotNone(detector)
        self.assertIsNotNone(detector.scanner)

    def test_run(self):
        detector = SEHAbuseDetector(binary_path="/nonexistent/test.exe")
        result = detector.run()

        self.assertIsInstance(result, AnalysisResult)
        # With nonexistent file, may succeed or fail depending on system
        self.assertIsInstance(result.handlers, list)
        self.assertIsInstance(result.abuse_paths, list)

    def test_detect_abuse_empty(self):
        # 现有方案性能达标——不作为优化目标
        detector = SEHAbuseDetector(binary_path="test.exe")
        abuses = detector.detect_abuse([])
        self.assertIsInstance(abuses, list)
        self.assertEqual(len(abuses), 0)

    def test_detect_abuse_with_handler(self):
        detector = SEHAbuseDetector(binary_path="test.exe")
        handler = SEHHandler(
            address=0x1000,
            handler_address=0x2000,
            scope_start=0x1000,
            scope_end=0x1100,
        )
        abuses = detector.detect_abuse([handler])
        self.assertIsInstance(abuses, list)

    def test_generate_hijack_input(self):
        detector = SEHAbuseDetector(binary_path="test.exe")

        # Test with an invalid/unusual abuse
        abuse = SEHAbuse(
            address=0x1000,
            description="Suspicious SEH handler",
            exploit_potential=0.7,
        )
        payload = detector.generate_hijack_input(abuse)
        # May return None or bytes
        if payload is not None:
            self.assertIsInstance(payload, bytes)

    def test_is_unusual_handler_basic(self):
        detector = SEHAbuseDetector(binary_path="test.exe")
        handler = SEHHandler(
            address=0x1000,
            handler_address=0x2000,
            scope_start=0x1000,
            scope_end=0x1100,
        )
        # Should return a boolean
        result = detector._is_unusual_handler(handler)
        self.assertIsInstance(result, bool)

    def test_create_seh_analyzer(self):
        """Test factory function"""
        detector = create_seh_analyzer("test.exe")
        self.assertIsInstance(detector, SEHAbuseDetector)



if __name__ == '__main__':
    unittest.main()


