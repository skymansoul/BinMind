import os
import sys
_MOD_DEBUG = False
import unittest
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from modules.dse_bypass import (
    DSEBypassDetector,
    DSEBypassIndicator,
    detect_dse_bypass,
    check_driver_signature
)


class TestDSEBypassDetector(unittest.TestCase):
    def setUp(self):
        """创建临时测试文件"""
        self.temp_file = tempfile.NamedTemporaryFile(delete=False)
        self.temp_file_path = self.temp_file.name
        self.temp_file.close()

    def tearDown(self):
        """清理临时文件"""
        if os.path.exists(self.temp_file_path):
            os.unlink(self.temp_file_path)

    def test_detector_init(self):
        detector = DSEBypassDetector(self.temp_file_path)
        self.assertEqual(detector.driver_path, self.temp_file_path)

    def test_extract_strings(self):
        detector = DSEBypassDetector(self.temp_file_path)
        strings = detector._extract_strings()
        self.assertIsInstance(strings, list)

    def test_check_bypass_keywords(self):
        detector = DSEBypassDetector()
        detector.strings = ['g_CiEnabled', 'DSEFix', 'EfiGuard', 'testsigning']
        detector._check_bypass_keywords()
        self.assertGreater(len(detector.bypass_indicators), 0)

    def test_check_certificate_info(self):
        detector = DSEBypassDetector()
        detector.strings = ['Microsoft Windows Hardware Compatibility Publisher']
        detector._check_certificate_info()
        self.assertIn('issuer', detector.certificate_info)

    def test_analyze_empty_driver(self):
        result = detect_dse_bypass(self.temp_file_path)
        self.assertEqual(result.filename, os.path.basename(self.temp_file_path))
        self.assertIsInstance(result.bypass_indicators, list)

    def test_generate_report(self):
        detector = DSEBypassDetector(self.temp_file_path)
        report = detector.generate_report()
        self.assertIsInstance(report, str)
        self.assertIn('Windows 驱动签名强制绕过检测报告', report)

    def test_calculate_risk_score(self):
        detector = DSEBypassDetector()
        detector.is_signed = False
        detector.bypass_indicators = [
            DSEBypassIndicator('test', 'high', 'desc', 'ev', 'rec'),
            DSEBypassIndicator('test', 'medium', 'desc', 'ev', 'rec')
        ]
        score = detector._calculate_risk_score()
        self.assertEqual(score, 35)  # 100 - 30 (unsigned) - 25 (high) - 10 (medium) = 35



if __name__ == '__main__':
    unittest.main()
