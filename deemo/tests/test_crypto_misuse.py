import os
import sys
import unittest
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from modules.crypto_misuse import (
    CryptoMisuseDetector,
    CryptoMisuse,
    detect_crypto_misuse,
    scan_for_weak_random,
    scan_for_hardcoded_secrets
)


class TestCryptoMisuseDetector(unittest.TestCase):
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
        detector = CryptoMisuseDetector(self.temp_file_path)
        self.assertEqual(detector.binary_path, self.temp_file_path)
    
    def test_extract_strings(self):
        detector = CryptoMisuseDetector(self.temp_file_path)
        strings = detector._extract_strings()
        self.assertIsInstance(strings, list)
    
    def test_detect_weak_random(self):
        detector = CryptoMisuseDetector()
        detector.imports = ['rand', 'srand']
        detector.strings = []
        misuses = detector.detect_weak_random()
        self.assertIsInstance(misuses, list)
        self.assertEqual(len(misuses), 2)
    
    def test_detect_hardcoded_iv(self):
        detector = CryptoMisuseDetector()
        detector.strings = ['0x1234567890abcdef', 'password=secret123']
        misuses = detector.detect_hardcoded_iv()
        self.assertIsInstance(misuses, list)
    
    def test_detect_weak_hash(self):
        detector = CryptoMisuseDetector()
        detector.imports = ['MD5_Init', 'SHA1_Init', 'SHA256_Init']
        misuses = detector.detect_weak_hash()
        self.assertIsInstance(misuses, list)
        self.assertEqual(len(misuses), 2)  # MD5 and SHA1 are weak
    
    def test_detect_weak_cipher(self):
        detector = CryptoMisuseDetector()
        detector.imports = ['DES_encrypt', 'AES_encrypt', 'RC4_encrypt']
        misuses = detector.detect_weak_cipher()
        self.assertIsInstance(misuses, list)
        self.assertEqual(len(misuses), 2)  # DES and RC4 are weak
    
    def test_detect_hardcoded_secrets(self):
        detector = CryptoMisuseDetector()
        detector.strings = [
            'password=supersecret123',
            'api_key=abcdef1234567890',
            'secret=0x1234567890abcdef'
        ]
        misuses = detector.detect_hardcoded_secrets()
        self.assertIsInstance(misuses, list)
    
    def test_analyze_empty_binary(self):
        result = detect_crypto_misuse(self.temp_file_path)
        self.assertEqual(result.filename, os.path.basename(self.temp_file_path))
        self.assertIsInstance(result.misuses, list)
    
    def test_generate_report(self):
        detector = CryptoMisuseDetector(self.temp_file_path)
        report = detector.generate_report()
        self.assertIsInstance(report, str)
        self.assertIn('密码误用检测报告', report)


if __name__ == '__main__':
    unittest.main()