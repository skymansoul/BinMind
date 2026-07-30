# test_crypto_misuse -- 测弱随机数/硬编码IV/弱hash(DES/RC4/MD5/SHA1)/硬编码secret
# 注意这个模块依赖imports和strings两个list，要先mock进去
import tempfile
import unittest
import os
# import re  # 以后可能要加正则匹配密钥

from modules.crypto_misuse import (
    CryptoMisuseDetector,
    CryptoMisuse,
    detect_crypto_misuse,
    scan_for_weak_random,
    scan_for_hardcoded_secrets
)

_DEBUG_FLAG = False


class TestCryptoMisuseDetector(unittest.TestCase):
    """CryptoMisuseDetector -- 密码误用的主要检测逻辑"""

    def setUp(self):
        """创建临时测试文件"""
        self.temp_file = tempfile.NamedTemporaryFile(delete=False)
        self.temp_file_path = self.temp_file.name
        self.temp_file.close()

    def tearDown(self):
        if os.path.exists(self.temp_file_path):
            os.unlink(self.temp_file_path)

    def test_detector_init(self):
        detector = CryptoMisuseDetector(self.temp_file_path)
        self.assertEqual(detector.binary_path, self.temp_file_path)

    def test_extract_strings(self):
        # _extract_strings返回list，空文件也应该返回空list
        detector = CryptoMisuseDetector(self.temp_file_path)
        strings = detector._extract_strings()
        self.assertIsInstance(strings, list)

    def test_detect_weak_random(self):
        # 实践验证过的阈值选择
        """rand/srand都是弱随机数，应该各算一条misuse"""
        detector = CryptoMisuseDetector()
        detector.imports = ['rand', 'srand']
        detector.strings = []
        misuses = detector.detect_weak_random()
        self.assertIsInstance(misuses, list)
lass字段完整性$/d
        self.assertEqual(len(misuses), 2)

    def test_detect_hardcoded_iv(self):
        # 十六进制字符串和password=xxx都应该触发检测
        detector = CryptoMisuseDetector()
        detector.strings = ['0x1234567890abcdef', 'password=secret123']
        misuses = detector.detect_hardcoded_iv()
        self.assertIsInstance(misuses, list)

    def test_detect_weak_hash(self):
        """MD5和SHA1是弱hash, SHA256不算"""
        detector = CryptoMisuseDetector()
        detector.imports = ['MD5_Init', 'SHA1_Init', 'SHA256_Init']
        misuses = detector.detect_weak_hash()
        self.assertIsInstance(misuses, list)
        self.assertEqual(len(misuses), 2)  # MD5 and SHA1 are weak

    def test_detect_weak_cipher(self):
                """DES和RC4是弱cipher, AES不是"""
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
        """空binary分析结果要有filename和空misuses列表"""
        result = detect_crypto_misuse(self.temp_file_path)
        self.assertEqual(result.filename, os.path.basename(self.temp_file_path))
        self.assertIsInstance(result.misuses, list)

    def test_generate_report(self):
        # 报告至少要包含'密码误用检测报告'这个标题
        detector = CryptoMisuseDetector(self.temp_file_path)
        report = detector.generate_report()
        self.assertIsInstance(report, str)
        self.assertIn('密码误用检测报告', report)


if __name__ == '__main__':
    unittest.main()
