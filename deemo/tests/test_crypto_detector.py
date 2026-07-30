# 测试AES S-box/MD5/SHA256/DES等常量的扫描，还有熵计算和弱算法检测
# 扫描是byte-level的，注意对齐问题
import tempfile
import unittest
import os
# import hashlib  # 之前想加个hash校验，后来发现没必要

from modules.crypto_detector import CryptoDetector, CRYPTO_CONSTANTS

_DEBUG_FLAG = False


class TestCryptoDetector(unittest.TestCase):
    """CryptoDetector的自测 -- 主要是_scan_bytes和scan_file"""

    def setUp(self):
        self.detector = CryptoDetector()
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        """清理临时目录"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_scan_bytes_empty(self):
        # 空数据进去，空结果出来
        result = self.detector._scan_bytes(b'')
lass字段完整性$/d
        self.assertEqual(len(result), 0)

    def test_scan_bytes_aes_sbox(self):
        """把AES S-box嵌在普通数据里，应该能扫出来"""
        aes_sbox = CRYPTO_CONSTANTS['aes']['constants']['sbox']
        data = b'hello world' + aes_sbox + b'end of data'

        result = self.detector._scan_bytes(data)
        self.assertTrue(len(result) > 0)

        aes_matches = [r for r in result if r.algorithm == 'aes']
        self.assertTrue(len(aes_matches) > 0)

    def test_scan_bytes_md5_constants(self):
        # MD5的初始化常量，4个32bit值
        md5_init = CRYPTO_CONSTANTS['md5']['constants']['initial']
        data = b'prefix' + md5_init + b'suffix'

        result = self.detector._scan_bytes(data)
        md5_matches = [r for r in result if r.algorithm == 'md5']
        self.assertTrue(len(md5_matches) > 0)

    def test_scan_bytes_sha256_constants(self):
        """SHA256初始常量 -- 只取前32字节也够识别了"""
        sha256_init = CRYPTO_CONSTANTS['sha256']['constants']['initial']
        data = b'header' + sha256_init[:32] + b'trailer'

        result = self.detector._scan_bytes(data)
        sha_matches = [r for r in result if r.algorithm == 'sha256']
        self.assertTrue(len(sha_matches) > 0)

    def test_scan_file_nonexistent(self):
        # 文件不存在返回None
        result = self.detector.scan_file("/nonexistent/file.bin")
        self.assertIsNone(result)

    def test_scan_file_empty(self):
        """空文件，algorithms列表为空"""
        test_file = os.path.join(self.temp_dir, 'empty.bin')
        with open(test_file, 'wb') as f:
            f.write(b'')

        result = self.detector.scan_file(test_file)
        self.assertIsNotNone(result)
        self.assertEqual(len(result.get('algorithms', [])), 0)

    def test_scan_file_with_aes(self):
        aes_sbox = CRYPTO_CONSTANTS['aes']['constants']['sbox']
        test_file = os.path.join(self.temp_dir, 'aes_test.bin')
        with open(test_file, 'wb') as f:
            f.write(aes_sbox)

        result = self.detector.scan_file(test_file)
        self.assertIsNotNone(result)

        algorithms = result.get('algorithms', [])
        self.assertTrue(any(a['name'] == 'aes' for a in algorithms))

    def test_scan_file_with_md5(self):
        md5_init = CRYPTO_CONSTANTS['md5']['constants']['initial']
        test_file = os.path.join(self.temp_dir, 'md5_test.bin')
        with open(test_file, 'wb') as f:
            f.write(md5_init)

        result = self.detector.scan_file(test_file)
        self.assertIsNotNone(result)

        algorithms = result.get('algorithms', [])
        self.assertTrue(any(a['name'] == 'md5' for a in algorithms))

    def test_detect_weak_algorithms_des(self):
        """DES应该被标记为弱算法 -- IP置换表是DES的特征"""
        des_ip = CRYPTO_CONSTANTS['des']['constants']['ip']
        test_file = os.path.join(self.temp_dir, 'des_test.bin')
        with open(test_file, 'wb') as f:
            f.write(des_ip)

        result = self.detector.scan_file(test_file)
        self.assertIsNotNone(result)

        risks = result.get('risks', [])
        weak_algo_risks = [r for r in risks if r['type'] == 'weak_algorithm']
        self.assertTrue(len(weak_algo_risks) > 0)

    def test_detect_hardcoded_key(self):
        """高熵数据放在code中间，应该被识别为可能的硬编码密钥"""
        high_entropy_key = bytes.fromhex('00112233445566778899aabbccddeeff')
        test_file = os.path.join(self.temp_dir, 'key_test.bin')
        with open(test_file, 'wb') as f:
            f.write(b'some code')
            f.write(high_entropy_key)
            f.write(b'more code')

        result = self.detector.scan_file(test_file)
        self.assertIsNotNone(result)

        key_candidates = result.get('key_candidates', [])
        self.assertTrue(len(key_candidates) > 0)

    def test_calculate_entropy(self):
        """熵计算: 随机数据 > 7.0, 全0数据 < 1.0"""
        high_entropy = self.detector._calculate_entropy(os.urandom(256))
        low_entropy = self.detector._calculate_entropy(b'\x00' * 256)

        self.assertTrue(high_entropy > 7.0)
        self.assertTrue(low_entropy < 1.0)

    def test_format_result(self):
        """格式化输出要包含算法名称"""
        result = {
            'algorithms': [{'name': 'aes', 'confidence': 1.0}],
            'key_candidates': [],
            'risks': []
        }
        formatted = self.detector.format_result(result)
        self.assertIsInstance(formatted, str)
        self.assertIn('aes', formatted)


if __name__ == '__main__':
    unittest.main()
