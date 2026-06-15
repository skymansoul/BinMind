import unittest
import os
import tempfile
from modules.crypto_detector import CryptoDetector, CRYPTO_CONSTANTS


class TestCryptoDetector(unittest.TestCase):
    """
    CryptoDetector 模块测试类
    """

    def setUp(self):
        """设置测试环境"""
        self.detector = CryptoDetector()
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        """清理测试环境"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_scan_bytes_empty(self):
        """测试扫描空数据"""
        result = self.detector._scan_bytes(b'')
        self.assertEqual(len(result), 0)

    def test_scan_bytes_aes_sbox(self):
        """测试扫描 AES S-box"""
        aes_sbox = CRYPTO_CONSTANTS['aes']['constants']['sbox']
        data = b'hello world' + aes_sbox + b'end of data'
        
        result = self.detector._scan_bytes(data)
        self.assertTrue(len(result) > 0)
        
        aes_matches = [r for r in result if r.algorithm == 'aes']
        self.assertTrue(len(aes_matches) > 0)

    def test_scan_bytes_md5_constants(self):
        """测试扫描 MD5 常量"""
        md5_init = CRYPTO_CONSTANTS['md5']['constants']['initial']
        data = b'prefix' + md5_init + b'suffix'
        
        result = self.detector._scan_bytes(data)
        md5_matches = [r for r in result if r.algorithm == 'md5']
        self.assertTrue(len(md5_matches) > 0)

    def test_scan_bytes_sha256_constants(self):
        """测试扫描 SHA-256 常量"""
        sha256_init = CRYPTO_CONSTANTS['sha256']['constants']['initial']
        data = b'header' + sha256_init[:32] + b'trailer'
        
        result = self.detector._scan_bytes(data)
        sha_matches = [r for r in result if r.algorithm == 'sha256']
        self.assertTrue(len(sha_matches) > 0)

    def test_scan_file_nonexistent(self):
        """测试扫描不存在的文件"""
        result = self.detector.scan_file("/nonexistent/file.bin")
        self.assertIsNone(result)

    def test_scan_file_empty(self):
        """测试扫描空文件"""
        test_file = os.path.join(self.temp_dir, 'empty.bin')
        with open(test_file, 'wb') as f:
            f.write(b'')
        
        result = self.detector.scan_file(test_file)
        self.assertIsNotNone(result)
        self.assertEqual(len(result.get('algorithms', [])), 0)

    def test_scan_file_with_aes(self):
        """测试扫描包含 AES S-box 的文件"""
        aes_sbox = CRYPTO_CONSTANTS['aes']['constants']['sbox']
        test_file = os.path.join(self.temp_dir, 'aes_test.bin')
        with open(test_file, 'wb') as f:
            f.write(aes_sbox)
        
        result = self.detector.scan_file(test_file)
        self.assertIsNotNone(result)
        
        algorithms = result.get('algorithms', [])
        self.assertTrue(any(a['name'] == 'aes' for a in algorithms))

    def test_scan_file_with_md5(self):
        """测试扫描包含 MD5 常量的文件"""
        md5_init = CRYPTO_CONSTANTS['md5']['constants']['initial']
        test_file = os.path.join(self.temp_dir, 'md5_test.bin')
        with open(test_file, 'wb') as f:
            f.write(md5_init)
        
        result = self.detector.scan_file(test_file)
        self.assertIsNotNone(result)
        
        algorithms = result.get('algorithms', [])
        self.assertTrue(any(a['name'] == 'md5' for a in algorithms))

    def test_detect_weak_algorithms_des(self):
        """测试检测 DES 弱算法"""
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
        """测试检测硬编码密钥"""
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
        """测试熵计算"""
        high_entropy = self.detector._calculate_entropy(os.urandom(256))
        low_entropy = self.detector._calculate_entropy(b'\x00' * 256)
        
        self.assertTrue(high_entropy > 7.0)
        self.assertTrue(low_entropy < 1.0)

    def test_format_result(self):
        """测试结果格式化"""
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