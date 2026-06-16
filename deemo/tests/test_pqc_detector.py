import unittest
import os
import tempfile
from modules.pqc_detector import PQCDetector, PQC_CONSTANTS

class TestPQCDetector(unittest.TestCase):
    """
    PQCDetector 模块测试类
    """

    def setUp(self):
        """设置测试环境"""
        self.detector = PQCDetector()
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        """清理测试环境"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_calculate_entropy(self):
        """测试熵计算"""
        high_entropy = self.detector._calculate_entropy(os.urandom(256))
        low_entropy = self.detector._calculate_entropy(b'\x00' * 256)
        
        self.assertTrue(high_entropy > 7.0)
        self.assertTrue(low_entropy < 1.0)

    def test_scan_for_constant(self):
        """测试常量扫描"""
        data = b'hello KYBER world'
        result = self.detector._scan_for_constant(data, b'KYBER')
        
        self.assertTrue(len(result) > 0)
        self.assertEqual(result[0], 6)

    def test_scan_bytes_empty(self):
        """测试扫描空数据"""
        result = self.detector._detect_pqc_algorithms(b'')
        self.assertEqual(len(result), 0)

    def test_scan_bytes_with_kyber(self):
        """测试扫描包含Kyber常量的数据"""
        kyber_sig = b'KYBER'
        data = b'prefix' + kyber_sig + b'suffix'
        
        result = self.detector._detect_pqc_algorithms(data)
        self.assertTrue(len(result) > 0)
        
        kyber_matches = [r for r in result if r.algorithm.name == 'Kyber']
        self.assertTrue(len(kyber_matches) > 0)

    def test_scan_bytes_with_dilithium(self):
        """测试扫描包含Dilithium常量的数据"""
        dilithium_sig = b'DILITHIUM'
        data = b'code' + dilithium_sig + b'more code'
        
        result = self.detector._detect_pqc_algorithms(data)
        dilithium_matches = [r for r in result if r.algorithm.name == 'Dilithium']
        self.assertTrue(len(dilithium_matches) > 0)

    def test_analyze_nonexistent_file(self):
        """测试分析不存在的文件"""
        result = self.detector.analyze_binary("/nonexistent/file.bin")
        self.assertEqual(result.summary, "文件不存在")

    def test_analyze_empty_file(self):
        """测试分析空文件"""
        test_file = os.path.join(self.temp_dir, 'empty.bin')
        with open(test_file, 'wb') as f:
            f.write(b'')
        
        result = self.detector.analyze_binary(test_file)
        self.assertIsNotNone(result)
        self.assertEqual(len(result.pqc_algorithms_found), 0)

    def test_analyze_file_with_pqc(self):
        """测试分析包含PQC常量的文件"""
        kyber_sig = b'KYBER'
        test_file = os.path.join(self.temp_dir, 'pqc_test.bin')
        with open(test_file, 'wb') as f:
            f.write(kyber_sig)
        
        result = self.detector.analyze_binary(test_file)
        self.assertIsNotNone(result)
        self.assertTrue(len(result.pqc_algorithms_found) > 0)

    def test_generate_migration_warnings(self):
        """测试生成迁移警告"""
        classical_algs = ['RSA', 'ECDSA']
        warnings = self.detector._generate_migration_warnings(classical_algs)
        
        self.assertTrue(len(warnings) > 0)
        rsa_warnings = [w for w in warnings if w.algorithm_name == 'RSA']
        self.assertTrue(len(rsa_warnings) > 0)

    def test_format_report(self):
        """测试报告格式化"""
        from modules.pqc_detector import PQCAnalysisResult, PQCAlgorithm, PQCDetectionResult
        
        pqc_alg = PQCAlgorithm(
            name='Kyber',
            family='lattice',
            algorithm_type='KEM',
            nist_status='standardized',
            key_size=128,
            security_level='NIST-L1',
            recommended=True,
            description='Test'
        )
        
        result = PQCAnalysisResult(
            pqc_algorithms_found=[PQCDetectionResult(algorithm=pqc_alg, confidence=1.0, offset=0)],
            classical_algorithms_found=['RSA'],
            migration_warnings=[],
            summary='Test summary'
        )
        
        report = self.detector.format_report(result)
        self.assertIsInstance(report, str)
        self.assertIn('Kyber', report)

    def test_pqc_constants_defined(self):
        """测试PQC常量定义"""
        self.assertIn('Kyber', PQC_CONSTANTS)
        self.assertIn('Dilithium', PQC_CONSTANTS)
        self.assertIn('NTRU', PQC_CONSTANTS)
        self.assertIn('Falcon', PQC_CONSTANTS)


if __name__ == '__main__':
    unittest.main()
