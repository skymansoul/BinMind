import unittest
import os
import tempfile
from modules.lattice_side_channel import LatticeSideChannelAnalyzer

class TestLatticeSideChannelAnalyzer(unittest.TestCase):
    """
    LatticeSideChannelAnalyzer 模块测试类
    """

    def setUp(self):
        """设置测试环境"""
        self.analyzer = LatticeSideChannelAnalyzer()
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        """清理测试环境"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_detect_lattice_operations_empty(self):
        """测试检测空函数列表"""
        result = self.analyzer._detect_lattice_operations([])
        self.assertEqual(len(result), 0)

    def test_detect_lattice_operations_poly_mul(self):
        """测试检测多项式乘法操作"""
        functions = ['poly_mul', 'ntru_mul', 'test_func']
        result = self.analyzer._detect_lattice_operations(functions)
        
        self.assertTrue(len(result) > 0)
        poly_ops = [r for r in result if 'polynomial' in r.operation_type.lower()]
        self.assertTrue(len(poly_ops) > 0)

    def test_detect_lattice_operations_ntt(self):
        """测试检测NTT操作"""
        functions = ['ntt_transform', 'kyber_ntt']
        result = self.analyzer._detect_lattice_operations(functions)
        
        ntt_ops = [r for r in result if 'NTT' in r.operation_type]
        self.assertTrue(len(ntt_ops) > 0)

    def test_detect_side_channel_vulnerabilities_empty(self):
        """测试检测空输入"""
        result = self.analyzer._detect_side_channel_vulnerabilities([], [])
        self.assertEqual(len(result), 0)

    def test_detect_side_channel_conditional(self):
        """测试检测条件分支漏洞"""
        functions = ['test_if_secret', 'normal_func']
        result = self.analyzer._detect_side_channel_vulnerabilities(functions, [])
        
        cond_vulns = [v for v in result if 'conditional' in v.vulnerability_type]
        self.assertTrue(len(cond_vulns) > 0)

    def test_detect_side_channel_memory(self):
        """测试检测内存访问模式漏洞"""
        strings = ['buffer[key]', 'normal_string']
        result = self.analyzer._detect_side_channel_vulnerabilities([], strings)
        
        mem_vulns = [v for v in result if 'memory_access' in v.vulnerability_type]
        self.assertTrue(len(mem_vulns) > 0)

    def test_identify_suspicious_functions(self):
        """测试识别可疑函数"""
        from modules.lattice_side_channel import PolynomialOperation
        
        ops = [
            PolynomialOperation(
                function_name='poly_mul',
                operation_type='polynomial multiplication',
                coefficient_handling='unknown',
                has_conditional_branching=True,
                has_memory_access_patterns=True,
                complexity='high'
            )
        ]
        
        result = self.analyzer._identify_suspicious_functions(ops)
        self.assertIn('poly_mul', result)

    def test_analyze_nonexistent_file(self):
        """测试分析不存在的文件"""
        result = self.analyzer.analyze_binary("/nonexistent/file.bin")
        self.assertEqual(result.summary, "文件不存在")

    def test_analyze_empty_file(self):
        """测试分析空文件"""
        test_file = os.path.join(self.temp_dir, 'empty.bin')
        with open(test_file, 'wb') as f:
            f.write(b'')
        
        result = self.analyzer.analyze_binary(test_file)
        self.assertIsNotNone(result)

    def test_format_report(self):
        """测试报告格式化"""
        from modules.lattice_side_channel import TimingAnalysisResult, SideChannelVulnerability
        
        vuln = SideChannelVulnerability(
            name='Test Vulnerability',
            vulnerability_type='test_type',
            severity='high',
            confidence=0.85,
            location=0,
            description='Test',
            mitigation='Test mitigation',
            affected_code='test_func'
        )
        
        result = TimingAnalysisResult(
            vulnerabilities=[vuln],
            suspicious_functions=['test_func'],
            timing_anomalies=1,
            summary='Test summary'
        )
        
        report = self.analyzer.format_report(result)
        self.assertIsInstance(report, str)
        self.assertIn('Test Vulnerability', report)

    def test_get_mitigation(self):
        """测试获取缓解建议"""
        mitigation = self.analyzer._get_mitigation('conditional_on_secret')
        self.assertIsInstance(mitigation, str)
        self.assertTrue(len(mitigation) > 0)


if __name__ == '__main__':
    unittest.main()
