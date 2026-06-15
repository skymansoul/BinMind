import os
import sys
import unittest
import tempfile
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from modules.ebpf_analyzer import EBPFAnalyzer, analyze_ebpf, disassemble_ebpf


class TestEBPFAnalyzer(unittest.TestCase):
    def setUp(self):
        """创建临时测试文件"""
        self.temp_file = tempfile.NamedTemporaryFile(delete=False)
        self.temp_file_path = self.temp_file.name
        self.temp_file.close()
    
    def tearDown(self):
        """清理临时文件"""
        if os.path.exists(self.temp_file_path):
            os.unlink(self.temp_file_path)
    
    def test_analyzer_init(self):
        analyzer = EBPFAnalyzer(self.temp_file_path)
        self.assertEqual(analyzer.file_path, self.temp_file_path)
    
    def test_invalid_file(self):
        with self.assertRaises(FileNotFoundError):
            analyzer = EBPFAnalyzer('/nonexistent/file.bpf')
    
    def test_parse_empty_data(self):
        analyzer = EBPFAnalyzer(self.temp_file_path)
        result = analyzer.parse_ebpf_binary()
        self.assertFalse(result)
    
    def test_analyze_empty_file(self):
        analyzer = EBPFAnalyzer(self.temp_file_path)
        result = analyzer.analyze()
        self.assertEqual(result.filename, os.path.basename(self.temp_file_path))
        self.assertEqual(result.security_score, 0)
    
    def test_generate_report(self):
        analyzer = EBPFAnalyzer(self.temp_file_path)
        report = analyzer.generate_report()
        self.assertIsInstance(report, str)
        self.assertIn('eBPF 程序安全分析报告', report)
    
    def test_disassemble_ebpf(self):
        result = disassemble_ebpf(self.temp_file_path)
        self.assertIsInstance(result, list)
    
    def test_analyze_ebpf_function(self):
        result = analyze_ebpf(self.temp_file_path)
        self.assertIsInstance(result.filename, str)
        self.assertIsInstance(result.vulnerabilities, list)
        self.assertIsInstance(result.warnings, list)


if __name__ == '__main__':
    unittest.main()