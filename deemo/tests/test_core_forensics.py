#!/usr/bin/env python3
"""
Core Dump 取证分析模块单元测试
"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock, mock_open
import tempfile
import struct

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.core_forensics import (
    CoreForensicsAnalyzer,
    CoreForensicsReport,
    ForensicFinding,
    SeverityLevel,
    is_elf_core_file,
    calculate_entropy,
    mask_sensitive_content,
    analyze_core_dump,
    format_forensics_report
)


class TestCoreForensics(unittest.TestCase):
    """Core Dump 取证分析器测试"""
    
    def setUp(self):
        """测试前准备"""
        self.analyzer = CoreForensicsAnalyzer(timeout=60)
    
    def test_analyzer_initialization(self):
        """测试分析器初始化"""
        self.assertEqual(self.analyzer.timeout, 60)
        self.assertIsNotNone(self.analyzer)
    
    def test_is_elf_core_file_valid(self):
        """测试 ELF core 文件检测 - 有效 core"""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.core') as f:
            f.write(b'\x7fELF')
            f.write(struct.pack('<H', 4))
            temp_path = f.name
        
        try:
            self.assertTrue(is_elf_core_file(temp_path))
        finally:
            os.unlink(temp_path)
    
    def test_is_elf_core_file_invalid(self):
        """测试 ELF core 文件检测 - 无效文件"""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.bin') as f:
            f.write(b'\x00\x00\x00\x00')
            temp_path = f.name
        
        try:
            self.assertFalse(is_elf_core_file(temp_path))
        finally:
            os.unlink(temp_path)
    
    def test_is_elf_core_file_too_short(self):
        """测试 ELF core 文件检测 - 文件太短"""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.bin') as f:
            f.write(b'\x7fELF\x02')
            temp_path = f.name
        
        try:
            self.assertFalse(is_elf_core_file(temp_path))
        finally:
            os.unlink(temp_path)
    
    def test_calculate_entropy(self):
        """测试熵计算"""
        low_entropy_data = b'AAAAAAAABBBBBBBB'
        high_entropy_data = os.urandom(32)
        
        low_entropy = calculate_entropy(low_entropy_data)
        high_entropy = calculate_entropy(high_entropy_data)
        
        self.assertLess(low_entropy, high_entropy)
        self.assertGreater(high_entropy, 4.0)
    
    def test_calculate_entropy_empty(self):
        """测试空数据熵计算"""
        self.assertEqual(calculate_entropy(b''), 0.0)
        self.assertEqual(calculate_entropy(None), 0.0)
    
    def test_mask_sensitive_content_normal(self):
        """测试敏感内容脱敏"""
        content = "AKIAIOSFODNN7EXAMPLE"
        masked = mask_sensitive_content(content, "aws_key")
        self.assertEqual(masked, "AKIA****MPLE")
    
    def test_mask_sensitive_content_short(self):
        """测试短内容脱敏"""
        content = "short"
        masked = mask_sensitive_content(content)
        self.assertEqual(masked, "*****")
    
    def test_mask_sensitive_content_empty(self):
        """测试空内容脱敏"""
        self.assertEqual(mask_sensitive_content(""), "")
        self.assertEqual(mask_sensitive_content(None), None)
    
    def test_report_initialization(self):
        """测试报告初始化"""
        report = CoreForensicsReport(core_file_path="/test/core")
        
        self.assertEqual(report.core_file_path, "/test/core")
        self.assertFalse(report.is_elf_core)
        self.assertFalse(report.analysis_success)
        self.assertEqual(len(report.findings), 0)
        self.assertEqual(len(report.memory_mappings), 0)
    
    def test_report_severity_scoring(self):
        """测试严重程度评分"""
        report = CoreForensicsReport(core_file_path="/test/core")
        
        report.severity_score = 25
        self.assertEqual(report.severity_score, 25)
    
    def test_report_get_findings_by_severity(self):
        """测试按严重程度筛选发现项"""
        report = CoreForensicsReport(core_file_path="/test/core")
        
        finding1 = ForensicFinding(
            category="TEST",
            description="Test1",
            severity=SeverityLevel.CRITICAL,
            location="memory",
            content_preview="****"
        )
        finding2 = ForensicFinding(
            category="TEST",
            description="Test2",
            severity=SeverityLevel.HIGH,
            location="memory",
            content_preview="****"
        )
        
        report.findings.append(finding1)
        report.findings.append(finding2)
        
        critical = report.get_critical_findings()
        self.assertEqual(len(critical), 1)
        self.assertEqual(critical[0].severity, SeverityLevel.CRITICAL)
    
    def test_forensic_finding_to_dict(self):
        """测试 ForensicFinding 转换为字典"""
        finding = ForensicFinding(
            category="CRYPTO_KEY",
            description="RSA 私钥发现",
            severity=SeverityLevel.CRITICAL,
            location="/test/path",
            content_preview="-----BEGIN RSA****",
            raw_content="-----BEGIN RSA PRIVATE KEY-----",
            offset=0x1000
        )
        
        result = finding.to_dict()
        
        self.assertEqual(result['category'], "CRYPTO_KEY")
        self.assertEqual(result['severity'], "Critical")
        self.assertEqual(result['offset'], 0x1000)
    
    def test_report_to_dict(self):
        """测试报告转换为字典"""
        report = CoreForensicsReport(
            core_file_path="/test/core",
            process_info={'PID': 1234},
            is_elf_core=True,
            analysis_success=True
        )
        
        result = report.to_dict()
        
        self.assertEqual(result['core_file_path'], "/test/core")
        self.assertTrue(result['is_elf_core'])
        self.assertTrue(result['analysis_success'])
        self.assertEqual(result['process_info']['PID'], 1234)
    
    @patch('modules.core_forensics.os.path.exists')
    def test_analyze_file_not_found(self, mock_exists):
        """测试分析不存在的文件"""
        mock_exists.return_value = False
        
        report = self.analyzer.analyze("/nonexistent/core")
        
        self.assertFalse(report.analysis_success)
        self.assertIn("不存在", report.error_message)
    
    def test_analyze_with_empty_path(self):
        """测试空路径分析"""
        report = self.analyzer.analyze("")
        
        self.assertFalse(report.analysis_success)
    
    def test_format_forensics_report(self):
        """测试报告格式化"""
        report = CoreForensicsReport(
            core_file_path="/test/core",
            is_elf_core=True,
            analysis_success=True,
            severity_score=45,
            process_info={'e_type': 'ET_CORE'}
        )
        
        report.memory_mappings.append({
            'start': '0x400000',
            'end': '0x401000',
            'readable': True,
            'writable': False,
            'executable': True
        })
        
        formatted = format_forensics_report(report)
        
        self.assertIn("Core Dump 取证分析报告", formatted)
        self.assertIn("/test/core", formatted)
        self.assertIn("45", formatted)


class TestSensitivePatternDetection(unittest.TestCase):
    """敏感数据模式检测测试"""
    
    def test_aws_key_pattern(self):
        """测试 AWS 密钥模式检测"""
        from modules.core_forensics import SENSITIVE_PATTERNS
        
        aws_key = "AKIAIOSFODNN7EXAMPLE"
        match = SENSITIVE_PATTERNS['aws_access_key'].search(aws_key)
        self.assertIsNotNone(match)
    
    def test_jwt_token_pattern(self):
        """测试 JWT token 模式检测"""
        from modules.core_forensics import SENSITIVE_PATTERNS
        
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        match = SENSITIVE_PATTERNS['jwt_token'].search(jwt)
        self.assertIsNotNone(match)
    
    def test_rsa_private_key_pattern(self):
        """测试 RSA 私钥模式检测"""
        from modules.core_forensics import SENSITIVE_PATTERNS
        
        rsa_key = "-----BEGIN RSA PRIVATE KEY-----"
        match = SENSITIVE_PATTERNS['rsa_private_key'].search(rsa_key)
        self.assertIsNotNone(match)
    
    def test_github_token_pattern(self):
        """测试 GitHub token 模式检测"""
        from modules.core_forensics import SENSITIVE_PATTERNS
        
        token = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        match = SENSITIVE_PATTERNS['github_token'].search(token)
        self.assertIsNotNone(match)


class TestStringExtraction(unittest.TestCase):
    """字符串提取测试"""
    
    def setUp(self):
        self.analyzer = CoreForensicsAnalyzer()
    
    def test_extract_strings_basic(self):
        """测试基本字符串提取"""
        data = b'Hello\x00World\x00\x00\x00Test\x00'
        strings = self.analyzer._extract_strings(data, min_length=4)
        
        self.assertTrue(len(strings) >= 2)
        self.assertTrue(any('Hello' in s for s in strings))
        self.assertTrue(any('World' in s for s in strings))
    
    def test_extract_strings_min_length(self):
        """测试最小长度过滤"""
        data = b'a\x00ab\x00abc\x00abcd\x00'
        strings = self.analyzer._extract_strings(data, min_length=4)
        
        self.assertTrue(len(strings) >= 1)
        self.assertTrue(all(len(s) >= 4 for s in strings))
    
    def test_extract_strings_no_strings(self):
        """测试无字符串的数据"""
        data = b'\x00\x01\x02\x03\xff\xfe\xfd'
        strings = self.analyzer._extract_strings(data, min_length=4)
        
        self.assertEqual(len(strings), 0)


class TestHighEntropyDetection(unittest.TestCase):
    """高熵检测测试"""
    
    def setUp(self):
        self.report = CoreForensicsReport(core_file_path="/test/core")
    
    def test_search_high_entropy_strings(self):
        """测试高熵字符串搜索"""
        self.report.strings_found = [
            "AAAAAAAAAAAAAA",  # 低熵
            "random_token_1234567890abcdef",  # 高熵
            "another_random_string_xyz123",  # 高熵
        ]
        
        self.analyzer._search_high_entropy_strings(self.report)
        
        high_entropy_findings = [f for f in self.report.findings 
                                 if f.category == 'HIGH_ENTROPY']
        self.assertGreaterEqual(len(high_entropy_findings), 2)


if __name__ == '__main__':
    unittest.main()
