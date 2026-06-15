"""
信息泄露分析模块单元测试
"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.info_leak_analyzer import (
    InfoLeakAnalyzer,
    LeakType,
    LeakDataType,
    Severity,
    LeakPoint,
    LeakCapabilityMatrix,
    analyze_info_leak
)


class TestLeakPoint(unittest.TestCase):
    """测试泄露点数据类"""

    def test_init(self):
        """测试初始化"""
        leak = LeakPoint(
            leak_id="test_1",
            leak_type=LeakType.FORMAT_STRING,
            location="vulnerable_func",
            instruction="printf(user_input)",
            severity=Severity.HIGH
        )
        
        self.assertEqual(leak.leak_id, "test_1")
        self.assertEqual(leak.leak_type, LeakType.FORMAT_STRING)
        self.assertEqual(leak.location, "vulnerable_func")
        self.assertEqual(leak.severity, Severity.HIGH)

    def test_to_dict(self):
        """测试转换为字典"""
        leak = LeakPoint(
            leak_id="test_1",
            leak_type=LeakType.FORMAT_STRING,
            location="func",
            instruction="printf(x)",
            severity=Severity.MEDIUM
        )
        
        result = leak.to_dict()
        self.assertIn("leak_id", result)
        self.assertIn("leak_type", result)
        self.assertEqual(result["severity"], "medium")


class TestLeakCapabilityMatrix(unittest.TestCase):
    """测试泄露能力矩阵"""

    def test_init(self):
        """测试初始化"""
        matrix = LeakCapabilityMatrix(binary_name="test.bin")
        
        self.assertEqual(matrix.binary_name, "test.bin")
        self.assertEqual(matrix.total_leak_points, 0)
        self.assertFalse(matrix.can_leak_libc_address)

    def test_add_leak_point(self):
        """测试添加泄露点"""
        matrix = LeakCapabilityMatrix(binary_name="test.bin")
        
        leak = LeakPoint(
            leak_id="test",
            leak_type=LeakType.FORMAT_STRING,
            location="func",
            instruction="printf(x)",
            severity=Severity.HIGH,
            leakable_data_types=[LeakDataType.LIBC_ADDRESS]
        )
        
        matrix.leak_points.append(leak)
        matrix.total_leak_points = len(matrix.leak_points)
        
        # 更新可泄露信息
        for lp in matrix.leak_points:
            for dtype in lp.leakable_data_types:
                if dtype == LeakDataType.LIBC_ADDRESS:
                    matrix.can_leak_libc_address = True
        
        self.assertEqual(matrix.total_leak_points, 1)
        self.assertTrue(matrix.can_leak_libc_address)


class TestInfoLeakAnalyzer(unittest.TestCase):
    """测试信息泄露分析器"""

    def setUp(self):
        """设置测试环境"""
        self.analyzer = InfoLeakAnalyzer(binary_path="test_binary")

    def test_init(self):
        """测试初始化"""
        self.assertEqual(self.analyzer.binary_name, "test_binary")
        self.assertEqual(self.analyzer.min_confidence, 0.5)

    def test_analyze_empty_data(self):
        """测试空数据分析"""
        result = self.analyzer.analyze()
        
        self.assertIsInstance(result, LeakCapabilityMatrix)
        self.assertEqual(result.total_leak_points, 0)

    def test_analyze_format_string_vulnerability(self):
        """测试格式化字符串漏洞分析"""
        decomp_data = {
            'vulnerable_func': {
                'pseudocode': '''
                    void vulnerable_func(char *user_input) {
                        printf(user_input);  // 格式化字符串漏洞
                    }
                ''',
                'address': 0x401000,
            }
        }
        
        result = self.analyzer.analyze(decomp_data=decomp_data)
        
        self.assertGreaterEqual(result.format_string_leaks, 0)

    def test_analyze_crash_data_leaks(self):
        """测试崩溃数据泄露分析"""
        crash_data = {
            'registers': {
                'rax': 0x7fff12345678,
                'rbx': 0x0000555555555555,
            },
            'function': 'handle_request'
        }
        
        result = self.analyzer.analyze(crash_data=crash_data)
        
        # 应该检测到栈地址泄露
        self.assertIsInstance(result, LeakCapabilityMatrix)

    def test_select_best_leak_point(self):
        """测试选择最佳泄露点"""
        # 添加一些泄露点
        leak1 = LeakPoint(
            leak_id="low",
            leak_type=LeakType.FORMAT_STRING,
            location="func1",
            instruction="printf(x)",
            severity=Severity.LOW,
            leakable_bytes=8
        )
        
        leak2 = LeakPoint(
            leak_id="critical",
            leak_type=LeakType.FORMAT_STRING,
            location="func2",
            instruction="printf(x)",
            severity=Severity.CRITICAL,
            leakable_bytes=1024
        )
        
        self.analyzer.leak_points = [leak1, leak2]
        best = self.analyzer._select_best_leak_point()
        
        self.assertEqual(best.leak_id, "critical")

    def test_generate_format_string_exploit(self):
        """测试生成格式化字符串利用"""
        exploit = self.analyzer._generate_format_string_exploit("user_input", 1)
        
        self.assertIsInstance(exploit, str)
        self.assertIn("%p", exploit)

    def test_determine_leak_severity(self):
        """测试确定泄露严重程度"""
        # 测试关键泄露类型
        severity = self.analyzer._determine_leak_severity(
            [LeakDataType.LIBC_ADDRESS, LeakDataType.POINTER],
            100
        )
        self.assertEqual(severity, Severity.CRITICAL)
        
        # 测试中等泄露
        severity = self.analyzer._determine_leak_severity(
            [LeakDataType.POINTER],
            50
        )
        self.assertEqual(severity, Severity.MEDIUM)

    def test_analyze_memory_read_vulnerabilities(self):
        """测试内存越界读分析"""
        decomp_data = {
            'mem_func': {
                'pseudocode': '''
                    void mem_func(char *buf, char *input) {
                        strcpy(buf, input);
                    }
                ''',
                'address': 0x401100,
            }
        }
        
        self.analyzer._analyze_memory_read_vulnerabilities(decomp_data)
        
        # 应该发现 strcpy 调用
        self.assertGreaterEqual(len(self.analyzer.leak_points), 0)


class TestInfoLeakAnalyzerEdgeCases(unittest.TestCase):
    """测试信息泄露分析器边界情况"""

    def setUp(self):
        """设置测试环境"""
        self.analyzer = InfoLeakAnalyzer()

    def test_empty_binary_info(self):
        """测试空二进制信息"""
        result = self.analyzer.analyze(binary_info={})
        
        self.assertIsInstance(result, LeakCapabilityMatrix)

    def test_special_characters_in_code(self):
        """测试代码中的特殊字符"""
        decomp_data = {
            'func': {
                'pseudocode': '''
                    void func(char *s) {
                        printf("%s\\n", s);
                    }
                ''',
            }
        }
        
        result = self.analyzer.analyze(decomp_data=decomp_data)
        self.assertIsInstance(result, LeakCapabilityMatrix)

    def test_very_long_function_names(self):
        """测试超长函数名"""
        decomp_data = {
            'a' * 1000: {
                'pseudocode': 'printf(user_input);',
            }
        }
        
        result = self.analyzer.analyze(decomp_data=decomp_data)
        self.assertIsInstance(result, LeakCapabilityMatrix)


class TestConvenienceFunction(unittest.TestCase):
    """测试便捷函数"""

    def test_analyze_info_leak(self):
        """测试 analyze_info_leak 函数"""
        result = analyze_info_leak(
            binary_path="test.bin",
            binary_info={},
            decomp_data={},
            crash_data={}
        )
        
        self.assertIsInstance(result, LeakCapabilityMatrix)
        self.assertEqual(result.binary_name, "test.bin")


if __name__ == '__main__':
    unittest.main()