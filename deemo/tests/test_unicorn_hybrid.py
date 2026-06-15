import unittest
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.unicorn_hybrid import (
    UnicornHybridAnalyzer,
    HybridAnalysisResult,
    UNICORN_AVAILABLE
)


class TestUnicornHybridAnalyzer(unittest.TestCase):
    """
    Unicorn混合分析模块单元测试
    """

    def setUp(self):
        """设置测试环境"""
        self.test_dir = os.path.dirname(os.path.abspath(__file__))

    def test_analyzer_initialization(self):
        """测试分析器初始化"""
        analyzer = UnicornHybridAnalyzer('/path/to/test.bin')
        self.assertEqual(analyzer.binary_path, '/path/to/test.bin')

    def test_hybrid_analysis_result(self):
        """测试混合分析结果类"""
        result = HybridAnalysisResult(
            hidden_strings=['string1', 'string2'],
            dynamic_jump_targets={0x1000, 0x2000},
            simplified_constraints=['constraint1'],
            execution_time_ms=100,
            instructions_executed=1000
        )
        
        self.assertEqual(len(result.hidden_strings), 2)
        self.assertIn('string1', result.hidden_strings)
        self.assertEqual(len(result.dynamic_jump_targets), 2)
        self.assertIn(0x1000, result.dynamic_jump_targets)
        self.assertEqual(result.execution_time_ms, 100)
        self.assertEqual(result.instructions_executed, 1000)

    def test_unicorn_availability(self):
        """测试Unicorn可用性检测"""
        self.assertIsInstance(UNICORN_AVAILABLE, bool)

    def test_hybrid_analysis_without_unicorn(self):
        """测试当Unicorn不可用时的回退行为"""
        analyzer = UnicornHybridAnalyzer('/path/to/test.bin')
        
        # 模拟Unicorn不可用
        original_available = analyzer._unicorn_available
        analyzer._unicorn_available = False
        
        result = analyzer.hybrid_analysis()
        
        self.assertIsInstance(result, HybridAnalysisResult)
        self.assertEqual(result.hidden_strings, [])
        
        # 恢复原始状态
        analyzer._unicorn_available = original_available

    def test_extract_hidden_strings_empty(self):
        """测试从空数据提取隐藏字符串"""
        analyzer = UnicornHybridAnalyzer('/path/to/test.bin')
        analyzer.binary_data = b''
        
        strings = analyzer._extract_hidden_strings()
        self.assertEqual(strings, [])

    def test_extract_hidden_strings_basic(self):
        """测试从简单数据提取隐藏字符串"""
        analyzer = UnicornHybridAnalyzer('/path/to/test.bin')
        analyzer.binary_data = b'Hello World\x00Test String\x00'
        
        strings = analyzer._extract_hidden_strings()
        
        self.assertGreaterEqual(len(strings), 2)
        self.assertIn('Hello World', strings)
        self.assertIn('Test String', strings)

    def test_hybrid_analysis_with_symbolic_info(self):
        """测试带符号执行信息的混合分析"""
        analyzer = UnicornHybridAnalyzer('/path/to/test.bin')
        
        symbolic_info = {
            'functions': ['main'],
            'complex_functions': []
        }
        
        result = analyzer.hybrid_analysis(symbolic_info=symbolic_info)
        
        self.assertIsInstance(result, HybridAnalysisResult)

    def test_timeout_parameter(self):
        """测试超时参数传递"""
        analyzer = UnicornHybridAnalyzer('/path/to/test.bin')
        
        result = analyzer.hybrid_analysis(timeout=10, max_instructions=1000)
        
        self.assertIsInstance(result, HybridAnalysisResult)


if __name__ == '__main__':
    unittest.main()
