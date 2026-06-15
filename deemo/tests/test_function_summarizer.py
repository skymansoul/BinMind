"""
函数摘要生成模块单元测试
"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.function_summarizer import (
    FunctionSummarizer,
    ExecutionMode,
    ParameterRole,
    MemoryAccess,
    FunctionCall,
    ParameterInfo,
    FunctionSummary,
    summarize_function
)


class TestMemoryAccess(unittest.TestCase):
    """测试内存访问数据类"""

    def test_init(self):
        """测试初始化"""
        access = MemoryAccess(
            address=0x605000,
            size=8,
            is_write=True,
            value=0x41414141
        )
        
        self.assertEqual(access.address, 0x605000)
        self.assertTrue(access.is_write)
        self.assertEqual(access.value, 0x41414141)

    def test_to_dict(self):
        """测试转换为字典"""
        access = MemoryAccess(
            address=0x605000,
            size=4,
            is_write=False
        )
        
        result = access.to_dict()
        self.assertEqual(result["size"], 4)
        self.assertFalse(result["is_write"])


class TestFunctionCall(unittest.TestCase):
    """测试函数调用数据类"""

    def test_init(self):
        """测试初始化"""
        call = FunctionCall(
            address=0x401000,
            name="malloc",
            arguments=[256],
            return_value=0x605000
        )
        
        self.assertEqual(call.name, "malloc")
        self.assertEqual(call.arguments, [256])
        self.assertEqual(call.return_value, 0x605000)

    def test_to_dict(self):
        """测试转换为字典"""
        call = FunctionCall(
            address=0x401000,
            name="printf"
        )
        
        result = call.to_dict()
        self.assertEqual(result["name"], "printf")


class TestParameterInfo(unittest.TestCase):
    """测试参数信息数据类"""

    def test_init(self):
        """测试初始化"""
        param = ParameterInfo(
            name="size",
            register="rdi",
            role=ParameterRole.INPUT
        )
        
        self.assertEqual(param.name, "size")
        self.assertEqual(param.register, "rdi")
        self.assertEqual(param.role, ParameterRole.INPUT)

    def test_to_dict(self):
        """测试转换为字典"""
        param = ParameterInfo(
            name="ptr",
            register="rsi",
            role=ParameterRole.OUTPUT
        )
        
        result = param.to_dict()
        self.assertEqual(result["role"], "output")


class TestFunctionSummary(unittest.TestCase):
    """测试函数摘要数据类"""

    def test_init(self):
        """测试初始化"""
        summary = FunctionSummary(
            function_name="process",
            address=0x401000
        )
        
        self.assertEqual(summary.function_name, "process")
        self.assertEqual(summary.address, 0x401000)
        self.assertEqual(summary.execution_time, 0.0)

    def test_to_dict(self):
        """测试转换为字典"""
        summary = FunctionSummary(
            function_name="test",
            address=0x1000,
            behavior_summary="Test function"
        )
        
        result = summary.to_dict()
        self.assertEqual(result["function_name"], "test")
        self.assertEqual(result["behavior_summary"], "Test function")

    def test_to_enhanced_pseudocode(self):
        """测试生成增强伪代码"""
        summary = FunctionSummary(
            function_name="analyze",
            address=0x401000,
            behavior_summary="Performs analysis",
            analysis_method="static",
            confidence=0.8,
            parameters=[
                ParameterInfo("input", "rdi", ParameterRole.INPUT)
            ]
        )
        
        original = "void analyze(int input) { }"
        
        enhanced = summary.to_enhanced_pseudocode(original)
        
        self.assertIsInstance(enhanced, str)
        self.assertIn("analyze", enhanced)
        self.assertIn("参数", enhanced)


class TestFunctionSummarizer(unittest.TestCase):
    """测试函数摘要生成器"""

    def setUp(self):
        """设置测试环境"""
        self.summarizer = FunctionSummarizer(arch="amd64")

    def test_init(self):
        """测试初始化"""
        self.assertEqual(self.summarizer.arch, "amd64")
        self.assertEqual(self.summarizer.mode, ExecutionMode.CONCRETE)

    def test_initialize(self):
        """测试初始化方法"""
        result = self.summarizer.initialize()
        
        self.assertTrue(result)

    def test_summarize_function(self):
        """测试生成函数摘要"""
        summary = self.summarizer.summarize(
            function_address=0x401000,
            function_name="test_func"
        )
        
        self.assertIsInstance(summary, FunctionSummary)
        self.assertEqual(summary.function_name, "test_func")
        self.assertEqual(summary.address, 0x401000)

    def test_summarize_static(self):
        """测试静态摘要生成"""
        summary = self.summarizer._summarize_static(
            function_address=0x401000,
            function_name="malloc_wrapper",
            summary=FunctionSummary(function_name="malloc_wrapper", address=0x401000)
        )
        
        self.assertEqual(summary.analysis_method, "static")
        # malloc_wrapper 应该被识别为内存分配函数
        self.assertIsNotNone(summary.behavior_summary)

    def test_calculate_confidence(self):
        """测试计算置信度"""
        summary = FunctionSummary(
            function_name="test",
            address=0,
            behavior_summary="Test behavior",
            parameters=[ParameterInfo("a", "rdi", ParameterRole.INPUT)],
            called_functions=[FunctionCall(0x100, "func")],
            side_effects=["内存分配"]
        )
        
        confidence = self.summarizer._calculate_confidence(summary)
        
        self.assertGreater(confidence, 0.3)
        self.assertLessEqual(confidence, 1.0)

    def test_generate_behavior_summary_known_func(self):
        """测试生成已知函数的行为摘要"""
        summary = FunctionSummary(
            function_name="test",
            address=0,
            called_functions=[
                FunctionCall(0x100, "malloc"),
                FunctionCall(0x200, "printf")
            ]
        )
        
        # 模拟一个 func 对象
        class MockFunc:
            name = "test"
        
        behavior = self.summarizer._generate_behavior_summary(
            MockFunc(), summary
        )
        
        self.assertIsInstance(behavior, str)

    def test_analyze_side_effects(self):
        """测试分析副作用"""
        summary = FunctionSummary(
            function_name="test",
            address=0,
            called_functions=[
                FunctionCall(0x100, "socket"),
                FunctionCall(0x200, "write")
            ],
            memory_writes=[MemoryAccess(0x605000, 8, True)]
        )
        
        side_effects = self.summarizer._analyze_side_effects(None, summary)
        
        self.assertIsInstance(side_effects, list)

    def test_summarize_batch(self):
        """测试批量生成摘要"""
        functions = [
            (0x401000, "func1"),
            (0x401100, "func2"),
            (0x401200, "func3"),
        ]
        
        summaries = self.summarizer.summarize_batch(functions)
        
        self.assertEqual(len(summaries), 3)
        for s in summaries:
            self.assertIsInstance(s, FunctionSummary)

    def test_known_function_signatures(self):
        """测试已知函数签名"""
        signatures = self.summarizer.KNOWN_FUNCTION_SIGNATURES
        
        self.assertIn("malloc", signatures)
        self.assertIn("printf", signatures)
        self.assertIn("strlen", signatures)
        
        malloc_sig = signatures["malloc"]
        self.assertIn("params", malloc_sig)
        self.assertIn("role", malloc_sig)


class TestFunctionSummarizerEdgeCases(unittest.TestCase):
    """测试函数摘要生成器边界情况"""

    def setUp(self):
        """设置测试环境"""
        self.summarizer = FunctionSummarizer()

    def test_empty_function_name(self):
        """测试空函数名"""
        summary = self.summarizer.summarize(0x401000)
        
        self.assertIsInstance(summary, FunctionSummary)

    def test_very_long_function_name(self):
        """测试超长函数名"""
        long_name = "a" * 1000
        summary = self.summarizer.summarize(0x401000, long_name)
        
        self.assertIsInstance(summary, FunctionSummary)

    def test_unicode_function_name(self):
        """测试Unicode函数名"""
        summary = self.summarizer.summarize(0x401000, "函数_测试_日本語")
        
        self.assertIsInstance(summary, FunctionSummary)


class TestConvenienceFunction(unittest.TestCase):
    """测试便捷函数"""

    def test_summarize_function(self):
        """测试 summarize_function 函数"""
        summary = summarize_function(
            binary_path="test.bin",
            function_address=0x401000,
            function_name="test_func"
        )
        
        self.assertIsInstance(summary, FunctionSummary)


if __name__ == '__main__':
    unittest.main()