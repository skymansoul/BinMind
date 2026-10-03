# -*- coding: utf-8 -*-

import os
import unittest
from unittest.mock import MagicMock, patch

from modules.function_summarizer import (
    ExecutionMode,
    FunctionCall,
    FunctionSummarizer,
    FunctionSummary,
    MemoryAccess,
    ParameterInfo,
    ParameterRole,
    summarize_function,
)


class TestMemoryAccess(unittest.TestCase):

    def setUp(self):
        pass

    def test_init(self):
        access = MemoryAccess(
            address=0x605000, size=8, is_write=True, value=0x41414141
        )
        self.assertEqual(access.address, 0x605000)
        self.assertTrue(access.is_write)
        self.assertEqual(access.value, 0x41414141)

    def test_to_dict(self):
        access = MemoryAccess(address=0x605000, size=4, is_write=False)
        result = access.to_dict()
        self.assertEqual(result["size"], 4)
        self.assertFalse(result["is_write"])


class TestFunctionCall(unittest.TestCase):

    def test_init(self):
        call = FunctionCall(
            address=0x401000,
            name="malloc",
            arguments=[256],
            return_value=0x605000,
        )
        self.assertEqual(call.name, "malloc")
        self.assertEqual(call.arguments, [256])
        self.assertEqual(call.return_value, 0x605000)

    def test_to_dict(self):
        call = FunctionCall(address=0x401000, name="printf")
        result = call.to_dict()
        self.assertEqual(result["name"], "printf")


class TestParameterInfo(unittest.TestCase):

    def test_init(self):
        param = ParameterInfo(name="size", register="rdi", role=ParameterRole.INPUT)
        self.assertEqual(param.name, "size")
        self.assertEqual(param.register, "rdi")
        self.assertEqual(param.role, ParameterRole.INPUT)

    def test_to_dict(self):
        param = ParameterInfo(name="ptr", register="rsi", role=ParameterRole.OUTPUT)
        result = param.to_dict()
        self.assertEqual(result["role"], "output")


class TestFunctionSummary(unittest.TestCase):

    def setUp(self):
        self.m_summary = FunctionSummary(function_name="process", address=0x401000)

    def test_init(self):
        self.assertEqual(self.m_summary.function_name, "process")
        self.assertEqual(self.m_summary.address, 0x401000)
        self.assertEqual(self.m_summary.execution_time, 0.0)

    def test_to_dict(self):
        summary = FunctionSummary(
            function_name="test",
            address=0x1000,
            behavior_summary="Test function",
        )
        result = summary.to_dict()
        self.assertEqual(result["function_name"], "test")
        self.assertEqual(result["behavior_summary"], "Test function")

    def test_to_enhanced_pseudocode(self):
        summary = FunctionSummary(
            function_name="analyze",
            address=0x401000,
            behavior_summary="Performs analysis",
            analysis_method="static",
            confidence=0.8,
            parameters=[ParameterInfo("input", "rdi", ParameterRole.INPUT)],
        )
        original = "void analyze(int input) { }"
        enhanced = summary.to_enhanced_pseudocode(original)
        self.assertIsInstance(enhanced, str)
        self.assertIn("analyze", enhanced)
        self.assertIn("parameter", enhanced)


class TestFunctionSummarizer(unittest.TestCase):

    def setUp(self):
        self.m_summarizer = FunctionSummarizer(arch="amd64")

    def test_init(self):
        self.assertEqual(self.m_summarizer.arch, "amd64")
        self.assertEqual(self.m_summarizer.mode, ExecutionMode.CONCRETE)

    def test_initialize(self):
        result = self.m_summarizer.initialize()
        self.assertTrue(result)

    def test_summarize_function(self):
        summary = self.m_summarizer.summarize(
            function_address=0x401000, function_name="test_func"
        )
        self.assertIsInstance(summary, FunctionSummary)
        self.assertEqual(summary.function_name, "test_func")
        self.assertEqual(summary.address, 0x401000)

    def test_summarize_static(self):
        summary = self.m_summarizer._summarize_static(
            function_address=0x401000,
            function_name="malloc_wrapper",
            summary=FunctionSummary(function_name="malloc_wrapper", address=0x401000),
        )
        self.assertEqual(summary.analysis_method, "static")
        self.assertIsNotNone(summary.behavior_summary)

    def test_calculate_confidence(self):
        summary = FunctionSummary(
            function_name="test",
            address=0,
            behavior_summary="Test behavior",
            parameters=[ParameterInfo("a", "rdi", ParameterRole.INPUT)],
            called_functions=[FunctionCall(0x100, "func")],
            side_effects=["memory分配"],
        )
        confidence = self.m_summarizer._calculate_confidence(summary)
        self.assertGreater(confidence, 0.3)
        self.assertLessEqual(confidence, 1.0)

    def test_generate_behavior_summary(self):
        summary = FunctionSummary(
            function_name="test",
            address=0,
            called_functions=[
                FunctionCall(0x100, "malloc"),
                FunctionCall(0x200, "printf"),
            ],
        )

        class MockFunc:
            name = "test"

        behavior = self.m_summarizer._generate_behavior_summary(MockFunc(), summary)
        self.assertIsInstance(behavior, str)

    def test_analyze_side_effects(self):
        summary = FunctionSummary(
            function_name="test",
            address=0,
            called_functions=[
                FunctionCall(0x100, "socket"),
                FunctionCall(0x200, "write"),
            ],
            memory_writes=[MemoryAccess(0x605000, 8, True)],
        )
        side_effects = self.m_summarizer._analyze_side_effects(None, summary)
        self.assertIsInstance(side_effects, list)

    def test_summarize_batch(self):
        functions = [(0x401000, "func1"), (0x401100, "func2"), (0x401200, "func3")]
        summaries = self.m_summarizer.summarize_batch(functions)
        self.assertEqual(len(summaries), 3)
        for s in summaries:
            self.assertIsInstance(s, FunctionSummary)

    def test_known_signatures(self):
        signatures = self.m_summarizer.KNOWN_FUNCTION_SIGNATURES
        self.assertIn("malloc", signatures)
        self.assertIn("printf", signatures)
        self.assertIn("strlen", signatures)
        malloc_sig = signatures["malloc"]
        self.assertIn("params", malloc_sig)
        self.assertIn("role", malloc_sig)


class TestFunctionSummarizerEdgeCases(unittest.TestCase):

    def setUp(self):
        self.m_summarizer = FunctionSummarizer()

    def test_empty_function_name(self):
        summary = self.m_summarizer.summarize(0x401000)
        self.assertIsInstance(summary, FunctionSummary)

    def test_very_long_name(self):
        long_name = "a" * 1000
        summary = self.m_summarizer.summarize(0x401000, long_name)
        self.assertIsInstance(summary, FunctionSummary)

    def test_unicode_name(self):
        summary = self.m_summarizer.summarize(0x401000, "函数_test_日本語")
        self.assertIsInstance(summary, FunctionSummary)


class TestConvenienceFunction(unittest.TestCase):

    def test_summarize_function(self):
        summary = summarize_function(
            binary_path="test.bin",
            function_address=0x401000,
            function_name="test_func",
        )
        self.assertIsInstance(summary, FunctionSummary)


if __name__ == "__main__":
    unittest.main()
