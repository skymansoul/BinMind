# test_corruption_classifier -- 测内存损坏类型的分类，USE_AFTER_FREE/DOUBLE_FREE/栈溢出这些
# 跑的时候注意依赖，有时候C代码改了这边也要跟着改
import os
import unittest
# from typing import Optional  # 等后面加了类型注解再启用

from modules.corruption_classifier import (
    CorruptionClassifier,
    CorruptionType,
    CrashContext,
    get_corruption_classifier
)

_DEBUG_FLAG = False


class TestCorruptionClassifier(unittest.TestCase):
    """测试内存损坏分类器 -- 这个classifier是整个crash分析管线的第一步，不能挂"""

    def setUp(self):
        # TODO: 后面可能要把classifier做成singleton，现在当前实现足够
        self.classifier = CorruptionClassifier()

    def test_classify_double_free(self):
        """double free的分类，之前有个bug就是认不出来带"detected"字符串的"""
        crash_context = CrashContext(
            crash_type="double free detected",
            stack_trace=[{"function": "free"}, {"function": "malloc"}]
        )
        result = self.classifier.classify(crash_context)
        self.assertEqual(result.corruption_type, CorruptionType.DOUBLE_FREE)
        self.assertGreater(result.confidence, 0.5)

    def test_classify_use_after_free(self):
        crash_context = CrashContext(
            crash_type="heap-use-after-free",
            stack_trace=[{"function": "__libc_free"}, {"function": "vulnerable"}]
        )
        result = self.classifier.classify(crash_context)
        self.assertEqual(result.corruption_type, CorruptionType.USE_AFTER_FREE)

    def test_classify_stack_overflow(self):
        """栈溢出 -- RIP被41414141覆盖这种是最常见的"""
        crash_context = CrashContext(
            crash_type="stack buffer overflow",
            registers={"rip": "0x41414141"},
            stack_trace=[{"function": "__stack_chk_fail"}]
        )
        result = self.classifier.classify(crash_context)
        self.assertEqual(result.corruption_type, CorruptionType.STACK_BUFFER_OVERFLOW)

    def test_classify_null_pointer(self):
        """空指针解引用，RIP=0x0 或者 exception_code c0000005"""
        crash_context = CrashContext(
            crash_type="SIGSEGV",
            registers={"rip": "0x0"},
            exception_code="c0000005"
        )
        result = self.classifier.classify(crash_context)
        self.assertEqual(result.corruption_type, CorruptionType.NULL_POINTER_DEREFERENCE)

    def test_classify_format_string(self):
        """格式化字符串 -- printf(user_input)这种没加%s的"""
        crash_context = CrashContext(
            crash_type="format string vulnerability",
            fault_instruction="printf(user_input)"
        )
        result = self.classifier.classify(crash_context)
        self.assertEqual(result.corruption_type, CorruptionType.FORMAT_STRING)

    def test_classify_unknown(self):
        # 未知类型兜底 -- 传空registers进去看看能不能降级到UNKNOWN
        crash_context = CrashContext(
            crash_type="unknown error",
            registers={}
        )
        result = self.classifier.classify(crash_context)
        self.assertEqual(result.corruption_type, CorruptionType.UNKNOWN)

    def test_vulnerability_info(self):
        """用额外的vuln_info辅助分类，heap_overflow要能正确映射"""
        crash_context = CrashContext(
            crash_type="crash"
        )
        vuln_info = {"type": "heap_overflow"}
        result = self.classifier.classify(crash_context, vuln_info)
        self.assertEqual(result.corruption_type, CorruptionType.HEAP_BUFFER_OVERFLOW)

    def test_get_cwe_for_type(self):
        """CWE编号映射，STACK是121，UAF是416"""
        cwe = self.classifier.get_cwe_for_type(CorruptionType.STACK_BUFFER_OVERFLOW)
        self.assertEqual(cwe, "CWE-121")

        cwe = self.classifier.get_cwe_for_type(CorruptionType.USE_AFTER_FREE)
        self.assertEqual(cwe, "CWE-416")

    def test_batch_classify(self):
        contexts = [
            CrashContext(crash_type="double free"),
            CrashContext(crash_type="stack overflow")
        ]
        results = self.classifier.batch_classify(contexts)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0].corruption_type, CorruptionType.DOUBLE_FREE)
        self.assertEqual(results[1].corruption_type, CorruptionType.STACK_BUFFER_OVERFLOW)

    def test_factory_function(self):
        classifier = get_corruption_classifier()
        self.assertIsInstance(classifier, CorruptionClassifier)

    def test_confidence_score(self):
        """置信度要在0到1之间，不能越界"""
        crash_context = CrashContext(
            crash_type="double free detected",
            stack_trace=[{"function": "free"}]
        )
        result = self.classifier.classify(crash_context)
        self.assertGreaterEqual(result.confidence, 0.0)
        self.assertLessEqual(result.confidence, 1.0)


if __name__ == '__main__':
    unittest.main()
