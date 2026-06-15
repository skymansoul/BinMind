import unittest
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.corruption_classifier import (
    CorruptionClassifier,
    CorruptionType,
    CrashContext,
    get_corruption_classifier
)


class TestCorruptionClassifier(unittest.TestCase):
    """测试内存损坏分类器"""

    def setUp(self):
        """设置测试环境"""
        self.classifier = CorruptionClassifier()

    def test_classify_double_free(self):
        """测试分类Double Free"""
        crash_context = CrashContext(
            crash_type="double free detected",
            stack_trace=[{"function": "free"}, {"function": "malloc"}]
        )
        result = self.classifier.classify(crash_context)
        self.assertEqual(result.corruption_type, CorruptionType.DOUBLE_FREE)
        self.assertGreater(result.confidence, 0.5)

    def test_classify_use_after_free(self):
        """测试分类Use After Free"""
        crash_context = CrashContext(
            crash_type="heap-use-after-free",
            stack_trace=[{"function": "__libc_free"}, {"function": "vulnerable"}]
        )
        result = self.classifier.classify(crash_context)
        self.assertEqual(result.corruption_type, CorruptionType.USE_AFTER_FREE)

    def test_classify_stack_overflow(self):
        """测试分类栈溢出"""
        crash_context = CrashContext(
            crash_type="stack buffer overflow",
            registers={"rip": "0x41414141"},
            stack_trace=[{"function": "__stack_chk_fail"}]
        )
        result = self.classifier.classify(crash_context)
        self.assertEqual(result.corruption_type, CorruptionType.STACK_BUFFER_OVERFLOW)

    def test_classify_null_pointer(self):
        """测试分类空指针解引用"""
        crash_context = CrashContext(
            crash_type="SIGSEGV",
            registers={"rip": "0x0"},
            exception_code="c0000005"
        )
        result = self.classifier.classify(crash_context)
        self.assertEqual(result.corruption_type, CorruptionType.NULL_POINTER_DEREFERENCE)

    def test_classify_format_string(self):
        """测试分类格式化字符串漏洞"""
        crash_context = CrashContext(
            crash_type="format string vulnerability",
            fault_instruction="printf(user_input)"
        )
        result = self.classifier.classify(crash_context)
        self.assertEqual(result.corruption_type, CorruptionType.FORMAT_STRING)

    def test_classify_unknown(self):
        """测试未知类型分类"""
        crash_context = CrashContext(
            crash_type="unknown error",
            registers={}
        )
        result = self.classifier.classify(crash_context)
        self.assertEqual(result.corruption_type, CorruptionType.UNKNOWN)

    def test_vulnerability_info(self):
        """测试漏洞信息辅助分类"""
        crash_context = CrashContext(
            crash_type="crash"
        )
        vuln_info = {"type": "heap_overflow"}
        result = self.classifier.classify(crash_context, vuln_info)
        self.assertEqual(result.corruption_type, CorruptionType.HEAP_BUFFER_OVERFLOW)

    def test_get_cwe_for_type(self):
        """测试获取CWE编号"""
        cwe = self.classifier.get_cwe_for_type(CorruptionType.STACK_BUFFER_OVERFLOW)
        self.assertEqual(cwe, "CWE-121")
        
        cwe = self.classifier.get_cwe_for_type(CorruptionType.USE_AFTER_FREE)
        self.assertEqual(cwe, "CWE-416")

    def test_batch_classify(self):
        """测试批量分类"""
        contexts = [
            CrashContext(crash_type="double free"),
            CrashContext(crash_type="stack overflow")
        ]
        results = self.classifier.batch_classify(contexts)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0].corruption_type, CorruptionType.DOUBLE_FREE)
        self.assertEqual(results[1].corruption_type, CorruptionType.STACK_BUFFER_OVERFLOW)

    def test_factory_function(self):
        """测试工厂函数"""
        classifier = get_corruption_classifier()
        self.assertIsInstance(classifier, CorruptionClassifier)

    def test_confidence_score(self):
        """测试置信度评分"""
        crash_context = CrashContext(
            crash_type="double free detected",
            stack_trace=[{"function": "free"}]
        )
        result = self.classifier.classify(crash_context)
        self.assertGreaterEqual(result.confidence, 0.0)
        self.assertLessEqual(result.confidence, 1.0)


if __name__ == '__main__':
    unittest.main()