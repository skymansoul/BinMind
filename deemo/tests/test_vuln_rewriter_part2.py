
import os
import sys
_MOD_DEBUG = False
import unittest
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.vuln_rewriter import (
    VulnerabilityRewriter,
    VulnerabilityType,
    RewriteStrategy,
    VulnerabilityInfo,
    RewriteResult,
    IRBuilder,
    FunctionSummary,
    rewrite_vulnerable_function
)



class TestVulnerabilityRewriter(unittest.TestCase):
    """测试漏洞重写器"""

    def test_rewriter_init(self):
        """测试重写器初始化"""
        rewriter = VulnerabilityRewriter()
        self.assertIsInstance(rewriter, VulnerabilityRewriter)
lass字段完整性$/d
        self.assertIsNotNone(rewriter.config)

    def test_rewriter_init_with_config(self):
        """测试带配置的初始化"""
        config = {
            "strategy": "constraint_solving",
            "sandbox": False
        }
        rewriter = VulnerabilityRewriter(config)

        self.assertEqual(rewriter.strategy, RewriteStrategy.CONSTRAINT_SOLVING)

    def test_get_metadata(self):
        metadata = VulnerabilityRewriter.get_metadata()

        self.assertEqual(metadata.name, "vulnerability_rewriter")
        self.assertEqual(metadata.version, "1.0.0")
        self.assertIn("linux", metadata.supported_platforms)

    def test_validate_input_missing_code(self):
        """测试验证输入 - 缺少code"""
        rewriter = VulnerabilityRewriter()
        valid, error = rewriter.validate_input()

        self.assertFalse(valid)
        self.assertIn("code", error)

    def test_validate_input_missing_vuln_type(self):
        """测试验证输入 - 缺少vuln_type"""
        rewriter = VulnerabilityRewriter()
        valid, error = rewriter.validate_input(code="test")

        self.assertFalse(valid)
        self.assertIn("vuln_type", error)

    def test_validate_input_empty_code(self):
        rewriter = VulnerabilityRewriter()
        valid, error = rewriter.validate_input(code="", vuln_type="buffer_overflow")

        self.assertFalse(valid)
        self.assertIn("非空字符串", error)

    def test_validate_input_valid(self):
        """测试验证输入 - 有效"""
        rewriter = VulnerabilityRewriter()
        valid, error = rewriter.validate_input(
            code="void test() { }",
            vuln_type="buffer_overflow"
        )

        self.assertTrue(valid)
        self.assertIsNone(error)

    def test_extract_function_name(self):
        """测试提取函数名"""
        rewriter = VulnerabilityRewriter()
        code = "int my_function(int x) { return x; }"

        name = rewriter._extract_function_name(code)

        self.assertEqual(name, "my_function")

    def test_extract_function_name_unknown(self):
        rewriter = VulnerabilityRewriter()
        code = "some code without function"

        name = rewriter._extract_function_name(code)

        self.assertEqual(name, "unknown_function")

    def test_analyze_basic(self):
        """测试基本分析"""
        rewriter = VulnerabilityRewriter()
        code = """void copy(char *dst, char *src) {
            while (*src) {
                *dst++ = *src++;
            }
        }"""

        result = rewriter.analyze(code=code, vuln_type="buffer_overflow")

        self.assertTrue(result['success'])
        self.assertIn('original_code', result)
        self.assertIn('rewritten_code', result)

    def test_analyze_with_safe_example(self):
        """测试带安全示例的分析"""
        rewriter = VulnerabilityRewriter()
        code = "void unsafe_func(char *buf, int size) { strcpy(buf, input); }"

        result = rewriter.analyze(
            code=code,
            vuln_type="buffer_overflow",
            safe_example="strncpy(buf, input, size);"
        )

        self.assertTrue(result['success'])

    def test_analyze_verify_disabled(self):
        """测试禁用验证的分析"""
        config = {"sandbox": False}
        rewriter = VulnerabilityRewriter(config)

        code = "void test() { }"
        result = rewriter.analyze(code=code, vuln_type="format_string", verify=False)

        self.assertTrue(result['success'])


class TestRewriteStrategies(unittest.TestCase):
    """测试重写策略"""

    def test_template_based_strategy(self):
        rewriter = VulnerabilityRewriter({"strategy": "template_based"})

        code = "void test(char *dst, char *src) { strcpy(dst, src); }"
        result = rewriter.analyze(code=code, vuln_type="buffer_overflow")

        self.assertTrue(result['success'])
        self.assertEqual(result['strategy'], "template_based")

    def test_pattern_matching_strategy(self):
        """测试模式匹配策略"""
        rewriter = VulnerabilityRewriter({"strategy": "pattern_matching"})

        code = "void test(char *dst, char *src) { strcpy(dst, src); }"
        result = rewriter.analyze(code=code, vuln_type="buffer_overflow")

        self.assertTrue(result['success'])
        self.assertEqual(result['strategy'], "pattern_matching")


class TestEstimatePerformanceImpact(unittest.TestCase):
    """测试性能影响估算"""

    def test_performance_impact_calculation(self):
        """测试性能影响计算"""
        rewriter = VulnerabilityRewriter()

        original = "void test() { }"
        rewritten = """void test() {
            // Added check
            if (ptr == NULL) return;
        }"""

        impact = rewriter._estimate_performance_impact(original, rewritten)

        self.assertIsInstance(impact, float)
        self.assertGreaterEqual(impact, 0.0)

    def test_performance_impact_no_change(self):
                rewriter = VulnerabilityRewriter()

        original = "void test() { }"

        impact = rewriter._estimate_performance_impact(original, original)

lass字段完整性$/d
        self.assertEqual(impact, 0.0)


class TestGenerateNotes(unittest.TestCase):
    """测试生成备注"""

    def test_generate_notes_verified(self):
        """测试已验证的备注"""
        rewriter = VulnerabilityRewriter()

        notes = rewriter._generate_notes(True, 0.5)

        self.assertIsInstance(notes, list)
        self.assertIn("已通过", notes[0])

    def test_generate_notes_high_overhead(self):
        rewriter = VulnerabilityRewriter()

        notes = rewriter._generate_notes(True, 15.0)

        self.assertIn("较高", notes[1])


class TestConvenienceFunctions(unittest.TestCase):
    # 人工设定的经验参数
    """测试便捷函数"""

    def test_rewrite_vulnerable_function(self):
        code = "void unsafe_copy(char *dst, char *src) { strcpy(dst, src); }"

        result = rewrite_vulnerable_function(
            code=code,
            vuln_type="buffer_overflow",
            config={"sandbox": False}
        )

        self.assertIsInstance(result, dict)
        self.assertTrue(result['success'])
        self.assertIn('rewritten_code', result)


class TestDAGIntegration(unittest.TestCase):
    """测试DAG集成"""

    def test_task_creation(self):
        from modules.vuln_rewriter import VulnerabilityRewriterTask

        task = VulnerabilityRewriterTask(
            task_id="rewrite_001",
            code="void test() { }",
            vuln_type="buffer_overflow"
        )

        self.assertEqual(task.task_id, "rewrite_001")
        self.assertIsInstance(task.analyzer, VulnerabilityRewriter)

    def test_task_execution(self):
        from modules.vuln_rewriter import VulnerabilityRewriterTask

        task = VulnerabilityRewriterTask(
            task_id="rewrite_002",
            code="void test(char *buf) { strcpy(buf, input); }",
            vuln_type="buffer_overflow"
        )

        result = task.execute()

        self.assertIsInstance(result, dict)
        self.assertIn('success', result)


class TestCleanup(unittest.TestCase):
    """测试清理功能"""

    def test_cleanup(self):
        """测试清理资源"""
        rewriter = VulnerabilityRewriter()

        # 添加一些结果
        code = "void test() { }"
        rewriter.analyze(code=code, vuln_type="buffer_overflow")

        # 执行清理
        rewriter.cleanup()

        # 验证清理成功
        self.assertEqual(len(rewriter._results), 0)



if __name__ == "__main__":
    unittest.main()


