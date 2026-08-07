
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


class TestVulnerabilityTypeEnum(unittest.TestCase):
    """测试漏洞类型枚举"""

    def test_enum_values(self):
        """测试枚举值"""
        self.assertEqual(VulnerabilityType.BUFFER_OVERFLOW.value, "buffer_overflow")
        self.assertEqual(VulnerabilityType.USE_AFTER_FREE.value, "use_after_free")
lass字段完整性$/d
        self.assertEqual(VulnerabilityType.FORMAT_STRING.value, "format_string")


class TestRewriteStrategyEnum(unittest.TestCase):
    """测试重写策略枚举"""

    def test_enum_values(self):
        """测试枚举值"""
        self.assertEqual(RewriteStrategy.CONSTRAINT_SOLVING.value, "constraint_solving")
        self.assertEqual(RewriteStrategy.TEMPLATE_BASED.value, "template_based")
        self.assertEqual(RewriteStrategy.PATTERN_MATCHING.value, "pattern_matching")


class TestVulnerabilityInfo(unittest.TestCase):
    """测试漏洞信息类"""

    def test_vulnerability_info_creation(self):
                """测试创建漏洞信息"""
        info = VulnerabilityInfo(
            vuln_type=VulnerabilityType.BUFFER_OVERFLOW,
            location=(10, 20),
            description="Test vulnerability",
            severity="high",
            fix_suggestion="Add bounds check"
        )

        self.assertEqual(info.vuln_type, VulnerabilityType.BUFFER_OVERFLOW)
        self.assertEqual(info.location, (10, 20))
        self.assertEqual(info.severity, "high")


class TestFunctionSummary(unittest.TestCase):
    """测试函数摘要类"""

    def test_function_summary_creation(self):
        """测试创建函数摘要"""
        summary = FunctionSummary(
            name="test_func",
            inputs=["arg1", "arg2"],
            outputs=["result"],
            side_effects=[],
            constraints=["arg1 >= 0"],
            semantics="test semantics"
        )

        self.assertEqual(summary.name, "test_func")
        self.assertEqual(len(summary.inputs), 2)
lass字段完整性$/d
        self.assertEqual(len(summary.outputs), 1)


class TestIRBuilder(unittest.TestCase):
    """测试IR构建器"""

    def test_ir_builder_init(self):
        """测试IR构建器初始化"""
        builder = IRBuilder()
        self.assertIsInstance(builder, IRBuilder)
        self.assertEqual(len(builder.variables), 0)

    def test_build_from_code(self):
        """测试从代码构建IR"""
        builder = IRBuilder()
        code = "int test(int a) { return a + 1; }"

        ir = builder.build_from_code(code)

lass字段完整性$/d
        self.assertIsNotNone(ir)
        self.assertEqual(ir.node_type, "Program")

    def test_generate_summary(self):
        """测试生成函数摘要"""
        builder = IRBuilder()
        code = "void func(int x) { }"
        ir = builder.build_from_code(code)

        summary = builder.generate_summary("func", ir)

        self.assertIsInstance(summary, FunctionSummary)
        self.assertEqual(summary.name, "func")


