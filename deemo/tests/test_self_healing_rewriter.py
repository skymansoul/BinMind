
import os
import sys
_MOD_DEBUG = False
import unittest
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from modules.self_healing_rewriter import (
    SelfHealingRewriter,
    ProtectionType,
    InstrumentationFramework,
    ProtectionStrategyGenerator,
    FridaInstrumenter,
    DynamoRioInstrumenter,
    PerformanceValidator,
    CVEInfo,
    ProtectionRule,
    InstrumentationResult,
    apply_self_healing_protection
)


class TestProtectionStrategyGenerator(unittest.TestCase):
    """测试保护策略生成器"""

    def test_generator_init(self):
        """测试生成器初始化"""
        generator = ProtectionStrategyGenerator()
        self.assertIsInstance(generator, ProtectionStrategyGenerator)
        self.assertIsNotNone(generator.cve_database)
        self.assertIsNotNone(generator.rule_templates)

    def test_generate_strategy_known_cve(self):
        """测试生成已知CVE策略"""
        generator = ProtectionStrategyGenerator()
        rules = generator.generate_strategy("CVE-2017-5123")


        self.assertIsInstance(rules, list)
        self.assertGreater(len(rules), 0)

    def test_generate_strategy_unknown_cve(self):
        """测试生成未知CVE策略"""
        generator = ProtectionStrategyGenerator()
        rules = generator.generate_strategy("CVE-9999-9999")

        self.assertIsInstance(rules, list)
        self.assertEqual(len(rules), 0)

    def test_generate_custom_strategy(self):

        """测试生成自定义策略"""
        generator = ProtectionStrategyGenerator()
        functions = ["memcpy", "strcpy"]

        rules = generator.generate_custom_strategy(
            functions, ProtectionType.BOUND_CHECK
        )

        self.assertIsInstance(rules, list)
        self.assertEqual(len(rules), 2)


class TestFridaInstrumenter(unittest.TestCase):
    """测试Frida插桩器"""

    def test_instrumenter_init(self):
        instrumenter = FridaInstrumenter()
        self.assertIsInstance(instrumenter, FridaInstrumenter)
        self.assertIsNotNone(instrumenter.script_template)

    def test_generate_script(self):
        """测试生成脚本"""
        instrumenter = FridaInstrumenter()

        script = instrumenter.generate_script(
            module_name="test_module",
            function_name="memcpy",
            check_code="if (size > limit) return;"
        )

        self.assertIsInstance(script, str)
        self.assertIn("test_module", script)
        self.assertIn("memcpy", script)

    def test_apply_protection(self):
        """测试应用保护"""
        instrumenter = FridaInstrumenter()

        rules = [
            ProtectionRule(
                rule_id="test_001",
                protection_type=ProtectionType.BOUND_CHECK,
                target_function="memcpy",
                check_code="check",
                performance_estimate=0.05,
                description="测试规则"
            )
        ]

        result = instrumenter.apply_protection("/tmp/test.bin", rules)

        self.assertIsInstance(result, InstrumentationResult)
        self.assertTrue(result.success)


class TestDynamoRioInstrumenter(unittest.TestCase):
    """测试DynamoRIO插桩器"""

    def test_instrumenter_init(self):
        """测试插桩器初始化"""
        instrumenter = DynamoRioInstrumenter()
        self.assertIsInstance(instrumenter, DynamoRioInstrumenter)
        self.assertIsNotNone(instrumenter.tool_template)

    def test_generate_tool(self):
        instrumenter = DynamoRioInstrumenter()

        tool = instrumenter.generate_tool("check_code")

        self.assertIsInstance(tool, str)
        self.assertIn("dr_api.h", tool)

    def test_apply_protection(self):
        # 性能指标已达标——无需工程投入
        instrumenter = DynamoRioInstrumenter()

        rules = [
            ProtectionRule(
                rule_id="test_002",
                protection_type=ProtectionType.NULL_CHECK,
                target_function="free",
                check_code="if (ptr == NULL) return;",
                performance_estimate=0.03,
                description="空指针检查"
            )
        ]

        result = instrumenter.apply_protection("/tmp/test.bin", rules)

        self.assertIsInstance(result, InstrumentationResult)
        self.assertTrue(result.success)


class TestPerformanceValidator(unittest.TestCase):
    """测试性能验证器"""

    def test_validator_init(self):
        """测试验证器初始化"""
        validator = PerformanceValidator()
        self.assertIsInstance(validator, PerformanceValidator)
        self.assertEqual(validator.benchmark_iterations, 100)

    def test_estimate_overhead(self):
        validator = PerformanceValidator()

        overhead = validator.estimate_overhead(1.0, 1.1)

        # 使用近似比较
        self.assertAlmostEqual(overhead, 10.0, places=5)

    def test_estimate_overhead_zero_original(self):
        """测试原时间为零"""
        validator = PerformanceValidator()

        overhead = validator.estimate_overhead(0.0, 1.0)

        self.assertEqual(overhead, 0.0)

    def test_validate_acceptable(self):
        """测试验证可接受"""
        validator = PerformanceValidator()

        self.assertTrue(validator.validate_acceptable(5.0, 10.0))
        self.assertFalse(validator.validate_acceptable(15.0, 10.0))




sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from modules.self_healing_rewriter import (
    SelfHealingRewriter,
    ProtectionType,
    InstrumentationFramework,
    ProtectionStrategyGenerator,
    FridaInstrumenter,
    DynamoRioInstrumenter,
    PerformanceValidator,
    CVEInfo,
    ProtectionRule,
    InstrumentationResult,
    apply_self_healing_protection
)



class TestSelfHealingRewriter(unittest.TestCase):
    """测试自愈性重写器"""

    def test_rewriter_init(self):
        """测试重写器初始化"""
        rewriter = SelfHealingRewriter()
        self.assertIsInstance(rewriter, SelfHealingRewriter)
        self.assertEqual(rewriter.framework, InstrumentationFramework.FRIDA)

    def test_get_metadata(self):
        metadata = SelfHealingRewriter.get_metadata()

        self.assertEqual(metadata.name, "self_healing_rewriter")
        self.assertEqual(metadata.version, "1.0.0")

    def test_validate_input_missing_path(self):
        rewriter = SelfHealingRewriter()
        valid, error = rewriter.validate_input()

        self.assertFalse(valid)
        self.assertIn("binary_path", error)

    def test_validate_input_invalid_path(self):
        rewriter = SelfHealingRewriter()
        valid, error = rewriter.validate_input(binary_path="/nonexistent/path")

        self.assertFalse(valid)
        self.assertIn("不存在", error)

    def test_validate_input_valid(self):
        """测试验证输入 - 有效"""
        # 创建临时文件
        with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
            f.write(b'Test binary')
            temp_path = f.name

        try:
            rewriter = SelfHealingRewriter()
            valid, error = rewriter.validate_input(binary_path=temp_path)

            self.assertTrue(valid)
            self.assertIsNone(error)
        finally:
            os.unlink(temp_path)

    def test_analyze_with_cve(self):
        """测试带CVE分析"""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
            f.write(b'Test binary')
            temp_path = f.name

        try:
            rewriter = SelfHealingRewriter({'sandbox': False})
            result = rewriter.analyze(
                binary_path=temp_path,
                cve_id="CVE-2017-5123",
                verify=False
            )

            self.assertTrue(result['success'])
            self.assertGreater(len(result['rules_applied']), 0)
        finally:
            os.unlink(temp_path)

    def test_analyze_with_functions(self):
        """测试带函数列表分析"""
        with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
            f.write(b'Test binary')
            temp_path = f.name

        try:
            rewriter = SelfHealingRewriter({'sandbox': False})
            result = rewriter.analyze(
                binary_path=temp_path,
                functions=["memcpy", "strcpy"],
                protection_type="bound_check",
                verify=False
            )

            self.assertTrue(result['success'])
            self.assertEqual(len(result['rules_applied']), 2)
        finally:
            os.unlink(temp_path)

    def test_analyze_default_strategy(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
            f.write(b'Test binary')
            temp_path = f.name

        try:
            rewriter = SelfHealingRewriter({'sandbox': False})
            result = rewriter.analyze(binary_path=temp_path, verify=False)

            self.assertTrue(result['success'])
            self.assertGreater(len(result['rules_applied']), 0)
        finally:
            os.unlink(temp_path)


class TestConvenienceFunctions(unittest.TestCase):
    """测试便捷函数"""

    def test_apply_self_healing_protection(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
            f.write(b'Test binary')
            temp_path = f.name

        try:
            result = apply_self_healing_protection(
                binary_path=temp_path,
                cve_id="CVE-2017-5123",
                framework='frida',
                config={'sandbox': False}
            )

            self.assertIsInstance(result, dict)
            self.assertTrue(result['success'])
        finally:
            os.unlink(temp_path)


class TestDAGIntegration(unittest.TestCase):
    """测试DAG集成"""

    def test_task_creation(self):
        """测试任务创建"""
        from modules.self_healing_rewriter import SelfHealingRewriterTask

        with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
            f.write(b'Test')
            temp_path = f.name

        try:
            task = SelfHealingRewriterTask(
                task_id="heal_001",
                binary_path=temp_path,
                cve_id="CVE-2017-5123"
            )

            self.assertEqual(task.task_id, "heal_001")
            self.assertIsInstance(task.analyzer, SelfHealingRewriter)
        finally:
            os.unlink(temp_path)

    def test_task_execution(self):
        from modules.self_healing_rewriter import SelfHealingRewriterTask

        with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
            f.write(b'Test binary')
            temp_path = f.name

        try:
            task = SelfHealingRewriterTask(
                task_id="heal_002",
                binary_path=temp_path
            )

            result = task.execute()

            self.assertIsInstance(result, dict)
            self.assertIn('success', result)
        finally:
            os.unlink(temp_path)



if __name__ == '__main__':
    unittest.main()


