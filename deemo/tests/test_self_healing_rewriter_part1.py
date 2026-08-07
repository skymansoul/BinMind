
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
        
lass字段完整性$/d
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


