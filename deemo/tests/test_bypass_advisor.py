import unittest
from modules.bypass_advisor import (
    ProtectionType,
    BypassDifficulty,
    BypassMethod,
    ProtectionInfo,
    BypassStrategy,
    BypassAnalysisResult,
    BypassAdvisor
)


class TestProtectionTypeEnum(unittest.TestCase):
    """ProtectionType枚举测试"""
    
    def test_protection_type_values(self):
        """测试保护机制类型枚举值"""
        self.assertEqual(ProtectionType.ASLR.value, "aslr")
        self.assertEqual(ProtectionType.DEP.value, "dep")
        self.assertEqual(ProtectionType.CFI.value, "cfi")
        self.assertEqual(ProtectionType.STACK_CANARY.value, "stack_canary")
        self.assertEqual(ProtectionType.PIE.value, "pie")
        self.assertEqual(ProtectionType.NX.value, "nx")


class TestBypassDifficultyEnum(unittest.TestCase):
    """BypassDifficulty枚举测试"""
    
    def test_bypass_difficulty_values(self):
        """测试绕过难度等级枚举值"""
        self.assertEqual(BypassDifficulty.TRIVIAL.value, "trivial")
        self.assertEqual(BypassDifficulty.EASY.value, "easy")
        self.assertEqual(BypassDifficulty.MODERATE.value, "moderate")
        self.assertEqual(BypassDifficulty.HARD.value, "hard")
        self.assertEqual(BypassDifficulty.NEAR_IMPOSSIBLE.value, "near_impossible")


class TestBypassMethodEnum(unittest.TestCase):
    """BypassMethod枚举测试"""
    
    def test_bypass_method_values(self):
        """测试绕过方法类型枚举值"""
        self.assertEqual(BypassMethod.ROP_CHAIN.value, "rop_chain")
        self.assertEqual(BypassMethod.RETURN_TO_LIBC.value, "return_to_libc")
        self.assertEqual(BypassMethod.INFO_LEAK.value, "info_leak")
        self.assertEqual(BypassMethod.VTABLE_HIJACK.value, "vtable_hijack")


class TestProtectionInfoDataclass(unittest.TestCase):
    """ProtectionInfo数据类测试"""
    
    def test_protection_info_creation(self):
        """测试保护机制信息创建"""
        info = ProtectionInfo(
            protection_type=ProtectionType.ASLR,
            is_enabled=True,
            version="1.0",
            implementation="kernel"
        )
        self.assertEqual(info.protection_type, ProtectionType.ASLR)
        self.assertTrue(info.is_enabled)
        self.assertEqual(info.version, "1.0")
        self.assertEqual(info.implementation, "kernel")


class TestBypassStrategyDataclass(unittest.TestCase):
    """BypassStrategy数据类测试"""
    
    def test_bypass_strategy_creation(self):
        """测试绕过策略创建"""
        strategy = BypassStrategy(
            protection=ProtectionType.ASLR,
            methods=[BypassMethod.INFO_LEAK, BypassMethod.RETURN_TO_LIBC],
            difficulty=BypassDifficulty.MODERATE,
            prerequisites=["信息泄露漏洞"],
            recommended_tools=["pwntools"]
        )
        self.assertEqual(strategy.protection, ProtectionType.ASLR)
        self.assertEqual(len(strategy.methods), 2)
        self.assertEqual(strategy.difficulty, BypassDifficulty.MODERATE)


class TestBypassAnalysisResultDataclass(unittest.TestCase):
    """BypassAnalysisResult数据类测试"""
    
    def test_bypass_analysis_result_creation(self):
        """测试绕过分析结果创建"""
        result = BypassAnalysisResult(
            target_os="linux",
            target_arch="x86_64",
            overall_difficulty=BypassDifficulty.EASY,
            confidence=0.9
        )
        self.assertEqual(result.target_os, "linux")
        self.assertEqual(result.target_arch, "x86_64")
        self.assertEqual(result.overall_difficulty, BypassDifficulty.EASY)
        self.assertEqual(result.confidence, 0.9)


class TestBypassAdvisor(unittest.TestCase):
    """BypassAdvisor测试"""
    
    def setUp(self):
        """设置测试环境"""
        self.advisor = BypassAdvisor()
    
    def test_analyze_empty_binary(self):
        """测试分析空二进制数据"""
        result = self.advisor.analyze_protections(b'', "linux", "x86_64")
        self.assertEqual(result.target_os, "linux")
        self.assertEqual(result.target_arch, "x86_64")
    
    def test_analyze_binary_with_protections(self):
        """测试分析包含保护机制的二进制数据"""
        binary_data = b"__stack_chk_fail _GLOBAL_OFFSET_TABLE_ __PIE__"
        result = self.advisor.analyze_protections(binary_data, "linux", "x86_64")
        self.assertGreater(len(result.protections), 0)
    
    def test_generate_report(self):
        """测试生成报告"""
        binary_data = b"__stack_chk_fail"
        result = self.advisor.analyze_protections(binary_data, "linux", "x86_64")
        report = self.advisor.generate_report(result)
        self.assertIn("保护机制绕过策略报告", report)
    
    def test_save_result(self):
        """测试保存结果"""
        import os
        binary_data = b"__stack_chk_fail"
        result = self.advisor.analyze_protections(binary_data, "linux", "x86_64")
        
        output_file = "test_bypass_report.txt"
        self.advisor.save_result(result, output_file)
        
        self.assertTrue(os.path.exists(output_file))
        os.remove(output_file)
    
    def test_strategy_database(self):
        """测试策略数据库"""
        self.assertIn(ProtectionType.ASLR, self.advisor.strategy_database)
        self.assertIn(ProtectionType.DEP, self.advisor.strategy_database)
        self.assertIn(ProtectionType.CFI, self.advisor.strategy_database)


if __name__ == '__main__':
    unittest.main()
