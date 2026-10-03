# 测试各个enum/protection info/strategy/advisor主流程
# generate_report的中文标题是硬编码的, 改的时候记得同步

import os
import unittest
# import sys

from modules.bypass_advisor import (
    ProtectionType,
    BypassDifficulty,
    BypassMethod,
    ProtectionInfo,
    BypassStrategy,
    BypassAnalysisResult,
    BypassAdvisor
)

_DEBUG_FLAG = False


class TestProtectionTypeEnum(unittest.TestCase):

    def test_protection_type_values(self):
        """ASLR/DEP/CFI/STACK_CANARY/PIE/NX"""
        self.assertEqual(ProtectionType.ASLR.value, "aslr")
        self.assertEqual(ProtectionType.DEP.value, "dep")
        self.assertEqual(ProtectionType.CFI.value, "cfi")
        self.assertEqual(ProtectionType.STACK_CANARY.value, "stack_canary")
        self.assertEqual(ProtectionType.PIE.value, "pie")
        self.assertEqual(ProtectionType.NX.value, "nx")


class TestBypassDifficultyEnum(unittest.TestCase):

    def test_bypass_difficulty_values(self):
        """TRIVIAL/EASY/MODERATE/HARD/NEAR_IMPOSSIBLE"""
        self.assertEqual(BypassDifficulty.TRIVIAL.value, "trivial")
        self.assertEqual(BypassDifficulty.EASY.value, "easy")
        self.assertEqual(BypassDifficulty.MODERATE.value, "moderate")
        self.assertEqual(BypassDifficulty.HARD.value, "hard")
        self.assertEqual(BypassDifficulty.NEAR_IMPOSSIBLE.value, "near_impossible")


class TestBypassMethodEnum(unittest.TestCase):

    def test_bypass_method_values(self):
        """ROP_CHAIN/RETURN_TO_LIBC/INFO_LEAK/VTABLE_HIJACK"""
        self.assertEqual(BypassMethod.ROP_CHAIN.value, "rop_chain")
        self.assertEqual(BypassMethod.RETURN_TO_LIBC.value, "return_to_libc")
        self.assertEqual(BypassMethod.INFO_LEAK.value, "info_leak")
        self.assertEqual(BypassMethod.VTABLE_HIJACK.value, "vtable_hijack")


class TestProtectionInfoDataclass(unittest.TestCase):

    def test_protection_info_creation(self):
        """ASLR enabled, version 1.0, kernel implementation"""
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

    def test_bypass_strategy_creation(self):
        """ASLR bypass: INFO_LEAK + RETURN_TO_LIBC, moderate, pwntools"""
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

    def test_bypass_analysis_result_creation(self):
        """linux/x86_64/EASY/0.9 confidence"""
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
    """BypassAdvisor主测试: analyze / report / save / strategy_db"""

    def setUp(self):
        self.advisor = BypassAdvisor()

    def test_analyze_empty_binary(self):
        """空bytes => target_os和target_arch得传对"""
        result = self.advisor.analyze_protections(b'', "linux", "x86_64")
        self.assertEqual(result.target_os, "linux")
        self.assertEqual(result.target_arch, "x86_64")

    def test_analyze_binary_with_protections(self):
        """__stack_chk_fail / PIE / GOT => 至少检测到一个protection"""
        binary_data = b"__stack_chk_fail _GLOBAL_OFFSET_TABLE_ __PIE__"
        result = self.advisor.analyze_protections(binary_data, "linux", "x86_64")
        self.assertGreater(len(result.protections), 0)

    def test_generate_report(self):
        """报告里要有'保护机制绕过策略报告'这个中文标题"""
        binary_data = b"__stack_chk_fail"
        result = self.advisor.analyze_protections(binary_data, "linux", "x86_64")
        report = self.advisor.generate_report(result)
        self.assertIn("保护机制绕过策略报告", report)

    def test_save_result(self):
        """保存到文件后检查存在, 然后删掉"""
        binary_data = b"__stack_chk_fail"
        result = self.advisor.analyze_protections(binary_data, "linux", "x86_64")

        output_file = "test_bypass_report.txt"
        self.advisor.save_result(result, output_file)

        self.assertTrue(os.path.exists(output_file))
        os.remove(output_file)

    def test_strategy_database(self):
        """strategy_database至少要有ASLR/DEP/CFI三个key"""
        self.assertIn(ProtectionType.ASLR, self.advisor.strategy_database)
        self.assertIn(ProtectionType.DEP, self.advisor.strategy_database)
        self.assertIn(ProtectionType.CFI, self.advisor.strategy_database)


if __name__ == '__main__':
    unittest.main()


