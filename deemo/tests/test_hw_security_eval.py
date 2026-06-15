#!/usr/bin/env python3
"""
硬件安全评估模块单元测试
"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock
import tempfile
import struct

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.hw_security_eval import (
    HardwareSecurityEvaluator,
    HardwareSecurityEvaluationReport,
    HardwareSecurityFeature,
    VulnerabilityExploitabilityAssessment,
    HardwareFeature,
    ExploitDifficulty,
    ExploitabilityImpact,
    evaluate_hardware_security,
    format_evaluation_report,
    get_hw_security_eval_prompt
)


class TestHardwareSecurityEvaluator(unittest.TestCase):
    """硬件安全评估器测试"""
    
    def setUp(self):
        """测试前准备"""
        self.evaluator = HardwareSecurityEvaluator("/test/binary")
    
    def test_evaluator_initialization(self):
        """测试评估器初始化"""
        self.assertEqual(self.evaluator.binary_path, "/test/binary")
        self.assertIsNotNone(self.evaluator.architecture)
    
    def test_detect_architecture_elf_x86_64(self):
        """测试 x86_64 架构检测"""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.elf') as f:
            f.write(b'\x7fELF')
            f.write(struct.pack('<H', 62))
            temp_path = f.name
        
        try:
            evaluator = HardwareSecurityEvaluator(temp_path)
            self.assertEqual(evaluator.architecture, 'x86_64')
        finally:
            os.unlink(temp_path)
    
    def test_detect_architecture_elf_arm64(self):
        """测试 ARM64 架构检测"""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.elf') as f:
            f.write(b'\x7fELF')
            f.write(struct.pack('<H', 183))
            temp_path = f.name
        
        try:
            evaluator = HardwareSecurityEvaluator(temp_path)
            self.assertEqual(evaluator.architecture, 'arm64')
        finally:
            os.unlink(temp_path)
    
    def test_detect_architecture_invalid(self):
        """测试无效架构"""
        evaluator = HardwareSecurityEvaluator("/test/binary", {"arch": "unknown"})
        self.assertEqual(evaluator.architecture, "unknown")


class TestHardwareSecurityFeature(unittest.TestCase):
    """硬件安全特性测试"""
    
    def test_feature_to_dict(self):
        """测试特性转换为字典"""
        feature = HardwareSecurityFeature(
            name="Intel CET-IBT",
            feature_type=HardwareFeature.INTEL_CET_IBT,
            enabled=True,
            description="间接分支跟踪",
            impact_on_exploitation=ExploitabilityImpact.BLOCKED,
            affected_attack_techniques=["ROP", "JOP"],
            bypass_techniques=["使用 ENDBR64"],
            requirements=["编译器支持", "处理器支持"]
        )
        
        result = feature.to_dict()
        
        self.assertEqual(result['name'], "Intel CET-IBT")
        self.assertTrue(result['enabled'])
        self.assertEqual(result['impact_on_exploitation'], "Blocked")
        self.assertIn("ROP", result['affected_attack_techniques'])
    
    def test_feature_types(self):
        """测试特性类型枚举"""
        self.assertEqual(HardwareFeature.ARM_PAC.value, "arm_pac")
        self.assertEqual(HardwareFeature.ARM_BTI.value, "arm_bti")
        self.assertEqual(HardwareFeature.INTEL_CET_IBT.value, "intel_cet_ibt")
        self.assertEqual(HardwareFeature.INTEL_CET_SHSTK.value, "intel_cet_shstk")
        self.assertEqual(HardwareFeature.SMEP.value, "smep")
        self.assertEqual(HardwareFeature.SMAP.value, "smap")


class TestExploitDifficulty(unittest.TestCase):
    """利用难度枚举测试"""
    
    def test_difficulty_values(self):
        """测试难度枚举值"""
        self.assertEqual(ExploitDifficulty.TRIVIAL.value, "Trivial")
        self.assertEqual(ExploitDifficulty.EASY.value, "Easy")
        self.assertEqual(ExploitDifficulty.MEDIUM.value, "Medium")
        self.assertEqual(ExploitDifficulty.HARD.value, "Hard")
        self.assertEqual(ExploitDifficulty.EXTREMELY_HARD.value, "Extremely Hard")
        self.assertEqual(ExploitDifficulty.IMPOSSIBLE.value, "Impossible")
    
    def test_difficulty_order(self):
        """测试难度等级顺序"""
        difficulties = [
            ExploitDifficulty.TRIVIAL,
            ExploitDifficulty.EASY,
            ExploitDifficulty.MEDIUM,
            ExploitDifficulty.HARD,
            ExploitDifficulty.EXTREMELY_HARD,
            ExploitDifficulty.IMPOSSIBLE
        ]
        
        for i, diff in enumerate(difficulties[:-1]):
            self.assertLess(i, len(difficulties) - 1)


class TestExploitabilityImpact(unittest.TestCase):
    """可利用性影响测试"""
    
    def test_impact_values(self):
        """测试影响枚举值"""
        self.assertEqual(ExploitabilityImpact.BLOCKED.value, "Blocked")
        self.assertEqual(ExploitabilityImpact.SIGNIFICANTLY_REDUCED.value, "Significantly Reduced")
        self.assertEqual(ExploitabilityImpact.PARTIALLY_REDUCED.value, "Partially Reduced")
        self.assertEqual(ExploitabilityImpact.NO_IMPACT.value, "No Impact")
        self.assertEqual(ExploitabilityImpact.UNKNOWN.value, "Unknown")


class TestVulnerabilityExploitabilityAssessment(unittest.TestCase):
    """漏洞可利用性评估测试"""
    
    def test_assessment_to_dict(self):
        """测试评估转换为字典"""
        feature = HardwareSecurityFeature(
            name="Intel CET-IBT",
            feature_type=HardwareFeature.INTEL_CET_IBT,
            enabled=True,
            description="间接分支跟踪",
            impact_on_exploitation=ExploitabilityImpact.BLOCKED
        )
        
        assessment = VulnerabilityExploitabilityAssessment(
            vulnerability_type="栈缓冲区溢出",
            original_difficulty=ExploitDifficulty.EASY,
            adjusted_difficulty=ExploitDifficulty.HARD,
            difficulty_change="难度增加: Easy → Hard",
            hardware_features=[feature],
            impacted_attack_techniques=["ROP"],
            suggested_bypass_techniques=["使用 ENDBR64 gadgets"],
            information_leak_requirements=["GOT 表地址"],
            assessment_notes=["CET IBT 阻止传统 ROP"],
            risk_adjustment="风险显著降低"
        )
        
        result = assessment.to_dict()
        
        self.assertEqual(result['vulnerability_type'], "栈缓冲区溢出")
        self.assertEqual(result['original_difficulty'], "Easy")
        self.assertEqual(result['adjusted_difficulty'], "Hard")
        self.assertIn("难度增加", result['difficulty_change'])


class TestHardwareSecurityEvaluationReport(unittest.TestCase):
    """硬件安全评估报告测试"""
    
    def test_report_initialization(self):
        """测试报告初始化"""
        report = HardwareSecurityEvaluationReport(
            binary_path="/test/binary",
            architecture="x86_64",
            overall_exploitability_rating="低",
            security_posture="强防护",
            evaluation_success=True
        )
        
        self.assertEqual(report.binary_path, "/test/binary")
        self.assertEqual(report.architecture, "x86_64")
        self.assertTrue(report.evaluation_success)
    
    def test_get_enabled_features(self):
        """测试获取已启用的特性"""
        report = HardwareSecurityEvaluationReport(
            binary_path="/test/binary",
            architecture="x86_64"
        )
        
        feature1 = HardwareSecurityFeature(
            name="CET-IBT",
            feature_type=HardwareFeature.INTEL_CET_IBT,
            enabled=True,
            description="Test",
            impact_on_exploitation=ExploitabilityImpact.BLOCKED
        )
        feature2 = HardwareSecurityFeature(
            name="CET-SHSTK",
            feature_type=HardwareFeature.INTEL_CET_SHSTK,
            enabled=False,
            description="Test",
            impact_on_exploitation=ExploitabilityImpact.NO_IMPACT
        )
        
        report.detected_features.append(feature1)
        report.detected_features.append(feature2)
        
        enabled = report.get_enabled_features()
        self.assertEqual(len(enabled), 1)
        self.assertEqual(enabled[0].name, "CET-IBT")
    
    def test_get_blocked_features(self):
        """测试获取被阻止的特性"""
        report = HardwareSecurityEvaluationReport(
            binary_path="/test/binary",
            architecture="x86_64"
        )
        
        feature1 = HardwareSecurityFeature(
            name="CET-IBT",
            feature_type=HardwareFeature.INTEL_CET_IBT,
            enabled=True,
            description="Test",
            impact_on_exploitation=ExploitabilityImpact.BLOCKED
        )
        feature2 = HardwareSecurityFeature(
            name="NX",
            feature_type=HardwareFeature.SMEP,
            enabled=False,
            description="Test",
            impact_on_exploitation=ExploitabilityImpact.NO_IMPACT
        )
        
        report.detected_features.append(feature1)
        report.detected_features.append(feature2)
        
        blocked = report.get_blocked_features()
        self.assertEqual(len(blocked), 1)
    
    def test_report_to_dict(self):
        """测试报告转换为字典"""
        report = HardwareSecurityEvaluationReport(
            binary_path="/test/binary",
            architecture="x86_64",
            overall_exploitability_rating="低",
            security_posture="强防护",
            evaluation_success=True
        )
        
        result = report.to_dict()
        
        self.assertEqual(result['binary_path'], "/test/binary")
        self.assertEqual(result['architecture'], "x86_64")
        self.assertEqual(result['overall_exploitability_rating'], "低")
        self.assertTrue(result['evaluation_success'])


class TestEvaluateHardwareSecurity(unittest.TestCase):
    """硬件安全评估函数测试"""
    
    @patch.object(HardwareSecurityEvaluator, 'evaluate')
    def test_evaluate_hardware_security_function(self, mock_evaluate):
        """测试 evaluate_hardware_security 函数"""
        mock_report = HardwareSecurityEvaluationReport(
            binary_path="/test/binary",
            architecture="x86_64",
            evaluation_success=True
        )
        mock_evaluate.return_value = mock_report
        
        result = evaluate_hardware_security("/test/binary")
        
        mock_evaluate.assert_called_once()
        self.assertEqual(result.binary_path, "/test/binary")


class TestFormatEvaluationReport(unittest.TestCase):
    """评估报告格式化测试"""
    
    def test_format_evaluation_report_basic(self):
        """测试基本报告格式化"""
        report = HardwareSecurityEvaluationReport(
            binary_path="/test/binary",
            architecture="x86_64",
            overall_exploitability_rating="极低",
            security_posture="强防护",
            evaluation_success=True
        )
        
        formatted = format_evaluation_report(report)
        
        self.assertIn("硬件辅助安全特性", formatted)
        self.assertIn("/test/binary", formatted)
        self.assertIn("x86_64", formatted)
        self.assertIn("极低", formatted)
    
    def test_format_evaluation_report_with_features(self):
        """测试带特性的报告格式化"""
        report = HardwareSecurityEvaluationReport(
            binary_path="/test/binary",
            architecture="x86_64",
            evaluation_success=True
        )
        
        feature = HardwareSecurityFeature(
            name="Intel CET-IBT",
            feature_type=HardwareFeature.INTEL_CET_IBT,
            enabled=True,
            description="间接分支跟踪",
            impact_on_exploitation=ExploitabilityImpact.BLOCKED,
            affected_attack_techniques=["ROP", "JOP"]
        )
        report.detected_features.append(feature)
        
        formatted = format_evaluation_report(report)
        
        self.assertIn("CET-IBT", formatted)
        self.assertIn("Blocked", formatted)


class TestGetHwSecurityEvalPrompt(unittest.TestCase):
    """硬件安全评估提示词测试"""
    
    def test_get_prompt_basic(self):
        """测试基本提示词生成"""
        vuln_info = {
            'type': '栈缓冲区溢出',
            'description': 'Test vulnerability',
            'location': '0x401000',
            'exploitability': 'High'
        }
        
        hw_features = [
            {
                'name': 'Intel CET-IBT',
                'description': '间接分支跟踪',
                'enabled': True,
                'impact_on_exploitation': 'Blocked'
            }
        ]
        
        prompt = get_hw_security_eval_prompt(vuln_info, hw_features)
        
        self.assertIn('栈缓冲区溢出', prompt)
        self.assertIn('Intel CET-IBT', prompt)
        self.assertIn('High', prompt)


class TestDifficultyChangeCalculation(unittest.TestCase):
    """难度变化计算测试"""
    
    def setUp(self):
        self.evaluator = HardwareSecurityEvaluator("/test/binary")
    
    def test_get_difficulty_change_increase(self):
        """测试难度增加"""
        result = self.evaluator._get_difficulty_change(
            ExploitDifficulty.EASY,
            ExploitDifficulty.HARD
        )
        
        self.assertIn("增加", result)
        self.assertIn("Easy", result)
        self.assertIn("Hard", result)
    
    def test_get_difficulty_change_decrease(self):
        """测试难度降低"""
        result = self.evaluator._get_difficulty_change(
            ExploitDifficulty.HARD,
            ExploitDifficulty.EASY
        )
        
        self.assertIn("降低", result)
    
    def test_get_difficulty_change_same(self):
        """测试难度不变"""
        result = self.evaluator._get_difficulty_change(
            ExploitDifficulty.MEDIUM,
            ExploitDifficulty.MEDIUM
        )
        
        self.assertEqual("难度不变", result)


class TestRiskAdjustment(unittest.TestCase):
    """风险调整测试"""
    
    def setUp(self):
        self.evaluator = HardwareSecurityEvaluator("/test/binary")
    
    def test_risk_adjustment_significant(self):
        """测试显著风险降低"""
        result = self.evaluator._get_risk_adjustment(
            ExploitDifficulty.EASY,
            ExploitDifficulty.EXTREMELY_HARD
        )
        
        self.assertIn("显著降低", result)
    
    def test_risk_adjustment_some(self):
        """测试部分风险降低"""
        result = self.evaluator._get_risk_adjustment(
            ExploitDifficulty.EASY,
            ExploitDifficulty.HARD
        )
        
        self.assertIn("降低", result)
    
    def test_risk_adjustment_no_change(self):
        """测试风险无变化"""
        result = self.evaluator._get_risk_adjustment(
            ExploitDifficulty.MEDIUM,
            ExploitDifficulty.MEDIUM
        )
        
        self.assertIn("变化", result)


if __name__ == '__main__':
    unittest.main()
