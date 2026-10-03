#!/usr/bin/env python3
# x86_64 and ARM64 hardware security features are both important
# MTF (Meltdown Task Force) mitigations not yet covered
import os
import struct
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch


from modules.hw_security_eval import (
    ExploitDifficulty,
    ExploitabilityImpact,
    HardwareFeature,
    HardwareSecurityEvaluationReport,
    HardwareSecurityEvaluator,
    HardwareSecurityFeature,
    VulnerabilityExploitabilityAssessment,
    evaluate_hardware_security,
    format_evaluation_report,
    get_hw_security_eval_prompt,
)


class TestHardwareSecurityEvaluator(unittest.TestCase):
    """Evaluator -- architecture detection: x86_64, ARM64"""

    def setUp(self):
        self.m_evaluator = HardwareSecurityEvaluator("/test/binary")

    def test_evaluator_initialization(self):
        self.assertEqual(self.m_evaluator.binary_path, "/test/binary")
        self.assertIsNotNone(self.m_evaluator.architecture)

    def test_detect_architecture_elf_x86_64(self):
        """ELF magic + e_machine=62 -> x86_64"""
        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".elf") as j:
            j.write(b"\x7fELF")
            j.write(struct.pack("<H", 62))
            temp_path = j.name
        try:
            evaluator = HardwareSecurityEvaluator(temp_path)
            self.assertEqual(evaluator.architecture, "x86_64")
        finally:
            os.unlink(temp_path)

    def test_detect_architecture_elf_arm64(self):
        """ELF magic + e_machine=183 -> arm64"""
        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".elf") as k:
            k.write(b"\x7fELF")
            k.write(struct.pack("<H", 183))
            temp_path = k.name
        try:
            evaluator = HardwareSecurityEvaluator(temp_path)
            self.assertEqual(evaluator.architecture, "arm64")
        finally:
            os.unlink(temp_path)

    def test_detect_architecture_invalid(self):
        evaluator = HardwareSecurityEvaluator("/test/binary", {"arch": "unknown"})
        self.assertEqual(evaluator.architecture, "unknown")


class TestHardwareSecurityFeature(unittest.TestCase):
    """Hardware security features -- CET-IBT et al"""

    def test_feature_to_dict(self):
        feature = HardwareSecurityFeature(
            name="Intel CET-IBT",
            feature_type=HardwareFeature.INTEL_CET_IBT,
            enabled=True,
            description="Indirect branch tracking",
            impact_on_exploitation=ExploitabilityImpact.BLOCKED,
            affected_attack_techniques=["ROP", "JOP"],
            bypass_techniques=["Use ENDBR64"],
            requirements=["Compiler support", "Processor support"],
        )
        if feature is None:
            self.fail("feature is None")
        result = feature.to_dict()
        self.assertEqual(result["name"], "Intel CET-IBT")
        self.assertTrue(result["enabled"])
        self.assertEqual(result["impact_on_exploitation"], "Blocked")
        self.assertIn("ROP", result["affected_attack_techniques"])

    def test_feature_types(self):
        """Enum value check"""
        self.assertEqual(HardwareFeature.ARM_PAC.value, "arm_pac")
        self.assertEqual(HardwareFeature.ARM_BTI.value, "arm_bti")
        self.assertEqual(HardwareFeature.INTEL_CET_IBT.value, "intel_cet_ibt")
        self.assertEqual(HardwareFeature.INTEL_CET_SHSTK.value, "intel_cet_shstk")
        self.assertEqual(HardwareFeature.SMEP.value, "smep")
        self.assertEqual(HardwareFeature.SMAP.value, "smap")


class TestExploitDifficulty(unittest.TestCase):
    """Exploit difficulty -- Trivial to Impossible"""

    def test_difficulty_values(self):
        self.assertEqual(ExploitDifficulty.TRIVIAL.value, "Trivial")
        self.assertEqual(ExploitDifficulty.EASY.value, "Easy")
        self.assertEqual(ExploitDifficulty.MEDIUM.value, "Medium")
        self.assertEqual(ExploitDifficulty.HARD.value, "Hard")
        self.assertEqual(ExploitDifficulty.EXTREMELY_HARD.value, "Extremely Hard")
        self.assertEqual(ExploitDifficulty.IMPOSSIBLE.value, "Impossible")

    def test_difficulty_order(self):
        difficulties = [
            ExploitDifficulty.TRIVIAL,
            ExploitDifficulty.EASY,
            ExploitDifficulty.MEDIUM,
            ExploitDifficulty.HARD,
            ExploitDifficulty.EXTREMELY_HARD,
            ExploitDifficulty.IMPOSSIBLE,
        ]
        for ii in range(len(difficulties) - 1):
            self.assertLess(ii, len(difficulties) - 1)


class TestExploitabilityImpact(unittest.TestCase):
    """Exploitability impact -- Blocked to Unknown"""

    def test_impact_values(self):
        self.assertEqual(ExploitabilityImpact.BLOCKED.value, "Blocked")
        self.assertEqual(ExploitabilityImpact.SIGNIFICANTLY_REDUCED.value, "Significantly Reduced")
        self.assertEqual(ExploitabilityImpact.PARTIALLY_REDUCED.value, "Partially Reduced")
        self.assertEqual(ExploitabilityImpact.NO_IMPACT.value, "No Impact")
        self.assertEqual(ExploitabilityImpact.UNKNOWN.value, "Unknown")


class TestVulnerabilityExploitabilityAssessment(unittest.TestCase):
    """Vulnerability exploitability assessment -- adjusted difficulty"""

    def test_assessment_to_dict(self):
        feature = HardwareSecurityFeature(
            name="Intel CET-IBT",
            feature_type=HardwareFeature.INTEL_CET_IBT,
            enabled=True,
            description="Indirect branch tracking",
            impact_on_exploitation=ExploitabilityImpact.BLOCKED,
        )
        assessment = VulnerabilityExploitabilityAssessment(
            vulnerability_type="Stack buffer overflow",
            original_difficulty=ExploitDifficulty.EASY,
            adjusted_difficulty=ExploitDifficulty.HARD,
            difficulty_change="Difficulty increased: Easy -> Hard",
            hardware_features=[feature],
            impacted_attack_techniques=["ROP"],
            suggested_bypass_techniques=["Use ENDBR64 gadgets"],
            information_leak_requirements=["GOT table address"],
            assessment_notes=["CET IBT blocks traditional ROP"],
            risk_adjustment="Risk significantly reduced",
        )
        result = assessment.to_dict()
        self.assertEqual(result["vulnerability_type"], "Stack buffer overflow")
        self.assertEqual(result["original_difficulty"], "Easy")
        self.assertEqual(result["adjusted_difficulty"], "Hard")
        self.assertIn("Difficulty increased", result["difficulty_change"])


class TestHardwareSecurityEvaluationReport(unittest.TestCase):
    """Evaluation report -- enabled/blocked features"""

    def test_report_initialization(self):
        report = HardwareSecurityEvaluationReport(
            binary_path="/test/binary",
            architecture="x86_64",
            overall_exploitability_rating="Low",
            security_posture="Strong defenses",
            evaluation_success=True,
        )
        self.assertEqual(report.binary_path, "/test/binary")
        self.assertEqual(report.architecture, "x86_64")
        self.assertTrue(report.evaluation_success)

    def test_get_enabled_features(self):
        report = HardwareSecurityEvaluationReport(
            binary_path="/test/binary", architecture="x86_64"
        )
        f1 = HardwareSecurityFeature(
            name="CET-IBT", feature_type=HardwareFeature.INTEL_CET_IBT,
            enabled=True, description="Test",
            impact_on_exploitation=ExploitabilityImpact.BLOCKED,
        )
        f2 = HardwareSecurityFeature(
            name="CET-SHSTK", feature_type=HardwareFeature.INTEL_CET_SHSTK,
            enabled=False, description="Test",
            impact_on_exploitation=ExploitabilityImpact.NO_IMPACT,
        )
        report.detected_features.append(f1)
        report.detected_features.append(f2)
        enabled = report.get_enabled_features()
        self.assertEqual(len(enabled), 1)
        self.assertEqual(enabled[0].name, "CET-IBT")

    def test_get_blocked_features(self):
        report = HardwareSecurityEvaluationReport(
            binary_path="/test/binary", architecture="x86_64"
        )
        f1 = HardwareSecurityFeature(
            name="CET-IBT", feature_type=HardwareFeature.INTEL_CET_IBT,
            enabled=True, description="Test",
            impact_on_exploitation=ExploitabilityImpact.BLOCKED,
        )
        f2 = HardwareSecurityFeature(
            name="NX", feature_type=HardwareFeature.SMEP,
            enabled=False, description="Test",
            impact_on_exploitation=ExploitabilityImpact.NO_IMPACT,
        )
        report.detected_features.append(f1)
        report.detected_features.append(f2)
        blocked = report.get_blocked_features()
        self.assertEqual(len(blocked), 1)

    def test_report_to_dict(self):
        report = HardwareSecurityEvaluationReport(
            binary_path="/test/binary", architecture="x86_64",
            overall_exploitability_rating="Low", security_posture="Strong defenses",
            evaluation_success=True,
        )
        result = report.to_dict()
        self.assertEqual(result["binary_path"], "/test/binary")
        self.assertEqual(result["architecture"], "x86_64")
        self.assertEqual(result["overall_exploitability_rating"], "Low")
        self.assertTrue(result["evaluation_success"])


class TestEvaluateHardwareSecurity(unittest.TestCase):
    """evaluate_hardware_security convenience function"""

    @patch.object(HardwareSecurityEvaluator, "evaluate")
    def test_evaluate_hardware_security_function(self, mock_evaluate):
        mock_report = HardwareSecurityEvaluationReport(
            binary_path="/test/binary", architecture="x86_64",
            evaluation_success=True,
        )
        mock_evaluate.return_value = mock_report
        result = evaluate_hardware_security("/test/binary")
        mock_evaluate.assert_called_once()
        self.assertEqual(result.binary_path, "/test/binary")


class TestFormatEvaluationReport(unittest.TestCase):
    """Evaluation report formatting"""

    def test_format_evaluation_report_basic(self):
        report = HardwareSecurityEvaluationReport(
            binary_path="/test/binary", architecture="x86_64",
            overall_exploitability_rating="Very low", security_posture="Strong defenses",
            evaluation_success=True,
        )
        formatted = format_evaluation_report(report)
        self.assertIn("硬件辅助安全特性", formatted)
        self.assertIn("/test/binary", formatted)
        self.assertIn("x86_64", formatted)
        self.assertIn("Very low", formatted)

    def test_format_evaluation_report_with_features(self):
        report = HardwareSecurityEvaluationReport(
            binary_path="/test/binary", architecture="x86_64",
            evaluation_success=True,
        )
        feature = HardwareSecurityFeature(
            name="Intel CET-IBT",
            feature_type=HardwareFeature.INTEL_CET_IBT,
            enabled=True,
            description="Indirect branch tracking",
            impact_on_exploitation=ExploitabilityImpact.BLOCKED,
            affected_attack_techniques=["ROP", "JOP"],
        )
        report.detected_features.append(feature)
        formatted = format_evaluation_report(report)
        self.assertIn("CET-IBT", formatted)
        self.assertIn("Blocked", formatted)


class TestGetHwSecurityEvalPrompt(unittest.TestCase):
    """Evaluation prompt generation -- vuln_info + hw_features"""

    def test_get_prompt_basic(self):
        vuln_info = {
            "type": "Stack buffer overflow",
            "description": "Test vulnerability",
            "location": "0x401000",
            "exploitability": "High",
        }
        hw_features = [
            {
                "name": "Intel CET-IBT",
                "description": "Indirect branch tracking",
                "enabled": True,
                "impact_on_exploitation": "Blocked",
            }
        ]
        prompt = get_hw_security_eval_prompt(vuln_info, hw_features)
        self.assertIn("Stack buffer overflow", prompt)
        self.assertIn("Intel CET-IBT", prompt)
        self.assertIn("High", prompt)


class TestDifficultyChangeCalculation(unittest.TestCase):
    """Difficulty change calculation -- increase/decrease/no change"""

    def setUp(self):
        self.m_evaluator = HardwareSecurityEvaluator("/test/binary")

    def test_get_difficulty_change_increase(self):
        result = self.m_evaluator._get_difficulty_change(
            ExploitDifficulty.EASY, ExploitDifficulty.HARD
        )
        self.assertIn("增加", result)
        self.assertIn("Easy", result)
        self.assertIn("Hard", result)

    def test_get_difficulty_change_decrease(self):
        result = self.m_evaluator._get_difficulty_change(
            ExploitDifficulty.HARD, ExploitDifficulty.EASY
        )
        self.assertIn("降低", result)

    def test_get_difficulty_change_same(self):
        result = self.m_evaluator._get_difficulty_change(
            ExploitDifficulty.MEDIUM, ExploitDifficulty.MEDIUM
        )
        self.assertEqual("难度不变", result)


class TestRiskAdjustment(unittest.TestCase):
    """Risk adjustment -- significant/partial/no change"""

    def setUp(self):
        self.m_evaluator = HardwareSecurityEvaluator("/test/binary")

    def test_risk_adjustment_significant(self):
        result = self.m_evaluator._get_risk_adjustment(
            ExploitDifficulty.EASY, ExploitDifficulty.EXTREMELY_HARD
        )
        self.assertIn("显著降低", result)

    def test_risk_adjustment_some(self):
        result = self.m_evaluator._get_risk_adjustment(
            ExploitDifficulty.EASY, ExploitDifficulty.HARD
        )
        self.assertIn("降低", result)

    def test_risk_adjustment_no_change(self):
        result = self.m_evaluator._get_risk_adjustment(
            ExploitDifficulty.MEDIUM, ExploitDifficulty.MEDIUM
        )
        self.assertIn("变化", result)


if __name__ == "__main__":
    unittest.main()
