#!/usr/bin/env python3
"""
二进制安全加固审计模块单元测试
"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.hardening_auditor import (
    HardeningAuditor,
    HardeningAuditReport,
    HardeningCheck,
    HardeningStatus,
    RiskLevel,
    HardeningRecommendation,
    audit_binary,
    format_audit_report
)


class TestHardeningAuditor(unittest.TestCase):
    """加固审计器测试"""
    
    def setUp(self):
        """测试前准备"""
        self.auditor = HardeningAuditor("/test/binary", timeout=30)
    
    def test_auditor_initialization(self):
        """测试审计器初始化"""
        self.assertEqual(self.auditor.binary_path, "/test/binary")
        self.assertEqual(self.auditor.timeout, 30)
    
    def test_detect_format_elf(self):
        """测试 ELF 格式检测"""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.elf') as f:
            f.write(b'\x7fELF')
            temp_path = f.name
        
        try:
            auditor = HardeningAuditor(temp_path)
            self.assertEqual(auditor.binary_format, 'ELF')
        finally:
            os.unlink(temp_path)
    
    def test_detect_format_pe(self):
        """测试 PE 格式检测"""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.exe') as f:
            f.write(b'MZ')
            temp_path = f.name
        
        try:
            auditor = HardeningAuditor(temp_path)
            self.assertEqual(auditor.binary_format, 'PE')
        finally:
            os.unlink(temp_path)
    
    def test_detect_format_unknown(self):
        """测试未知格式检测"""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.bin') as f:
            f.write(b'\x00\x00\x00\x00')
            temp_path = f.name
        
        try:
            auditor = HardeningAuditor(temp_path)
            self.assertEqual(auditor.binary_format, 'UNKNOWN')
        finally:
            os.unlink(temp_path)
    
    def test_report_initialization(self):
        """测试报告初始化"""
        report = HardeningAuditReport(
            binary_path="/test/binary",
            binary_format="ELF"
        )
        
        self.assertEqual(report.binary_path, "/test/binary")
        self.assertEqual(report.binary_format, "ELF")
        self.assertFalse(report.audit_success)
        self.assertEqual(len(report.checks), 0)
        self.assertEqual(report.overall_score, 0)
    
    def test_get_enabled_checks(self):
        """测试获取已启用的检查项"""
        report = HardeningAuditReport(
            binary_path="/test/binary",
            binary_format="ELF"
        )
        
        check1 = HardeningCheck(
            name="NX",
            description="Test",
            status=HardeningStatus.ENABLED,
            risk_level=RiskLevel.INFO
        )
        check2 = HardeningCheck(
            name="PIE",
            description="Test",
            status=HardeningStatus.DISABLED,
            risk_level=RiskLevel.MEDIUM
        )
        
        report.checks.append(check1)
        report.checks.append(check2)
        
        enabled = report.get_enabled_checks()
        disabled = report.get_disabled_checks()
        
        self.assertEqual(len(enabled), 1)
        self.assertEqual(len(disabled), 1)
        self.assertEqual(enabled[0].name, "NX")
    
    def test_get_failed_checks(self):
        """测试获取失败的检查项"""
        report = HardeningAuditReport(
            binary_path="/test/binary",
            binary_format="ELF"
        )
        
        check1 = HardeningCheck(
            name="NX",
            description="Test",
            status=HardeningStatus.ENABLED,
            risk_level=RiskLevel.INFO
        )
        check2 = HardeningCheck(
            name="Canary",
            description="Test",
            status=HardeningStatus.DISABLED,
            risk_level=RiskLevel.HIGH
        )
        check3 = HardeningCheck(
            name="RELRO",
            description="Test",
            status=HardeningStatus.UNKNOWN,
            risk_level=RiskLevel.MEDIUM
        )
        
        report.checks.append(check1)
        report.checks.append(check2)
        report.checks.append(check3)
        
        failed = report.get_failed_checks()
        
        self.assertEqual(len(failed), 2)
    
    def test_calculate_overall_score(self):
        """测试整体评分计算"""
        report = HardeningAuditReport(
            binary_path="/test/binary",
            binary_format="ELF"
        )
        
        check1 = HardeningCheck(
            name="NX",
            description="Test",
            status=HardeningStatus.ENABLED,
            risk_level=RiskLevel.HIGH
        )
        check2 = HardeningCheck(
            name="Canary",
            description="Test",
            status=HardeningStatus.DISABLED,
            risk_level=RiskLevel.HIGH
        )
        check3 = HardeningCheck(
            name="PIE",
            description="Test",
            status=HardeningStatus.ENABLED,
            risk_level=RiskLevel.MEDIUM
        )
        
        report.checks.append(check1)
        report.checks.append(check2)
        report.checks.append(check3)
        
        self.auditor._calculate_overall_score(report)
        
        self.assertGreater(report.overall_score, 0)
        self.assertLessEqual(report.overall_score, 100)
    
    def test_hardening_check_to_dict(self):
        """测试 HardeningCheck 转换为字典"""
        check = HardeningCheck(
            name="NX",
            description="不可执行位",
            status=HardeningStatus.ENABLED,
            risk_level=RiskLevel.HIGH,
            current_value="启用",
            recommended_value="启用",
            fix_command="gcc -z noexecstack",
            cve_references=["CVE-2021-1234"],
            details="测试详情"
        )
        
        result = check.to_dict()
        
        self.assertEqual(result['name'], "NX")
        self.assertEqual(result['status'], "Enabled")
        self.assertEqual(result['risk_level'], "High")
        self.assertIn("CVE-2021-1234", result['cve_references'])
    
    def test_report_to_dict(self):
        """测试报告转换为字典"""
        report = HardeningAuditReport(
            binary_path="/test/binary",
            binary_format="ELF",
            overall_score=75,
            audit_success=True
        )
        
        result = report.to_dict()
        
        self.assertEqual(result['binary_path'], "/test/binary")
        self.assertEqual(result['overall_score'], 75)
        self.assertTrue(result['audit_success'])


class TestHardeningCheckStatus(unittest.TestCase):
    """加固状态枚举测试"""
    
    def test_hardening_status_values(self):
        """测试状态枚举值"""
        self.assertEqual(HardeningStatus.ENABLED.value, "Enabled")
        self.assertEqual(HardeningStatus.DISABLED.value, "Disabled")
        self.assertEqual(HardeningStatus.PARTIAL.value, "Partial")
        self.assertEqual(HardeningStatus.UNKNOWN.value, "Unknown")
    
    def test_risk_level_values(self):
        """测试风险等级枚举值"""
        self.assertEqual(RiskLevel.CRITICAL.value, "Critical")
        self.assertEqual(RiskLevel.HIGH.value, "High")
        self.assertEqual(RiskLevel.MEDIUM.value, "Medium")
        self.assertEqual(RiskLevel.LOW.value, "Low")
        self.assertEqual(RiskLevel.INFO.value, "Info")


class TestHardeningScriptGeneration(unittest.TestCase):
    """加固脚本生成测试"""
    
    def setUp(self):
        self.auditor = HardeningAuditor("/test/binary", timeout=30)
    
    def test_generate_hardening_script_elf(self):
        """测试 ELF 加固脚本生成"""
        report = HardeningAuditReport(
            binary_path="/test/binary",
            binary_format="ELF"
        )
        
        nx_check = HardeningCheck(
            name="NX",
            description="Test",
            status=HardeningStatus.DISABLED,
            risk_level=RiskLevel.HIGH,
            fix_command="-z noexecstack"
        )
        pie_check = HardeningCheck(
            name="PIE",
            description="Test",
            status=HardeningStatus.DISABLED,
            risk_level=RiskLevel.MEDIUM,
            fix_command="-fPIE -pie"
        )
        
        report.checks.append(nx_check)
        report.checks.append(pie_check)
        
        self.auditor._generate_hardening_script(report)
        
        self.assertGreater(len(report.hardening_script), 0)
        self.assertIn("bash", report.hardening_script)
        self.assertIn("-z noexecstack", report.hardening_script)
    
    def test_generate_hardening_script_pe(self):
        """测试 PE 加固脚本生成"""
        report = HardeningAuditReport(
            binary_path="/test/binary.exe",
            binary_format="PE"
        )
        
        self.auditor._generate_hardening_script(report)
        
        self.assertIn("cl.exe", report.hardening_script)


class TestFormatAuditReport(unittest.TestCase):
    """报告格式化测试"""
    
    def test_format_audit_report_basic(self):
        """测试基本报告格式化"""
        report = HardeningAuditReport(
            binary_path="/test/binary",
            binary_format="ELF",
            overall_score=65,
            risk_level=RiskLevel.MEDIUM,
            audit_success=True
        )
        
        formatted = format_audit_report(report)
        
        self.assertIn("加固审计报告", formatted)
        self.assertIn("/test/binary", formatted)
        self.assertIn("65", formatted)
        self.assertIn("Medium", formatted)
    
    def test_format_audit_report_with_checks(self):
        """测试带检查项的报告格式化"""
        report = HardeningAuditReport(
            binary_path="/test/binary",
            binary_format="ELF",
            audit_success=True
        )
        
        check = HardeningCheck(
            name="NX",
            description="不可执行位",
            status=HardeningStatus.ENABLED,
            risk_level=RiskLevel.INFO
        )
        report.checks.append(check)
        
        formatted = format_audit_report(report)
        
        self.assertIn("NX", formatted)
        self.assertIn("Enabled", formatted)
    
    def test_format_audit_report_with_recommendations(self):
        """测试带建议的报告格式化"""
        report = HardeningAuditReport(
            binary_path="/test/binary",
            binary_format="ELF",
            audit_success=True
        )
        
        report.recommendations.append("启用 NX: -z noexecstack")
        report.recommendations.append("启用 Canary: -fstack-protector-strong")
        
        formatted = format_audit_report(report)
        
        self.assertIn("修复建议", formatted)
        self.assertIn("-z noexecstack", formatted)


class TestAuditBinary(unittest.TestCase):
    """便捷审计函数测试"""
    
    @patch.object(HardeningAuditor, 'audit')
    def test_audit_binary_function(self, mock_audit):
        """测试 audit_binary 函数"""
        mock_report = HardeningAuditReport(
            binary_path="/test/binary",
            binary_format="ELF",
            audit_success=True
        )
        mock_audit.return_value = mock_report
        
        result = audit_binary("/test/binary")
        
        mock_audit.assert_called_once()
        self.assertEqual(result.binary_path, "/test/binary")


if __name__ == '__main__':
    unittest.main()
