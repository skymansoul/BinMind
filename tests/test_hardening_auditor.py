#!/usr/bin/env python3
# hardening auditor test suite, mostly checksec-style checks
# Planned: CFI and SafeStack detection patterns
import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch


from modules.hardening_auditor import (
    HardeningAuditReport,
    HardeningAuditor,
    HardeningCheck,
    HardeningRecommendation,
    HardeningStatus,
    RiskLevel,
    audit_binary,
    format_audit_report,
)


class TestHardeningAuditor(unittest.TestCase):
    """Hardening auditor -- ELF/PE detection, scoring"""

    def setUp(self):
        self.m_auditor = HardeningAuditor("/test/binary", timeout=30)

    def test_auditor_initialization(self):
        self.assertEqual(self.m_auditor.binary_path, "/test/binary")
        self.assertEqual(self.m_auditor.timeout, 30)

    def test_detect_format_elf(self):
        """\\x7fELF header -> ELF format"""
        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".elf") as j:
            j.write(b"\x7fELF")
            temp_path = j.name
        try:
            auditor = HardeningAuditor(temp_path)
            self.assertEqual(auditor.binary_format, "ELF")
        finally:
            os.unlink(temp_path)

    def test_detect_format_pe(self):
        """MZ header -> PE format"""
        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".exe") as k:
            k.write(b"MZ")
            temp_path = k.name
        try:
            auditor = HardeningAuditor(temp_path)
            self.assertEqual(auditor.binary_format, "PE")
        finally:
            os.unlink(temp_path)

    def test_detect_format_unknown(self):
        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".bin") as ii:
            ii.write(b"\x00\x00\x00\x00")
            temp_path = ii.name
        try:
            auditor = HardeningAuditor(temp_path)
            self.assertEqual(auditor.binary_format, "UNKNOWN")
        finally:
            os.unlink(temp_path)

    def test_report_initialization(self):
        report = HardeningAuditReport(
            binary_path="/test/binary", binary_format="ELF"
        )
        if report is None:
            self.fail("report is None")
        self.assertEqual(report.binary_path, "/test/binary")
        self.assertEqual(report.binary_format, "ELF")
        self.assertFalse(report.audit_success)
        self.assertEqual(len(report.checks), 0)
        self.assertEqual(report.overall_score, 0)

    def test_get_enabled_checks(self):
        report = HardeningAuditReport(
            binary_path="/test/binary", binary_format="ELF"
        )
        c1 = HardeningCheck(
            name="NX", description="Test",
            status=HardeningStatus.ENABLED, risk_level=RiskLevel.INFO,
        )
        c2 = HardeningCheck(
            name="PIE", description="Test",
            status=HardeningStatus.DISABLED, risk_level=RiskLevel.MEDIUM,
        )
        report.checks.append(c1)
        report.checks.append(c2)
        enabled = report.get_enabled_checks()
        disabled = report.get_disabled_checks()
        self.assertEqual(len(enabled), 1)
        self.assertEqual(len(disabled), 1)
        self.assertEqual(enabled[0].name, "NX")

    def test_get_failed_checks(self):
        report = HardeningAuditReport(
            binary_path="/test/binary", binary_format="ELF"
        )
        c1 = HardeningCheck(
            name="NX", description="Test",
            status=HardeningStatus.ENABLED, risk_level=RiskLevel.INFO,
        )
        c2 = HardeningCheck(
            name="Canary", description="Test",
            status=HardeningStatus.DISABLED, risk_level=RiskLevel.HIGH,
        )
        c3 = HardeningCheck(
            name="RELRO", description="Test",
            status=HardeningStatus.UNKNOWN, risk_level=RiskLevel.MEDIUM,
        )
        report.checks.append(c1)
        report.checks.append(c2)
        report.checks.append(c3)
        failed = report.get_failed_checks()
        self.assertEqual(len(failed), 2)

    def test_calculate_overall_score(self):
        """Scoring: 1 enabled-high + 1 disabled-high + 1 enabled-med"""
        report = HardeningAuditReport(
            binary_path="/test/binary", binary_format="ELF"
        )
        c1 = HardeningCheck(
            name="NX", description="Test",
            status=HardeningStatus.ENABLED, risk_level=RiskLevel.HIGH,
        )
        c2 = HardeningCheck(
            name="Canary", description="Test",
            status=HardeningStatus.DISABLED, risk_level=RiskLevel.HIGH,
        )
        c3 = HardeningCheck(
            name="PIE", description="Test",
            status=HardeningStatus.ENABLED, risk_level=RiskLevel.MEDIUM,
        )
        report.checks.append(c1)
        report.checks.append(c2)
        report.checks.append(c3)
        self.m_auditor._calculate_overall_score(report)
        self.assertGreater(report.overall_score, 0)
        self.assertLessEqual(report.overall_score, 100)

    def test_hardening_check_to_dict(self):
        """NX check -> dict, with CVE reference"""
        check = HardeningCheck(
            name="NX",
            description="Non-executable stack",
            status=HardeningStatus.ENABLED,
            risk_level=RiskLevel.HIGH,
            current_value="enabled",
            recommended_value="enabled",
            fix_command="gcc -z noexecstack",
            cve_references=["CVE-2021-1234"],
            details="test details",
        )
        result = check.to_dict()
        self.assertEqual(result["name"], "NX")
        self.assertEqual(result["status"], "Enabled")
        self.assertEqual(result["risk_level"], "High")
        self.assertIn("CVE-2021-1234", result["cve_references"])

    def test_report_to_dict(self):
        report = HardeningAuditReport(
            binary_path="/test/binary", binary_format="ELF",
            overall_score=75, audit_success=True,
        )
        result = report.to_dict()
        self.assertEqual(result["binary_path"], "/test/binary")
        self.assertEqual(result["overall_score"], 75)
        self.assertTrue(result["audit_success"])


class TestHardeningCheckStatus(unittest.TestCase):
    """HardeningStatus + RiskLevel enums"""

    def test_hardening_status_values(self):
        self.assertEqual(HardeningStatus.ENABLED.value, "Enabled")
        self.assertEqual(HardeningStatus.DISABLED.value, "Disabled")
        self.assertEqual(HardeningStatus.PARTIAL.value, "Partial")
        self.assertEqual(HardeningStatus.UNKNOWN.value, "Unknown")

    def test_risk_level_values(self):
        self.assertEqual(RiskLevel.CRITICAL.value, "Critical")
        self.assertEqual(RiskLevel.HIGH.value, "High")
        self.assertEqual(RiskLevel.MEDIUM.value, "Medium")
        self.assertEqual(RiskLevel.LOW.value, "Low")
        self.assertEqual(RiskLevel.INFO.value, "Info")


class TestHardeningScriptGeneration(unittest.TestCase):
    """Hardening script generation -- bash for ELF, cl.exe for PE"""

    def setUp(self):
        self.m_auditor = HardeningAuditor("/test/binary", timeout=30)

    def test_generate_hardening_script_elf(self):
        report = HardeningAuditReport(
            binary_path="/test/binary", binary_format="ELF"
        )
        nx = HardeningCheck(
            name="NX", description="Test",
            status=HardeningStatus.DISABLED, risk_level=RiskLevel.HIGH,
            fix_command="-z noexecstack",
        )
        pie = HardeningCheck(
            name="PIE", description="Test",
            status=HardeningStatus.DISABLED, risk_level=RiskLevel.MEDIUM,
            fix_command="-fPIE -pie",
        )
        report.checks.append(nx)
        report.checks.append(pie)
        self.m_auditor._generate_hardening_script(report)
        self.assertGreater(len(report.hardening_script), 0)
        self.assertIn("bash", report.hardening_script)
        self.assertIn("-z noexecstack", report.hardening_script)

    def test_generate_hardening_script_pe(self):
        report = HardeningAuditReport(
            binary_path="/test/binary.exe", binary_format="PE"
        )
        self.m_auditor._generate_hardening_script(report)
        self.assertIn("MSVC", report.hardening_script)


class TestFormatAuditReport(unittest.TestCase):
    """format_audit_report -- produces readable output"""

    def test_format_audit_report_basic(self):
        report = HardeningAuditReport(
            binary_path="/test/binary", binary_format="ELF",
            overall_score=65, risk_level=RiskLevel.MEDIUM,
            audit_success=True,
        )
        formatted = format_audit_report(report)
        self.assertIn("Binary Hardening Audit Report", formatted)
        self.assertIn("/test/binary", formatted)
        self.assertIn("65", formatted)
        self.assertIn("Medium", formatted)

    def test_format_audit_report_with_checks(self):
        report = HardeningAuditReport(
            binary_path="/test/binary", binary_format="ELF",
            audit_success=True,
        )
        check = HardeningCheck(
            name="NX", description="Non-executable stack",
            status=HardeningStatus.ENABLED, risk_level=RiskLevel.INFO,
        )
        report.checks.append(check)
        formatted = format_audit_report(report)
        self.assertIn("NX", formatted)
        self.assertIn("Enabled", formatted)

    def test_format_audit_report_with_recommendations(self):
        report = HardeningAuditReport(
            binary_path="/test/binary", binary_format="ELF",
            audit_success=True,
        )
        report.recommendations.append("Enable NX: -z noexecstack")
        report.recommendations.append("Enable Canary: -fstack-protector-strong")
        formatted = format_audit_report(report)
        self.assertIn("Recommendations", formatted)
        self.assertIn("-z noexecstack", formatted)


class TestAuditBinary(unittest.TestCase):
    """audit_binary convenience function"""

    @patch.object(HardeningAuditor, "audit")
    def test_audit_binary_function(self, mock_audit):
        mock_report = HardeningAuditReport(
            binary_path="/test/binary", binary_format="ELF",
            audit_success=True,
        )
        mock_audit.return_value = mock_report
        result = audit_binary("/test/binary")
        mock_audit.assert_called_once()
        self.assertEqual(result.binary_path, "/test/binary")


if __name__ == "__main__":
    unittest.main()
