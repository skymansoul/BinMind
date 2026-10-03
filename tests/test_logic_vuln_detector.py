# -*- coding: utf-8 -*-

import pytest
from unittest.mock import Mock, patch, MagicMock
from modules.logic_vuln_detector import (
    LogicVulnDetector,
    SimpleLogicVulnDetector,
    AngrLogicVulnDetector,
    TOCTORuleEngine,
    PermissionAnalysisEngine,
    VulnerabilityType,
    VulnerabilitySeverity,
    VulnerabilityFinding,
    create_logic_vuln_detector,
    analyze_logic_vulnerabilities,
)


class TestVulnerabilityTypes:

    def test_type_enum_values(self):
        assert VulnerabilityType.TOCTOU.value == "toctou"
        assert VulnerabilityType.PERMISSION_BYPASS.value == "permission_bypass"
        assert VulnerabilityType.PATH_TRAVERSAL.value == "path_traversal"

    def test_severity_enum_values(self):
        assert VulnerabilitySeverity.CRITICAL.value == "Critical"
        assert VulnerabilitySeverity.HIGH.value == "High"
        assert VulnerabilitySeverity.MEDIUM.value == "Medium"
        assert VulnerabilitySeverity.LOW.value == "Low"


class TestTOCTORuleEngine:

    def test_analyze_call_sequence(self):
        engine = TOCTORuleEngine()
        call_sequence = [
            ('access', 0x1000),
            ('open', 0x1010),
            ('read', 0x1020),
            ('stat', 0x1030),
            ('chmod', 0x1040),
        ]
        matches = engine.analyze_call_sequence(call_sequence)
        # access+open and stat+chmod pairs
        assert len(matches) == 2
        assert any(m.check_function == 'access' and m.use_function == 'open'
                   for m in matches)
        assert any(m.check_function == 'stat' and m.use_function == 'chmod'
                   for m in matches)

    def test_detect_dangerous_sequences(self):
        engine = TOCTORuleEngine()
        call_graph = {
            'unsafe_func': ['access', 'open', 'read'],
            'safe_func': ['lstat', 'open'],
            'normal_func': ['printf', 'scanf'],
        }
        dangerous = engine.detect_dangerous_sequences(call_graph)
        assert len(dangerous) == 1
        assert 'unsafe_func' in dangerous[0]
        assert 'access -> open' in dangerous[0]


class TestPermissionAnalysisEngine:

    def test_find_permission_checks(self):
        engine = PermissionAnalysisEngine()
        functions = {
            'check_file': {
                'calls': [
                    {'name': 'access', 'address': 0x1000, 'args': {'mode': 4}}
                ]
            },
            'no_check': {
                'calls': [{'name': 'open', 'address': 0x2000}]
            },
        }
        checks = engine.find_permission_checks(functions)
        assert len(checks) == 1
        assert checks[0].function_name == 'check_file'
        assert checks[0].check_type == 'access'

    def test_detect_missing_checks(self):
        engine = PermissionAnalysisEngine()
        call_graph = {
            'unsafe_delete': ['unlink'],
            'safe_delete': ['access', 'unlink'],
            'safe_chmod': ['stat', 'chmod'],
        }
        missing = engine.detect_missing_checks(call_graph)
        assert len(missing) == 1
        assert missing[0]['function'] == 'unsafe_delete'
        assert missing[0]['dangerous_op'] == 'unlink'


class TestSimpleLogicVulnDetector:

    def test_detect_path_traversal(self):
        detector = SimpleLogicVulnDetector('/tmp/test_binary')
        with patch.object(detector, '_find_string_constants') as mock_strings:
            mock_strings.return_value = ['../../etc/passwd', '/home/user/file.txt']
            findings = detector.detect_path_traversal()
            assert len(findings) >= 1
            assert any(
                f.vuln_type == VulnerabilityType.PATH_TRAVERSAL for f in findings
            )

    def test_generate_report(self):
        detector = SimpleLogicVulnDetector('/tmp/test_binary')
        detector.findings = [
            VulnerabilityFinding(
                vuln_type=VulnerabilityType.TOCTOU,
                severity=VulnerabilitySeverity.HIGH,
                function_name='test_func',
                address=0x1000,
                description='Test TOCTOU',
                confidence=0.8,
            )
        ]
        report = detector.generate_report()
        assert report['binary_path'] == '/tmp/test_binary'
        assert report['summary']['total_findings'] == 1
        assert report['summary']['high'] == 1


class TestAngrLogicVulnDetector:

    def test_not_available_without_angr(self):
        with patch.dict('sys.modules', {'angr': None}):
            detector = AngrLogicVulnDetector('/tmp/test_binary')
            assert not detector.is_available()

    def test_fallback_to_simple(self):
        with patch.dict('sys.modules', {'angr': None}):
            detector = AngrLogicVulnDetector('/tmp/test_binary')
            assert not detector.is_available()
            with patch.object(SimpleLogicVulnDetector, 'analyze') as mock_analyze:
                mock_analyze.return_value = []
                findings = detector.analyze()
                assert findings == []


class TestDetectorFactory:

    def test_create_default(self):
        with patch.dict('sys.modules', {'angr': None}):
            detector = create_logic_vuln_detector('/tmp/test_binary')
            assert isinstance(detector, SimpleLogicVulnDetector)

    def test_create_simple(self):
        detector = create_logic_vuln_detector('/tmp/test_binary', use_angr=False)
        assert isinstance(detector, SimpleLogicVulnDetector)

    def test_convenience_function(self):
        with patch.object(SimpleLogicVulnDetector, 'analyze') as mock_analyze:
            mock_analyze.return_value = []
            result = analyze_logic_vulnerabilities(
                '/tmp/test_binary', use_angr=False
            )
            assert result['success'] is True
            assert result['binary_path'] == '/tmp/test_binary'
            assert result['total_findings'] == 0


class TestVulnerabilityFinding:

    def test_full_creation(self):
        finding = VulnerabilityFinding(
            vuln_type=VulnerabilityType.PERMISSION_BYPASS,
            severity=VulnerabilitySeverity.CRITICAL,
            function_name='test',
            address=0x1000,
            description='Test finding',
            evidence=['evidence1'],
            affected_code=['code1'],
            recommendation='Fix it',
            confidence=0.9,
        )
        assert finding.vuln_type == VulnerabilityType.PERMISSION_BYPASS
        assert finding.severity == VulnerabilitySeverity.CRITICAL
        assert finding.function_name == 'test'
        assert finding.address == 0x1000
        assert finding.confidence == 0.9


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
