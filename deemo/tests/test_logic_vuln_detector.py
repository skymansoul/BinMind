#!/usr/bin/env python3
"""
逻辑漏洞检测模块单元测试
"""

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
    analyze_logic_vulnerabilities
)


class TestVulnerabilityTypes:
    """测试漏洞类型枚举"""
    
    def test_vulnerability_type_enum(self):
        """测试漏洞类型枚举值"""
        assert VulnerabilityType.TOCTOU.value == "toctou"
        assert VulnerabilityType.PERMISSION_BYPASS.value == "permission_bypass"
        assert VulnerabilityType.PATH_TRAVERSAL.value == "path_traversal"
    
    def test_severity_enum(self):
        """测试严重程度枚举值"""
        assert VulnerabilitySeverity.CRITICAL.value == "Critical"
        assert VulnerabilitySeverity.HIGH.value == "High"
        assert VulnerabilitySeverity.MEDIUM.value == "Medium"
        assert VulnerabilitySeverity.LOW.value == "Low"


class TestTOCTORuleEngine:
    """测试TOCTOU规则引擎"""
    
    def test_analyze_call_sequence(self):
        """测试调用序列分析"""
        engine = TOCTORuleEngine()
        call_sequence = [
            ('access', 0x1000),
            ('open', 0x1010),
            ('read', 0x1020),
            ('stat', 0x1030),
            ('chmod', 0x1040)
        ]
        
        matches = engine.analyze_call_sequence(call_sequence)
        
        assert len(matches) == 2  # access+open 和 stat+chmod
        assert any(m.check_function == 'access' and m.use_function == 'open' for m in matches)
        assert any(m.check_function == 'stat' and m.use_function == 'chmod' for m in matches)
    
    def test_detect_dangerous_sequences(self):
        """测试危险序列检测"""
        engine = TOCTORuleEngine()
        call_graph = {
            'unsafe_func': ['access', 'open', 'read'],
            'safe_func': ['lstat', 'open'],
            'normal_func': ['printf', 'scanf']
        }
        
        dangerous = engine.detect_dangerous_sequences(call_graph)
        
        assert len(dangerous) == 1
        assert 'unsafe_func' in dangerous[0]
        assert 'access -> open' in dangerous[0]


class TestPermissionAnalysisEngine:
    """测试权限分析引擎"""
    
    def test_find_permission_checks(self):
        """测试查找权限检查点"""
        engine = PermissionAnalysisEngine()
        functions = {
            'check_file': {
                'calls': [
                    {'name': 'access', 'address': 0x1000, 'args': {'mode': 4}}
                ]
            },
            'no_check': {
                'calls': [{'name': 'open', 'address': 0x2000}]
            }
        }
        
        checks = engine.find_permission_checks(functions)
        
        assert len(checks) == 1
        assert checks[0].function_name == 'check_file'
        assert checks[0].check_type == 'access'
    
    def test_detect_missing_checks(self):
        """测试检测缺失的权限检查"""
        engine = PermissionAnalysisEngine()
        call_graph = {
            'unsafe_delete': ['unlink'],
            'safe_delete': ['access', 'unlink'],
            'safe_chmod': ['stat', 'chmod']
        }
        
        missing = engine.detect_missing_checks(call_graph)
        
        assert len(missing) == 1
        assert missing[0]['function'] == 'unsafe_delete'
        assert missing[0]['dangerous_op'] == 'unlink'


class TestSimpleLogicVulnDetector:
    """测试简单逻辑漏洞检测器"""
    
    def test_detect_path_traversal(self):
        """测试路径遍历检测"""
        detector = SimpleLogicVulnDetector('/tmp/test_binary')
        
        with patch.object(detector, '_find_string_constants') as mock_find_strings:
            mock_find_strings.return_value = ['../../etc/passwd', '/home/user/file.txt']
            
            findings = detector.detect_path_traversal()
            
            assert len(findings) >= 1
            assert any(f.vuln_type == VulnerabilityType.PATH_TRAVERSAL for f in findings)
    
    def test_generate_report(self):
        """测试生成报告"""
        detector = SimpleLogicVulnDetector('/tmp/test_binary')
        detector.findings = [
            VulnerabilityFinding(
                vuln_type=VulnerabilityType.TOCTOU,
                severity=VulnerabilitySeverity.HIGH,
                function_name='test_func',
                address=0x1000,
                description='Test TOCTOU',
                confidence=0.8
            )
        ]
        
        report = detector.generate_report()
        
        assert report['binary_path'] == '/tmp/test_binary'
        assert report['summary']['total_findings'] == 1
        assert report['summary']['high'] == 1


class TestAngrLogicVulnDetector:
    """测试基于Angr的逻辑漏洞检测器"""
    
    def test_is_available_without_angr(self):
        """测试angr不可用时的回退行为"""
        with patch.dict('sys.modules', {'angr': None}):
            detector = AngrLogicVulnDetector('/tmp/test_binary')
            assert not detector.is_available()
    
    def test_analyze_fallback_to_simple(self):
        """测试分析时回退到简单检测器"""
        with patch.dict('sys.modules', {'angr': None}):
            detector = AngrLogicVulnDetector('/tmp/test_binary')
            assert not detector.is_available()
            
            # 分析应该回退到简单检测器
            with patch.object(SimpleLogicVulnDetector, 'analyze') as mock_analyze:
                mock_analyze.return_value = []
                findings = detector.analyze()
                assert findings == []


class TestDetectorFactory:
    """测试检测器工厂函数"""
    
    def test_create_logic_vuln_detector_default(self):
        """测试创建逻辑漏洞检测器（默认参数）"""
        with patch.dict('sys.modules', {'angr': None}):
            detector = create_logic_vuln_detector('/tmp/test_binary')
            assert isinstance(detector, SimpleLogicVulnDetector)
    
    def test_create_logic_vuln_detector_simple(self):
        """测试强制使用简单检测器"""
        detector = create_logic_vuln_detector('/tmp/test_binary', use_angr=False)
        assert isinstance(detector, SimpleLogicVulnDetector)
    
    def test_analyze_logic_vulnerabilities_convenience(self):
        """测试便捷函数"""
        with patch.object(SimpleLogicVulnDetector, 'analyze') as mock_analyze:
            mock_analyze.return_value = []
            result = analyze_logic_vulnerabilities('/tmp/test_binary', use_angr=False)
            
            assert result['success'] == True
            assert result['binary_path'] == '/tmp/test_binary'
            assert result['total_findings'] == 0


class TestVulnerabilityFinding:
    """测试漏洞检测结果数据类"""
    
    def test_vulnerability_finding_creation(self):
        """测试漏洞检测结果创建"""
        finding = VulnerabilityFinding(
            vuln_type=VulnerabilityType.PERMISSION_BYPASS,
            severity=VulnerabilitySeverity.CRITICAL,
            function_name='test',
            address=0x1000,
            description='Test finding',
            evidence=['evidence1'],
            affected_code=['code1'],
            recommendation='Fix it',
            confidence=0.9
        )
        
        assert finding.vuln_type == VulnerabilityType.PERMISSION_BYPASS
        assert finding.severity == VulnerabilitySeverity.CRITICAL
        assert finding.function_name == 'test'
        assert finding.address == 0x1000
        assert finding.confidence == 0.9


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
