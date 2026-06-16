#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试自动化漏洞根因解释模块
"""

import pytest
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from modules.auto_root_cause import (
    AutoRootCauseAnalyzer, VulnerabilityContext, RootCauseAnalysis,
    VulnerabilitySeverity, Exploitability, CWEDatabase,
    analyze_root_cause, format_root_cause_report
)


class TestAutoRootCause:
    """测试自动化漏洞根因分析模块"""

    def test_initialization(self):
        """测试初始化"""
        analyzer = AutoRootCauseAnalyzer(analyzer_type="heuristic")
        assert analyzer is not None
        assert analyzer.analyzer_type == "heuristic"

    def test_cwe_database(self):
        """测试CWE数据库"""
        cwe_db = CWEDatabase()
        
        # 测试搜索
        results = cwe_db.search_cwe(['buffer', 'overflow'])
        assert len(results) > 0
        
        # 验证结果格式
        for result in results:
            assert 'cwe_id' in result
            assert 'cwe_name' in result
            assert 'description' in result
            assert 'score' in result

    def test_analyze_vulnerability(self):
        """测试分析漏洞"""
        analyzer = AutoRootCauseAnalyzer(analyzer_type="heuristic")
        
        context = VulnerabilityContext(
            vulnerability_type="buffer_overflow",
            function_name="vulnerable_function",
            function_address=0x401000,
            binary_path="/tmp/test.bin",
            pseudocode="void vulnerable_function(char *input) { char buf[100]; strcpy(buf, input); }",
            assembly="call strcpy"
        )
        
        result = analyzer.analyze_vulnerability(context)
        
        assert isinstance(result, RootCauseAnalysis)
        assert result.vulnerability_type == "buffer_overflow"
        assert result.vulnerability_id is not None
        
        # 验证CWE映射
        assert len(result.cwe_mappings) > 0
        
        # 验证严重程度
        assert result.severity in [VulnerabilitySeverity.CRITICAL, VulnerabilitySeverity.HIGH]
        
        # 验证可利用性
        assert result.exploitability in [Exploitability.EASY, Exploitability.MEDIUM]

    def test_analyze_buffer_overflow(self):
        """测试分析缓冲区溢出漏洞"""
        analyzer = AutoRootCauseAnalyzer(analyzer_type="heuristic")
        
        context = VulnerabilityContext(
            vulnerability_type="buffer_overflow",
            function_name="strcpy_test",
            function_address=0x401050,
            binary_path="/tmp/test.bin",
            pseudocode="void strcpy_test(char *src) { char dest[20]; strcpy(dest, src); }",
            assembly="mov rdi, dest\nmov rsi, src\ncall strcpy"
        )
        
        result = analyzer.analyze_vulnerability(context)
        
        # 应该识别为CRITICAL
        assert result.severity == VulnerabilitySeverity.CRITICAL
        
        # 应该映射到CWE-119或CWE-120
        cwe_ids = [cwe.cwe_id for cwe in result.cwe_mappings]
        assert any(cwe in cwe_ids for cwe in ['CWE-119', 'CWE-120'])

    def test_analyze_command_injection(self):
        """测试分析命令注入漏洞"""
        analyzer = AutoRootCauseAnalyzer(analyzer_type="heuristic")
        
        context = VulnerabilityContext(
            vulnerability_type="command_injection",
            function_name="system_call",
            function_address=0x401100,
            binary_path="/tmp/test.bin",
            pseudocode="void system_call(char *cmd) { system(cmd); }",
            assembly="mov rdi, cmd\ncall system"
        )
        
        result = analyzer.analyze_vulnerability(context)
        
        # 应该识别为CRITICAL
        assert result.severity == VulnerabilitySeverity.CRITICAL
        
        # 应该映射到CWE-78
        cwe_ids = [cwe.cwe_id for cwe in result.cwe_mappings]
        assert 'CWE-78' in cwe_ids

    def test_analyze_use_after_free(self):
        """测试分析UAF漏洞"""
        analyzer = AutoRootCauseAnalyzer(analyzer_type="heuristic")
        
        context = VulnerabilityContext(
            vulnerability_type="use_after_free",
            function_name="dangling_ptr",
            function_address=0x401200,
            binary_path="/tmp/test.bin",
            pseudocode="void dangling_ptr() { char *p = malloc(100); free(p); *p = 0; }",
            assembly="call malloc\ncall free\nmov qword ptr [rax], 0"
        )
        
        result = analyzer.analyze_vulnerability(context)
        
        # 应该识别为HIGH或CRITICAL
        assert result.severity in [VulnerabilitySeverity.CRITICAL, VulnerabilitySeverity.HIGH]
        
        # 应该映射到CWE-416
        cwe_ids = [cwe.cwe_id for cwe in result.cwe_mappings]
        assert 'CWE-416' in cwe_ids

    def test_batch_analyze(self):
        """测试批量分析"""
        analyzer = AutoRootCauseAnalyzer(analyzer_type="heuristic")
        
        contexts = [
            VulnerabilityContext(
                vulnerability_type="buffer_overflow",
                function_name="func1",
                function_address=0x401000,
                binary_path="/tmp/test.bin",
                pseudocode="void func1(char *input) { char buf[10]; strcpy(buf, input); }",
                assembly=""
            ),
            VulnerabilityContext(
                vulnerability_type="format_string",
                function_name="func2",
                function_address=0x401050,
                binary_path="/tmp/test.bin",
                pseudocode="void func2(char *fmt) { printf(fmt); }",
                assembly=""
            )
        ]
        
        results = analyzer.batch_analyze(contexts)
        
        assert len(results) == 2
        assert all(isinstance(r, RootCauseAnalysis) for r in results)

    def test_generate_report(self):
        """测试生成报告"""
        analyzer = AutoRootCauseAnalyzer(analyzer_type="heuristic")
        
        context = VulnerabilityContext(
            vulnerability_type="buffer_overflow",
            function_name="test_func",
            function_address=0x401000,
            binary_path="/tmp/test.bin",
            pseudocode="void test_func(char *input) { char buf[100]; strcpy(buf, input); }",
            assembly=""
        )
        
        analyzer.analyze_vulnerability(context)
        report = analyzer.generate_report()
        
        assert report.analysis_id is not None
        assert report.generated_at > 0
        assert len(report.vulnerabilities) == 1
        
        # 验证摘要
        assert report.summary['total_vulnerabilities'] == 1
        assert report.summary['critical_count'] >= 0

    def test_format_report(self):
        """测试格式化报告"""
        from modules.auto_root_cause import AnalysisReport
        
        report = AnalysisReport(
            generated_at=1600000000,
            target_binary="test.bin",
            analysis_id="ANALYSIS_001",
            vulnerabilities=[],
            summary={
                'total_vulnerabilities': 3,
                'critical_count': 1,
                'high_count': 2,
                'severity_distribution': {'critical': 1, 'high': 2}
            }
        )
        
        formatted = format_root_cause_report(report)
        
        assert "自动化漏洞根因分析报告" in formatted
        assert "检测到漏洞数: 3" in formatted
        assert "严重漏洞数: 1" in formatted

    def test_analyze_root_cause_convenience(self):
        """测试便捷函数"""
        result = analyze_root_cause(
            vulnerability_type="buffer_overflow",
            function_name="conv_func",
            pseudocode="void conv_func(char *input) { char buf[50]; strcpy(buf, input); }",
            function_address=0x401000,
            binary_path="/tmp/test.bin"
        )
        
        assert isinstance(result, RootCauseAnalysis)
        assert result.vulnerability_type == "buffer_overflow"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])