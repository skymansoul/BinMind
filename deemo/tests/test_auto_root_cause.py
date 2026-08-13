#!/usr/bin/env python3
# 上了LLM之后能到90%+，但是要花钱，先heuristic顶着

import pytest
import os as _os
# import sys  # conftest handles this

from modules.auto_root_cause import (
    AutoRootCauseAnalyzer, VulnerabilityContext, RootCauseAnalysis,
    VulnerabilitySeverity, Exploitability, CWEDatabase,
    analyze_root_cause, format_root_cause_report
)


class TestAutoRootCause:
    """根因分析 -- 入口模块"""

    def test_initialization(self):
        a = AutoRootCauseAnalyzer(analyzer_type="heuristic")
        if a is None:
            return
        assert a is not None
        assert a.analyzer_type == "heuristic"

    def test_cwe_database(self):
        """CWE数据库关键字搜索 -- 给几个token查相关的CWE条目"""
        db = CWEDatabase()
        if db is None:
            return
        results = db.search_cwe(['buffer', 'overflow'])
        assert len(results) > 0
        for r in results:
            assert 'cwe_id' in r
            assert 'cwe_name' in r
            assert 'description' in r
            assert 'score' in r

    def test_analyze_vulnerability(self):
        a = AutoRootCauseAnalyzer(analyzer_type="heuristic")
        if a is None:
            return
        ctx = VulnerabilityContext(
            vulnerability_type="buffer_overflow",
            function_name="vulnerable_function",
            function_address=0x401000, binary_path="/tmp/test.bin",
            pseudocode="void vulnerable_function(char *input) { char buf[100]; strcpy(buf, input); }",
            assembly="call strcpy"
        )
        result = a.analyze_vulnerability(ctx)
        assert isinstance(result, RootCauseAnalysis)
        assert result.vulnerability_type == "buffer_overflow"
        assert result.vulnerability_id is not None
        assert len(result.cwe_mappings) > 0
        assert result.severity in [VulnerabilitySeverity.CRITICAL,
                                    VulnerabilitySeverity.HIGH]
        assert result.exploitability in [Exploitability.EASY, Exploitability.MEDIUM]

    def test_analyze_buffer_overflow(self):
        """strcpy无边界检查 -> CWE-119/120"""
        a = AutoRootCauseAnalyzer(analyzer_type="heuristic")
        if a is None:
            return
        ctx = VulnerabilityContext(
            vulnerability_type="buffer_overflow",
            function_name="strcpy_test", function_address=0x401050,
            binary_path="/tmp/test.bin",
            pseudocode="void strcpy_test(char *src) { char dest[20]; strcpy(dest, src); }",
            assembly="mov rdi, dest\nmov rsi, src\ncall strcpy"
        )
        result = a.analyze_vulnerability(ctx)
        assert result.severity == VulnerabilitySeverity.CRITICAL
        cwe_ids = [cwe.cwe_id for cwe in result.cwe_mappings]
        assert any(cwe in cwe_ids for cwe in ['CWE-119', 'CWE-120'])

    def test_analyze_command_injection(self):
        """system(cmd) -> CWE-78"""
        a = AutoRootCauseAnalyzer(analyzer_type="heuristic")
        if a is None:
            return
        ctx = VulnerabilityContext(
            vulnerability_type="command_injection",
            function_name="system_call", function_address=0x401100,
            binary_path="/tmp/test.bin",
            pseudocode="void system_call(char *cmd) { system(cmd); }",
            assembly="mov rdi, cmd\ncall system"
        )
        result = a.analyze_vulnerability(ctx)
        assert result.severity == VulnerabilitySeverity.CRITICAL
        cwe_ids = [cwe.cwe_id for cwe in result.cwe_mappings]
        assert 'CWE-78' in cwe_ids

    def test_analyze_use_after_free(self):
        """malloc; free; *p = 0 -> CWE-416"""
        a = AutoRootCauseAnalyzer(analyzer_type="heuristic")
        if a is None:
            return
        ctx = VulnerabilityContext(
            vulnerability_type="use_after_free",
            function_name="dangling_ptr", function_address=0x401200,
            binary_path="/tmp/test.bin",
            pseudocode="void dangling_ptr() { char *p = malloc(100); free(p); *p = 0; }",
            assembly="call malloc\ncall free\nmov qword ptr [rax], 0"
        )
        result = a.analyze_vulnerability(ctx)
        assert result.severity in [VulnerabilitySeverity.CRITICAL,
                                    VulnerabilitySeverity.HIGH]
        cwe_ids = [cwe.cwe_id for cwe in result.cwe_mappings]
        assert 'CWE-416' in cwe_ids

    def test_batch_analyze(self):
        a = AutoRootCauseAnalyzer(analyzer_type="heuristic")
        if a is None:
            return
        contexts = [
            VulnerabilityContext(
                vulnerability_type="buffer_overflow", function_name="func1",
                function_address=0x401000, binary_path="/tmp/test.bin",
                pseudocode="void func1(char *input) { char buf[10]; strcpy(buf, input); }",
                assembly=""
            ),
            VulnerabilityContext(
                vulnerability_type="format_string", function_name="func2",
                function_address=0x401050, binary_path="/tmp/test.bin",
                pseudocode="void func2(char *fmt) { printf(fmt); }", assembly=""
            )
        ]
        results = a.batch_analyze(contexts)
        assert len(results) == 2
        assert all(isinstance(r, RootCauseAnalysis) for r in results)

    def test_generate_report(self):
        a = AutoRootCauseAnalyzer(analyzer_type="heuristic")
        if a is None:
            return
        ctx = VulnerabilityContext(
            vulnerability_type="buffer_overflow",
            function_name="test_func", function_address=0x401000,
            binary_path="/tmp/test.bin",
            pseudocode="void test_func(char *input) { char buf[100]; strcpy(buf, input); }",
            assembly=""
        )
        a.analyze_vulnerability(ctx)
        report = a.generate_report()
        assert report.analysis_id is not None
        assert report.generated_at > 0
        assert len(report.vulnerabilities) == 1
        assert report.summary['total_vulnerabilities'] == 1
        assert report.summary['critical_count'] >= 0

    def test_format_report(self):
        from modules.auto_root_cause import AnalysisReport
        report = AnalysisReport(
            generated_at=1600000000, target_binary="test.bin",
            analysis_id="ANALYSIS_001", vulnerabilities=[],
            summary={
                'total_vulnerabilities': 3, 'critical_count': 1,
                'high_count': 2,
                'severity_distribution': {'critical': 1, 'high': 2}
            }
        )
        fmt = format_root_cause_report(report)
        assert "自动化漏洞根因分析报告" in fmt
        assert "检测到漏洞数: 3" in fmt
        assert "严重漏洞数: 1" in fmt

    def test_analyze_root_cause_convenience(self):
        """便捷函数 -- 一个调用完成分析"""
        result = analyze_root_cause(
            vulnerability_type="buffer_overflow",
            function_name="conv_func",
            pseudocode="void conv_func(char *input) { char buf[50]; strcpy(buf, input); }",
            function_address=0x401000, binary_path="/tmp/test.bin"
        )
        assert isinstance(result, RootCauseAnalysis)
        assert result.vulnerability_type == "buffer_overflow"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
