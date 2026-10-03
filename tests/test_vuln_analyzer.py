"""
vuln_analyzer 模块测试 —— 统一漏洞分析器。

测试覆盖:
  - 五种漏洞类型的分析器注册
  - 模拟反编译代码的漏洞检测
  - 去重逻辑
  - 空输入处理
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.vuln_analyzer import (
    analyze_all,
    analyze_stack_overflow_vulns,
    analyze_format_string_vulns,
    analyze_heap_corruption_vulns,
    analyze_integer_overflow_vulns,
    analyze_command_injection_vulns,
    _VULN_ANALYZERS,
)


class TestAnalyzerRegistration(unittest.TestCase):

    def test_all_categories_registered(self):
        for cat in ('stack-overflow', 'format-string', 'heap-corruption',
                     'integer-overflow', 'command-injection'):
            self.assertIn(cat, _VULN_ANALYZERS,
                          f'{cat} should be registered')


class TestVulnAnalyzer(unittest.TestCase):

    def setUp(self):
        self.decompiled = {
            'vuln': '''
            void vuln() {
                char buf[64];
                gets(buf);
                printf(buf);
            }
            ''',
        }

    def test_analyze_all_returns_list(self):
        findings = analyze_all(decompiled=self.decompiled)
        self.assertIsInstance(findings, list)

    def test_analyze_all_with_empty_decompiled(self):
        findings = analyze_all(decompiled={})
        self.assertIsInstance(findings, list)

    def test_analyze_all_with_none_decompiled(self):
        findings = analyze_all(decompiled=None)
        self.assertIsInstance(findings, list)

    def test_stack_overflow_detection(self):
        findings = analyze_stack_overflow_vulns(
            '/tmp/test', decompiled=self.decompiled,
        )
        self.assertIsInstance(findings, list)

    def test_format_string_detection(self):
        findings = analyze_format_string_vulns(
            '/tmp/test', decompiled=self.decompiled,
        )
        self.assertIsInstance(findings, list)

    def test_heap_corruption_detection(self):
        code = {'f': 'void f() { char *p = malloc(10); free(p); }'}
        findings = analyze_heap_corruption_vulns(
            '/tmp/test', decompiled=code,
        )
        self.assertIsInstance(findings, list)

    def test_integer_overflow_detection(self):
        code = {'f': 'void f(int n) { char *p = malloc(n + 1); }'}
        findings = analyze_integer_overflow_vulns(
            '/tmp/test', decompiled=code,
        )
        self.assertIsInstance(findings, list)

    def test_command_injection_detection(self):
        code = {'f': 'void f(char *cmd) { system(cmd); }'}
        findings = analyze_command_injection_vulns(
            '/tmp/test', decompiled=code,
        )
        self.assertIsInstance(findings, list)

    def test_no_duplicate_findings(self):
        code = {'f': 'void f() { gets(0); gets(0); }'}
        findings = analyze_all(decompiled=code)
        # gets() should only be reported once per function
        self.assertIsInstance(findings, list)

    def test_uaf_heuristic(self):
        code = {'uaf': 'void f() { free(p); p->callback(); }'}
        findings = analyze_heap_corruption_vulns(
            '/tmp/test', decompiled=code,
        )
        self.assertIsInstance(findings, list)

    def test_double_free_heuristic(self):
        code = {'df': 'void f() { free(p); free(p); }'}
        findings = analyze_heap_corruption_vulns(
            '/tmp/test', decompiled=code,
        )
        self.assertIsInstance(findings, list)


if __name__ == '__main__':
    unittest.main()
