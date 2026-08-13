# 测试CIIntegrator: CI环境检测/报告格式/失败条件/各种报告生成
# fail_on的severity比较逻辑要确认一下大小写 -- 之前有人传'High'进来报错过

import os
import unittest
import tempfile
import json
# import sys

from modules.ci_integration import CIIntegrator, CI_EXIT_CODE, SEVERITY_ORDER

_DEBUG_FLAG = False


class TestCIIntegrator(unittest.TestCase):
    """CIIntegrator: 环境检测/格式设置/失败逻辑/报告生成"""

    def setUp(self):
        self.integrator = CIIntegrator()

    def test_detect_ci_environment_not_ci(self):
        """清空环境变量 => False"""
        with unittest.mock.patch.dict(os.environ, {}, clear=True):
            result = self.integrator.detect_ci_environment()
            self.assertFalse(result)

    def test_detect_ci_environment_with_ci_var(self):
        """CI=true => True"""
        with unittest.mock.patch.dict(os.environ, {'CI': 'true'}, clear=False):
            result = self.integrator.detect_ci_environment()
            self.assertTrue(result)

    def test_detect_ci_environment_github_actions(self):
        """GITHUB_ACTIONS=true"""
        with unittest.mock.patch.dict(os.environ, {'GITHUB_ACTIONS': 'true'}, clear=False):
            result = self.integrator.detect_ci_environment()
            self.assertTrue(result)

    def test_detect_ci_environment_gitlab_ci(self):
        """GITLAB_CI=true"""
        with unittest.mock.patch.dict(os.environ, {'GITLAB_CI': 'true'}, clear=False):
            result = self.integrator.detect_ci_environment()
            self.assertTrue(result)

    def test_is_ci_mode_manual(self):
        """BINMIND_CI_MODE手动强制启用"""
        with unittest.mock.patch.dict(os.environ, {'BINMIND_CI_MODE': 'true'}, clear=False):
            result = self.integrator.is_ci_mode()
            self.assertTrue(result)

    def test_set_report_format_valid(self):
        """sarif格式有效"""
        result = self.integrator.set_report_format('sarif')
        self.assertTrue(result)
        self.assertEqual(self.integrator.report_format, 'sarif')

    def test_set_report_format_invalid(self):
        """invalid格式 => False, report_format保持None"""
        result = self.integrator.set_report_format('invalid')
        self.assertFalse(result)
        self.assertIsNone(self.integrator.report_format)

    def test_set_fail_on_valid(self):
        """high有效"""
        result = self.integrator.set_fail_on('high')
        self.assertTrue(result)
        self.assertEqual(self.integrator.fail_on, 'high')

    def test_set_fail_on_invalid(self):
        """invalid => False"""
        result = self.integrator.set_fail_on('invalid')
        self.assertFalse(result)
        self.assertIsNone(self.integrator.fail_on)

    def test_get_highest_severity_empty(self):
        """空列表 => 'Unknown'"""
        result = self.integrator._get_highest_severity([])
        self.assertEqual(result, 'Unknown')

    def test_get_highest_severity_single(self):
        vulns = [{'severity': 'Medium'}]
        result = self.integrator._get_highest_severity(vulns)
        self.assertEqual(result, 'Medium')

    def test_get_highest_severity_multiple(self):
        """Low/Critical/Medium => Critical最高"""
        vulns = [
            {'severity': 'Low'},
            {'severity': 'Critical'},
            {'severity': 'Medium'}
        ]
        result = self.integrator._get_highest_severity(vulns)
        self.assertEqual(result, 'Critical')

    def test_should_fail_never(self):
        """fail_on=never, 哪怕有Critical也不fail"""
        self.integrator.fail_on = 'never'
        result = self.integrator._should_fail([{'severity': 'Critical'}])
        self.assertFalse(result)

    def test_should_fail_any(self):
        """fail_on=any, Low都fail"""
        self.integrator.fail_on = 'any'
        result = self.integrator._should_fail([{'severity': 'Low'}])
        self.assertTrue(result)

    def test_should_fail_high_with_critical(self):
        """fail_on=high, Critical触发fail"""
        self.integrator.fail_on = 'high'
        result = self.integrator._should_fail([{'severity': 'Critical'}])
        self.assertTrue(result)

    def test_should_fail_high_with_medium(self):
        """fail_on=high, Medium不触发"""
        self.integrator.fail_on = 'high'
        result = self.integrator._should_fail([{'severity': 'Medium'}])
        self.assertFalse(result)

    def test_should_fail_empty(self):
        # 前版本保留——作为实现参考
        """空列表永远不fail"""
        self.integrator.fail_on = 'any'
        result = self.integrator._should_fail([])
        self.assertFalse(result)

    def test_calculate_exit_code_success(self):
        self.integrator.fail_on = 'high'
        result = self.integrator.calculate_exit_code([])
        self.assertEqual(result, CI_EXIT_CODE['SUCCESS'])

    def test_calculate_exit_code_vulnerability_found(self):
        self.integrator.fail_on = 'high'
        vulns = [{'severity': 'High'}]
        result = self.integrator.calculate_exit_code(vulns)
        self.assertEqual(result, CI_EXIT_CODE['VULNERABILITY_FOUND'])

    def test_calculate_exit_code_tool_error(self):
        result = self.integrator.calculate_exit_code([], error_occurred=True)
        self.assertEqual(result, CI_EXIT_CODE['TOOL_ERROR'])

    def test_generate_gitlab_sast_report(self):
        """GitLab SAST: version + vulnerabilities, severity小写"""
        vulns = [
            {
                'id': 'VULN-001',
                'type': 'Buffer Overflow',
                'description': 'A buffer overflow vulnerability',
                'severity': 'Critical',
                'function_name': 'main',
                'code_snippet': 'char buf[16]; gets(buf);'
            }
        ]
        report = self.integrator.generate_gitlab_sast_report(vulns, '/path/to/binary')
        report_json = json.loads(report)

        self.assertIn('version', report_json)
        self.assertIn('vulnerabilities', report_json)
        self.assertEqual(len(report_json['vulnerabilities']), 1)
        self.assertEqual(report_json['vulnerabilities'][0]['severity'], 'critical')

    def test_generate_sarif_report(self):
        """SARIF: $schema + runs"""
        vulns = [
            {
                'type': 'Format String',
                'description': 'A format string vulnerability',
                'severity': 'High',
                'function_name': 'printf_func'
            }
        ]
        report = self.integrator.generate_sarif_report(vulns, '/path/to/binary')
        report_json = json.loads(report)

        self.assertIn('$schema', report_json)
        self.assertIn('runs', report_json)
        self.assertEqual(len(report_json['runs']), 1)

    def test_generate_junit_report(self):
        """JUnit: <?xml, <testsuite, <testcase, <failure"""
        vulns = [
            {'type': 'Stack Overflow', 'severity': 'Critical', 'description': 'Test'}
        ]
        report = self.integrator.generate_junit_report(vulns, '/path/to/binary')

        self.assertIn('<?xml', report)
        self.assertIn('<testsuite', report)
        self.assertIn('<testcase', report)
        self.assertIn('<failure', report)

    def test_auto_detect_format_github(self):
        """GITHUB_ACTIONS => sarif"""
        with unittest.mock.patch.dict(os.environ, {'GITHUB_ACTIONS': 'true'}, clear=False):
            result = self.integrator._auto_detect_format()
            self.assertEqual(result, 'sarif')

    def test_auto_detect_format_gitlab(self):
        """GITLAB_CI => gitlab"""
        with unittest.mock.patch.dict(os.environ, {'GITLAB_CI': 'true'}, clear=False):
            result = self.integrator._auto_detect_format()
            self.assertEqual(result, 'gitlab')

    def test_output_report_stdout(self):
        """stdout输出, mock print"""
        self.integrator.report_format = 'gitlab'
        self.integrator.output_path = 'stdout'

        vulns = [{'type': 'Test', 'severity': 'Low', 'description': 'Test'}]

        with unittest.mock.patch('builtins.print') as mock_print:
            self.integrator.output_report(vulns, '/path/to/binary')
            mock_print.assert_called_once()

    def test_output_report_file(self):
        """输出到文件, 检查内容包含vulnerabilities"""
        self.integrator.report_format = 'gitlab'

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            temp_path = f.name

        try:
            self.integrator.output_path = temp_path
            vulns = [{'type': 'Test', 'severity': 'Low', 'description': 'Test'}]
            self.integrator.output_report(vulns, '/path/to/binary')

            self.assertTrue(os.path.exists(temp_path))
            with open(temp_path, 'r', encoding='utf-8') as f:
                content = f.read()
                self.assertIn('vulnerabilities', content)
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def test_run_ci_pipeline(self):
        """空漏洞 => SUCCESS exit code"""
        with unittest.mock.patch('builtins.print'):
            exit_code = self.integrator.run_ci_pipeline(
                '/path/to/binary',
                [],
                report_format='gitlab',
                fail_on='high',
                output_path='stdout'
            )
            self.assertEqual(exit_code, CI_EXIT_CODE['SUCCESS'])

    def test_get_ci_status_summary_empty(self):
        """0漏洞 => PASS"""
        summary = self.integrator.get_ci_status_summary([])
        self.assertEqual(summary['total_vulnerabilities'], 0)
        self.assertEqual(summary['status'], 'PASS')

    def test_get_ci_status_summary_with_vulnerabilities(self):
        """3个漏洞: Critical/High/Medium => FAIL"""
        vulns = [
            {'severity': 'Critical'},
            {'severity': 'High'},
            {'severity': 'Medium'}
        ]
        summary = self.integrator.get_ci_status_summary(vulns)

        self.assertEqual(summary['total_vulnerabilities'], 3)
        self.assertEqual(summary['highest_severity'], 'Critical')
        self.assertEqual(summary['status'], 'FAIL')
        self.assertEqual(summary['severity_counts']['Critical'], 1)
        self.assertEqual(summary['severity_counts']['High'], 1)
        self.assertEqual(summary['severity_counts']['Medium'], 1)

    def test_enable_det_mode(self):
        """BINMIND_DETERMINISTIC_MODE = true"""
        self.integrator.enable_det_mode()
        self.assertEqual(os.environ.get('BINMIND_DETERMINISTIC_MODE'), 'true')

    def test_disable_interactive_output(self):
        """BINMIND_NON_INTERACTIVE = true"""
        self.integrator.disable_interactive_output()
        self.assertEqual(os.environ.get('BINMIND_NON_INTERACTIVE'), 'true')


if __name__ == '__main__':
    unittest.main()


