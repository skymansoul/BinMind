import os
import sys
import unittest
import tempfile
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.ci_integration import CIIntegrator, CI_EXIT_CODE, SEVERITY_ORDER


class TestCIIntegrator(unittest.TestCase):

    def setUp(self):
        self.integrator = CIIntegrator()

    def test_detect_ci_environment_not_ci(self):
        """测试非 CI 环境检测"""
        with unittest.mock.patch.dict(os.environ, {}, clear=True):
            result = self.integrator.detect_ci_environment()
            self.assertFalse(result)

    def test_detect_ci_environment_with_ci_var(self):
        """测试 CI 环境变量检测"""
        with unittest.mock.patch.dict(os.environ, {'CI': 'true'}, clear=False):
            result = self.integrator.detect_ci_environment()
            self.assertTrue(result)

    def test_detect_ci_environment_github_actions(self):
        """测试 GitHub Actions 环境检测"""
        with unittest.mock.patch.dict(os.environ, {'GITHUB_ACTIONS': 'true'}, clear=False):
            result = self.integrator.detect_ci_environment()
            self.assertTrue(result)

    def test_detect_ci_environment_gitlab_ci(self):
        """测试 GitLab CI 环境检测"""
        with unittest.mock.patch.dict(os.environ, {'GITLAB_CI': 'true'}, clear=False):
            result = self.integrator.detect_ci_environment()
            self.assertTrue(result)

    def test_is_ci_mode_manual(self):
        """测试手动启用 CI 模式"""
        with unittest.mock.patch.dict(os.environ, {'DEEMO_CI_MODE': 'true'}, clear=False):
            result = self.integrator.is_ci_mode()
            self.assertTrue(result)

    def test_set_report_format_valid(self):
        """测试设置有效报告格式"""
        result = self.integrator.set_report_format('sarif')
        self.assertTrue(result)
        self.assertEqual(self.integrator.report_format, 'sarif')

    def test_set_report_format_invalid(self):
        """测试设置无效报告格式"""
        result = self.integrator.set_report_format('invalid')
        self.assertFalse(result)
        self.assertIsNone(self.integrator.report_format)

    def test_set_fail_on_valid(self):
        """测试设置有效失败条件"""
        result = self.integrator.set_fail_on('high')
        self.assertTrue(result)
        self.assertEqual(self.integrator.fail_on, 'high')

    def test_set_fail_on_invalid(self):
        """测试设置无效失败条件"""
        result = self.integrator.set_fail_on('invalid')
        self.assertFalse(result)
        self.assertIsNone(self.integrator.fail_on)

    def test_get_highest_severity_empty(self):
        """测试获取空漏洞列表的最高严重等级"""
        result = self.integrator._get_highest_severity([])
        self.assertEqual(result, 'Unknown')

    def test_get_highest_severity_single(self):
        """测试获取单个漏洞的最高严重等级"""
        vulns = [{'severity': 'Medium'}]
        result = self.integrator._get_highest_severity(vulns)
        self.assertEqual(result, 'Medium')

    def test_get_highest_severity_multiple(self):
        """测试获取多个漏洞的最高严重等级"""
        vulns = [
            {'severity': 'Low'},
            {'severity': 'Critical'},
            {'severity': 'Medium'}
        ]
        result = self.integrator._get_highest_severity(vulns)
        self.assertEqual(result, 'Critical')

    def test_should_fail_never(self):
        """测试 fail_on=never 时不失败"""
        self.integrator.fail_on = 'never'
        result = self.integrator._should_fail([{'severity': 'Critical'}])
        self.assertFalse(result)

    def test_should_fail_any(self):
        """测试 fail_on=any 时任何漏洞都失败"""
        self.integrator.fail_on = 'any'
        result = self.integrator._should_fail([{'severity': 'Low'}])
        self.assertTrue(result)

    def test_should_fail_high_with_critical(self):
        """测试 fail_on=high 时 Critical 漏洞导致失败"""
        self.integrator.fail_on = 'high'
        result = self.integrator._should_fail([{'severity': 'Critical'}])
        self.assertTrue(result)

    def test_should_fail_high_with_medium(self):
        """测试 fail_on=high 时 Medium 漏洞不失败"""
        self.integrator.fail_on = 'high'
        result = self.integrator._should_fail([{'severity': 'Medium'}])
        self.assertFalse(result)

    def test_should_fail_empty(self):
        """测试空漏洞列表不失败"""
        self.integrator.fail_on = 'any'
        result = self.integrator._should_fail([])
        self.assertFalse(result)

    def test_calculate_exit_code_success(self):
        """测试计算成功退出码"""
        self.integrator.fail_on = 'high'
        result = self.integrator.calculate_exit_code([])
        self.assertEqual(result, CI_EXIT_CODE['SUCCESS'])

    def test_calculate_exit_code_vulnerability_found(self):
        """测试发现漏洞时的退出码"""
        self.integrator.fail_on = 'high'
        vulns = [{'severity': 'High'}]
        result = self.integrator.calculate_exit_code(vulns)
        self.assertEqual(result, CI_EXIT_CODE['VULNERABILITY_FOUND'])

    def test_calculate_exit_code_tool_error(self):
        """测试工具错误时的退出码"""
        result = self.integrator.calculate_exit_code([], error_occurred=True)
        self.assertEqual(result, CI_EXIT_CODE['TOOL_ERROR'])

    def test_generate_gitlab_sast_report(self):
        """测试生成 GitLab SAST 报告"""
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
        """测试生成 SARIF 报告"""
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
        """测试生成 JUnit 报告"""
        vulns = [
            {'type': 'Stack Overflow', 'severity': 'Critical', 'description': 'Test'}
        ]
        report = self.integrator.generate_junit_report(vulns, '/path/to/binary')
        
        self.assertIn('<?xml', report)
        self.assertIn('<testsuite', report)
        self.assertIn('<testcase', report)
        self.assertIn('<failure', report)

    def test_auto_detect_format_github(self):
        """测试自动检测 GitHub Actions 格式"""
        with unittest.mock.patch.dict(os.environ, {'GITHUB_ACTIONS': 'true'}, clear=False):
            result = self.integrator._auto_detect_format()
            self.assertEqual(result, 'sarif')

    def test_auto_detect_format_gitlab(self):
        """测试自动检测 GitLab CI 格式"""
        with unittest.mock.patch.dict(os.environ, {'GITLAB_CI': 'true'}, clear=False):
            result = self.integrator._auto_detect_format()
            self.assertEqual(result, 'gitlab')

    def test_output_report_stdout(self):
        """测试输出报告到 stdout"""
        self.integrator.report_format = 'gitlab'
        self.integrator.output_path = 'stdout'
        
        vulns = [{'type': 'Test', 'severity': 'Low', 'description': 'Test'}]
        
        with unittest.mock.patch('builtins.print') as mock_print:
            self.integrator.output_report(vulns, '/path/to/binary')
            mock_print.assert_called_once()

    def test_output_report_file(self):
        """测试输出报告到文件"""
        self.integrator.report_format = 'gitlab'
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            temp_path = f.name
        
        try:
            self.integrator.output_path = temp_path
            vulns = [{'type': 'Test', 'severity': 'Low', 'description': 'Test'}]
            self.integrator.output_report(vulns, '/path/to/binary')
            
            self.assertTrue(os.path.exists(temp_path))
            with open(temp_path, 'r') as f:
                content = f.read()
                self.assertIn('vulnerabilities', content)
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def test_run_ci_pipeline(self):
        """测试运行 CI 管道"""
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
        """测试获取空漏洞列表的状态摘要"""
        summary = self.integrator.get_ci_status_summary([])
        
        self.assertEqual(summary['total_vulnerabilities'], 0)
        self.assertEqual(summary['status'], 'PASS')

    def test_get_ci_status_summary_with_vulnerabilities(self):
        """测试获取有漏洞的状态摘要"""
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
        """测试启用确定性模式"""
        self.integrator.enable_det_mode()
        self.assertEqual(os.environ.get('DEEMO_DETERMINISTIC_MODE'), 'true')

    def test_disable_interactive_output(self):
        """测试禁用交互式输出"""
        self.integrator.disable_interactive_output()
        self.assertEqual(os.environ.get('DEEMO_NON_INTERACTIVE'), 'true')


if __name__ == '__main__':
    unittest.main()