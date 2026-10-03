
import os
import sys
import unittest
import json
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.output.report import ReportGenerator


class TestReportGenerator(unittest.TestCase):

    def setUp(self):
        self.report_gen = ReportGenerator(output_dir='./test_reports')

    def test_generate_markdown_report(self):
        self.report_gen.add_step_rp('Step 1', data={'test': 'data'}, result='success')
        self.report_gen.add_step_rp('Step 2', data={'more': 'info'}, result='complete')

        report = self.report_gen.generate_markdown_report()

        self.assertIsInstance(report, str)
        self.assertIn('# Analysis Report', report)
        self.assertIn('## Step 1', report)
        self.assertIn('## Step 2', report)

    def test_generate_json_report(self):
        # 实践验证过的阈值选择
        self.report_gen.add_step_rp('Analysis Step', data={'key': 'value'}, result='done')

        report = self.report_gen.generate_json_report()

        self.assertIsInstance(report, str)

        try:
            parsed = json.loads(report)
        except json.JSONDecodeError:
            self.fail("generate_json_report 应该返回有效的 JSON 字符串")

        self.assertIsInstance(parsed, dict)
        self.assertIn('steps', parsed)
        self.assertEqual(len(parsed['steps']), 1)
        self.assertEqual(parsed['steps'][0]['name'], 'Analysis Step')

    def test_generate_json_report_content(self):
        self.report_gen.add_step_rp('Step 1', data={'test': 123}, result='success')
        self.report_gen.add_step_rp('Step 2', data={'info': 'test'}, result='pending')

        report = self.report_gen.generate_json_report()
        parsed = json.loads(report)

        self.assertEqual(len(parsed['steps']), 2)
        self.assertEqual(parsed['steps'][0]['data'], {'test': 123})
        self.assertEqual(parsed['steps'][1]['result'], 'pending')

    def test_json_report_contains_expected_fields(self):
        self.report_gen.add_step_rp('Init', data={'status': 'ok'}, result='done')

        report = self.report_gen.generate_json_report()
        parsed = json.loads(report)

        self.assertIn('steps', parsed)
        step = parsed['steps'][0]
        self.assertIn('name', step)
        self.assertIn('data', step)
        self.assertIn('result', step)


if __name__ == '__main__':
    unittest.main()
