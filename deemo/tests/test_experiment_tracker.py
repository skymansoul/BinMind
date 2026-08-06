"""
experiment_tracker 模块测试 —— 实验记录与四维评估。

测试覆盖:
  - ExperimentTracker 生命周期（start→record→finish）
  - 四维评估指标计算
  - 汇总统计
  - 评估报告生成
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.experiment_tracker import ExperimentTracker


class TestExperimentTracker(unittest.TestCase):
    """实验追踪器基础测试。"""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix='binmind_test_et_')
        self.db_path = os.path.join(self.tmpdir, 'experiments_test.db')
        self.tracker = ExperimentTracker(db_path=self.db_path)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_start_experiment(self):
        """开始实验返回有效 ID。"""
        exp_id = self.tracker.start_experiment(
            name='test_exp',
            sample_path='/tmp/test_binary',
            binfo={'arch': 'x86-64', 'bits': 64, 'format': 'ELF'},
        )
        self.assertIsInstance(exp_id, int)
        self.assertGreater(exp_id, 0)

    def test_start_experiment_minimal(self):
        """最小参数开始实验。"""
        exp_id = self.tracker.start_experiment(name='minimal_test')
        self.assertGreater(exp_id, 0)

    def test_record_result(self):
        """记录实验结果。"""
        exp_id = self.tracker.start_experiment(name='record_test')
        self.tracker.record_result(
            exp_id,
            total_vulns=3,
            critical_vulns=1,
            high_vulns=2,
            report_md_path='/tmp/report.md',
        )
        exp = self.tracker.get_experiment(exp_id)
        self.assertIsNotNone(exp)
        self.assertEqual(exp['total_vulns'], 3)
        self.assertEqual(exp['critical_vulns'], 1)

    def test_finish_experiment(self):
        """完成实验并计算四维指标。"""
        exp_id = self.tracker.start_experiment(name='finish_test')
        self.tracker.record_result(exp_id, total_vulns=5, false_positives=1)
        self.tracker.finish_experiment(exp_id, status='completed', elapsed_sec=120.0)

        exp = self.tracker.get_experiment(exp_id)
        self.assertEqual(exp['status'], 'completed')
        self.assertGreater(exp['discovery_efficiency'], 0)
        self.assertGreaterEqual(exp['result_quality_score'], 0)

    def test_get_nonexistent_experiment(self):
        """不存在的实验返回 None。"""
        self.assertIsNone(self.tracker.get_experiment(99999))

    def test_list_experiments(self):
        """列出实验记录。"""
        self.tracker.start_experiment(name='exp1')
        self.tracker.start_experiment(name='exp2')
        exps = self.tracker.list_experiments()
        self.assertEqual(len(exps), 2)

    def test_list_experiments_by_status(self):
        """按状态筛选实验。"""
        exp_id = self.tracker.start_experiment(name='completed_exp')
        self.tracker.finish_experiment(exp_id, status='completed')
        self.tracker.start_experiment(name='running_exp')

        completed = self.tracker.list_experiments(status='completed')
        self.assertEqual(len(completed), 1)

        running = self.tracker.list_experiments(status='running')
        self.assertEqual(len(running), 1)

    def test_summary_empty(self):
        """空数据库的汇总统计。"""
        summary = self.tracker.summary()
        self.assertEqual(summary['total_experiments'], 0)

    def test_summary_with_data(self):
        """含数据的汇总统计。"""
        exp_id = self.tracker.start_experiment(
            name='summary_test', binfo={'arch': 'x86-64'},
        )
        self.tracker.record_result(exp_id, total_vulns=3)
        self.tracker.finish_experiment(exp_id, status='completed', elapsed_sec=60)

        summary = self.tracker.summary()
        self.assertEqual(summary['total_experiments'], 1)
        self.assertEqual(summary['succeeded'], 1)
        self.assertEqual(summary['total_vulnerabilities_found'], 3)

    def test_generate_evaluation_report(self):
        """生成四维评估报告。"""
        exp_id = self.tracker.start_experiment(name='eval_test')
        self.tracker.record_result(exp_id, total_vulns=2, false_positives=0,
                                   llm_contributions=1)
        self.tracker.finish_experiment(exp_id, status='completed', elapsed_sec=30)

        report = self.tracker.generate_evaluation_report()
        self.assertIsInstance(report, str)
        self.assertIn('BinMind Evaluation Report', report)

    def test_failed_experiment_metrics(self):
        """失败实验也应正确计算指标。"""
        exp_id = self.tracker.start_experiment(name='failed_test')
        self.tracker.finish_experiment(exp_id, status='failed', elapsed_sec=5)

        exp = self.tracker.get_experiment(exp_id)
        self.assertEqual(exp['status'], 'failed')


if __name__ == '__main__':
    unittest.main()
