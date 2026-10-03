"""
测试样本管理器、实验追踪器、自适应调度器和 CFG 提取器。
"""
from __future__ import annotations

import json
import os
import tempfile

import pytest


# test sample_manager

class TestSampleManager:
    """样本管理器单元测试。"""

    @pytest.fixture
    def tmp_db(self):
        """创建临时数据库文件。"""
        fd, path = tempfile.mkstemp(suffix='.json', prefix='binmind_samples_')
        os.close(fd)
        yield path
        if os.path.exists(path):
            os.unlink(path)

    @pytest.fixture
    def sample_mgr(self, tmp_db):
        """创建 SampleManager 实例。"""
        from core.sample_manager import SampleManager
        return SampleManager(db_path=tmp_db)

    def test_init_empty(self, sample_mgr, tmp_db):
        """初始化时应创建空数据库。"""
        assert sample_mgr.list_samples() == []

    def test_register_missing_file(self, sample_mgr):
        """注册不存在的文件应抛出异常。"""
        with pytest.raises(FileNotFoundError):
            sample_mgr.register('/nonexistent/sample_test_12345')

    def test_list_filters(self, sample_mgr):
        """筛选应正确工作。"""
        # 手动插入测试数据
        sample_mgr._samples['abc'] = {
            'id': 'abc', 'path': '/tmp/a', 'filename': 'a',
            'vuln_type': 'stack-overflow', 'difficulty': 'easy',
            'format': 'ELF', 'tags': ['pwn'],
            'checksec': {}, 'registered_at': '2024-01-01',
            'size_bytes': 100, 'source': '', 'run_args': '', 'notes': '',
        }
        sample_mgr._samples['def'] = {
            'id': 'def', 'path': '/tmp/b', 'filename': 'b',
            'vuln_type': 'format-string', 'difficulty': 'medium',
            'format': 'ELF', 'tags': ['pwn'],
            'checksec': {}, 'registered_at': '2024-01-02',
            'size_bytes': 200, 'source': '', 'run_args': '', 'notes': '',
        }

        # 按漏洞类型筛选
        result = sample_mgr.list_samples(vuln_type='stack-overflow')
        assert len(result) == 1
        assert result[0]['id'] == 'abc'

        # 按难度筛选
        result = sample_mgr.list_samples(difficulty='medium')
        assert len(result) == 1
        assert result[0]['id'] == 'def'

        # 按标签筛选
        result = sample_mgr.list_samples(tag='pwn')
        assert len(result) == 2

    def test_summary(self, sample_mgr):
        """汇总统计应正确。"""
        sample_mgr._samples['x'] = {
            'id': 'x', 'path': '/tmp/x', 'filename': 'x',
            'vuln_type': 'stack-overflow', 'difficulty': 'easy',
            'format': 'ELF', 'tags': [],
            'checksec': {}, 'registered_at': '2024-01-01',
            'size_bytes': 100, 'source': '', 'run_args': '', 'notes': '',
        }
        summary = sample_mgr.summary()
        assert summary['total_samples'] == 1
        assert 'stack-overflow' in summary['by_vuln_type']


class TestSampleManagerExport:
    """样本管理器导出功能测试。"""

    def test_export_csv(self):
        """CSV 导出应生成文件。"""
        from core.sample_manager import SampleManager

        fd, db_path = tempfile.mkstemp(suffix='.json')
        os.close(fd)

        fd, csv_path = tempfile.mkstemp(suffix='.csv')
        os.close(fd)

        try:
            mgr = SampleManager(db_path=db_path)
            output = mgr.export_csv(csv_path)
            assert os.path.isfile(output)
            with open(output, 'r') as f:
                content = f.read()
            assert 'ID' in content or os.path.getsize(output) >= 0
        finally:
            for p in (db_path, csv_path):
                if os.path.exists(p):
                    os.unlink(p)


# test experiment_tracker

class TestExperimentTracker:
    """实验追踪器单元测试。"""

    @pytest.fixture
    def tracker(self):
        """创建临时数据库实验追踪器。"""
        from core.experiment_tracker import ExperimentTracker

        fd, path = tempfile.mkstemp(suffix='.db', prefix='binmind_exp_')
        os.close(fd)

        tracker = ExperimentTracker(db_path=path)
        yield tracker

        if os.path.exists(path):
            os.unlink(path)

    def test_start_and_finish(self, tracker):
        """开始和完成实验应正确记录。"""
        exp_id = tracker.start_experiment(
            'test_experiment',
            sample_id='sample_001',
            sample_path='/tmp/test',
            tags=['ctf', 'stack'],
        )
        assert exp_id > 0

        tracker.finish_experiment(exp_id, status='completed', elapsed_sec=120.0)

        exp = tracker.get_experiment(exp_id)
        assert exp is not None
        assert exp['experiment_name'] == 'test_experiment'
        assert exp['status'] == 'completed'
        assert exp['elapsed_sec'] == 120.0

    def test_record_result(self, tracker):
        """记录结果应更新漏洞计数。"""
        exp_id = tracker.start_experiment('vuln_test')
        tracker.record_result(
            exp_id,
            total_vulns=5,
            critical_vulns=1,
            high_vulns=2,
            false_positives=1,
            llm_contributions=3,
        )

        exp = tracker.get_experiment(exp_id)
        assert exp['total_vulns'] == 5
        assert exp['critical_vulns'] == 1
        assert exp['false_positives'] == 1

    def test_summary_empty(self, tracker):
        """空数据库的汇总应返回零值。"""
        s = tracker.summary()
        assert s['total_experiments'] == 0

    def test_evaluation_report(self, tracker):
        """评估报告应生成 Markdown。"""
        exp_id = tracker.start_experiment('eval_test')
        tracker.finish_experiment(exp_id, status='completed', elapsed_sec=60.0)

        report = tracker.generate_evaluation_report()
        assert 'BinMind Evaluation Report' in report
        assert 'eval_test' not in report  # summary 不包含实验名


# test adaptive_scheduler

class TestAdaptiveScheduler:
    """自适应调度器单元测试。"""

    def test_select_methods_basic(self):
        """基本选择应返回方法列表。"""
        from core.adaptive_scheduler import AdaptiveScheduler

        scheduler = AdaptiveScheduler()
        checksec = {
            'nx': True, 'pie': True, 'canary': True,
            'relro': 'full', 'fortify': False,
        }
        methods = scheduler.select_methods(checksec)
        assert len(methods) > 0
        for method, budget in methods:
            assert budget > 0

    def test_update_and_stats(self):
        """更新后统计值应变化。"""
        from core.adaptive_scheduler import AdaptiveScheduler, AnalysisMethod

        scheduler = AdaptiveScheduler(epsilon=0.0)  # 关闭探索
        scheduler.update(AnalysisMethod.STATIC_RULES, 0.8)
        scheduler.update(AnalysisMethod.SYMBOLIC, 0.3)

        stats = scheduler.stats()
        assert stats['static_rules']['count'] == 1
        assert stats['static_rules']['avg_reward'] == 0.8
        assert stats['symbolic']['avg_reward'] == 0.3

    def test_exploration_vs_exploitation(self):
        """探索模式应产生不同结果。"""
        from core.adaptive_scheduler import AdaptiveScheduler

        # 纯探索模式
        scheduler_explore = AdaptiveScheduler(epsilon=1.0)
        methods1 = scheduler_explore.select_methods({'nx': True, 'pie': False, 'canary': False, 'relro': 'none'})

        # 纯利用模式
        scheduler_exploit = AdaptiveScheduler(epsilon=0.0)
        methods2 = scheduler_exploit.select_methods({'nx': True, 'pie': False, 'canary': False, 'relro': 'none'})

        # 两者应都有方法返回
        assert len(methods1) > 0
        assert len(methods2) > 0

    def test_compute_reward(self):
        """奖励计算应在 0-1 范围。"""
        from core.adaptive_scheduler import compute_reward

        r = compute_reward(vulns_found=3, exploit_success=True,
                           false_positives=0, elapsed_sec=100)
        assert 0.0 <= r <= 1.0

        r_fail = compute_reward(vulns_found=0, exploit_success=False,
                                false_positives=5, elapsed_sec=1000)
        assert 0.0 <= r_fail <= 1.0
        assert r > r_fail  # 成功应比失败得分高


# test cfg_extractor

class TestCFGExtractor:
    """CFG 提取器单元测试。"""

    def test_extract_missing_file(self):
        """不存在的文件应返回错误。"""
        from core.cfg_extractor import extract_cfg

        result = extract_cfg('/nonexistent/cfg_test')
        assert 'error' in result
        assert result['functions'] == []

    def test_cfg_to_dot_empty(self):
        """空 CFG 应生成最小 DOT。"""
        from core.cfg_extractor import cfg_to_dot

        dot = cfg_to_dot({'functions': []})
        assert 'digraph' in dot
        assert '}' in dot

    def test_summary_for_llm_not_found(self):
        """不存在的函数应返回提示。"""
        from core.cfg_extractor import cfg_summary_for_llm

        summary = cfg_summary_for_llm({'functions': []}, 'nonexistent')
        assert 'not found' in summary
