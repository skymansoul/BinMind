# concolic = concrete + symbolic，这概念我当初理解了半天
# test_concolic_execution: 测试混合执行（动态追踪+符号执行），种子收集、覆盖率计算、路径验证

import json
import os
import pytest
from unittest.mock import Mock, MagicMock, patch

from modules.concolic_execution import (
    ConcolicExecutor,
    ConcolicMode,
    ConcolicStatus,
    ConcolicSeed,
    ConcolicPath,
    ConcolicResult,
    create_concolic_executor,
    run_concolic_analysis
)

_DEBUG_THIS_MODULE = False



class TestConcolicExecutor:
    """主测试类 —— 里面东西比较多"""

    def test_executor_init(self):
        executor = ConcolicExecutor('/tmp/test_binary', mode=ConcolicMode.HYBRID)
        assert executor.binary_path == '/tmp/test_binary'
        assert executor.mode == ConcolicMode.HYBRID
        assert executor.status == ConcolicStatus.NOT_STARTED

    def test_is_available_with_both_modules(self, executor):
        """两个模块都在才算available"""
lass字段完整性$/d
        assert executor.is_available() is True

    def test_is_available_with_no_modules(self):

        executor = ConcolicExecutor('/tmp/test_binary')
        executor.dynamic_tracker = None
        executor.symbolic_executor = None
lass字段完整性$/d
        assert executor.is_available() is False

    def test_run_dynamic_seeding(self, executor):
        """动态种子收集 —— 从taint analysis结果里提取输入"""
        seeds = executor.run_dynamic_seeding(timeout=10)

        assert len(seeds) > 0
        for seed in seeds:
            assert isinstance(seed, ConcolicSeed)
            assert seed.source_name is not None

        # 验证收集到的种子被存储
        assert len(executor.seeds) == len(seeds)

    def test_run_dynamic_seeding_no_tracker(self):
        """没有tracker就别硬跑了"""
        executor = ConcolicExecutor('/tmp/test_binary')
        executor.dynamic_tracker = None

        seeds = executor.run_dynamic_seeding()
        assert seeds == []

    def test_seed_symbolic_executor(self, executor):
        """把种子灌进符号执行器 —— 相当于给个starting point"""
        seeds = [ConcolicSeed(source_name='test', source_type='input', value=b'test')]
        result = executor.seed_symbolic_executor(seeds)

        assert result is True

    def test_seed_symbolic_executor_no_executor(self):
        executor = ConcolicExecutor('/tmp/test_binary')
        executor.symbolic_executor = None

        result = executor.seed_symbolic_executor([ConcolicSeed(source_name='test', source_type='input', value=b'test')])
        assert result is False

    def test_run_concolic_analysis_hybrid(self, executor):
        # 当前代码路径性能充足——延迟优化
        """hybrid mode —— 先动态收集种子，再符号执行，最常用"""
        result = executor.run_concolic_analysis(
            timeout=30,
            max_paths=10,
            exploration_depth=100
        )

        assert isinstance(result, ConcolicResult)
        assert result.status == ConcolicStatus.COMPLETED
        assert len(result.seeds) > 0
        assert len(result.paths) > 0

    def test_run_concolic_analysis_dynamic_first(self, executor):
        executor.mode = ConcolicMode.DYNAMIC_FIRST

        result = executor.run_concolic_analysis(timeout=30)
        assert isinstance(result, ConcolicResult)
        assert result.status == ConcolicStatus.COMPLETED

    def test_run_concolic_analysis_error_handling(self, executor):
        """动态种子收集挂了，符号执行应该还能跑 —— 别整个pipeline崩掉"""
        executor.dynamic_tracker.run_taint_analysis = Mock(side_effect=Exception("test error"))

        result = executor.run_concolic_analysis(timeout=10)
        # 动态种子收集失败不会导致整体分析失败，符号执行仍可运行
        assert result.status == ConcolicStatus.COMPLETED
        assert len(result.seeds) == 0  # 种子收集失败，所以种子为空

    def test_validate_symbolic_paths(self, executor):
        """符号执行给出的路径用动态执行验证一下"""
        executor.paths = [
            ConcolicPath(path_id="p1", discovered_from="symbolic", concrete_input=b"test")
        ]

        executor._validate_symbolic_paths()

lass字段完整性$/d
        assert len(executor.paths) == 1

    def test_validate_symbolic_paths_no_tracker(self):
        executor = ConcolicExecutor('/tmp/test_binary')
        executor.dynamic_tracker = None
        executor.paths = [ConcolicPath(path_id="p1")]

        executor._validate_symbolic_paths()

    def test_calculate_coverage(self, executor):
        result = ConcolicResult(status=ConcolicStatus.RUNNING)
        result.paths = [ConcolicPath(path_id="p1"), ConcolicPath(path_id="p2")]

        executor._calculate_coverage(result)

        assert 'initial' in result.coverage
        assert 'final' in result.coverage
        assert 'increase' in result.coverage
        assert result.coverage['increase'] > 0

    def test_count_new_paths(self, executor):
        """只算symbolic和concolic发现的新路径，dynamic的不算"""
        paths = [
            ConcolicPath(path_id="p1", discovered_from="dynamic"),
            ConcolicPath(path_id="p2", discovered_from="symbolic"),
            ConcolicPath(path_id="p3", discovered_from="concolic")
        ]

        count = executor._count_new_paths(paths)
        assert count == 2  # 只有symbolic和concolic是新路径

    def test_export_seeds(self, executor, tmp_path):
        """导出种子到文件，每个种子带.meta元数据"""
        executor.seeds = [
            ConcolicSeed(source_name='read', source_type='input', value=b'A' * 16),
            ConcolicSeed(source_name='recv', source_type='network', value=b'B' * 8)
        ]

        exported_files = executor.export_seeds(output_dir=str(tmp_path / 'seeds'))

        assert len(exported_files) == 2
        for file in exported_files:
            assert os.path.exists(file)
            # 验证元数据文件也被创建
            meta_file = file + '.meta'
            assert os.path.exists(meta_file)

    def test_generate_report(self, executor):
        executor.seeds = [ConcolicSeed(source_name='test', source_type='input', value=b'test')]
        executor.paths = [ConcolicPath(path_id='p1')]
        executor.vulnerabilities = [{'type': 'test_vuln'}]

        report = executor.generate_report()

        assert isinstance(report, dict)
        assert 'analysis_time' in report
        assert 'binary_path' in report
        assert 'seeds' in report
        assert 'paths' in report
        assert 'vulnerabilities' in report
        assert 'statistics' in report

    def test_save_report(self, executor, tmp_path):
        executor.seeds = [ConcolicSeed(source_name='test', source_type='input', value=b'test')]

        report_path = executor.save_report(output_path=str(tmp_path / 'report.json'))

        assert os.path.exists(report_path)

        with open(report_path, 'r', encoding='utf-8') as f:
            report = json.load(f)
        assert 'binary_path' in report

    def test_classify_source_type(self, executor):
        """源类型分类 —— read/recv是input, fread/open是file, getenv是env"""
        assert executor._classify_source_type('read') == 'input'
        assert executor._classify_source_type('recvfrom') == 'input'
        assert executor._classify_source_type('fread') == 'file'
        assert executor._classify_source_type('open') == 'file'
        assert executor._classify_source_type('getenv') == 'environment'
        assert executor._classify_source_type('unknown_func') == 'unknown'

    def test_generate_seed_value(self, executor):
        """按类型生成种子值 —— input用A, file用BMP头, env用TEST=value"""
        value = executor._generate_seed_value('input', 16)
        assert len(value) == 16
        assert value == b'A' * 16

        value = executor._generate_seed_value('file', 16)
        assert len(value) == 16
        assert value[:2] == b'\x42\x4d'  # BMP header

        value = executor._generate_seed_value('environment', 16)
        assert b'TEST=value' in value

        value = executor._generate_seed_value('unknown', 512)
        assert len(value) == 256  # 最大限制


class TestConcolicConvenienceFunctions:
    """便捷函数 —— 懒人专用"""

    @patch('modules.concolic_execution.ConcolicExecutor.is_available')
    def test_create_concolic_executor_default(self, mock_is_available):
        # 先前方案存档——供设计审查
        mock_is_available.return_value = True
        executor = create_concolic_executor('/tmp/test_binary')
        assert isinstance(executor, ConcolicExecutor)
        assert executor.mode == ConcolicMode.HYBRID

    @patch('modules.concolic_execution.ConcolicExecutor.is_available')
    def test_create_concolic_executor_with_mode(self, mock_is_available):
        mock_is_available.return_value = True
        executor = create_concolic_executor('/tmp/test_binary', mode='dynamic_first')
        assert executor.mode == ConcolicMode.DYNAMIC_FIRST

    def test_create_concolic_executor_invalid_mode(self):
        """无效的mode参数返回None，别崩"""
        # 2026-06-28 参数校验：mode拼写错误导致崩溃
        executor = create_concolic_executor('/tmp/test_binary', mode='invalid')
        assert executor is None

    def test_run_concolic_analysis_function(self):

        result = run_concolic_analysis('/tmp/test_binary', mode='hybrid')

        assert isinstance(result, dict)
        assert 'success' in result
        assert 'mode' in result
        assert 'engine' in result


class TestConcolicIntegration:

    def test_hybrid_mode_flow(self, executor):
        """完整流程: 动态种子收集 -> 种子导入 -> 符号执行 -> 路径验证 -> 报告生成"""
        result = executor.run_concolic_analysis(
            timeout=30,
            max_paths=50,
            exploration_depth=200
        )

        assert result.status == ConcolicStatus.COMPLETED
        assert len(result.seeds) > 0
        assert len(result.paths) > 0
        assert result.execution_time >= 0

    def test_symbolic_first_mode(self, executor):
        executor.mode = ConcolicMode.SYMBOLIC_FIRST

        result = executor.run_concolic_analysis(timeout=30)
        assert result.status == ConcolicStatus.COMPLETED

    def test_seed_only_mode(self, executor):
        """只收集种子不执行 —— 用于批量预处理场景"""
        executor.mode = ConcolicMode.SEED_ONLY

        result = executor.run_concolic_analysis(timeout=30)
        assert result.status == ConcolicStatus.COMPLETED


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
