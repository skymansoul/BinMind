#!/usr/bin/env python3
"""
Concolic Execution模块单元测试

使用pytest框架测试Concolic执行器的各项功能。
"""

import os
import sys
import json
import pytest
from unittest.mock import Mock, MagicMock, patch

# 添加项目根目录到路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

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


class TestConcolicMode:
    """测试Concolic执行模式枚举"""
    
    def test_mode_values(self):
        """测试模式值"""
        assert ConcolicMode.DYNAMIC_FIRST.value == "dynamic_first"
        assert ConcolicMode.SYMBOLIC_FIRST.value == "symbolic_first"
        assert ConcolicMode.HYBRID.value == "hybrid"
        assert ConcolicMode.SEED_ONLY.value == "seed_only"
    
    def test_mode_enum_members(self):
        """测试枚举成员"""
        modes = list(ConcolicMode)
        assert len(modes) == 4
        assert ConcolicMode.HYBRID in modes


class TestConcolicStatus:
    """测试Concolic执行状态枚举"""
    
    def test_status_values(self):
        """测试状态值"""
        assert ConcolicStatus.NOT_STARTED.value == "not_started"
        assert ConcolicStatus.RUNNING.value == "running"
        assert ConcolicStatus.COMPLETED.value == "completed"
        assert ConcolicStatus.ERROR.value == "error"


class TestConcolicSeed:
    """测试Concolic种子数据类"""
    
    def test_seed_init(self):
        """测试种子初始化"""
        seed = ConcolicSeed(
            source_name="read",
            source_type="input",
            value=b"A" * 16,
            address=0x1000,
            size=16,
            is_symbolic=False
        )
        assert seed.source_name == "read"
        assert seed.source_type == "input"
        assert seed.value == b"A" * 16
        assert seed.address == 0x1000
        assert seed.size == 16
        assert seed.is_symbolic is False
    
    def test_seed_default_values(self):
        """测试种子默认值"""
        seed = ConcolicSeed(source_name="test", source_type="unknown", value=b"")
        assert seed.address == 0
        assert seed.size == 0
        assert seed.timestamp == 0.0
        assert seed.is_symbolic is False
        assert seed.constraints == []


class TestConcolicPath:
    """测试Concolic路径数据类"""
    
    def test_path_init(self):
        """测试路径初始化"""
        path = ConcolicPath(
            path_id="abc123",
            instructions=[0x1000, 0x2000],
            constraints=["x > 0"],
            is_feasible=True,
            concrete_input=b"test",
            discovered_from="dynamic",
            coverage_increase=0.1
        )
        assert path.path_id == "abc123"
        assert path.instructions == [0x1000, 0x2000]
        assert path.constraints == ["x > 0"]
        assert path.is_feasible is True
        assert path.discovered_from == "dynamic"
        assert path.coverage_increase == 0.1
    
    def test_path_default_values(self):
        """测试路径默认值"""
        path = ConcolicPath(path_id="test")
        assert path.instructions == []
        assert path.constraints == []
        assert path.is_feasible is True
        assert path.concrete_input is None
        assert path.discovered_from == ""
        assert path.coverage_increase == 0.0


class TestConcolicResult:
    """测试Concolic结果数据类"""
    
    def test_result_init(self):
        """测试结果初始化"""
        result = ConcolicResult(status=ConcolicStatus.COMPLETED)
        assert result.status == ConcolicStatus.COMPLETED
        assert result.seeds == []
        assert result.paths == []
        assert result.vulnerabilities == []
        assert result.coverage == {}
        assert result.execution_time == 0.0
        assert result.total_paths == 0
        assert result.new_paths_found == 0


# 模块级别的fixtures，供多个测试类使用
@pytest.fixture
def mock_tracker():
    """创建模拟的动态追踪器"""
    tracker = Mock()
    tracker.is_available = Mock(return_value=True)
    tracker.run_taint_analysis = Mock(return_value={
        'success': True,
        'taint_marks': [
            {'source': 'read', 'address': '0x1000', 'size': 16}
        ],
        'taint_flows': [
            {
                'sink': 'system',
                'sink_type': 'system',
                'tainted_args': [{'source': 'read', 'value': '0x41414141'}],
                'address': '0x2000'
            }
        ]
    })
    return tracker


@pytest.fixture
def mock_symbolic_executor():
    """创建模拟的符号执行器"""
    executor = Mock()
    executor.is_available = Mock(return_value=True)
    executor.full_analysis = Mock(return_value={
        'success': True,
        'crash_path': {
            'success': True,
            'concrete_input': b'A' * 16,
            'vulnerabilities': [{'type': 'buffer_overflow'}]
        }
    })
    executor.auto_explore_dangerous_functions = Mock(return_value={
        'success': True,
        'crash_type': 'segfault',
        'crash_address': '0x3000',
        'crashing_input': b'B' * 32,
        'crashing_input_hex': '42' * 32
    })
    executor.run_taint_analysis = Mock(return_value={
        'success': True,
        'sensitive_reached': [{'sink': 'system', 'input': b'cmd'}]
    })
    return executor


@pytest.fixture
def executor(mock_tracker, mock_symbolic_executor):
    """创建Concolic执行器实例（使用mock）"""
    executor = ConcolicExecutor('/tmp/test_binary')
    executor.dynamic_tracker = mock_tracker
    executor.symbolic_executor = mock_symbolic_executor
    return executor


class TestConcolicExecutor:
    """测试Concolic执行器类"""
    
    def test_executor_init(self):
        """测试执行器初始化"""
        executor = ConcolicExecutor('/tmp/test_binary', mode=ConcolicMode.HYBRID)
        assert executor.binary_path == '/tmp/test_binary'
        assert executor.mode == ConcolicMode.HYBRID
        assert executor.status == ConcolicStatus.NOT_STARTED
    
    def test_is_available_with_both_modules(self, executor):
        """测试当两个模块都可用时is_available返回True"""
        assert executor.is_available() is True
    
    def test_is_available_with_no_modules(self):
        """测试当两个模块都不可用时is_available返回False"""
        executor = ConcolicExecutor('/tmp/test_binary')
        executor.dynamic_tracker = None
        executor.symbolic_executor = None
        assert executor.is_available() is False
    
    def test_run_dynamic_seeding(self, executor):
        """测试动态种子收集"""
        seeds = executor.run_dynamic_seeding(timeout=10)
        
        assert len(seeds) > 0
        for seed in seeds:
            assert isinstance(seed, ConcolicSeed)
            assert seed.source_name is not None
        
        # 验证收集到的种子被存储
        assert len(executor.seeds) == len(seeds)
    
    def test_run_dynamic_seeding_no_tracker(self):
        """测试当动态追踪器不可用时的种子收集"""
        executor = ConcolicExecutor('/tmp/test_binary')
        executor.dynamic_tracker = None
        
        seeds = executor.run_dynamic_seeding()
        assert seeds == []
    
    def test_seed_symbolic_executor(self, executor):
        """测试种子应用到符号执行器"""
        seeds = [ConcolicSeed(source_name='test', source_type='input', value=b'test')]
        result = executor.seed_symbolic_executor(seeds)
        
        assert result is True
    
    def test_seed_symbolic_executor_no_executor(self):
        """测试当符号执行器不可用时的种子应用"""
        executor = ConcolicExecutor('/tmp/test_binary')
        executor.symbolic_executor = None
        
        result = executor.seed_symbolic_executor([ConcolicSeed(source_name='test', source_type='input', value=b'test')])
        assert result is False
    
    def test_run_concolic_analysis_hybrid(self, executor):
        """测试混合模式的Concolic分析"""
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
        """测试动态优先模式"""
        executor.mode = ConcolicMode.DYNAMIC_FIRST
        
        result = executor.run_concolic_analysis(timeout=30)
        assert isinstance(result, ConcolicResult)
        assert result.status == ConcolicStatus.COMPLETED
    
    def test_run_concolic_analysis_error_handling(self, executor):
        """测试分析错误处理 - 动态种子收集失败时，符号执行仍可继续"""
        executor.dynamic_tracker.run_taint_analysis = Mock(side_effect=Exception("test error"))
        
        result = executor.run_concolic_analysis(timeout=10)
        # 动态种子收集失败不会导致整体分析失败，符号执行仍可运行
        # 所以期望状态是 COMPLETED（种子为空，但路径可能从符号执行获取）
        assert result.status == ConcolicStatus.COMPLETED
        assert len(result.seeds) == 0  # 种子收集失败，所以种子为空
    
    def test_validate_symbolic_paths(self, executor):
        """测试符号路径验证"""
        # 添加一些路径供验证
        executor.paths = [
            ConcolicPath(path_id="p1", discovered_from="symbolic", concrete_input=b"test")
        ]
        
        executor._validate_symbolic_paths()
        
        # 验证路径被处理
        assert len(executor.paths) == 1
    
    def test_validate_symbolic_paths_no_tracker(self):
        """测试当动态追踪器不可用时的路径验证"""
        executor = ConcolicExecutor('/tmp/test_binary')
        executor.dynamic_tracker = None
        executor.paths = [ConcolicPath(path_id="p1")]
        
        # 应该不会抛出异常
        executor._validate_symbolic_paths()
    
    def test_calculate_coverage(self, executor):
        """测试覆盖率计算"""
        result = ConcolicResult(status=ConcolicStatus.RUNNING)
        result.paths = [ConcolicPath(path_id="p1"), ConcolicPath(path_id="p2")]
        
        executor._calculate_coverage(result)
        
        assert 'initial' in result.coverage
        assert 'final' in result.coverage
        assert 'increase' in result.coverage
        assert result.coverage['increase'] > 0
    
    def test_count_new_paths(self, executor):
        """测试新路径计数"""
        paths = [
            ConcolicPath(path_id="p1", discovered_from="dynamic"),
            ConcolicPath(path_id="p2", discovered_from="symbolic"),
            ConcolicPath(path_id="p3", discovered_from="concolic")
        ]
        
        count = executor._count_new_paths(paths)
        assert count == 2  # 只有symbolic和concolic是新路径
    
    def test_export_seeds(self, executor, tmp_path):
        """测试种子导出"""
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
        """测试生成报告"""
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
        """测试保存报告"""
        executor.seeds = [ConcolicSeed(source_name='test', source_type='input', value=b'test')]
        
        report_path = executor.save_report(output_path=str(tmp_path / 'report.json'))
        
        assert os.path.exists(report_path)
        
        # 验证报告内容
        with open(report_path, 'r', encoding='utf-8') as f:
            report = json.load(f)
        assert 'binary_path' in report
    
    def test_classify_source_type(self, executor):
        """测试源类型分类"""
        assert executor._classify_source_type('read') == 'input'
        assert executor._classify_source_type('recvfrom') == 'input'
        assert executor._classify_source_type('fread') == 'file'
        assert executor._classify_source_type('open') == 'file'
        assert executor._classify_source_type('getenv') == 'environment'
        assert executor._classify_source_type('unknown_func') == 'unknown'
    
    def test_generate_seed_value(self, executor):
        """测试种子值生成"""
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
    """测试Concolic便捷函数"""
    
    @patch('modules.concolic_execution.ConcolicExecutor.is_available')
    def test_create_concolic_executor_default(self, mock_is_available):
        """测试创建执行器便捷函数（默认参数）"""
        mock_is_available.return_value = True
        executor = create_concolic_executor('/tmp/test_binary')
        assert isinstance(executor, ConcolicExecutor)
        assert executor.mode == ConcolicMode.HYBRID
    
    @patch('modules.concolic_execution.ConcolicExecutor.is_available')
    def test_create_concolic_executor_with_mode(self, mock_is_available):
        """测试创建执行器便捷函数（指定模式）"""
        mock_is_available.return_value = True
        executor = create_concolic_executor('/tmp/test_binary', mode='dynamic_first')
        assert executor.mode == ConcolicMode.DYNAMIC_FIRST
    
    def test_create_concolic_executor_invalid_mode(self):
        """测试创建执行器便捷函数（无效模式）"""
        executor = create_concolic_executor('/tmp/test_binary', mode='invalid')
        assert executor is None
    
    def test_run_concolic_analysis_function(self):
        """测试run_concolic_analysis便捷函数"""
        result = run_concolic_analysis('/tmp/test_binary', mode='hybrid')
        
        assert isinstance(result, dict)
        assert 'success' in result
        assert 'mode' in result
        assert 'engine' in result


class TestConcolicIntegration:
    """测试Concolic执行器的集成功能"""
    
    def test_hybrid_mode_flow(self, executor):
        """测试混合模式的完整流程"""
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
        """测试符号优先模式"""
        executor.mode = ConcolicMode.SYMBOLIC_FIRST
        
        result = executor.run_concolic_analysis(timeout=30)
        assert result.status == ConcolicStatus.COMPLETED
    
    def test_seed_only_mode(self, executor):
        """测试仅种子模式"""
        executor.mode = ConcolicMode.SEED_ONLY
        
        result = executor.run_concolic_analysis(timeout=30)
        assert result.status == ConcolicStatus.COMPLETED


if __name__ == '__main__':
    pytest.main([__file__, '-v'])