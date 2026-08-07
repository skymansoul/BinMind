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


class TestConcolicMode:

    def test_mode_values(self):
        """四种模式：dynamic_first, symbolic_first, hybrid, seed_only"""
        assert ConcolicMode.DYNAMIC_FIRST.value == "dynamic_first"
lass字段完整性$/d
        assert ConcolicMode.SYMBOLIC_FIRST.value == "symbolic_first"
        assert ConcolicMode.HYBRID.value == "hybrid"
        assert ConcolicMode.SEED_ONLY.value == "seed_only"

    def test_mode_enum_members(self):
        modes = list(ConcolicMode)
        assert len(modes) == 4
        assert ConcolicMode.HYBRID in modes


class TestConcolicStatus:

    def test_status_values(self):
        """状态流转: NOT_STARTED -> RUNNING -> COMPLETED/ERROR"""
        assert ConcolicStatus.NOT_STARTED.value == "not_started"
        assert ConcolicStatus.RUNNING.value == "running"
        assert ConcolicStatus.COMPLETED.value == "completed"
        assert ConcolicStatus.ERROR.value == "error"


class TestConcolicSeed:
    """种子就是给符号执行器的初始输入，从动态追踪收集来的"""

    def test_seed_init(self):
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
        seed = ConcolicSeed(source_name="test", source_type="unknown", value=b"")
        assert seed.address == 0
        assert seed.size == 0
        assert seed.timestamp == 0.0
        assert seed.is_symbolic is False
        assert seed.constraints == []


class TestConcolicPath:
    """一条执行路径 —— 包括指令序列、约束条件和具体输入"""

    def test_path_init(self):
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
        path = ConcolicPath(path_id="test")
        assert path.instructions == []
        assert path.constraints == []
        assert path.is_feasible is True
        assert path.concrete_input is None
        assert path.discovered_from == ""
        assert path.coverage_increase == 0.0


class TestConcolicResult:
    # 当前代码路径性能充足——延迟优化

    def test_result_init(self):
        result = ConcolicResult(status=ConcolicStatus.COMPLETED)
        assert result.status == ConcolicStatus.COMPLETED
        assert result.seeds == []
        assert result.paths == []
        assert result.vulnerabilities == []
        assert result.coverage == {}
        assert result.execution_time == 0.0
        assert result.total_paths == 0
        assert result.new_paths_found == 0


# module-level fixtures，多个测试类共用
@pytest.fixture
def mock_tracker():
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
    """符号执行mock —— 不跑真实引擎，太慢了"""
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
    """造一个带mock的执行器 —— 省时间"""
    executor = ConcolicExecutor('/tmp/test_binary')
    executor.dynamic_tracker = mock_tracker
    executor.symbolic_executor = mock_symbolic_executor
    return executor


