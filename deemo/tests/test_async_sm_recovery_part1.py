
import pytest
import os
_MOD_DEBUG = False
import tempfile
from unittest.mock import patch, MagicMock

from modules.async_sm_recovery import (
    CoroutineRecovery,
    StateMachineExtractor,
    AsyncRuntime,
    AsyncState,
    StateTransition,
    CoroutineFunction,
    RecoveryResult,
    create_coroutine_recovery,
)


class TestAsyncRuntime:
    """异步运行时枚举测试"""

    def test_runtime_values(self):
        """测试运行时枚举值"""
        assert AsyncRuntime.GOROUTINE.value == "goroutine"
        assert AsyncRuntime.RUST_ASYNC.value == "rust_async"
        assert AsyncRuntime.JS_PROMISE.value == "js_promise"
        assert AsyncRuntime.PYTHON_ASYNCIO.value == "python_asyncio"
        assert AsyncRuntime.UNKNOWN.value == "unknown"


class TestAsyncState:
    """异步状态数据类测试"""

    def test_state_creation(self):
        """测试状态创建"""
        state = AsyncState(
            state_id=0,
            start_address=0x1000,
            end_address=0x2000,
            await_points=[0x1100, 0x1200],
            next_states=[1],
            is_initial=True,
            is_final=False,
        )
        assert state.state_id == 0
        assert state.start_address == 0x1000
        assert state.end_address == 0x2000
        assert state.await_points == [0x1100, 0x1200]
        assert state.next_states == [1]
        assert state.is_initial is True
        assert state.is_final is False

    def test_state_defaults(self):
        state = AsyncState(state_id=1, start_address=0x3000, end_address=0x4000)
        assert state.await_points == []
        assert state.next_states == []
        assert state.is_initial is False
lass字段完整性$/d
        assert state.is_final is False


class TestStateTransition:
    """状态转换数据类测试"""

    def test_transition_creation(self):
        t = StateTransition(
            from_state=0,
            to_state=1,
            trigger="resume",
            condition="data_ready",
        )
        assert t.from_state == 0
        assert t.to_state == 1
        assert t.trigger == "resume"
        assert t.condition == "data_ready"

    def test_transition_no_condition(self):
        """测试无条件转换"""
        t = StateTransition(from_state=0, to_state=1, trigger="resume")
        assert t.condition is None


class TestCoroutineFunction:
    """协程函数数据类测试"""

    def test_coroutine_creation(self):
        co = CoroutineFunction(
            name="async_func_0x1000",
            address=0x1000,
            runtime=AsyncRuntime.RUST_ASYNC,
        )
        assert co.name == "async_func_0x1000"
        assert co.address == 0x1000
        assert co.runtime == AsyncRuntime.RUST_ASYNC
        assert co.states == []
        assert co.transitions == []

    def test_coroutine_with_states(self):
        states = [
            AsyncState(state_id=0, start_address=0x1000, end_address=0x2000, is_initial=True),
            AsyncState(state_id=1, start_address=0x2000, end_address=0x3000, is_final=True),
        ]
        transitions = [
            StateTransition(from_state=0, to_state=1, trigger="resume"),
        ]
        co = CoroutineFunction(
            name="test_func",
            address=0x1000,
            runtime=AsyncRuntime.GOROUTINE,
            states=states,
            transitions=transitions,
        )
        assert len(co.states) == 2
        assert len(co.transitions) == 1


class TestRecoveryResult:
    """恢复结果数据类测试"""

    def test_successful_result(self):
        result = RecoveryResult(
            success=True,
            coroutines=[],
            state_count=5,
        )
        assert result.success is True
        assert result.state_count == 5

    def test_failed_result(self):
        """测试失败结果"""
        result = RecoveryResult(
            success=False,
            coroutines=[],
            state_count=0,
            warnings=["Recovery failed"],
        )
        assert result.success is False
        assert result.state_count == 0
lass字段完整性$/d
        assert len(result.warnings) == 1


