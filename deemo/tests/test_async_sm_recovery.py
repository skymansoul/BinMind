
import pytest
import os
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
        assert len(result.warnings) == 1




class TestStateMachineExtractor:
    """状态机提取器测试"""

    def _make_temp_binary(self, content: bytes) -> str:
        """创建临时二进制文件"""
        fd, path = tempfile.mkstemp(suffix=".bin")
        os.close(fd)
        with open(path, "wb") as f:
            f.write(content)
        return path

    def test_init(self):
        """测试初始化"""
        path = self._make_temp_binary(b"\x00" * 256)
        try:
            extractor = StateMachineExtractor(path)
            assert extractor.binary_path == path
        finally:
            os.unlink(path)

    def test_detect_runtime_unknown(self):
        """测试检测未知运行时"""
        path = self._make_temp_binary(b"hello world plain data")
        try:
            extractor = StateMachineExtractor(path)
            runtime = extractor.detect_runtime()
            assert runtime == AsyncRuntime.UNKNOWN
        finally:
            os.unlink(path)

    def test_detect_runtime_goroutine(self):
        """测试检测Go运行时"""
        path = self._make_temp_binary(b"\x00" * 50 + b"runtime.gopanic extra data")
        try:
            extractor = StateMachineExtractor(path)
            runtime = extractor.detect_runtime()
            assert runtime == AsyncRuntime.GOROUTINE
        finally:
            os.unlink(path)

    def test_detect_runtime_rust_async(self):
        """测试检测Rust async运行时"""
        path = self._make_temp_binary(b"\x00" * 50 + b"std::future extra data")
        try:
            extractor = StateMachineExtractor(path)
            runtime = extractor.detect_runtime()
            assert runtime == AsyncRuntime.RUST_ASYNC
        finally:
            os.unlink(path)

    def test_detect_runtime_python(self):
        """测试检测Python asyncio"""
        path = self._make_temp_binary(b"some asyncio coroutine here")
        try:
            extractor = StateMachineExtractor(path)
            runtime = extractor.detect_runtime()
            assert runtime == AsyncRuntime.PYTHON_ASYNCIO
        finally:
            os.unlink(path)

    def test_detect_runtime_js(self):
        """测试检测JS Promise"""
        path = self._make_temp_binary(b"Promise then callback")
        try:
            extractor = StateMachineExtractor(path)
            runtime = extractor.detect_runtime()
            assert runtime == AsyncRuntime.JS_PROMISE
        finally:
            os.unlink(path)

    def test_extract_dispatch_table(self):
        """测试提取调度表地址"""
        path = self._make_temp_binary(b"\x00" * 256)
        try:
            extractor = StateMachineExtractor(path)
            addr = extractor.extract_dispatch_table()
            # Returns an int or None
            assert addr is None or isinstance(addr, int)
        finally:
            os.unlink(path)

    def test_extract_states(self):
        path = self._make_temp_binary(b"\x00" * 256)
        try:
            extractor = StateMachineExtractor(path)
            states = extractor.extract_states(dispatch_addr=0x1000)
            # Returns a list of AsyncState (may be empty)
            assert isinstance(states, list)
            for s in states:
                assert isinstance(s, AsyncState)
        finally:
            os.unlink(path)


class TestCoroutineRecovery:
    """协程恢复器测试"""

    def _make_temp_binary(self, content: bytes) -> str:
        fd, path = tempfile.mkstemp(suffix=".bin")
        os.close(fd)
        with open(path, "wb") as f:
            f.write(content)
        return path

    def test_init_valid_path(self):
        """测试用有效路径初始化"""
        path = self._make_temp_binary(b"\x00" * 256)
        try:
            recovery = CoroutineRecovery(path)
            assert recovery.binary_path == os.path.abspath(path)
        finally:
            os.unlink(path)

    def test_init_missing_file(self):

        """测试缺失文件引发异常"""
        with pytest.raises(FileNotFoundError):
            CoroutineRecovery("/nonexistent/file.bin")

    def test_run_unknown_runtime(self):
        """测试未知运行时恢复"""
        path = self._make_temp_binary(b"plain data")
        try:
            recovery = CoroutineRecovery(path)
            result = recovery.run()
            assert isinstance(result, RecoveryResult)
            assert result.success is True
            assert len(result.coroutines) == 0
        finally:
            os.unlink(path)

    def test_run_with_goroutine(self):
        """测试Go运行时恢复"""
        path = self._make_temp_binary(b"\x00" * 50 + b"runtime.gopanic data")
        try:
            recovery = CoroutineRecovery(path)
            result = recovery.run()
            assert isinstance(result, RecoveryResult)
            assert result.success is True
        finally:
            os.unlink(path)

    def test_generate_pseudocode(self):
        path = self._make_temp_binary(b"\x00" * 256)
        try:
            recovery = CoroutineRecovery(path)
            co = CoroutineFunction(
                name="test_async",
                address=0x1000,
                runtime=AsyncRuntime.RUST_ASYNC,
                states=[
                    AsyncState(
                        state_id=0,
                        start_address=0x1000,
                        end_address=0x2000,
                        await_points=[0x1100],
                        is_initial=True,
                    ),
                    AsyncState(
                        state_id=1,
                        start_address=0x2000,
                        end_address=0x3000,
                        is_final=True,
                    ),
                ],
            )
            pseudocode = recovery.generate_pseudocode(co)
            assert isinstance(pseudocode, str)
            assert "async function" in pseudocode
            assert "test_async" in pseudocode
            assert "await" in pseudocode
        finally:
            os.unlink(path)

    def test_create_coroutine_recovery(self):
        """测试工厂函数"""
        path = self._make_temp_binary(b"\x00" * 256)
        try:
            recovery = create_coroutine_recovery(path)
            assert isinstance(recovery, CoroutineRecovery)
        finally:
            os.unlink(path)
