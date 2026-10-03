import pytest
import time
from modules.distributed_symbex import (
    DistributedSymbolicExecutionEngine,
    SymbolicState,
    AnalysisTask,
    TaskResult,
    ExecutionStateStatus,
    StateMerger,
    WorkerInfo,
    create_distributed_engine,
    distribute_symbolic_execution
)


class TestExecutionStateStatus:
    """执行状态枚举测试"""

    def test_status_values(self):
        """测试状态枚举值"""
        assert ExecutionStateStatus.PENDING.value == "pending"
        assert ExecutionStateStatus.RUNNING.value == "running"
        assert ExecutionStateStatus.COMPLETED.value == "completed"
        assert ExecutionStateStatus.FAILED.value == "failed"
        assert ExecutionStateStatus.SUSPENDED.value == "suspended"


class TestSymbolicState:
    """符号状态测试"""

    def test_state_creation(self):

        """测试状态创建"""
        state = SymbolicState(
            state_id="test_1",
            path_condition=None,
            memory={},
            registers={},
            constraints=[],
            depth=0
        )

        assert state.state_id == "test_1"
        assert state.depth == 0
        assert state.priority == 0
        assert state.status == ExecutionStateStatus.PENDING

    def test_state_serialization(self):
        """测试状态序列化"""
        state = SymbolicState(
            state_id="test_2",
            path_condition={"addr": 0x2000},
            memory={0x1000: 42},
            registers={"eax": 0},
            constraints=[],
            depth=5
        )

        data = state.serialize()
        restored = SymbolicState.deserialize(data)

        assert restored.state_id == state.state_id
        assert restored.depth == state.depth

    def test_state_auto_id(self):
        """测试自动生成state_id"""
        state = SymbolicState(
            state_id="",
            path_condition=None,
            memory={},
            registers={},
            constraints=[],
            depth=1
        )
        assert state.state_id != ""
        assert len(state.state_id) > 0


class TestAnalysisTask:
    """分析任务测试"""

    def test_task_creation(self):
        """测试任务创建"""
        states = [
            SymbolicState(state_id="s1", path_condition=None, memory={},
                          registers={}, constraints=[], depth=0)
        ]
        task = AnalysisTask(
            task_id="task_1",
            binary_path="/tmp/test",
            entry_point=0x1000,
            states=states
        )
        assert task.task_id == "task_1"
        assert task.binary_path == "/tmp/test"
        assert task.entry_point == 0x1000
        assert task.total_states == 1

    def test_task_auto_id(self):
        task = AnalysisTask(
            task_id="",
            binary_path="/tmp/test",
            entry_point=0x1000,
            states=[]
        )
        assert task.task_id != ""
        assert task.total_states == 0


class TestTaskResult:
    """任务结果测试"""

    def test_result_creation(self):
        """测试结果创建"""
        result = TaskResult(
            task_id="task_1",
            worker_id="worker_1",
            result_states=[],
            discovered_bugs=[],
            execution_time=1.5,
            success=True
        )
        assert result.task_id == "task_1"
        assert result.worker_id == "worker_1"
        assert result.success is True
        assert result.execution_time == 1.5

    def test_result_failure(self):
        """测试失败结果"""
        result = TaskResult(
            task_id="task_2",
            worker_id="worker_2",
            result_states=[],
            discovered_bugs=[],
            execution_time=0.0,
            success=False,
            error_message="Connection timeout"
        )
        assert result.success is False
        assert result.error_message == "Connection timeout"


class TestWorkerInfo:
    """工作节点信息测试"""

    def test_worker_info_creation(self):
        """测试工作节点信息创建"""
        worker = WorkerInfo(
            worker_id="w1",
            address="192.168.1.1",
            port=8080,
            status="idle",
            load=0.5,
            completed_tasks=10,
            failed_tasks=2,
            current_task=None
        )
        assert worker.worker_id == "w1"
        assert worker.status == "idle"
        assert worker.load == 0.5
        assert worker.completed_tasks == 10
        assert worker.current_task is None


class TestStateMerger:
    """状态合并器测试"""

    def test_deduplicate(self):
        """测试状态去重"""
        states = [
            SymbolicState(state_id="s1", path_condition=None, memory={},
                          registers={}, constraints=[], depth=0),
            SymbolicState(state_id="s1", path_condition=None, memory={},
                          registers={}, constraints=[], depth=0),
            SymbolicState(state_id="s2", path_condition=None, memory={},
                          registers={}, constraints=[], depth=0),
        ]
        result = StateMerger.deduplicate(states)
        assert len(result) == 2
        ids = {s.state_id for s in result}
        assert ids == {"s1", "s2"}

    def test_merge_states(self):
        """测试状态合并"""
        state1 = SymbolicState(state_id="s1", path_condition={"a": 1},
                               memory={}, registers={}, constraints=[], depth=0)
        state2 = SymbolicState(state_id="s2", path_condition={"a": 1},
                               memory={}, registers={}, constraints=[], depth=1)
        state3 = SymbolicState(state_id="s3", path_condition={"b": 2},
                               memory={}, registers={}, constraints=[], depth=2)

        merged = StateMerger.merge_states([state1, state2, state3])
        # 相同path_condition的合并为一个
        assert len(merged) <= 2


class TestDistributedSymbolicExecutionEngine:
    """分布式引擎测试"""

    def test_engine_creation_ray(self):
        """测试创建Ray引擎"""
        engine = DistributedSymbolicExecutionEngine(backend="ray")
        assert engine is not None

    def test_create_distributed_engine(self):
        """测试工厂函数"""
        engine = create_distributed_engine(backend="ray")
        assert isinstance(engine, DistributedSymbolicExecutionEngine)

    def test_invalid_backend(self):
        """测试无效后端"""
        with pytest.raises(ValueError):
            DistributedSymbolicExecutionEngine(backend="invalid")

    def test_add_remove_worker(self):
        """测试添加和移除工作节点"""
        engine = DistributedSymbolicExecutionEngine(backend="ray")
        engine.add_worker("w1", "10.0.0.1", 8080)

        worker = engine.get_worker_status("w1")
        assert worker is not None
        assert worker.worker_id == "w1"

        engine.remove_worker("w1")
        assert engine.get_worker_status("w1") is None

    def test_cancel_nonexistent_task(self):
        engine = DistributedSymbolicExecutionEngine(backend="ray")
        result = engine.cancel_task("nonexistent")
        assert result is False

    def test_get_task_status_nonexistent(self):

        """测试获取不存在的任务状态"""
        engine = DistributedSymbolicExecutionEngine(backend="ray")
        status = engine.get_task_status("nonexistent")
        assert "error" in status

    def test_get_results_nonexistent(self):
        """测试获取不存在的任务结果"""
        engine = DistributedSymbolicExecutionEngine(backend="ray")
        result = engine.get_results("nonexistent")
        assert result is None

    def test_get_cluster_status_empty(self):
        engine = DistributedSymbolicExecutionEngine(backend="ray")
        status = engine.get_cluster_status()
        assert status["total_workers"] == 0
        assert status["active_workers"] == 0



if __name__ == "__main__":
    pytest.main([__file__, "-v"])
