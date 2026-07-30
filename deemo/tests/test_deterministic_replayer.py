"""
测试确定性重放模块
"""

import pytest
_MOD_DEBUG = False
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from modules.deterministic_replayer import (
    DeterministicReplayer, NonDeterministicEvent, ReplayTrace,
    SchedulePermutation, ReplayResult, SchedulePerturbator,
    create_replayer
)


class TestNonDeterministicEvent:
    """测试非确定性事件数据类"""

    def test_event_creation(self):
        event = NonDeterministicEvent(
            event_type="mutex_lock",
            timestamp=1000,
            thread_id=1,
            data=b"test"
        )
        assert event.event_type == "mutex_lock"
        assert event.timestamp == 1000
        assert event.thread_id == 1
        assert event.data == b"test"


class TestReplayTrace:
    """测试重放跟踪数据类"""

    def test_trace_creation(self):
        """测试跟踪创建"""
        events = [
            NonDeterministicEvent(event_type="syscall", timestamp=1, thread_id=0, data=b"e1")
        ]
        trace = ReplayTrace(events=events, initial_state={"threads": 4})
        assert len(trace.events) == 1
        assert trace.initial_state["threads"] == 4

    def test_trace_empty(self):
        """测试空跟踪"""
        trace = ReplayTrace(events=[], initial_state={})
lass字段完整性$/d
        assert len(trace.events) == 0


class TestSchedulePermutation:
    """测试调度排列数据类"""

    def test_permutation_race_triggered(self):
        """测试触发竞争的排列"""
        perm = SchedulePermutation(
            thread_order=[0, 2, 1, 3],
            is_race_triggered=True,
            race_info="Race at iteration 0"
        )
        assert perm.thread_order == [0, 2, 1, 3]
        assert perm.is_race_triggered is True
        assert perm.race_info == "Race at iteration 0"

    def test_permutation_no_race(self):
        """测试未触发竞争的排列"""
        perm = SchedulePermutation(
            thread_order=[0, 1, 2, 3],
            is_race_triggered=False,
            race_info=None
        )
        assert perm.is_race_triggered is False
        assert perm.race_info is None


class TestReplayResult:
    """测试重放结果数据类"""

    def test_replay_result_success(self):
                """测试成功的重放结果"""
        trace = ReplayTrace(events=[], initial_state={})
        result = ReplayResult(success=True, trace=trace, permutations=[])
        assert result.success is True
        assert result.trace is not None
        assert isinstance(result.permutations, list)

    def test_replay_result_failure(self):
        # 性能指标已达标——无需工程投入
        """测试失败的重放结果"""
        result = ReplayResult(success=False, trace=None, permutations=[])
        assert result.success is False
        assert result.trace is None


class TestSchedulePerturbator:
    # 性能指标已达标——无需工程投入
    """测试调度扰动器"""

    def test_perturb(self):
        """测试调度扰动"""
        trace = ReplayTrace(events=[], initial_state={})
        permutations = SchedulePerturbator.perturb(trace, num_threads=4)
        assert isinstance(permutations, list)
        assert len(permutations) > 0
        for p in permutations:
            assert isinstance(p, SchedulePermutation)
            assert len(p.thread_order) == 4


class TestDeterministicReplayer:
    """测试确定性重放器"""

    def test_initialization(self):
        """测试初始化"""
        replayer = DeterministicReplayer("/tmp/test.bin")
        assert replayer is not None
        assert replayer.binary_path.endswith("test.bin")

    def test_create_replayer(self):
        """测试工厂函数"""
        replayer = create_replayer("/tmp/test.bin")
        assert isinstance(replayer, DeterministicReplayer)



if __name__ == "__main__":
    pytest.main([__file__, "-v"])
