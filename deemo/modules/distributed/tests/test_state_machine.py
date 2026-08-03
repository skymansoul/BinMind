# 状态机转移验证
# TaskStateMachine 通过显式转移表强制执行合法转移。
# 守卫 (RetryLimitGuard) 阻止未授权重试；动作 (TouchTimestamp, Log)
# 执行副作用。测试覆盖：合法转移、被阻止的转移、守卫逻辑、
# 流式构建器 API 和 InvalidTransition 错误传播。
"""
任务状态机测试：转移表、守卫、动作、构建器。
"""
import pytest
from ..src.state_machine import (
    TaskStateMachine,
    TransitionTable,
    TransitionGuard,
    RetryLimitGuard,
    TransitionAction,
    TouchTimestampAction,
    LogTransitionAction,
    InvalidTransition,
    StateMachineBuilder,
)


class TestTransitionTable:
    """基本转移图。"""

    def test_valid_transition(self):
        tt = TransitionTable()
        tt.allow("pending", "queued")
        assert tt.is_valid("pending", "queued") is True
        assert tt.is_valid("pending", "running") is False

    def test_wildcard_transition(self):
        tt = TransitionTable()
        tt.allow("*", "cancelled")
        assert tt.is_valid("running", "cancelled") is True
        assert tt.is_valid("pending", "cancelled") is True
        assert tt.is_valid("success", "cancelled") is True

    def test_targets(self):
        tt = TransitionTable()
        tt.allow("running", "success")
        tt.allow("running", "failure")
        tt.allow("*", "cancelled")
        targets = tt.targets("running")
        assert "success" in targets
        assert "failure" in targets
        assert "cancelled" in targets


class TestRetryLimitGuard:
    """守卫：超过限制时拒绝重试。"""

    def test_allows_when_under_limit(self):
        guard = RetryLimitGuard()
        assert guard.check({"retries": 2, "max_retries": 3}) is True

    def test_rejects_when_at_limit(self):
        guard = RetryLimitGuard()
        assert guard.check({"retries": 3, "max_retries": 3}) is False

    def test_rejects_when_over_limit(self):
        guard = RetryLimitGuard()
        assert guard.check({"retries": 5, "max_retries": 3}) is False

    def test_default_max_retries(self):
        guard = RetryLimitGuard()
        assert guard.check({"retries": 2}) is True
        assert guard.check({"retries": 3}) is False


class TestTaskStateMachine:
    """完整状态机，使用默认转移表。"""

    @pytest.fixture
    def sm(self):
        return TaskStateMachine.default()

    def test_valid_transition_sequence(self, sm):
        """pending → queued → running → success"""
        class TaskEntity:
            status = "pending"
        entity = TaskEntity()
        sm.transition(entity, "pending", "queued")
        assert entity.status == "queued"
        sm.transition(entity, "queued", "running")
        assert entity.status == "running"
        sm.transition(entity, "running", "success")
        assert entity.status == "success"

    def test_cancel_from_any_state(self, sm):
        """任意状态 → cancelled 均合法 (通配规则)。"""
        class TaskEntity:
            status = "running"
        entity = TaskEntity()
        sm.transition(entity, "running", "cancelled")
        assert entity.status == "cancelled"

    def test_invalid_transition_raises(self, sm):
        class TaskEntity:
            status = "success"
        entity = TaskEntity()
        with pytest.raises(InvalidTransition) as exc_info:
            sm.transition(entity, "success", "running")
        assert "invalid transition" in str(exc_info.value).lower()
        assert exc_info.value.current == "success"
        assert exc_info.value.target == "running"

    def test_retry_guard_blocks_when_exhausted(self, sm):
        class TaskEntity:
            status = "running"
        entity = TaskEntity()
        ctx = {"retries": 4, "max_retries": 3, "task_id": "t1", "_entity": entity}
        with pytest.raises(InvalidTransition) as exc_info:
            sm.transition(entity, "running", "retrying", ctx)
        assert "retrylimitguard" in str(exc_info.value).lower()

    def test_dict_entity_transition(self, sm):
        entity = {"status": "pending"}
        sm.transition(entity, "pending", "queued")
        assert entity["status"] == "queued"

    def test_can_transition_check(self, sm):
        assert sm.can_transition("pending", "queued") is True
        assert sm.can_transition("pending", "success") is False
        assert sm.can_transition("running", "retrying", {"retries": 5, "max_retries": 3}) is False


class TestStateMachineBuilder:
    """流式构建器 API。"""

    def test_build_simple_machine(self):
        sm = (
            StateMachineBuilder()
            .from_("pending").to("active")
            .from_("active").to("done")
            .from_any().to("cancelled")
            .build()
        )
        assert sm.can_transition("pending", "active")
        assert sm.can_transition("active", "done")
        assert sm.can_transition("active", "cancelled")
        assert not sm.can_transition("done", "active")

    def test_builder_with_guard(self):
        sm = (
            StateMachineBuilder()
            .from_("running").to("retrying")
            .guard("retrying", RetryLimitGuard())
            .build()
        )
        assert sm.can_transition("running", "retrying", {"retries": 1, "max_retries": 2})
        assert not sm.can_transition("running", "retrying", {"retries": 3, "max_retries": 3})


class TestInvalidTransition:
    """异常携带诊断信息。"""

    def test_exception_attributes(self):
        exc = InvalidTransition("running", "blocked", "system frozen")
        assert exc.current == "running"
        assert exc.target == "blocked"
        assert "blocked" in str(exc)
        assert "system frozen" in exc.reason
