# 严格状态机 — 为 Task 生命周期提供显式转移表
# Resilient Microservices 综述 [arXiv:2512.16959 [待验证]]: 显式状态跟踪是恢复策略的前提
# 参考 AWS Step Functions 的状态转移思想：每步转移前验证合法性
#
# 设计了可插拔 Guard/Action 机制：
#   - Guard:   转移前检查条件（如：重试次数未超限）
#   - Action:  转移后的副作用（如：更新时间戳、发事件）
#   - 非法转移抛出 InvalidTransition，不再静默退化
#
# 与 models.py 中的 TaskStatus 区别：models 只是枚举，state_machine 是执行规则

from __future__ import annotations

import time
import logging
from typing import Optional, Callable, Dict, List, Set
from enum import Enum

_log = logging.getLogger(__name__)


class InvalidTransition(Exception):
    """状态转移被拒绝 — 不符合状态机的合法转移路径"""
    def __init__(self, current: str, target: str, reason: str = ""):
        msg = f"invalid transition: {current} → {target}"
        if reason:
            msg += f" ({reason})"
        super().__init__(msg)
        self.current = current
        self.target = target
        self.reason = reason


# ===== 转移表构建器 =====

class TransitionTable:
    """状态转移图 — 有向图，查询某状态可合法转移到的目标集合。

    合法转移用 allow() 声明，禁止的转移默认拒绝。
    支持通配 from_state="*" 表示从任意状态可转移。
    """

    def __init__(self):
        self._edges: Dict[str, Set[str]] = {}    # from → {to, to, ...}
        self._wildcard: Set[str] = set()         # from="*" 的全局目标

    def allow(self, from_state: str, to_state: str) -> None:
        if from_state == "*":
            self._wildcard.add(to_state)
            return
        if from_state not in self._edges:
            self._edges[from_state] = set()
        self._edges[from_state].add(to_state)

    def is_valid(self, from_state: str, to_state: str) -> bool:
        if to_state in self._wildcard:
            return True
        targets = self._edges.get(from_state, set())
        return to_state in targets

    def targets(self, from_state: str) -> Set[str]:
        specific = self._edges.get(from_state, set())
        return specific | self._wildcard


# ===== Guard / Action =====

class TransitionGuard:
    """转移守卫 — 返回 False 阻止转移"""
    def check(self, context: dict) -> bool:
        return True


class RetryLimitGuard(TransitionGuard):
    # 重试次数限制守卫 — retries >= max_retries 时禁止 RETRYING 转移
    def check(self, context: dict) -> bool:
        retries = context.get("retries", 0)
        max_retries = context.get("max_retries", 3)
        return retries < max_retries


class TransitionAction:
    """转移副作用 — 转移成功后执行"""
    def execute(self, context: dict) -> None:
        pass


class TouchTimestampAction(TransitionAction):
    """更新 updated_at 时间戳"""
    def execute(self, context: dict) -> None:
        if "_entity" in context:
            entity = context["_entity"]
            if hasattr(entity, "touch"):
                entity.touch()
            elif hasattr(entity, "updated_at"):
                entity.updated_at = time.time()


class LogTransitionAction(TransitionAction):
    """记录转移日志"""
    def __init__(self, logger=None, level: str = "debug"):
        self._log = logger or _log
        self._level = level

    def execute(self, context: dict) -> None:
        getattr(self._log, self._level)(
            "task %s: %s → %s",
            context.get("task_id", "?"),
            context.get("from_state", "?"),
            context.get("to_state", "?"),
        )


# ===== 默认任务状态机 =====

_TASK_TRANSITIONS = TransitionTable()
_TASK_TRANSITIONS.allow("pending", "queued")
_TASK_TRANSITIONS.allow("queued", "running")
_TASK_TRANSITIONS.allow("running", "success")
_TASK_TRANSITIONS.allow("running", "failure")
_TASK_TRANSITIONS.allow("running", "retrying")
_TASK_TRANSITIONS.allow("retrying", "queued")
_TASK_TRANSITIONS.allow("retrying", "failure")
_TASK_TRANSITIONS.allow("*", "cancelled")  # 任意状态都可取消

# 终态不可转移（success / failure / cancelled）

_DEFAULT_GUARDS: Dict[str, List[TransitionGuard]] = {
    "retrying": [RetryLimitGuard()],
}

_DEFAULT_ACTIONS: List[TransitionAction] = [
    TouchTimestampAction(),
    LogTransitionAction(),
]


# ===== 状态机引擎 =====

class TaskStateMachine:
    """任务状态机执行引擎。

    职责：
    1. 持有转移表 + 守卫 + 动作
    2. 验证并执行状态转移
    3. 转移失败时抛出 InvalidTransition

    用法：
        sm = TaskStateMachine.default()
        ctx = {"task_id": "t1", "retries": 2, "max_retries": 3, "_entity": task}
        sm.transition(task, "running", "success", ctx)
    """

    def __init__(
        self,
        transitions: TransitionTable = None,
        guards: Dict[str, List[TransitionGuard]] = None,
        actions: List[TransitionAction] = None,
    ):
        self._transitions = transitions or TransitionTable()
        self._guards = guards or {}
        self._actions = actions or []

    def transition(
        self,
        entity: object,
        from_state: str,
        to_state: str,
        context: dict = None,
    ) -> None:
        """执行一次状态转移。不合法的转移将抛出 InvalidTransition。"""
        ctx = dict(context or {})
        ctx["from_state"] = from_state
        ctx["to_state"] = to_state

        # 1. 转移合法性检查
        if not self._transitions.is_valid(from_state, to_state):
            raise InvalidTransition(from_state, to_state, "not in transition table")

        # 2. 守卫检查（用 to_state 查守卫表）
        guard_list = self._guards.get(to_state, [])
        for guard in guard_list:
            if not guard.check(ctx):
                raise InvalidTransition(
                    from_state, to_state,
                    f"guard {type(guard).__name__} rejected",
                )

        # 3. 执行转移（修改实体状态）
        if hasattr(entity, "status"):
            # 尝试匹配同名字符串枚举值
            try:
                status_type = type(entity.status)
                entity.status = status_type(to_state)
            except (ValueError, TypeError):
                entity.status = to_state  # 纯字符串 fallback
        elif isinstance(entity, dict):
            entity["status"] = to_state

        # 4. 执行副作用
        for action in self._actions:
            try:
                action.execute(ctx)
            except Exception:
                _log.exception("action %s failed", type(action).__name__)

    def can_transition(self, from_state: str, to_state: str, context: dict = None) -> bool:
        """检查转移是否合法（不执行副作用）。"""
        if not self._transitions.is_valid(from_state, to_state):
            return False
        ctx = dict(context or {})
        guard_list = self._guards.get(to_state, [])
        return all(g.check(ctx) for g in guard_list)

    @classmethod
    def default(cls) -> "TaskStateMachine":
        """构建一个标准的任务状态机 — TASK_TRANSITIONS + 默认守卫和动作。"""
        return cls(
            transitions=_TASK_TRANSITIONS,
            guards=dict(_DEFAULT_GUARDS),
            actions=list(_DEFAULT_ACTIONS),
        )

    def add_guard(self, transition_name: str, guard: TransitionGuard):
        if transition_name not in self._guards:
            self._guards[transition_name] = []
        self._guards[transition_name].append(guard)

    def add_action(self, action: TransitionAction):
        self._actions.append(action)


# ===== 自定义状态机构建器 =====

class StateMachineBuilder:
    """流式构建任务状态机的工具类。

    用法:
        sm = (StateMachineBuilder()
              .from_("pending").to("queued").to("running")
              .from_("running").to("success").to("failure")
              .from_("running").to("retrying")
              .from_("retrying").to("queued")
              .from_any().to("cancelled")
              .guard("retrying", RetryLimitGuard())
              .on_transition(TouchTimestampAction())
              .build())
    """

    def __init__(self):
        self._transitions = TransitionTable()
        self._guards: Dict[str, List[TransitionGuard]] = {}
        self._actions: List[TransitionAction] = []
        self._last_from: str = ""

    def from_(self, state: str) -> "StateMachineBuilder":
        self._last_from = state
        return self

    def from_any(self) -> "StateMachineBuilder":
        self._last_from = "*"
        return self

    def to(self, state: str) -> "StateMachineBuilder":
        self._transitions.allow(self._last_from, state)
        return self

    def guard(self, transition: str, guard: TransitionGuard) -> "StateMachineBuilder":
        if transition not in self._guards:
            self._guards[transition] = []
        self._guards[transition].append(guard)
        return self

    def on_transition(self, action: TransitionAction) -> "StateMachineBuilder":
        self._actions.append(action)
        return self

    def build(self) -> TaskStateMachine:
        return TaskStateMachine(self._transitions, self._guards, self._actions)
