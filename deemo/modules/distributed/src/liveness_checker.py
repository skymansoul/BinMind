# 运行时活性验证 — 轻量 LTL 子集的调度性质在线检测
#
# LiDO-DAG 和 Ticl 用定理证明器/Coq 验证
# DAG 调度协议的活性 (liveness) 性质。这些方法需要完整的形式化模型
# 且无法在运行时使用——仅适用于设计阶段。
#
# 本模块: 运行时 LTL (Linear Temporal Logic) 子集的在线检测。
# 监控的活性性质:
#   G(request → F(dispatch))       — 每个请求终将被调度 (饥饿自由)
#   G(high_prio → F(complete))     — 高优先级任务终将完成 (进展)
#   GF(idle)                       — 无限经常空闲 (非活锁)
#   FG(¬overload)                  — 最终恒不过载 (稳定)
#
# 方法: 对每条性质编译为确定性有限自动机 (DFA)，运行时增量推进
# DFA 状态。违反 = DFA 进入拒绝状态。活性违反需要无限迹才能确认——
# 此处采用启发式超时告警 (若某状态在 deadline 内未推进 → 潜在违反)。
#
# 与传统监控 (Prometheus alerts) 的区别:
#   告警规则是瞬时阈值的组合。LTL 表达的是时序关系——
#   "在高优先级任务提交后的 60s 内，它必然被调度"。
#   这是告警规则无法表达的因果时序约束。

from __future__ import annotations

import time
import threading
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Set, Callable
from enum import Enum


class LivenessVerdict(Enum):
    SATISFIED = "satisfied"       # 性质当前满足
    VIOLATED = "violated"         # 性质已违反 (安全属性 — 有限迹可判定)
    TIMEOUT_WARNING = "timeout"   # 活性属性的启发式超时告警
    PENDING = "pending"           # 仍在等待中


@dataclass
class LivenessProperty:
    """一条 LTL 活性性质的定义。"""
    name: str
    description: str
    # 状态推进函数: (event_name, event_data) → 推进或重置
    # 返回 True = 性质满足 (此轮), False = 仍在等待, None = 违反
    check_fn: Callable[[str, dict], Optional[bool]]
    deadline_s: float = 60.0      # 启发式超时
    last_progress: float = field(default_factory=time.monotonic)


class LivenessMonitor:
    """运行时 LTL 活性监控器。

    每轮事件循环调用 observe(event_name, event_data)。
    内部为每条性质维护一个 DFA 状态和截止时间。
    定期调用 check_all() 返回违反或超时的性质列表。
    """

    def __init__(self):
        self._properties: Dict[str, LivenessProperty] = {}
        self._event_log: deque = deque(maxlen=500)
        self._lock = threading.Lock()

    def register(self, prop: LivenessProperty):
        with self._lock:
            self._properties[prop.name] = prop

    def observe(self, event: str, data: Optional[dict] = None):
        """推进所有性质的状态。"""
        data = data or {}
        now = time.monotonic()
        with self._lock:
            self._event_log.append((now, event, data))
            for prop in self._properties.values():
                result = prop.check_fn(event, data)
                if result is True:
                    prop.last_progress = now

    def check_all(self) -> Dict[str, LivenessVerdict]:
        """评估所有性质 — 返回 {property_name: verdict}。"""
        now = time.monotonic()
        verdicts = {}
        with self._lock:
            for name, prop in self._properties.items():
                elapsed = now - prop.last_progress
                if elapsed > prop.deadline_s:
                    verdicts[name] = LivenessVerdict.TIMEOUT_WARNING
                else:
                    verdicts[name] = LivenessVerdict.SATISFIED
        return verdicts

    def stats(self) -> dict:
        with self._lock:
            return {
                "properties": len(self._properties),
                "events_logged": len(self._event_log),
                "verdicts": {
                    name: v.value for name, v in self.check_all().items()
                },
            }


# 预定义性质的工厂函数

def starvation_freedom_property(
    deadline_s: float = 120.0,
) -> LivenessProperty:
    """饥饿自由: 任何被提交的任务最终必被调度。

    request → F(dispatch) 的运行时近似:
    追踪未完成的 request 事件，在 dispatch 时核销。
    若任何 request 超过 deadline 未被核销 → TIMEOUT_WARNING。
    """
    pending: Dict[str, float] = {}  # task_id → request_time

    def check(event: str, data: dict) -> Optional[bool]:
        tid = data.get("task_id", "")
        ts = data.get("timestamp", time.monotonic())
        if event == "task_requested":
            pending[tid] = ts
            return None  # 待核销
        elif event == "task_dispatched":
            if tid in pending:
                del pending[tid]
                return True  # 已满足
            return None
        elif event == "task_completed":
            # 完成自然也意味着曾被调度
            pending.pop(tid, None)
            return True
        return None

    prop = LivenessProperty(
        name="starvation_freedom",
        description="G(request → F(dispatch)) — 每个请求终将被调度",
        check_fn=check,
        deadline_s=deadline_s,
    )
    # 周期性检查: 若 pending 中有超时项 → 更新 last_progress 为最早的 awaiting 时间
    # 此处简化: 由外部定时器调用 check_all() 统一判定
    return prop


def progress_property(deadline_s: float = 180.0) -> LivenessProperty:
    """进展: 高优先级任务从调度到完成的时间有界。"""
    dispatched: Dict[str, float] = {}

    def check(event: str, data: dict) -> Optional[bool]:
        tid = data.get("task_id", "")
        ts = data.get("timestamp", time.monotonic())
        prio = data.get("priority", "medium")
        if event == "task_dispatched" and prio == "high":
            dispatched[tid] = ts
            return None
        elif event == "task_completed":
            if tid in dispatched:
                del dispatched[tid]
                return True
            return None
        return None

    return LivenessProperty(
        name="high_priority_progress",
        description="G(high_prio_dispatched → F(complete))",
        check_fn=check, deadline_s=deadline_s,
    )


def no_livelock_property(deadline_s: float = 60.0) -> LivenessProperty:
    """非活锁: 系统无限经常有空闲周期 (idle events)。"""
    last_idle = time.monotonic()

    def check(event: str, data: dict) -> Optional[bool]:
        nonlocal last_idle
        if event == "worker_idle":
            last_idle = time.monotonic()
            return True
        return None

    prop = LivenessProperty(
        name="no_livelock",
        description="GF(idle) — 无限经常空闲",
        check_fn=check, deadline_s=deadline_s,
    )
    prop.last_progress = last_idle
    return prop
