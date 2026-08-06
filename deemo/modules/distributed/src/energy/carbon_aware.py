# 修改记录:
# 2025-08-05 15:42 - 初始实现：碳感知调度——延迟容忍任务向低碳时段迁移

"""碳感知分布式调度 — 基于电网碳强度的延迟容忍任务时移调度。

分布式二进制分析任务具备天然的延迟容忍度差异：
- CI/CD安全扫描：严格延迟约束（≤5min）
- 每日批量分析：中等（≤2h）
- 深度审计/代码考古：高度可延迟（≤24h）

现有调度器（capacity_scheduler/oco_scheduler）仅优化吞吐量和延迟，
完全忽略能耗与碳排放。lyapunov_carbon 面向数据中心总能耗优化，
但不感知电网实时碳排放强度（gCO₂/kWh）。

本模块的方案——碳感知延迟容忍调度：
1. 为每个任务标注延迟容忍度等级（strict / moderate / flexible）。
2. 实时获取电网碳强度信号（来自 ElectricityMaps/WattTime API）。
3. strict任务立即调度；flexible任务进入推迟队列——等待低碳窗口。
4. 当碳强度低于24h均值的70%时→释放推迟队列中的flexible任务。
5. Lyapunov优化保证：推迟队列长度有界（≤Q_max），避免无限积压。

关键创新——碳信号+延迟容忍的联合优化：
不同于简单"关掉非必要负载"（数据中心常见策略），
本方案利用二进制分析管道中各阶段的天然延迟差异，
在不影响业务SLA的前提下将flexible负载时移至低碳窗口。

参考：
- "Carbon-Aware Computing" (Google 2022): 数据中心碳感知负载转移。
- Lyapunov优化在排队系统中的应用 (Neely 2010)。
"""

import math
import time as _time_module
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

_EPS: float = 1e-9


class DelayTolerance(Enum):
    STRICT = "strict"        # ≤5min，不可推迟
    MODERATE = "moderate"    # ≤2h，可推迟到低碳窗口
    FLEXIBLE = "flexible"    # ≤24h，高度可推迟


@dataclass
class CarbonTask:
    """一个标注了碳感知属性的任务。"""
    task_id: str
    tolerance: DelayTolerance
    estimated_energy_kwh: float  # 估计能耗
    arrival_time: float
    deadline: float  # 绝对截止时间戳
    priority: int = 0  # 在推迟队列中的优先级

    @property
    def slack_seconds(self) -> float:
        """剩余可推迟时间。"""
        return max(0.0, self.deadline - self.arrival_time)


@dataclass
class CarbonSignal:
    """电网碳强度信号。"""
    timestamp: float
    carbon_intensity: float       # gCO₂/kWh
    rolling_24h_mean: float
    is_low_carbon: bool


class CarbonAwareScheduler:
    """碳感知分布式任务调度器。

    使用范式：
      scheduler = CarbonAwareScheduler(max_queue=100)
      scheduler.update_carbon_signal(intensity=350.0)
      scheduler.submit(CarbonTask("t1", DelayTolerance.FLEXIBLE, 0.5, now, now+3600))
      dispatch_list = scheduler.dispatch()
    """

    def __init__(
        self,
        max_queue: int = 100,
        carbon_ratio_threshold: float = 0.7,
        urgency_factor: float = 0.3,
    ):
        """
        max_queue: 推迟队列最大容量（Lyapunov界的Q_max）。
        carbon_ratio_threshold: 碳强度低于均值的比例→释放推迟任务。
        urgency_factor: 紧急度权重——截止时间越近，优先级越高。
        """
        self.max_queue = max_queue
        self.carbon_ratio_threshold = carbon_ratio_threshold
        self.urgency_factor = urgency_factor

        # 当前碳信号
        self._carbon_signal: Optional[CarbonSignal] = None
        self._carbon_history: deque = deque(maxlen=288)  # 24h * 12 samples/h

        # 推迟队列——按优先级排序
        self._deferred: List[CarbonTask] = []

        # 统计
        self._total_deferred: int = 0
        self._total_dispatched: int = 0
        self._estimated_carbon_saved: float = 0.0  # kgCO₂

    def update_carbon_signal(self, intensity: float, timestamp: Optional[float] = None):
        """更新电网碳强度信号。"""
        _ts = timestamp or _time_module.time()
        self._carbon_history.append((_ts, intensity))

        _rolling_mean = (
            sum(c for _, c in self._carbon_history) / max(len(self._carbon_history), 1)
            if self._carbon_history else intensity
        )
        _is_low = intensity < _rolling_mean * self.carbon_ratio_threshold

        self._carbon_signal = CarbonSignal(
            timestamp=_ts,
            carbon_intensity=intensity,
            rolling_24h_mean=_rolling_mean,
            is_low_carbon=_is_low,
        )

    def submit(self, task: CarbonTask):
        """提交一个碳感知任务。"""
        if task.tolerance == DelayTolerance.STRICT:
            # 严格任务——立即分发，不入推迟队列
            self._total_dispatched += 1
            return

        if len(self._deferred) >= self.max_queue:
            # 队列满→强制分发最早的任务（Lyapunov界约束）
            self._deferred.sort(key=self._task_priority, reverse=True)
            _oldest = self._deferred.pop(0)
            self._total_dispatched += 1

        self._deferred.append(task)
        self._total_deferred += 1

    def dispatch(self) -> List[str]:
        """返回当前应分发的任务ID列表。

        分发条件按优先级降序：
        1. 低碳窗口→分发flexible+moderate
        2. 任务超过slack的一半→紧急分发（避免错过deadline）
        3. 碳信号高→仅分发moderate（flexible继续等待）
        """
        _to_dispatch: List[str] = []
        _now = _time_module.time()

        _remaining: List[CarbonTask] = []

        for _task in self._deferred:
            _slack_used = _now - _task.arrival_time
            _slack_total = _task.slack_seconds
            _urgency = _slack_used / max(_slack_total, 1) if _slack_total > 0 else 1.0

            _should_dispatch = False

            # 紧急：slack用了超过一半→必须分发
            if _urgency > 0.5:
                _should_dispatch = True
            # 低碳窗口→分发
            elif self._carbon_signal and self._carbon_signal.is_low_carbon:
                _should_dispatch = True
            # moderate任务可在正常碳强度时分发
            elif _task.tolerance == DelayTolerance.MODERATE and _urgency > 0.2:
                _should_dispatch = True

            if _should_dispatch:
                _to_dispatch.append(_task.task_id)
                self._total_dispatched += 1
                # 估算碳节省（相比在高峰时段的排放）
                if self._carbon_signal:
                    _carbon_saved = (
                        _task.estimated_energy_kwh
                        * (self._carbon_signal.rolling_24h_mean
                           - self._carbon_signal.carbon_intensity)
                        / 1000.0  # g→kg
                    )
                    self._estimated_carbon_saved += max(0.0, _carbon_saved)
            else:
                _remaining.append(_task)

        self._deferred = _remaining
        return _to_dispatch

    def get_carbon_savings(self) -> Dict[str, float]:
        """返回碳排放节省统计。"""
        return {
            "estimated_kg_co2_saved": round(self._estimated_carbon_saved, 3),
            "total_deferred_tasks": self._total_deferred,
            "total_dispatched_tasks": self._total_dispatched,
            "current_queue_depth": len(self._deferred),
            "current_carbon_intensity": (
                self._carbon_signal.carbon_intensity if self._carbon_signal else 0.0
            ),
        }

    def _task_priority(self, task: CarbonTask) -> float:
        """计算推迟队列中的任务优先级。"""
        _now = _time_module.time()
        _slack_total = task.slack_seconds
        if _slack_total <= 0:
            return 1.0
        _slack_used = _now - task.arrival_time
        return min(1.0, _slack_used / _slack_total * self.urgency_factor + 0.1)


# ---- 冒烟测试 ----
def _smoke_test():
    import time
    _scheduler = CarbonAwareScheduler(max_queue=20)
    _now = time.time()

    # 高峰碳强度（600 gCO₂/kWh）
    _scheduler.update_carbon_signal(600.0, _now)
    _scheduler.submit(CarbonTask("t_flex_1", DelayTolerance.FLEXIBLE, 0.3, _now, _now + 7200))
    _scheduler.submit(CarbonTask("t_mod_1", DelayTolerance.MODERATE, 0.5, _now, _now + 1800))
    _scheduler.submit(CarbonTask("t_strict", DelayTolerance.STRICT, 0.1, _now, _now + 300))

    # 高碳→推迟灵活任务
    _d1 = _scheduler.dispatch()
    print(f"[carbon] peak dispatch: {_d1}")

    # 低碳窗口（200 gCO₂/kWh）
    _scheduler.update_carbon_signal(200.0, _now + 600)
    _d2 = _scheduler.dispatch()
    print(f"[carbon] low-carbon dispatch: {_d2}")

    _savings = _scheduler.get_carbon_savings()
    print(f"[carbon] savings: {_savings}")

    # 低碳窗口应释放推迟的flexible任务
    assert len(_d2) >= 1, "low-carbon window should dispatch deferred tasks"
    print("[OK] CarbonAwareScheduler smoke test passed.")


if __name__ == "__main__":
    _smoke_test()
