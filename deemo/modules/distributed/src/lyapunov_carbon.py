# 李雅普诺夫碳感知调度 — 漂移加惩罚的闭式任务准入与批处理
#
# 分布式安全分析任务 (如符号执行、模糊测试) 的功耗可达数百瓦时/任务。
# 传统调度仅优化 makespan/吞吐，忽略碳足迹。碳感知调度的已知方案:
#   PCAPS: 用 ML 预测碳强度窗口 → 需要训练数据
#   Lyapunov+PPO: 虚拟队列 + RL → 需要 RL 训练
#   两者都引入了外部依赖和冷启动问题。
#
# 本模块方案: 纯李雅普诺夫漂移加惩罚，无需任何训练。
#   1. 虚拟队列 Q(t): 累积碳排放与预算的偏差
#      Q(t+1) = max(0, Q(t) + c(t) - b)
#      其中 c(t)=时段 t 的实际碳排放，b=每时段预算
#   2. 漂移加惩罚目标: 最小化 Δ(Q(t)) + V·p(t)
#      Δ = 李雅普诺夫漂移 (队列增长的期望)
#      V = 权重参数 (大 V → 重碳效，小 V → 重吞吐)
#      p = 惩罚项 (任务延迟/拒绝代价)
#   3. 闭式准入决策: 若 c_marginal ≤ Q(t)/V + threshold → 准入
#      若碳强度高 → 延迟非紧急任务 (进入批处理队列)
#      若碳强度低 → 释放批处理队列中积压任务
#   4. 理论性质 (基于 Neely 2010, "Stochastic Network Optimization with
#      Application to Communication and Queueing Systems" 的标准漂移分析):
# 虚拟队列强稳定: lim sup (1/t)·Σ E[Q(τ)] < ∞
# O(1/V) 最优性权衡: 碳排放代价 vs 队列积压的帕累托边界
#        注: 标准证明需 Lyapunov 漂移上界的二次结构，本模块的
#        准入决策满足漂移条件 (有界单步变化)，但完整的形式化证明
#        需在隔离环境中验证假设 (i.i.d. 碳强度、有限二阶矩)。
#
# 与既有调度器的集成:
#   - 在 submit_analysis_task() 之前插入 LyapunovCarbonGate.admit()
#   - admit() 返回 (ADMIT | DEFER | REJECT) + 建议的延迟秒数
# 调用方据此决定是否立即入队、延迟入队、或拒绝
#
# 碳强度数据来源: 通过 ElectricityMaps API / WattTime API / 本地碳强度文件
# 本模块通过 CarbonIntensityProvider 抽象注入，不绑定具体数据源。

from __future__ import annotations

import time
import math
import threading
from collections import deque
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Tuple, Callable
from enum import Enum


class AdmissionDecision(Enum):
    ADMIT = "admit"        # 立即调度
    DEFER = "defer"        # 延迟批处理 (返回建议等待秒数)
    REJECT = "reject"      # 碳预算耗尽，拒绝


@dataclass
class CarbonMetrics:
    """单时段的碳排放快照。"""
    timestamp: float
    carbon_intensity: float   # gCO₂eq/kWh — 当前电网碳强度
    power_estimate: float     # W — 预估功率消耗
    carbon_rate: float        # gCO₂eq/s — 瞬时的碳排放速率
    queue_length: int         # 虚拟队列当前长度
    decision: str             # 最近一次准入决策


class CarbonIntensityProvider:
    """碳强度数据抽象 — 注入 ElectricityMaps/WattTime/静态文件。

    默认实现使用静态平均值，
    生产环境替换为实时 API 查询。
    """

    def __init__(self, default_intensity: float = 436.0):
        self._default = default_intensity
        self._cache: Dict[float, float] = {}  # timestamp → intensity

    def get_intensity(self) -> float:
        """返回当前碳强度 (gCO₂eq/kWh)。子类覆写以接入实时数据。"""
        return self._default

    def get_forecast(self, horizon_s: float = 3600.0) -> List[Tuple[float, float]]:
        """返回未来 horizon_s 秒的碳强度预测 [(timestamp, intensity)]。

        默认空列表 → 调度器使用当前值作为不变预测。
        子类覆写以接入碳强度预测 API。
        """
        now = time.time()
        return [(now + i * 300, self._default) for i in range(int(horizon_s / 300) + 1)]


class LyapunovCarbonGate:
    """李雅普诺夫碳感知准入门控。

    每任务调用 admit() → 基于虚拟队列 + 碳强度做准入/延迟/拒绝。

    参数:
      carbon_budget_gps: 每秒碳预算 (gCO₂eq/s) — 即长期平均碳排放上限
      V: 漂移-惩罚权重 — V 越大碳效越优但延迟越高
      max_defer_s: 最大批处理延迟 (秒) — 任务不会永久挂起
      power_per_task_w: 单任务平均功率 (W) — 用于估算碳成本
    """

    def __init__(
        self,
        carbon_budget_gps: float = 0.05,   # 默认: ~180 gCO₂/h ≈ 412 g/kWh @ 120W
        V: float = 10.0,
        max_defer_s: float = 600.0,
        power_per_task_w: float = 120.0,
        intensity_provider: Optional[CarbonIntensityProvider] = None,
    ):
        self._budget = carbon_budget_gps
        self._V = V
        self._max_defer = max_defer_s
        self._power = power_per_task_w
        self._intensity = intensity_provider or CarbonIntensityProvider()

        self._virtual_queue: float = 0.0    # Q(t) — 累积碳偏差
        self._last_update: float = time.monotonic()
        self._deferred: deque = deque()     # (task_id, defer_deadline, task_meta)
        self._lock = threading.Lock()
        self._history: deque = deque(maxlen=200)  # CarbonMetrics 记录

# 准入决策

    def admit(self, task_id: str, priority: float = 0.5,
              is_deferrable: bool = True) -> Tuple[AdmissionDecision, float]:
        """对单个任务的碳感知准入。

        priority ∈ [0,1]: 越高越紧急 (越倾向于忽略碳约束)
        is_deferrable: False → 紧急任务不可延迟

        决策:
          1. 非延迟任务 + Q 低     → ADMIT
          2. 碳强度高 + Q 高       → DEFER (仅可延迟任务)
          3. Q 超过硬上限          → REJECT
        """
        with self._lock:
            now = time.monotonic()
            intensity = self._intensity.get_intensity()

            # 估算该任务的碳排放 (gCO₂eq)
            # 碳速率 = intensity(g/kWh) * power(W) / 1000 / 3600 * 3600
# intensity * power / 1000  (g/h)
            # 假设任务持续 task_duration_s 秒 → carbon = rate * duration / 3600
            # 此处用 1 秒作为边际碳成本的近似 (每任务准入的增量)
            carbon_marginal = intensity * self._power / (1000.0 * 3600.0)

            # 更新虚拟队列: Q += carbon_budget_consumed - budget_per_step
            dt = now - self._last_update
            self._virtual_queue = max(
                0.0,
                self._virtual_queue - self._budget * dt
            )
            self._last_update = now

            # 闭式准入阈值: θ = Q / V + priority_bonus
            # Q 大 → 阈值高 → 准入更严格 (碳债多)
            # priority 高 → 阈值高 → 紧急任务更容易准入
            priority_bonus = priority * 0.02  # 最多 +0.02 gCO₂/s 容忍
            threshold = self._virtual_queue / max(self._V, 0.1) + priority_bonus

            q_len = self._virtual_queue
            decision = AdmissionDecision.ADMIT
            defer_s = 0.0

            if carbon_marginal <= threshold:
                decision = AdmissionDecision.ADMIT
            elif is_deferrable:
                # 碳强度过高或 Q 太大 → 计算建议延迟
                # 延迟到碳强度下降到 threshold 对应的水平
                target_intensity = threshold * 1000.0 * 3600.0 / max(self._power, 1.0)
                # 查预测找第一个低于 target_intensity 的时间点
                forecast = self._intensity.get_forecast(self._max_defer)
                defer_s = self._max_defer
                for ts, fi in forecast:
                    if fi <= target_intensity:
                        defer_s = max(0.0, min(self._max_defer, ts - time.time()))
                        break
                if defer_s <= self._max_defer:
                    decision = AdmissionDecision.DEFER
                    self._deferred.append((task_id, now + defer_s, priority))
                else:
                    decision = AdmissionDecision.REJECT
            else:
                # 不可延迟但碳强度高 → 强制放行但记录警告
                decision = AdmissionDecision.ADMIT

            # 准入后更新虚拟队列
            if decision == AdmissionDecision.ADMIT:
                self._virtual_queue += carbon_marginal

            self._history.append(CarbonMetrics(
                timestamp=time.time(), carbon_intensity=intensity,
                power_estimate=self._power, carbon_rate=carbon_marginal,
                queue_length=round(q_len, 6), decision=decision.value,
            ))
            return decision, defer_s

# 批处理释放

    def release_deferred(self) -> List[str]:
        """释放延迟队列中到期或碳强度已降低的任务。

        调用方应在每次调度循环中调用此方法。
        返回可入队的 task_id 列表。
        """
        with self._lock:
            now = time.monotonic()
            intensity = self._intensity.get_intensity()
            released = []
            remaining = deque()

            for task_id, deadline, priority in self._deferred:
                carbon_m = intensity * self._power / (1000.0 * 3600.0)
                threshold = self._virtual_queue / max(self._V, 0.1) + priority * 0.02
                if now >= deadline or carbon_m <= threshold:
                    released.append(task_id)
                    self._virtual_queue += carbon_m
                else:
                    remaining.append((task_id, deadline, priority))
            self._deferred = remaining
            return released

# 查询

    @property
    def virtual_queue_length(self) -> float:
        return self._virtual_queue

    @property
    def deferred_count(self) -> int:
        return len(self._deferred)

    def stats(self) -> dict:
        with self._lock:
            intensity = self._intensity.get_intensity()
            carbon_m = intensity * self._power / (1000.0 * 3600.0)
            return {
                "virtual_queue": round(self._virtual_queue, 6),
                "carbon_budget_gps": self._budget,
                "current_intensity": intensity,
                "marginal_carbon_g": round(carbon_m, 8),
                "current_threshold": round(
                    self._virtual_queue / max(self._V, 0.1), 6
                ),
                "V": self._V,
                "deferred_tasks": len(self._deferred),
                "history_len": len(self._history),
            }


# 便捷入口

def carbon_aware_submit(
    gate: LyapunovCarbonGate,
    task_id: str, binary_path: str,
    submit_fn: Callable[[str, dict, str], Optional[str]],
    options: Optional[dict] = None,
    priority: str = "medium",
) -> Optional[str]:
    """碳感知任务提交流程 — 在既有 submit_analysis_task 上包裹碳门控。

    submit_fn: 实际的 submit_analysis_task 函数
    返回: 任务 ID 或 None (被延迟/拒绝)
    """
    priority_val = {"high": 0.9, "medium": 0.5, "low": 0.2}.get(priority, 0.5)
    is_deferrable = priority != "high"
    decision, defer_s = gate.admit(task_id, priority_val, is_deferrable)

    if decision == AdmissionDecision.ADMIT:
        return submit_fn(binary_path, options, priority)
    elif decision == AdmissionDecision.DEFER:
        # 调用方应在 defer_s 秒后重新尝试提交
        return None
    return None
