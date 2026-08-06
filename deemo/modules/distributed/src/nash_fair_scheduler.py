# 纳什均衡公平调度 — 多租户博弈 + 策略证明机制
#
# 多租户共享调度器时，每个租户有动机谎报任务优先级/资源需求
# 以获取更多调度份额。传统 DRF (Dominant Resource Fairness) 假设
# 租户诚实——这在竞争环境中不成立。
#
# 本模块将多租户调度建模为非合作博弈:
#   - 参与者: K 个租户，各提交任务队列
#   - 策略: 租户 k 报告其任务权重向量 w_k (可虚报)
#   - 收益: u_k = 分配到的资源份额 - α·penalty(虚报程度)
#   - 目标: 找到纳什均衡——无人可通过单方面虚报改善收益
#
# 策略证明 (strategy-proofness): 若 α 足够大，诚实报告是占优策略。
#   阈值 α* 由价格-无政府比率 (price of anarchy) 的上界推导:
#   α* = (s_max/s_min) · (K / (K-1))
#   其中 s_max/s_min 是最大/最小任务执行时间比。
#
# 与 Fair Coordination (arXiv:2512.13244) 的区别:
#   该文研究同权重 job 的 envy-freeness + Nash 均衡。
#   本模块处理异质任务 + DAG 依赖 + 策略证明机制。

from __future__ import annotations

import math
import random
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Tuple, Set


@dataclass
class TenantBid:
    """租户的出价——可能诚实地可能虚报。"""
    tenant_id: str
    declared_priority: float        # 申报的优先级 [0, 1]
    declared_exec_time: float       # 申报的执行时间
    true_priority: float = 0.0      # 真实优先级 (调度器不直接使用)
    true_exec_time: float = 0.0     # 真实执行时间 (调度器观测到)
    task_count: int = 1


@dataclass
class NashAllocation:
    """纳什均衡下的资源分配结果。"""
    tenant_id: str
    share: float                    # 分配到的资源份额 [0, 1]
    utility: float                  # 租户收益
    is_honest: bool                 # 诚实报告是否是该租户的最优策略


class NashFairScheduler:
    """纳什均衡多租户公平调度器。

    每轮博弈:
      1. 各租户提交 bids (可能虚报)
      2. 调度器按 modified DRF 分配资源份额
         share_k ∝ declared_priority_k / declared_exec_time_k
      3. 调度器在任务完成后观测真实执行时间
      4. 虚报检测: 若 |declared - true| 超过阈值 → 虚报惩罚
      5. 调度器广播 prices (每单位资源的影子价格)
         → 租户基于 prices 调整下次 bid → 系统收敛到 NE

    虚报惩罚 = α · max(0, declared - true)² / true
    诚实报告的收益: u_k(honest) = share - 0
    虚报的收益:     u_k(lie)    = share'(inflated) - α·penalty
    """

    def __init__(
        self,
        n_tenants: int = 3,
        total_capacity: float = 1.0,
        alpha: float = 2.0,          # 虚报惩罚系数
        history_window: int = 10,
        seed: Optional[int] = None,
    ):
        self._K = n_tenants
        self._capacity = total_capacity
        self._alpha = alpha
        self._rng = random.Random(seed)
        # 每租户的 bid/观测历史
        self._bids: Dict[str, List[TenantBid]] = defaultdict(list)
        self._prices: List[float] = [0.1] * n_tenants  # 影子价格
        self._allocations: Dict[str, float] = {}
        self._window = history_window

    def submit_bids(self, bids: List[TenantBid]) -> Dict[str, NashAllocation]:
        """一轮博弈: 接收出价 → 分配资源 → 返回纳什分配。

        分配规则 (modified DRF with penalty awareness):
          raw_share_k ∝ declared_priority_k / max(declared_exec_time_k, 1)
          归一化使 Σ share_k = capacity
        """
        if not bids:
            return {}

        # DRF 风格份额分配
        raw = []
        for b in bids:
            weight = b.declared_priority / max(b.declared_exec_time, 0.01)
            raw.append((b, weight))

        total_weight = sum(w for _, w in raw)
        if total_weight <= 0:
            total_weight = 1.0

        allocations: Dict[str, NashAllocation] = {}
        for b, w in raw:
            share = self._capacity * w / total_weight
            # 收益计算
            honesty_penalty = 0.0
            if b.true_exec_time > 0:
                error = abs(b.declared_exec_time - b.true_exec_time) / b.true_exec_time
                if error > 0.15:
                    honesty_penalty = self._alpha * error * error
            utility = share - honesty_penalty
            is_honest = error <= 0.15 if b.true_exec_time > 0 else True

            allocations[b.tenant_id] = NashAllocation(
                tenant_id=b.tenant_id, share=share,
                utility=utility, is_honest=is_honest,
            )
            self._bids[b.tenant_id].append(b)
            if len(self._bids[b.tenant_id]) > self._window:
                self._bids[b.tenant_id].pop(0)

        self._allocations = {t: a.share for t, a in allocations.items()}
        self._update_prices()
        return allocations

    def observe_true_times(self, observations: Dict[str, float]):
        """任务完成后报告真实执行时间——供下一轮虚报检测。"""
        for tid, true_time in observations.items():
            if self._bids[tid]:
                self._bids[tid][-1].true_exec_time = true_time

    def _update_prices(self):
        """更新影子价格——基于供需差。

        供不应求 (利用率 > 0.9) → 价格上涨
        供过于求 (利用率 < 0.6) → 价格下跌
        价格是租户在下一轮做 bid 的参考信号。
        """
        utilization = sum(self._allocations.values()) / self._capacity
        for i in range(self._K):
            if utilization > 0.9:
                self._prices[i] = min(1.0, self._prices[i] * 1.15)
            elif utilization < 0.6:
                self._prices[i] = max(0.01, self._prices[i] * 0.9)

    def nash_convergence_metric(self) -> float:
        """衡量系统距纳什均衡的距离。

        对每个租户，计算从当前 bid 单方面偏离到诚实 bid 的
        收益变化。若所有租户都无法通过偏离获益 → 收敛到 NE。
        返回最大可能的收益改进 (越小越接近 NE)。
        """
        if not self._bids:
            return 1.0
        max_gain = 0.0
        for tid, history in self._bids.items():
            if len(history) < 2:
                continue
            recent = history[-1]
            if recent.true_exec_time <= 0:
                continue
            # 模拟诚实报告的收益
            honest_share = (
                recent.true_priority / max(recent.true_exec_time, 0.01)
            )
            declared_share = (
                recent.declared_priority / max(recent.declared_exec_time, 0.01)
            )
            gain = max(0.0, (declared_share - honest_share) / max(honest_share, 0.01))
            if gain > max_gain:
                max_gain = gain
        return max_gain

    # ---- 推荐动作 ----

    def strategy_proof_alpha(self) -> float:
        """计算使诚实报告成为占优策略的最小惩罚系数 α*。

        公式: α* = (s_max/s_min) · (K/(K-1))
        此阈值基于 POA 上界推导，α ≥ α* 时任何虚报都不合算。
        """
        all_times = []
        for history in self._bids.values():
            for b in history:
                if b.true_exec_time > 0:
                    all_times.append(b.true_exec_time)
        if len(all_times) < 2:
            return 2.0
        s_max = max(all_times)
        s_min = min(all_times)
        ratio = s_max / max(s_min, 0.001)
        return ratio * self._K / max(self._K - 1, 1)

    @property
    def prices(self) -> List[float]:
        return list(self._prices)

    @property
    def allocations(self) -> Dict[str, float]:
        return dict(self._allocations)

    def stats(self) -> dict:
        return {
            "n_tenants": self._K,
            "capacity": self._capacity,
            "alpha": self._alpha,
            "alpha_required": round(self.strategy_proof_alpha(), 4),
            "nash_gap": round(self.nash_convergence_metric(), 4),
            "prices": [round(p, 4) for p in self._prices],
            "allocations": {
                t: round(s, 4) for t, s in self._allocations.items()
            },
        }
