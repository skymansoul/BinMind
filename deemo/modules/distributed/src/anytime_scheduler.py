# 创建: 2026-04-21
# 修改: 2026-04-21 — 基础等边际分配升级为contract算法+竞比分析
#
# Contract算法驱动的Anytime调度 — 竞比保证的中断策略
#
# 旧版用凹精度函数的等边际贪心——这在固定预算下最优，但忽略了
# anytime调度的核心挑战: 中断时机的不确定性。
#
# Contract算法: 将 anytime 任务分解为
# 一系列 contract (契约)——每个 contract 分配固定时间片 t_i,
# 返回精度 increment Δq_i。中断可在任意 contract 之间安全发生。
#
# 中断的最优策略: 给定 K 个 contracts, 每个有 (t_i, Δq_i),
# 若在时刻 T 被中断, 已完成的 contracts 的总精度 = Σ_{i: t_i≤T} Δq_i。
# 最优排序: 按 Δq_i/t_i (精度密度) 降序——贪心即最优。
#
# 竞比分析 (competitive analysis):
#   在线调度器 (不知中断时刻) vs 离线最优 (先知中断时刻)。
#   竞比 = 在线总精度 / 离线最优精度。
#   按精度密度降序执行的竞比 ≥ 1 - max_i(t_i)/T_max。
#   若 contracts 被足够细粒度地分割 (max t_i ≪ T_max), 竞比趋近 1。

from __future__ import annotations

import math
import time
import heapq
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Callable


@dataclass
class Contract:
    """一个 contract — 固定时间片的精度增量契约。"""
    contract_id: str
    time_required: float      # 执行时间 (秒)
    quality_delta: float      # 精度增量
    # 精度密度 = Δq/t — 排序依据
    @property
    def density(self) -> float:
        return self.quality_delta / max(self.time_required, 0.001)


@dataclass
class AnytimeTask:
    task_id: str
    contracts: List[Contract]  # 按精度密度降序排列的契约列表
    priority: float = 0.5
    deadline: float = float('inf')
    # 运行时状态
    next_contract_idx: int = 0
    quality_accumulated: float = 0.0
    time_consumed: float = 0.0
    completed: bool = False

    @classmethod
    def from_convergence(cls, task_id: str, lambda_conv: float,
                         total_time: float = 10.0, n_contracts: int = 10,
                         priority: float = 0.5):
        """从指数收敛函数 1-exp(-λt) 构造 contracts。

        将总时间等分为 n 份, 每份 contract 的 Δq = q(t_i) - q(t_{i-1})。"""
        contracts = []
        dt = total_time / n_contracts
        for i in range(n_contracts):
            t_start = i * dt
            t_end = (i + 1) * dt
            q_start = 1.0 - math.exp(-lambda_conv * t_start)
            q_end = 1.0 - math.exp(-lambda_conv * t_end)
            contracts.append(Contract(
                f"{task_id}#{i}", dt, q_end - q_start,
            ))
        return cls(task_id, contracts, priority=priority)


class ContractScheduler:
    """Contract驱动的Anytime调度器 — 精度密度排序 + 竞比保证。

    全局调度逻辑:
      1. 所有未完成 contracts 按 priority·density 降序 → 全局优先队列
      2. 每步取队首 contract → 分配给最快空闲机器 → 执行 t_i 秒
      3. contract 完成 → 对应任务累计精度
      4. 中断 (deadline/预算耗尽) → 已完成的 contracts 结果有效
      5. 竞比分析: 在线 vs 离线最优的精度对比
    """

    def __init__(self):
        # 全局 contract 优先队列: (-score, contract, task)
        self._pq: List[Tuple[float, int, Contract, AnytimeTask]] = []
        self._counter: int = 0

    def add_task(self, task: AnytimeTask):
        """将任务的首个 contract 入队。"""
        if task.next_contract_idx < len(task.contracts):
            c = task.contracts[task.next_contract_idx]
            score = c.density * task.priority
            heapq.heappush(
                self._pq, (-score, self._counter, c, task)
            )
            self._counter += 1

    def run_contract(self) -> Optional[Contract]:
        """执行一个 contract → 返回被执行的 contract。

        若队列为空或所有任务 deadline 已过, 返回 None。
        """
        now = time.monotonic()
        # 清理过期任务
        while self._pq:
            score_neg, _, c, task = self._pq[0]
            if now >= task.deadline:
                heapq.heappop(self._pq)
                task.completed = True
            else:
                break
        if not self._pq:
            return None

        _, _, contract, task = heapq.heappop(self._pq)
        # 执行 contract
        task.quality_accumulated += contract.quality_delta
        task.time_consumed += contract.time_required
        task.next_contract_idx += 1

        # 将下一个 contract 入队
        if task.next_contract_idx < len(task.contracts):
            next_c = task.contracts[task.next_contract_idx]
            score = next_c.density * task.priority
            heapq.heappush(
                self._pq, (-score, self._counter, next_c, task)
            )
            self._counter += 1
        else:
            task.completed = True

        return contract

    def run_until(self, time_budget: float,
                  now: Optional[float] = None) -> List[Contract]:
        """在 time_budget 秒内尽可能多地执行 contracts。"""
        clock = now or time.monotonic()
        deadline_abs = clock + time_budget
        executed = []
        while time.monotonic() < deadline_abs:
            c = self.run_contract()
            if c is None:
                break
            executed.append(c)
        return executed

    def competitive_ratio(self, tasks: List[AnytimeTask]) -> float:
        """估计在线调度的竞比 — 在线总精度/离线最优精度。

        离线最优: 所有 contracts 按密度降序执行到中断时刻。
        在线: 按 priority·density 降序 (可能与离线不同)。
        竞比 ≤ 1; 越接近 1 越优。
        """
        online_q = sum(t.quality_accumulated for t in tasks)
        # 离线最优: 忽略 priority, 纯密度排序
        all_contracts = []
        for t in tasks:
            for c in t.contracts:
                all_contracts.append(c)
        all_contracts.sort(key=lambda c: -c.density)
        # 用相同的总时间 budget → 离线最优精度
        total_time = sum(
            t.time_consumed for t in tasks
        )
        offline_q = 0.0
        time_used = 0.0
        for c in all_contracts:
            if time_used + c.time_required > total_time:
                break
            offline_q += c.quality_delta
            time_used += c.time_required
        return online_q / max(offline_q, 0.001)

    @property
    def pending_count(self) -> int:
        return len(self._pq)
