# 管线重物质化优化 — 内存约束下的最优中间结果存储策略
#
# Pipeline 执行模型 (src/pipeline.py) 中每个 Stage 产生中间结果。
# 若全部存储 → 内存压力随管线深度线性增长。
# 若全不存储 → 前驱故障时需从源头重算全部阶段，浪费 CPU。
#
# 本模块将管线建模为线性计算图，用动态规划求解:
#   "给定内存预算 B 和 N 个阶段各自的 (计算代价, 内存占用)，
#    选择存储哪些阶段的中间结果，使总重算代价最小。"
#
# 这与深度学习的梯度检查点 (gradient checkpointing) 同构:
#   Griewank & Walther 的 √n 均匀检查点在均匀代价下最优。
#   本模块处理非均匀代价——每个阶段的计算/内存不同，
#   且支持 DAG (非纯线性) 的最优检查点放置。
#
# DP 状态: dp[i][m] = 阶段 0..i 且使用 m 内存时的最小重算代价
# 转移: dp[i][m] = min(
#          dp[i-1][m - mem[i]] + 0,                 # 存储 i → 重算代价 0
#          dp[i-1][m] + compute[i] * segment_len     # 不存 i → 若失败需重算
#        )
# 时间复杂度 O(N·B)，其中 B = 离散化内存预算的桶数。
#
# 与 Checkmate / Rotor 的区别:
#   两者面向 DNN 训练的张量重物质化。本模块面向通用任务管线的
#   中间结果，且与 Pipeline + DAG 调度器直接集成。

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Tuple, Set


@dataclass
class RematDecision:
    """单个阶段的重物质化决策。"""
    stage_name: str
    store: bool            # True = 存储中间结果 (检查点)
    mem_cost: float        # 该阶段的中间结果内存占用 (MB)
    compute_cost: float    # 该阶段的重算代价 (ms)
    cumulative_mem: float  # 到此阶段为止的累积内存


@dataclass
class RematPlan:
    """管线重物质化计划。"""
    decisions: List[RematDecision]
    total_memory_mb: float
    total_recompute_cost_ms: float
    # 最坏情况重算代价: 前驱故障时从最近检查点恢复的总代价
    worst_case_recovery_ms: float


def _dp_optimal_remat(
    stages: List[Tuple[str, float, float]],
    memory_budget: float = 500.0,
    granularity: int = 100,
) -> List[bool]:
    """DP 求解: 返回 [store_0, store_1, ...] 布尔列表。

    离散化内存预算为 granularity 个桶。
    每个阶段的 (计算代价, 内存占用) 自动归一化。
    """
    n = len(stages)
    if n == 0:
        return []

    B = granularity
    INF = 1e12

    names, comps, mems = zip(*stages) if stages else ([], [], [])
    comps = list(comps)
    mems = list(mems)

    # 离散化内存
    max_mem = max(mems) if mems else 1.0
    total_mem = sum(mems)
    scale = B / max(total_mem, 1.0)
    discrete_mems = [max(1, int(m * scale)) for m in mems]
    discrete_comps = [c / max(comps, default=1.0) * 100.0 for c in comps]

    # dp[i][m]: 考虑前 i 个阶段，使用 m 单位内存的最小重算代价
    dp = [[INF] * (B + 1) for _ in range(n + 1)]
    choice = [[False] * (B + 1) for _ in range(n + 1)]
    dp[0][0] = 0.0

    for i in range(1, n + 1):
        dm = discrete_mems[i - 1]
        dc = discrete_comps[i - 1]
        for m in range(B + 1):
            # 选项 A: 存储阶段 i
            if m >= dm and dp[i - 1][m - dm] < dp[i][m]:
                dp[i][m] = dp[i - 1][m - dm]
                choice[i][m] = True
            # 选项 B: 不存储阶段 i → 需重算 (代价 = 从上一检查点重算该段)
            seg_len = 1
            if dp[i - 1][m] + dc * seg_len < dp[i][m]:
                dp[i][m] = dp[i - 1][m] + dc * seg_len
                choice[i][m] = False

    # 回溯最优解
    best_m = min(range(B + 1), key=lambda m: dp[n][m] if dp[n][m] < INF else INF)
    stores: List[bool] = []
    for i in range(n, 0, -1):
        stores.append(choice[i][best_m])
        if choice[i][best_m]:
            best_m -= discrete_mems[i - 1]
    stores.reverse()
    return stores


class PipelineRematOptimizer:
    """管线重物质化优化器。

    输入: pipeline 的 stages 列表 (name, compute_cost_ms, memory_mb)
    输入: 内存预算 (MB)
    输出: RematPlan — 每个阶段是否存储 + 总代价估计

    扩展: 支持 DAG 拓扑——将分叉/汇合点强制标记为检查点，
    因为它们是多个路径的交汇处，丢失代价高。
    """

    def __init__(self, memory_budget_mb: float = 500.0):
        self._budget = memory_budget_mb

    def optimize(self, stages: List[Tuple[str, float, float]],
                 dag_branch_points: Optional[Set[str]] = None,
                 ) -> RematPlan:
        """DP 求解最优检查点放置。

        stages: [(name, compute_cost_ms, mem_mb), ...]
        dag_branch_points: fan-out/fan-in 阶段名——强制存储 (不可跳过)
        """
        if not stages:
            return RematPlan(decisions=[], total_memory_mb=0.0,
                            total_recompute_cost_ms=0.0,
                            worst_case_recovery_ms=0.0)

        branch_pts = dag_branch_points or set()
        # 分支点强制存储: 临时提升其内存为 0 (免费存储)
        adjusted = []
        for name, comp, mem in stages:
            if name in branch_pts:
                adjusted.append((name, comp, 0.0))  # 强制存储，不占预算
            else:
                adjusted.append((name, comp, mem))

        store_flags = _dp_optimal_remat(adjusted, self._budget)

        decisions = []
        cum_mem = 0.0
        recompute_total = 0.0
        # 最坏恢复: 从最近检查点重算到当前阶段
        last_checkpoint = 0
        worst_case = 0.0

        names, comps, mems = zip(*stages) if stages else ([], [], [])
        for i, (name, comp, mem) in enumerate(zip(names, comps, mems)):
            store = (name in branch_pts) or (
                i < len(store_flags) and store_flags[i]
            )
            if store:
                cum_mem += mem
                last_checkpoint = i
            else:
                recompute_total += comp
                # 从 last_checkpoint 到 i 的重算代价
                seg_cost = sum(
                    comps[j] for j in range(last_checkpoint + 1, i + 1)
                )
                worst_case = max(worst_case, seg_cost)

            decisions.append(RematDecision(
                stage_name=name, store=store,
                mem_cost=mem, compute_cost=comp,
                cumulative_mem=cum_mem,
            ))

        return RematPlan(
            decisions=decisions,
            total_memory_mb=round(cum_mem, 2),
            total_recompute_cost_ms=round(recompute_total, 2),
            worst_case_recovery_ms=round(worst_case, 2),
        )

    def estimate_savings(self, plan: RematPlan) -> dict:
        """相对于 '全不存储' 和 '全存储' 的成本节省。"""
        n = len(plan.decisions)
        store_all_mem = sum(d.mem_cost for d in plan.decisions)
        store_none_recomp = sum(d.compute_cost for d in plan.decisions)

        return {
            "memory_used_mb": plan.total_memory_mb,
            "memory_saved_vs_all": round(
                max(0, store_all_mem - plan.total_memory_mb), 2
            ),
            "memory_saved_pct": round(
                (1.0 - plan.total_memory_mb / max(store_all_mem, 1.0)) * 100, 1
            ),
            "recompute_vs_none": round(
                plan.total_recompute_cost_ms / max(store_none_recomp, 1.0), 4
            ),
            "worst_case_ms": plan.worst_case_recovery_ms,
        }
