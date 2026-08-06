# 修改记录:
# 2025-08-05 13:02 - 密率递减调度: 合并密度随状态池增长而指数降低, 防止合并开销超过收益
# 2025-08-05 16:41 - 合并收益预估: Deltastates x avg_solver_time vs merge_overhead -> 收益为正才执行

"""符号状态合并决策 oracle - 基于 LSH 候选的精度感知合并策略

state_merge_lsh.py 提供 O(1) 的合并候选发现--但它不知道哪些候选
真正值得合并。不是所有 LSH 碰撞都意味着高相似度, 也不是所有相似状态
合并后都能带来性能收益

本模块的决策流水线:
  1. LSH 候选过滤: 只考虑至少 2 张哈希表碰撞的候选 (TF-IDF 风格去噪)
  2. 快速相似度验证: 对候选对计算 Jaccard 估计--< 0.5 的丢弃
  3. 合并收益预估: 预估合并后节省的求解时间 vs 合并本身的约束膨胀开销
  4. 合并密度调度: 状态池 < 100 -> 激进合并; 100-500 -> 中等; > 500 -> 保守
  5. 调用栈相容性: 不同调用栈的状态即使 PC 相同也不合并

合并精度控制:
  precision_loss = |dropped_constraints| / |total_constraints|
  若 > 0.3 -> 拒绝合并--损失的约束信息过多 (与 symbolic_path_merge.py 一致)

设计依据:
  合并收益 = avg_solver_time x merged_states - merge_cost
  merge_cost = constraint_union_time + expression_simplify_time
  当状态池超过 500 时, merge_cost 可能超过收益--此时降低合并密度
"""

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, FrozenSet, List, Optional, Set, Tuple

from .state_merge_lsh import (
    StateFingerprinter, MergeCandidateLSH, StateFingerprint,
)


# ---------------------------------------------------------------------------
# 合并候选评估
# ---------------------------------------------------------------------------

@dataclass
class MergeCandidate:
    """一对合并候选的评估信息"""
    state_a: int
    state_b: int
    jaccard_estimate: float          # 约束集的 Jaccard 相似度估计
    pc_match: bool                   # 两状态是否在同一程序点
    callstack_compatible: bool       # 调用栈是否相容
    precision_loss_estimate: float   # 预估精度损失
    merge_beneficial: bool           # 合并是否有利 (收益 > 成本)
    band_collisions: int = 0         # LSH band 碰撞数


class StateMergeOracle:
    """符号状态合并决策 oracle

    用法:
    oracle = StateMergeOracle()
    oracle.index_states(all_states)                   # 批量索引
    merge_plan = oracle.plan_merges(current_states)   # 获取合并计划
    # merge_plan: [(state_a_id, state_b_id, confidence), ...]
    """

    # 合并密度调度表: (状态数上限, 合并尝试率, 最小 Jaccard 阈值)
    _DENSITY_SCHEDULE = [
        (100,   0.30, 0.45),   # 小规模: 激进合并, 低阈值
        (300,   0.20, 0.55),   # 中等规模
        (500,   0.12, 0.60),   # 较大规模
        (float('inf'), 0.05, 0.70),  # 大规模: 保守合并, 高阈值
    ]

    def __init__(self):
        self._lsh = MergeCandidateLSH(num_bands=8, rows_per_band=16)
        self._fingerprinter = StateFingerprinter()
        self._fingerprints: Dict[int, StateFingerprint] = {}
        self._callstack_cache: Dict[int, int] = {}  # state_id -> callstack hash
        self._merge_count = 0
        self._reject_count = 0

    def index_states(self, states: List[Any]) -> None:
        """批量索引状态--提取指纹 + 插入 LSH"""
        for s in states:
            fp = self._fingerprinter.fingerprint(s)
            self._fingerprints[s.state_id] = fp
            self._callstack_cache[s.state_id] = hash(tuple(s.call_stack))
            self._lsh.insert(fp)

    def index_state(self, state: Any) -> None:
        """索引单个新状态 (fork 后调用)"""
        fp = self._fingerprinter.fingerprint(state)
        self._fingerprints[state.state_id] = fp
        self._callstack_cache[state.state_id] = hash(tuple(state.call_stack))
        self._lsh.insert(fp)

    def plan_merges(
        self,
        states: List[Any],
        avg_solver_time_ms: float = 50.0,
    ) -> List[Tuple[int, int, float]]:
        """为当前状态池生成合并计划

        states: 当前活跃状态列表
        avg_solver_time_ms: 平均每次求解的耗时 (毫秒)--用于收益预估

        返回: [(state_a_id, state_b_id, merge_confidence), ...]
        按 confidence 降序排列
        """
        n = len(states)
        if n < 10:
            return []

        # 选择合并密度参数
        attempt_rate, jaccard_threshold = self._select_density(n)
        max_attempts = max(1, int(n * attempt_rate))

        # 从 LSH 获取每状态的候选
        candidates: Dict[Tuple[int, int], MergeCandidate] = {}
        for s in states:
            fp = self._fingerprints.get(s.state_id)
            if fp is None:
                continue
            candidate_ids = self._lsh.query_candidates(fp)
            for other_id in candidate_ids:
                if other_id <= s.state_id:
                    continue  # 避免重复对
                pair = (s.state_id, other_id)
                if pair in candidates:
                    candidates[pair].band_collisions += 1
                else:
                    other_fp = self._fingerprints.get(other_id)
                    if other_fp is None:
                        continue
                    candidates[pair] = MergeCandidate(
                        state_a=s.state_id,
                        state_b=other_id,
                        jaccard_estimate=0.0,
                        pc_match=(fp.pc == other_fp.pc),
                        callstack_compatible=(
                            self._callstack_cache.get(s.state_id) ==
                            self._callstack_cache.get(other_id)
                        ),
                        precision_loss_estimate=0.0,
                        merge_beneficial=False,
                        band_collisions=1,
                    )

        # 多 band 碰撞过滤 (至少 2 band)
        viable = [
            (pair, c) for pair, c in candidates.items()
            if c.band_collisions >= 2
        ]
        # 限制尝试次数
        viable.sort(key=lambda x: -x[1].band_collisions)
        viable = viable[:max_attempts]

        # 对每候选计算 Jaccard 估计和精度损失
        merge_plan: List[Tuple[int, int, float]] = []
        for (a_id, b_id), candidate in viable:
            fp_a = self._fingerprints.get(a_id)
            fp_b = self._fingerprints.get(b_id)
            if fp_a is None or fp_b is None:
                continue

            # Jaccard 估计--基于约束类型直方图
            jaccard = self._estimate_jaccard(fp_a, fp_b)
            candidate.jaccard_estimate = jaccard

            if jaccard < jaccard_threshold:
                self._reject_count += 1
                continue

            # 调用栈相容性
            if not candidate.callstack_compatible:
                self._reject_count += 1
                continue

            # 精度损失预估
            candidate.precision_loss_estimate = self._estimate_precision_loss(
                fp_a, fp_b
            )
            if candidate.precision_loss_estimate > 0.30:
                self._reject_count += 1
                continue

            # 合并收益预估
            merge_cost = len(fp_a.constraint_type_histogram) * 0.5  # ms
            saved_solver_time = avg_solver_time_ms
            candidate.merge_beneficial = saved_solver_time > merge_cost

            if candidate.merge_beneficial:
                confidence = jaccard * (1.0 - candidate.precision_loss_estimate)
                merge_plan.append((a_id, b_id, confidence))
                self._merge_count += 1
            else:
                self._reject_count += 1

        merge_plan.sort(key=lambda x: -x[2])
        return merge_plan

    def on_state_merged(self, absorbed_id: int) -> None:
        """合并完成后--从索引中移除被吸收的状态"""
        self._lsh.remove(absorbed_id)
        self._fingerprints.pop(absorbed_id, None)
        self._callstack_cache.pop(absorbed_id, None)

    # ---- 内部方法 ----

    def _select_density(self, n_states: int) -> Tuple[float, float]:
        """根据状态池大小选择合并密度"""
        for limit, rate, threshold in self._DENSITY_SCHEDULE:
            if n_states <= limit:
                return rate, threshold
        return 0.05, 0.70

    @staticmethod
    def _estimate_jaccard(fp_a: StateFingerprint, fp_b: StateFingerprint) -> float:
        """基于约束类型直方图的 Jaccard 估计

        使用直方图交 (histogram intersection) 作为 Jaccard 的近似:
        Jaccard ≈ Σ min(h_a[i], h_b[i]) / Σ max(h_a[i], h_b[i])
        """
        sum_min = 0.0
        sum_max = 0.0
        for i in range(32):
            a = fp_a.constraint_type_histogram[i]
            b = fp_b.constraint_type_histogram[i]
            sum_min += min(a, b)
            sum_max += max(a, b)

        if sum_max < 1e-9:
            return 0.0
        return sum_min / sum_max

    @staticmethod
    def _estimate_precision_loss(
        fp_a: StateFingerprint, fp_b: StateFingerprint
    ) -> float:
        """预估合并精度损失--基于约束类型分布的差异

        分布差异大 -> 合并会丢失有区分度的约束 -> 精度损失大
        使用 1 - histogram_intersection 作为损失估计
        """
        intersection = 0.0
        total = 0.0
        for i in range(32):
            a = fp_a.constraint_type_histogram[i]
            b = fp_b.constraint_type_histogram[i]
            intersection += min(a, b)
            total += max(a, b)
        if total < 1e-9:
            return 0.0
        return 1.0 - (intersection / total)

    @property
    def stats(self) -> Dict[str, int]:
        return {
            'states_indexed': len(self._fingerprints),
            'merges_accepted': self._merge_count,
            'merges_rejected': self._reject_count,
            'lsh_tables': self._lsh._L,
        }
