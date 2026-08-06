# 多目标Pareto最优能量调度器 — 平衡覆盖增长、崩溃发现和速度
#
# 核心问题:
#   power_schedule.py 用单目标能量分配——通常最大化覆盖率。
#   但fuzzing有三个竞争目标:
#     a) 覆盖增长 (探索新代码)
#     b) 崩溃发现 (发现漏洞)
#     c) 执行速度 (吞吐量)
#   三者之间存在Pareto trade-off: 复杂种子覆盖多但慢, 简单种子快但覆盖少。
#   单目标调度无法表达这种权衡。
#
# 本模块的方法 — Pareto前沿种子排序:
#   1. 每个种子有三个目标值: coverage_gain, crash_prob, exec_speed
#   2. 计算Pareto前沿: 不被任何其他种子在所有目标上同时超越的种子集合
#   3. 对前沿上的种子分配更高能量 (它们是"非支配的", 代表最佳权衡)
#   4. 用户可通过权重向量表达偏好: [w_cov, w_crash, w_speed]
#
# 参考文献:
#   Deb et al. 2002, "A Fast and Elitist Multiobjective Genetic Algorithm:
#     NSGA-II", IEEE Trans. Evolutionary Computation 6(2):182-197
#     — 非支配排序+拥挤距离的经典算法, 本模块的Pareto层计算基于此
#   Pareto 1896, "Cours d'Économie Politique" — Pareto最优的原始定义

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class SeedObjectives:
    """单个种子的三个目标值"""
    seed_id: str
    # 三个目标 (均为越大越好)
    coverage_gain: float = 0.0     # 本种子历史新边发现率 [0, 1]
    crash_prob: float = 0.0        # 本种子产生崩溃的概率估计 [0, 1]
    exec_speed: float = 0.0        # 归一化执行速度 (越快越好) [0, 1]
    # Pareto层: 0=前沿, 1=第二层, ...
    pareto_rank: int = 0
    # 拥挤距离 (同一Pareto层内的多样性度量)
    crowding_distance: float = 0.0
    # 最终能量
    energy: float = 1.0


@dataclass
class ParetoSchedule:
    """Pareto调度的输出"""
    ranked_seeds: List[Tuple[str, float, int]]  # (seed_id, energy, rank)
    pareto_front_size: int
    total_seeds: int
    summary: str = ""


class ParetoPowerScheduler:
    """多目标Pareto最优能量调度器。

    典型用法:
        scheduler = ParetoPowerScheduler(weights=[0.5, 0.3, 0.2])
        # 每轮更新种子目标值:
        scheduler.update_seed('s1', cov_gain=0.8, crash_p=0.1, speed=0.9)
        # 调度:
        schedule = scheduler.schedule()
    """

    def __init__(self, weights: Optional[List[float]] = None,
                  min_energy: float = 0.1, max_energy: float = 10.0):
        """
        weights: [coverage_weight, crash_weight, speed_weight] 默认均衡
        """
        self._weights = weights or [0.4, 0.35, 0.25]
        self._min_e = min_energy
        self._max_e = max_energy
        self._seeds: Dict[str, SeedObjectives] = {}

    def update_seed(self, seed_id: str,
                     coverage_gain: float = 0.0,
                     crash_prob: float = 0.0,
                     exec_speed: float = 0.0) -> None:
        """更新或注册种子的三目标值"""
        so = self._seeds.get(seed_id)
        if so is None:
            so = SeedObjectives(seed_id=seed_id)
            self._seeds[seed_id] = so
        so.coverage_gain = coverage_gain
        so.crash_prob = crash_prob
        so.exec_speed = exec_speed

    def schedule(self) -> ParetoSchedule:
        """主入口: 计算Pareto前沿并分配能量"""
        seeds = list(self._seeds.values())
        if not seeds:
            return ParetoSchedule([], 0, 0, "无种子")

        # Step 1: 非支配排序 (Pareto ranking)
        ranks = self._non_dominated_sort(seeds)
        for seed, rank in zip(seeds, ranks):
            seed.pareto_rank = rank

        # Step 2: 计算每个Pareto层内的拥挤距离
        fronts = self._group_by_rank(seeds)
        for rank, front in fronts.items():
            self._compute_crowding_distance(front)

        # Step 3: 分配能量——前沿种子高能量, 深层种子低能量
        max_rank = max(ranks) if ranks else 1
        for seed in seeds:
            rank_factor = 1.0 / (1.0 + seed.pareto_rank)
            crowd_bonus = min(0.3, seed.crowding_distance * 0.1)
            weighted = (
                self._weights[0] * seed.coverage_gain
                + self._weights[1] * seed.crash_prob
                + self._weights[2] * seed.exec_speed
            )
            seed.energy = self._min_e + (
                self._max_e - self._min_e) * (rank_factor + crowd_bonus) * weighted

        # 排序输出
        ranked = sorted(
            [(s.seed_id, s.energy, s.pareto_rank) for s in seeds],
            key=lambda x: (x[2], -x[1]))  # 按rank升序, 同rank按energy降序

        front_size = len(fronts.get(0, []))
        return ParetoSchedule(
            ranked_seeds=ranked,
            pareto_front_size=front_size,
            total_seeds=len(seeds),
            summary=f"Pareto: {front_size}前沿, {len(seeds)}种子",
        )

    def _non_dominated_sort(self,
                             seeds: List[SeedObjectives]) -> List[int]:
        """非支配排序——返回每个种子的Pareto层号"""
        n = len(seeds)
        ranks = [0] * n
        dominated_count = [0] * n
        dominates = [[] for _ in range(n)]

        for i in range(n):
            for j in range(n):
                if i == j:
                    continue
                if self._dominates(seeds[i], seeds[j]):
                    dominates[i].append(j)
                elif self._dominates(seeds[j], seeds[i]):
                    dominated_count[i] += 1

        # 第0层: 未被任何其他种子支配的
        front = [i for i in range(n) if dominated_count[i] == 0]
        rank = 0
        while front:
            for i in front:
                ranks[i] = rank
            next_front = []
            for i in front:
                for j in dominates[i]:
                    dominated_count[j] -= 1
                    if dominated_count[j] == 0:
                        next_front.append(j)
            front = next_front
            rank += 1

        return ranks

    def _dominates(self, a: SeedObjectives, b: SeedObjectives) -> bool:
        """a支配b: a在所有目标上≥b, 且至少一个严格>"""
        a_vals = [a.coverage_gain, a.crash_prob, a.exec_speed]
        b_vals = [b.coverage_gain, b.crash_prob, b.exec_speed]
        all_ge = all(av >= bv for av, bv in zip(a_vals, b_vals))
        any_gt = any(av > bv for av, bv in zip(a_vals, b_vals))
        return all_ge and any_gt

    def _group_by_rank(self, seeds: List[SeedObjectives]
                        ) -> Dict[int, List[SeedObjectives]]:
        groups: Dict[int, List[SeedObjectives]] = {}
        for s in seeds:
            groups.setdefault(s.pareto_rank, []).append(s)
        return groups

    def _compute_crowding_distance(self,
                                     front: List[SeedObjectives]) -> None:
        """计算同一Pareto层内每个种子的拥挤距离"""
        m = len(front)
        if m <= 2:
            for s in front:
                s.crowding_distance = 1.0
            return
        for s in front:
            s.crowding_distance = 0.0

        for obj_idx in range(3):
            sorted_f = sorted(front, key=lambda s: [
                s.coverage_gain, s.crash_prob, s.exec_speed][obj_idx])
            obj_range = ([s.coverage_gain, s.crash_prob, s.exec_speed][obj_idx]
                          for s in sorted_f)
            min_v = sorted_f[0].coverage_gain if obj_idx == 0 else (
                sorted_f[0].crash_prob if obj_idx == 1 else sorted_f[0].exec_speed)
            max_v = sorted_f[-1].coverage_gain if obj_idx == 0 else (
                sorted_f[-1].crash_prob if obj_idx == 1 else sorted_f[-1].exec_speed)
            rng = max_v - min_v
            if rng < 1e-9:
                continue
            sorted_f[0].crowding_distance = float('inf')
            sorted_f[-1].crowding_distance = float('inf')
            for i in range(1, m - 1):
                prev_v = ([sorted_f[i-1].coverage_gain,
                           sorted_f[i-1].crash_prob,
                           sorted_f[i-1].exec_speed][obj_idx])
                next_v = ([sorted_f[i+1].coverage_gain,
                           sorted_f[i+1].crash_prob,
                           sorted_f[i+1].exec_speed][obj_idx])
                sorted_f[i].crowding_distance += (next_v - prev_v) / rng

    def stats(self) -> Dict[str, Any]:
        if not self._seeds:
            return {"seeds": 0}
        ranks = [s.pareto_rank for s in self._seeds.values()]
        return {
            "total_seeds": len(self._seeds),
            "pareto_front_size": sum(1 for r in ranks if r == 0),
            "max_rank": max(ranks),
            "weights": self._weights,
        }
