#
# 稀有度加权种子调度器 — 优先调度覆盖"全局稀有边"的种子。
#
# AFL 的种子调度基于执行速度和覆盖增长量——忽略了边的"全局稀有度"。
# 一条边若仅被 1-2 个种子覆盖，意味着该边对应的代码路径非常难以到达——
# 而往往正是这些难以到达的路径包含最多漏洞（输入校验后的核心逻辑）。
#
# 传统方案（AFLFast 的"低频路径优先"）仅考虑种子的局部覆盖数。
# 本模块在全局视角评估每条边的稀有度，将稀有边被覆盖的种子标记为高优先级。
#
# 稀有度定义: rarity(edge) = log2(total_execs / hit_count_of_edge)
# 若某条边在 10000 次执行中仅被命中 2 次，其稀有度 = log2(5000) ≈ 12.3。
# 若某条边被命中 8000 次，稀有度 = log2(1.25) ≈ 0.3。
#
# 种子的优先级 score = Σ rarity(edge) for each edge in seed's coverage

import math
from typing import Dict, List, Set, Tuple, Optional


class RarityWeightedScheduler:
    """基于边全局稀有度的种子调度器。

    维护 edge_id → hit_count 的全局映射。每次执行后更新命中计数。
    周期性（每 1000 次执行）重新计算各边的稀有度并更新种子优先级。
    """

    def __init__(self, recalc_interval: int = 1000):
        self._recalc_interval = recalc_interval
        self._edge_hits: Dict[int, int] = {}       # edge_id → 累计命中次数
        self._total_execs: int = 0
        self._edge_rarity: Dict[int, float] = {}     # edge_id → 稀有度分数
        self._seed_coverage: Dict[str, Set[int]] = {}  # seed_id → 覆盖的边集
        self._seed_priority: Dict[str, float] = {}     # seed_id → 优先级
        self._execs_since_recalc: int = 0

    def register_seed(self, seed_id: str, covered_edges: Set[int]):
        """注册一个新种子及其覆盖的边集。"""
        self._seed_coverage[seed_id] = covered_edges
        for e in covered_edges:
            self._edge_hits[e] = self._edge_hits.get(e, 0) + 1
        self._total_execs += 1
        self._execs_since_recalc += 1

    def update_from_execution(self, seed_id: str, new_edges: Set[int]):
        """种子执行后更新——记录新发现的边。

        此方法在 fuzzer 每轮执行后调用。若种子发现了新边，
        更新 edge_hits 并将新边加入该种子的覆盖集。
        """
        if seed_id not in self._seed_coverage:
            self._seed_coverage[seed_id] = set()

        for e in new_edges:
            if e not in self._seed_coverage[seed_id]:
                self._seed_coverage[seed_id].add(e)
            self._edge_hits[e] = self._edge_hits.get(e, 0) + 1

        self._total_execs += 1
        self._execs_since_recalc += 1

        if self._execs_since_recalc >= self._recalc_interval:
            self._recalculate_rarity()
            self._execs_since_recalc = 0

    def _recalculate_rarity(self):
        """重新计算所有边的稀有度分数和种子的优先级。

        稀有度 = log2(total / hit_count)。hit_count 最小为 1（避免除零）。
        """
        if self._total_execs == 0:
            return

        # 边稀有度
        self._edge_rarity.clear()
        for e, hits in self._edge_hits.items():
            if hits > 0:
                self._edge_rarity[e] = math.log2(self._total_execs / hits)

        # 全局稀有度阈值 —— P5 分位数
        # 稀有度低于此阈值的边视为"常见"，在种子评分中不贡献
        if len(self._edge_rarity) >= 20:
            sorted_rarity = sorted(self._edge_rarity.values())
            p5_idx = max(0, len(sorted_rarity) // 20)
            global_rarity_threshold = sorted_rarity[p5_idx]
        else:
            global_rarity_threshold = 2.0  # 回退值——种子太少时分位数无意义

        # 种子优先级
        self._seed_priority.clear()
        for sid, edges in self._seed_coverage.items():
            score = 0.0
            for e in edges:
                r = self._edge_rarity.get(e, 0.0)
                if r > global_rarity_threshold:
                    score += r  # 仅稀有边贡献——常见边不计入
            self._seed_priority[sid] = score

    def next_seed(self) -> Optional[str]:
        """返回优先级最高的种子 ID。

        平局时返回覆盖集较小的种子——节约执行时间。
        此分支待压测后确认是否需引入随机扰动以避免确定性循环。
        """
        if not self._seed_priority:
            return None

        # 按优先级降序，优先级相同则按覆盖集大小升序
        ranked = sorted(self._seed_priority.items(),
                        key=lambda x: (-x[1], len(self._seed_coverage.get(x[0], set()))))
        return ranked[0][0] if ranked else None

    def seed_stats(self) -> Dict:
        return {
            'total_execs': self._total_execs,
            'unique_edges': len(self._edge_hits),
            'registered_seeds': len(self._seed_coverage),
            'top_priority': round(max(self._seed_priority.values()) if self._seed_priority else 0, 2),
            'median_rarity': round(
                sorted(self._edge_rarity.values())[len(self._edge_rarity)//2]
                if self._edge_rarity else 0, 2),
        }
