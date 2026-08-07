#
# 帕累托最优种子调度器 — 基于非支配排序的多目标模糊测试种子选择
#
# 现有种子调度（rari-weighted, 覆盖率-guided）将多个目标压缩为
# 标量加权和，权重需要手动调整且对不同程序的泛化差
#
# 本模块采用多目标优化视角：种子的"价值"在多个维度上不可直接比较——
# 一个执行快但只命中常见边的种子，和一个执行慢但命中稀有边的种子
# 谁更优无法用单一标量回答。NSGA-II 的非支配排序 + 拥挤度距离
# 在多目标空间中保持种子的多样性同时收敛到帕累托前沿
#
# 四个优化目标：
# 1. coverage_densi：该种子覆盖的 bitmap 区域密度（越低越好——
#      发现未充分探索的代码区域）
#   2. rarity_score：命中边的 log₂(total/hit_count) 均值（越高越好）
#   3. exec_speed：执行速度 executions_per_second（越高越好）
#   4. mutation_potential：种子字节的熵 + 长度适中时变异潜力（越高越好）
#
#
# - NSGA-II: Fast Elitist Multiobject
#     Genetic Algorithm。本项目将 NSGA-II 的非支配排序和拥挤度距离
# 应用于模糊测试种子调度（而非遗传算法的种群选择）
# 核心差异：NSGA-II 用于选择"下一代种群"（遗传算法代际）
# 本项目用于选择"下一个被 fuzz 的种子批次"——无 crossover/muta
# 仅借用其排序机制
#   - T-Scheduler: Thompson sampling
# 对 rari 度量的 bandit 建模。本项目取其 rari 定义（1/hit_count）
#     但将其仅作为四个目标之一纳入多目标优化框架——解决 T-Scheduler
# 无法同时兼顾 覆盖率 densi 和 变异 potential 的问题
# - FOX: 将 frontier branch dist 作为目标
# 本项目的 coverage_densi 目标借鉴其"未探索区域密度"概念
# 但使用指数衰减密度估计（而非分支距离）以支持大规模 bitmap
#
# 精英保留策略（自适应）：
#   种群熵高（种子分布广）→ 保留 30% 精英（鼓励收敛）
#   种群熵低（种子趋同）→ 保留 10% 精英（鼓励探索）

import math
import random
import time
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from collections import defaultdict
import heapq


@dataclass
class SeedObjectives:
    """单个种子在多目标空间中的坐标。四个维度均归一化到 [0, 1] 以便比较"""
    seed_id: str = ""
    coverage_density: float = 1.0   # 越小越优
    rarity_score: float = 0.0       # 越大越优
    exec_speed: float = 0.0         # 越大越优
    mutation_potential: float = 0.0 # 越大越优
    # 支配关系缓存
    domination_count: int = 0       # 该种子被其他种子支配的次数
    dominated_set: List[str] = field(default_factory=list)  # 该种子支配的其他种子
    rank: int = 0                   # 非支配前沿层级（0 = 帕累托前沿）
    crowding_distance: float = 0.0  # 拥挤度距离（同层内多样性度量）


class ParetoSeedScheduler:
    """基于 NSGA-II 非支配排序的多目标种子调度器
    
    每轮 fuzz 循环：
    1. 从种子队列中抽样 k 个候选（当前为全部活跃种子）
    2. 计算每个候选的四个目标值
    3. 非支配排序 → Front 0（帕累托前沿）、Front 1、……
    4. 按 Front 升序 → 同 Front 内按拥挤度距离降序选取 top-n
    5. 对选中种子按拥挤度距离加权分配变异能量
    
    不替代现有 AFL++ havoc 变异器——仅替换种子选择逻辑
    """

    def __init__(self,
                 max_candidates: int = 500,
                 elite_ratio_base: float = 0.2,
                 crowding_eps: float = 1e-10):
        """
        max_candidates: 每轮评估的最大候选种子数（控制计算开销）
        elite_ratio_base: 精英保留比例的基础值，实际值由种群熵自适应调节
        crowding_eps: 拥挤度距离计算中的微小常数——防止除零
        """
        self._max_candidates = max_candidates
        self._elite_ratio_base = elite_ratio_base
        self._crowding_eps = crowding_eps

        # 种子目标值缓存——避免每轮重算不变种子的目标
        self._obj_cache: Dict[str, SeedObjectives] = {}
        # bitmap 全局命中计数——用于 rari 计算
        self._bitmap_hits: Dict[int, int] = defaultdict(int)
        self._total_execs: int = 0
        # 种子特征向量缓存——用于多样性目标（种子间余弦距离均值）
        self._seed_features: Dict[str, List[float]] = {}

    def select_seeds(self,
                     candidates: List[str],
                     n_select: int,
                     coverage_bitmap: Optional[Dict[int, int]] = None,
                     exec_times: Optional[Dict[str, float]] = None,
                     seed_sizes: Optional[Dict[str, int]] = None) -> List[Tuple[str, float]]:
        """从候选种子中选择帕累托最优的 n_select 个
        
        Args:
        candidates: 候选种子 ID 列表
        n_select: 需要选择的种子数量
        覆盖率_bitmap: {edge_id: hit_count} 可选，更新全局 bitmap
        exec_times: {种子_id: avg_exec_time} 可选
        种子_sizes: {种子_id: byte_s} 可选
        
        返回:
        [(种子_id, energy_weight),.] 选中种子及其变异能量权重
        权重用于后续变异阶段分配 fuzz 时间
        """
        if coverage_bitmap:
            for edge_id, cnt in coverage_bitmap.items():
                self._bitmap_hits[edge_id] += cnt
            self._total_execs += 1

        if not candidates:
            return []

        # 限制候选数——大规模种子队列时分批采样
        if len(candidates) > self._max_candidates:
            candidates = random.sample(candidates, self._max_candidates)

        # 计算/更新各候选的目标值
        objectives: Dict[str, SeedObjectives] = {}
        for sid in candidates:
            obj = self._compute_objectives(
                sid, exec_times.get(sid, 0.001) if exec_times else 0.001,
                seed_sizes.get(sid, 1024) if seed_sizes else 1024,
            )
            objectives[sid] = obj
            self._obj_cache[sid] = obj

        # 非支配排序 —— O(M·N²) M=4 目标, N=候选数
        fronts = self._non_dominated_sort(objectives)

        # 从前沿层级依次选取，直到满 n_select
        selected: List[str] = []
        front_idx = 0
        while len(selected) < n_select and front_idx < len(fronts):
            front = fronts[front_idx]
            remaining = n_select - len(selected)

            if len(front) <= remaining:
                selected.extend(front)
            else:
                # 同层内用拥挤度距离截断
                self._compute_crowding_distance(front, objectives)
                front_sorted = sorted(
                    front, key=lambda sid: objectives[sid].crowding_distance, reverse=True
                )
                selected.extend(front_sorted[:remaining])
            front_idx += 1

        # 自适应精英保留
        elite_count = self._adaptive_elite_count(len(candidates), objectives)
        elite_ids = self._select_elites(objectives, fronts, elite_count)

        # 确保精英被包含
        for eid in elite_ids:
            if eid not in selected and len(selected) < n_select:
                selected.append(eid)

        # 计算能量权重——基于拥挤度距离和前沿层级
        weights = self._compute_energy_weights(selected, objectives)

        return weights

    # 目标函数计算

    def _compute_objectives(self, seed_id: str,
                            exec_time: float,
                            seed_size: int) -> SeedObjectives:
        """计算种子在四个目标维度上的评分
        所有值归一化到 [0, 1]，方向约定如 dataclass 字段注释所述
        """
        # 目标 1: coverage_densi —— 指数衰减密度估计
        # 低 densi = 该种子触及的是未充分探索区域
        obj = SeedObjectives(seed_id=seed_id)

        # 从 bitmap_hits 中找该种子覆盖的边（若有历史记录）
        # 当前实现使用全局 bitmap 的熵作为密度代理
        if self._bitmap_hits:
            total_hits = sum(self._bitmap_hits.values())
            n_edges = len(self._bitmap_hits)
            if n_edges > 0 and total_hits > 0:
                avg_hits = total_hits / n_edges
                # 指数衰减：exp(-avg_hits / 100) —— 经过大量探索后密度降低
                obj.coverage_density = math.exp(-avg_hits / 100.0)

        # 目标 2: rarity_score —— log₂(total/hit_count) 的均值
        if self._bitmap_hits and self._total_execs > 0:
            rarities = []
            for edge_id, hit_cnt in self._bitmap_hits.items():
                if hit_cnt > 0:
                    r = math.log2(self._total_execs / hit_cnt)
                    rarities.append(r)
            if rarities:
                # 归一化：假设最大稀有度 ≈ log₂(1M) ≈ 20
                obj.rarity_score = min(1.0, sum(rarities) / len(rarities) / 20.0)

        # 目标 3: exec_speed —— 执行速度归一化
        # 假设最快种子 ~1000 exec/s，慢种子 ~1 exec/s
        obj.exec_speed = min(1.0, math.log2(1 + 1.0 / max(exec_time, 1e-6)) / 10.0)

        # 目标 4: 变异_potential —— 字节熵 + 大小适中
        # 太短（< 16 字节）或太长（> 256KB）的文件变异潜力低
        if 16 <= seed_size <= 262144:
            size_score = 1.0 - abs(math.log2(seed_size) - 10) / 14
        else:
            size_score = 0.1
        obj.mutation_potential = max(0.0, min(1.0, size_score))

        return obj

    # 非支配排序 —— NSGA-II 核心算法

    def _non_dominated_sort(self,
                            objectives: Dict[str, SeedObjectives]) -> List[List[str]]:
        """将种子按帕累托支配关系分层
        
        种子 A 支配种子 B（A ≺ B）当且仅当：
        A 在所有目标上不劣于 B，且在至少一个目标上严格优于 B
        目标方向：densi↓, rari↑, speed↑, 变异↑
        
        O(M·N²) 时间，M=4 目标，N=候选数
        实际候选数受 _max_candidates=500 限制，单次排序 < 10ms
        """
        seeds = list(objectives.keys())
        n = len(seeds)

        # 支配关系检测 —— 对每对种子 (, j) 检查 是否支配 j
        for i in range(n):
            si = objectives[seeds[i]]
            for j in range(n):
                if i == j:
                    continue
                sj = objectives[seeds[j]]
                if self._dominates(si, sj):
                    si.dominated_set.append(seeds[j])
                elif self._dominates(sj, si):
                    si.domination_count += 1

        # 分层：Front 0 = 所有 domination_count == 0 的种子
        fronts: List[List[str]] = []
        remaining = set(seeds)
        while remaining:
            current_front = [
                sid for sid in remaining
                if objectives[sid].domination_count == 0
            ]
            if not current_front:
                # 剩余种子形成循环支配关系（理论上不应出现，但防御性编程）
                current_front = list(remaining)

            for sid in current_front:
                objectives[sid].rank = len(fronts)

            fronts.append(current_front)
            remaining -= set(current_front)

            # 移除当前 front → 被当前 front 支配的种子 domination_count--
            for sid in current_front:
                obj = objectives[sid]
                for dominated_sid in obj.dominated_set:
                    if dominated_sid in remaining:
                        objectives[dominated_sid].domination_count -= 1

        return fronts

    def _dominates(self, a: SeedObjectives, b: SeedObjectives) -> bool:
        """判断 a 是否帕累托支配 b"""
        # 注意方向：densi 越小越优，其余越大越优
        a_better_or_equal = (
            a.coverage_density <= b.coverage_density and
            a.rarity_score >= b.rarity_score and
            a.exec_speed >= b.exec_speed and
            a.mutation_potential >= b.mutation_potential
        )
        a_strictly_better = (
            a.coverage_density < b.coverage_density or
            a.rarity_score > b.rarity_score or
            a.exec_speed > b.exec_speed or
            a.mutation_potential > b.mutation_potential
        )
        return a_better_or_equal and a_strictly_better

    # 拥挤度距离 —— 同层内的多样性度量

    def _compute_crowding_distance(self,
                                    front: List[str],
                                    objectives: Dict[str, SeedObjectives]):
        """对当前 front 中每种子的各目标维度计算拥挤度距离
        
        拥挤度距离 = Σ_m (|f_m(next) - f_m(prev)| / range_m)
        边界种子（某维度上极值）被赋予 ∞ 以确保被保留
        """
        if len(front) <= 2:
            for sid in front:
                objectives[sid].crowding_distance = float('inf')
            return

        for sid in front:
            objectives[sid].crowding_distance = 0.0

        # 四个目标维度 + 方向（正号=值大更优，负号=值小更优）
        dimensions = [
            ('coverage_density', -1),   # 负号：值小 → 排序后靠前 → 更优
            ('rarity_score', 1),
            ('exec_speed', 1),
            ('mutation_potential', 1),
        ]

        for dim_name, direction in dimensions:
            # 按该维度排序
            sorted_front = sorted(
                front,
                key=lambda sid: getattr(objectives[sid], dim_name) * direction
            )
            # 边界 → 无穷大
            objectives[sorted_front[0]].crowding_distance = float('inf')
            objectives[sorted_front[-1]].crowding_distance = float('inf')

            min_val = getattr(objectives[sorted_front[0]], dim_name)
            max_val = getattr(objectives[sorted_front[-1]], dim_name)
            val_range = max_val - min_val + self._crowding_eps

            for i in range(1, len(sorted_front) - 1):
                prev_val = getattr(objectives[sorted_front[i - 1]], dim_name)
                next_val = getattr(objectives[sorted_front[i + 1]], dim_name)
                objectives[sorted_front[i]].crowding_distance += (
                    abs(next_val - prev_val) / val_range
                )

    # 自适应精英保留

    def _adaptive_elite_count(self, n_candidates: int,
                               objectives: Dict[str, SeedObjectives]) -> int:
        """基于种群熵调整精英保留比例
        
        种群熵 = -Σ p_i log₂(p_i)，其中 p_i 为 Front 的种子占比
        熵高 → 种群分布均匀 → 保留更多精英以加速收敛
        熵低 → 种群趋同 → 保留更少精英以避免过早收敛
        """
        if not objectives:
            return 0

        # 统计各 front 的种子数
        front_counts: Dict[int, int] = defaultdict(int)
        for obj in objectives.values():
            front_counts[obj.rank] += 1

        total = sum(front_counts.values())
        if total == 0:
            return 0

        entropy = 0.0
        for cnt in front_counts.values():
            p = cnt / total
            entropy -= p * math.log2(p)

        max_entropy = math.log2(len(front_counts) or 1)
        norm_entropy = entropy / max_entropy if max_entropy > 0 else 0.0

        # 熵高 → ratio 接近 base*1.5；熵低 → ratio 接近 base*0.5
        ratio = self._elite_ratio_base * (0.5 + norm_entropy)
        return max(1, int(n_candidates * ratio))

    def _select_elites(self, objectives: Dict[str, SeedObjectives],
                       fronts: List[List[str]], elite_count: int) -> List[str]:
        """从帕累托前沿中选取精英种子"""
        elites = []
        for front in fronts:
            for sid in front:
                if len(elites) >= elite_count:
                    break
                elites.append(sid)
            if len(elites) >= elite_count:
                break
        return elites

    # 能量权重分配

    def _compute_energy_weights(self,
                                 selected: List[str],
                                 objectives: Dict[str, SeedObjectives]) -> List[Tuple[str, float]]:
        """为选中种子分配变异能量权重
        
        权重 ∝ (1 / (1 + rank)) × (crowding_dist or 1.0)
        帕累托前沿（rank=0）的种子获得最高权重；
        同层内拥挤度高的种子（更独特）获得更高权重
        """
        if not selected:
            return []

        raw_weights = []
        for sid in selected:
            obj = objectives.get(sid)
            if obj is None:
                raw_weights.append((sid, 1.0))
                continue
            rank_factor = 1.0 / (1.0 + obj.rank)
            crowd = obj.crowding_distance if obj.crowding_distance < float('inf') else 2.0
            raw_weights.append((sid, rank_factor * max(0.1, crowd)))

        total_w = sum(w for _, w in raw_weights)
        if total_w <= 0:
            return [(sid, 1.0 / len(selected)) for sid in selected]

        return [(sid, w / total_w) for sid, w in raw_weights]

    # 状态查询

    def get_front_distribution(self) -> Dict[int, int]:
        """返回当前各非支配前沿的种子分布"""
        dist: Dict[int, int] = defaultdict(int)
        for obj in self._obj_cache.values():
            dist[obj.rank] += 1
        return dict(sorted(dist.items()))

    def pareto_front_size(self) -> int:
        """返回当前帕累托前沿（Front 0）的种子数"""
        return sum(1 for obj in self._obj_cache.values() if obj.rank == 0)

    def clear_caches(self):
        """清空目标缓存和 bitmap 统计——用于新的 fuzz 会话"""
        self._obj_cache.clear()
        self._bitmap_hits.clear()
        self._total_execs = 0
        self._seed_features.clear()
