"""
 帕累托最优补丁选择 - NSGA-II多目标优化在传播图补丁策略中的应用.

三目标:最大化风险降幅,最小化补丁成本,最小化运维影响.
首次将NSGA-II非支配排序+counterfactual适应度+层特定成本模型联合应用.

ref: Deb et al. "A Fast and Elitist Multiobjective Genetic Algorithm: NSGA-II".
ref: CyGATE - 博弈论补丁优化,最接近的已有工作.
"""
from __future__ import annotations

import math
import random
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from .propagation_graph import PlatformLayer, PropagationGraph


@dataclass
class PatchCandidate:
    """单个补丁候选, 传播图中的一个可修复节点."""
    node_id: str
    layer: PlatformLayer
    cost: float           # 补丁成本 (0-1归一化)
    impact: float         # 运维影响 (0-1归一化,越大影响越重)
    risk_contribution: float  # 节点对全局风险的贡献(由counterfactual计算)


@dataclass
class PatchSolution:
    """一个补丁方案, 选中的节点子集及其评估指标."""
    selected_nodes: List[str]
    risk_reduction: float      # 总风险降幅 (应最大化)
    total_cost: float           # 总成本 (应最小化)
    total_impact: float         # 总运维影响 (应最小化)
    rank: int = 0               # 非支配排序层(0=Pareto前沿)
    crowding_distance: float = 0.0


class NSGA2PatchOptimizer:
    """NSGA-II 多目标补丁选择优化器.

    用法::

        candidates = [PatchCandidate(...), ...]
        optimizer = NSGA2PatchOptimizer(
            candidates, risk_evaluator_fn, cost_model_fn, impact_model_fn,
            population_size=60, n_generations=80,
        )
        pareto_front = optimizer.optimize()
    """

    def __init__(self,
                 candidates: List[PatchCandidate],
                 risk_evaluator: Callable[[List[str]], float],
                 cost_model: Optional[Callable[[str], float]] = None,
                 impact_model: Optional[Callable[[str], float]] = None,
                 population_size: int = 50,
                 n_generations: int = 60):
        self._candidates = candidates
        self._n = len(candidates)
        self._eval_risk = risk_evaluator
        self._eval_cost = cost_model or (lambda nid: 0.5)
        self._eval_impact = impact_model or (lambda nid: 0.3)
        self._pop_size = min(population_size, 2 ** min(self._n, 12))
        self._n_gen = n_generations

        # 预计算每节点的成本和影响
        self._node_costs = {c.node_id: c.cost for c in candidates}
        self._node_impacts = {c.node_id: c.impact for c in candidates}

    def optimize(self) -> List[PatchSolution]:
        """执行 NSGA-II 优化,返回 Pareto 前沿(第一非支配层)."""
        if self._n == 0:
            return []

        # 初始化种群
        population = self._init_population()
        # 评估
        for sol in population:
            self._evaluate(sol)

        # 非支配排序
        fronts = self._non_dominated_sort(population)
        for rank, front in enumerate(fronts):
            self._crowding_distance(front)
            for sol in front:
                sol.rank = rank

        for gen in range(self._n_gen):
            # 选择 + 交叉 + 变异 -> 子代
            offspring = []
            while len(offspring) < self._pop_size:
                p1 = self._tournament_select(population)
                p2 = self._tournament_select(population)
                c1, c2 = self._crossover(p1, p2)
                self._mutate(c1)
                self._mutate(c2)
                offspring.append(c1)
                if len(offspring) < self._pop_size:
                    offspring.append(c2)

            for sol in offspring:
                self._evaluate(sol)

            # 精英保留:合并父代和子代,重排序,截断
            combined = population + offspring
            fronts = self._non_dominated_sort(combined)
            population = []
            for front in fronts:
                if len(population) + len(front) <= self._pop_size:
                    self._crowding_distance(front)
                    population.extend(front)
                else:
                    self._crowding_distance(front)
                    needed = self._pop_size - len(population)
                    front.sort(key=lambda s: s.crowding_distance, reverse=True)
                    population.extend(front[:needed])
                    break

            for rank, front in enumerate(fronts):
                for sol in front:
                    sol.rank = rank

        # 最终非支配排序, 返回 Pareto 前沿
        final_fronts = self._non_dominated_sort(population)
        for sol in final_fronts[0]:
            sol.rank = 0
        return final_fronts[0]

    # 内部：种群初始化与遗传算子
    def _init_population(self) -> List[PatchSolution]:
        pop = []
        # 种子方案:全不选,全选,每节点单独选
        pop.append(self._make_solution(set()))
        all_ids = {c.node_id for c in self._candidates}
        if len(all_ids) <= 8:
            pop.append(self._make_solution(all_ids))
        for c in self._candidates:
            pop.append(self._make_solution({c.node_id}))
        # 随机填充
        while len(pop) < self._pop_size:
            k = random.randint(1, max(1, self._n // 3))
            sel = set(random.sample([c.node_id for c in self._candidates], k))
            pop.append(self._make_solution(sel))
        return pop[:self._pop_size]

    def _make_solution(self, selected: Set[str]) -> PatchSolution:
        return PatchSolution(
            selected_nodes=list(selected),
            risk_reduction=0.0, total_cost=0.0, total_impact=0.0,
        )

    def _evaluate(self, sol: PatchSolution) -> None:
        selected = sol.selected_nodes
        if not selected:
            sol.risk_reduction = 0.0
            sol.total_cost = 0.0
            sol.total_impact = 0.0
        else:
            sol.risk_reduction = self._eval_risk(selected)
            sol.total_cost = sum(self._node_costs.get(n, 0.5) for n in selected)
            sol.total_impact = sum(self._node_impacts.get(n, 0.3) for n in selected)

    def _non_dominated_sort(self, population: List[PatchSolution]
                            ) -> List[List[PatchSolution]]:
        """Deb的快速非支配排序 - O(M·N²),M=3个目标."""
        dominated_by: Dict[int, Set[int]] = defaultdict(set)
        dominates_count: Dict[int, int] = defaultdict(int)
        fronts: List[List[int]] = [[]]

        for i, pi in enumerate(population):
            for j, pj in enumerate(population):
                if i == j:
                    continue
                if self._dominates(pi, pj):
                    dominated_by[i].add(j)
                elif self._dominates(pj, pi):
                    dominates_count[i] += 1
            if dominates_count[i] == 0:
                fronts[0].append(i)

        idx = 0
        while idx < len(fronts) and fronts[idx]:
            next_front: List[int] = []
            for i in fronts[idx]:
                for j in dominated_by[i]:
                    dominates_count[j] -= 1
                    if dominates_count[j] == 0:
                        next_front.append(j)
            idx += 1
            if next_front:
                if idx >= len(fronts):
                    fronts.append([])
                fronts[idx] = next_front

        return [[population[i] for i in f] for f in fronts if f]

    @staticmethod
    def _dominates(a: PatchSolution, b: PatchSolution) -> bool:
        """a支配b: a在所有目标上不差于b,且至少一个目标严格优于b.

        目标方向:risk_reduction最大化 -> 取负转最小化
                   cost最小化,impact最小化
        """
        ar = -a.risk_reduction  # 最大化 -> 取负
        br = -b.risk_reduction
        better = False
        if ar > br or a.total_cost > b.total_cost or a.total_impact > b.total_impact:
            return False  # a 在某个目标上更差
        if ar < br or a.total_cost < b.total_cost or a.total_impact < b.total_impact:
            better = True
        return better

    def _crowding_distance(self, front: List[PatchSolution]) -> None:
        """拥挤距离: 每目标边界解=inf,内部解按归一化目标差累加."""
        for sol in front:
            sol.crowding_distance = 0.0
        if len(front) <= 2:
            for sol in front:
                sol.crowding_distance = float('inf')
            return

        # 三目标各自计算
        for obj_idx, getter in enumerate([
            lambda s: -s.risk_reduction,  # 风险降幅(取负统一方向)
            lambda s: s.total_cost,
            lambda s: s.total_impact,
        ]):
            sorted_f = sorted(front, key=getter)
            obj_min = getter(sorted_f[0])
            obj_max = getter(sorted_f[-1])
            obj_range = max(obj_max - obj_min, 1e-9)

            sorted_f[0].crowding_distance = float('inf')
            sorted_f[-1].crowding_distance = float('inf')
            for i in range(1, len(sorted_f) - 1):
                dist = (getter(sorted_f[i + 1]) - getter(sorted_f[i - 1])) / obj_range
                sorted_f[i].crowding_distance += abs(dist)

    def _tournament_select(self, population: List[PatchSolution]) -> PatchSolution:
        """二元锦标赛:先比rank,再比拥挤距离."""
        a, b = random.sample(population, 2)
        if a.rank < b.rank:
            return a
        if b.rank < a.rank:
            return b
        return a if a.crowding_distance > b.crowding_distance else b

    def _crossover(self, p1: PatchSolution, p2: PatchSolution
                   ) -> Tuple[PatchSolution, PatchSolution]:
        """均匀交叉: 每个基因位50%概率从父代之一继承."""
        s1 = set(p1.selected_nodes)
        s2 = set(p2.selected_nodes)
        child1: Set[str] = set()
        child2: Set[str] = set()
        all_nodes = [c.node_id for c in self._candidates]

        for nid in all_nodes:
            if random.random() < 0.5:
                if nid in s1: child1.add(nid)
                if nid in s2: child2.add(nid)
            else:
                if nid in s2: child1.add(nid)
                if nid in s1: child2.add(nid)

        return self._make_solution(child1), self._make_solution(child2)

    def _mutate(self, sol: PatchSolution) -> None:
        """逐位变异: 每位以 1/n 概率翻转."""
        current = set(sol.selected_nodes)
        all_nodes = [c.node_id for c in self._candidates]
        for nid in all_nodes:
            if random.random() < 1.0 / max(self._n, 1):
                if nid in current:
                    current.discard(nid)
                else:
                    current.add(nid)
        sol.selected_nodes = list(current)


def layer_specific_cost(node_id: str, layer: PlatformLayer,
                        graph: Optional[PropagationGraph] = None) -> float:
    """层特定补丁成本模型 -- 基于平台层的运维现实.

    固件修复需物理接触 -> 高成本.智能合约仅需发交易 -> 低成本.
    """
    base = {
        PlatformLayer.FIRMWARE: 0.85,
        PlatformLayer.HARDWARE: 0.90,
        PlatformLayer.KERNEL: 0.60,
        PlatformLayer.MOBILE: 0.45,
        PlatformLayer.MALWARE: 0.30,
        PlatformLayer.SMART_CONTRACT: 0.15,
    }
    cost = base.get(layer, 0.50)

    # 入度越高->受影响组件越多->测试回归成本越高
    if graph:
        indeg = len(graph._rev_adj.get(node_id, []))
        cost = min(1.0, cost + 0.02 * indeg)

    return cost


def layer_specific_impact(node_id: str, layer: PlatformLayer,
                          graph: Optional[PropagationGraph] = None) -> float:
    """层特定运维影响模型 -- 修复对系统可用性的影响程度.

    内核修复需重启 -> 高影响.恶意软件样本分析不影响线上 -> 低影响.
    """
    base = {
        PlatformLayer.KERNEL: 0.80,
        PlatformLayer.FIRMWARE: 0.75,
        PlatformLayer.HARDWARE: 0.70,
        PlatformLayer.MOBILE: 0.40,
        PlatformLayer.SMART_CONTRACT: 0.20,
        PlatformLayer.MALWARE: 0.10,
    }
    return base.get(layer, 0.50)
