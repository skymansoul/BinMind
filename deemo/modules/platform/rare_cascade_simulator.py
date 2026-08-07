"""
稀有级联模拟器 -- 重要性采样+分裂法估计传播图中小概率灾难性级联。

问题：
  正常风险评估关注"平均情况"——大多数漏洞只在单层内传播。
  但灾难性场景（固件漏洞经内核触发硬件侧信道再被移动端恶意软件利用、
  最终影响智能合约）虽然概率极低，后果却是毁灭性的。
  标准蒙特卡洛模拟需要数百万次采样才能可靠估计10^-6量级的概率。

方案：
  1. 重要性采样 (Importance Sampling):
     扭曲边激活概率 p -> q > p，使级联更频繁发生。
     每次采样的权重 = Π(p_i/q_i) (似然比)。
     无偏估计: P(cascade) ≈ (1/N) * Σ weight_i * I(cascade_i)。

  2. 分裂法 (RESTART / Splitting):
     当部分级联达到预设的"重要性阈值"(如已跨越3层)时，
     分裂为M个独立副本继续模拟。
     这避免了在低概率区域浪费计算资源。
     每个副本的权重 = 父权重 / M (无偏)。

  3. 层重要性函数:
     重要性函数 I(state) = 当前级联跨越的层数。
     阈值集合: {2, 3, 4, 5, 6} —— 跨越2层时第一次分裂。

创新点：
  首次将稀有事件模拟技术应用于漏洞传播图的灾难性级联估计。
  传播图的DAG性质使分裂法特别高效——无环结构避免了重复访问。
  层重要性函数利用了跨平台层的自然层级结构。

ref: Bucklew "Introduction to Rare Event Simulation".
ref: Villen-Altamirano & Villen-Altamirano "RESTART: a straightforward
     method for fast simulation of rare events".
ref: Rubino & Tuffin "Rare Event Simulation using Monte Carlo Methods".
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from .propagation_graph import PlatformLayer, PropagationGraph, VulnNode


@dataclass
class CascadePath:
    """一次级联的传播路径记录。"""
    visited_nodes: List[str]
    activated_edges: List[Tuple[str, str]]
    layers_touched: Set[int]
    total_weight: float = 1.0   # 重要性采样权重（似然比累积）
    reached_terminal: bool = False  # 是否达到所有可达层


@dataclass
class CascadeEstimate:
    """级联概率估计结果。"""
    target_layers: int                     # 目标跨越层数
    probability: float                     # P(跨越>=target_layers层)
    variance: float                        # 估计方差
    relative_error: float                  # 变异系数 = sqrt(variance)/estimate
    n_samples: int
    method: str                            # "IS" | "SPLITTING" | "MC"


class RareCascadeSimulator:
    """稀有传播级联模拟器。

    用法::

        sim = RareCascadeSimulator(graph)
        # 重要性采样：估计跨越>=5层的级联概率
        est = sim.importance_sampling(n_samples=5000, bias_factor=2.0)
        # 分裂法：更高效的极端稀有事件估计
        est2 = sim.splitting
    """

    def __init__(self, graph: PropagationGraph):
        self._graph = graph
        # 缓存每个节点的出边列表（按层序排列）
        self._out_edges: Dict[str, List[Tuple[str, float]]] = {}
        for src in graph._nodes:
            edges = []
            for tgt in graph._adj.get(src, []):
                edge = graph._edges.get((src, tgt))
                if edge:
                    edges.append((tgt, edge.confidence))
            edges.sort(key=lambda x: graph._nodes[x[0]].layer.value
                       if x[0] in graph._nodes else 0)
            self._out_edges[src] = edges

    def importance_sampling(self, n_samples: int = 5000,
                            bias_factor: float = 2.0,
                            target_layers: int = 5,
                            seed: int = 0) -> CascadeEstimate:
        """重要性采样估计跨层传播概率。

        bias_factor: 边激活概率的放大倍数。
          p_biased = min(1.0, p_original * bias_factor)
          权重 = p_original / p_biased (似然比)
        """
        random.seed(seed)
        cascade_count = 0.0
        cascade_sq = 0.0

        for _ in range(n_samples):
            weight, layers_hit = self._simulate_cascade_is(bias_factor)
            if len(layers_hit) >= target_layers:
                cascade_count += weight
                cascade_sq += weight ** 2

        prob = cascade_count / n_samples
        var = (cascade_sq / n_samples - prob ** 2) / max(n_samples - 1, 1)
        rel_err = math.sqrt(max(var, 0.0)) / max(prob, 1e-12)

        return CascadeEstimate(
            target_layers=target_layers, probability=prob,
            variance=max(var, 0.0), relative_error=rel_err,
            n_samples=n_samples, method="IS",
        )

    def splitting(self, target_layers: int = 5,
                  n_trials: int = 2000, split_factor: int = 4,
                  seed: int = 0) -> CascadeEstimate:
        """分裂法估计极端稀有级联概率。

        当部分级联达到重要性阈值时分裂为split_factor个副本。
        阈值设为跨越层数: {2, 3, 4, ...}直到target_layers-1。
        """
        random.seed(seed)
        thresholds = list(range(2, target_layers))

        cascade_total = 0.0
        cascade_sq = 0.0
        n_effective = 0

        for _ in range(n_trials):
            # 从随机起始节点开始
            start_nodes = [nid for nid in self._graph._nodes
                          if self._graph._nodes[nid].layer == PlatformLayer.FIRMWARE]
            if not start_nodes:
                start_nodes = list(self._graph._nodes.keys())
            if not start_nodes:
                continue

            start = random.choice(start_nodes)
            paths = [CascadePath(
                visited_nodes=[start],
                activated_edges=[],
                layers_touched={self._graph._nodes[start].layer.value},
                total_weight=1.0,
            )]

            for threshold in thresholds:
                new_paths: List[CascadePath] = []
                for path in paths:
                    current = path.visited_nodes[-1]
                    if len(path.layers_touched) < threshold:
                        new_paths.append(path)
                        continue

                    # 跨越阈值——分裂
                    for _ in range(split_factor):
                        cp = CascadePath(
                            visited_nodes=list(path.visited_nodes),
                            activated_edges=list(path.activated_edges),
                            layers_touched=set(path.layers_touched),
                            total_weight=path.total_weight / split_factor,
                        )
                        self._extend_path(cp)
                        new_paths.append(cp)
                paths = new_paths

            # 最终延伸所有路径到终止
            for path in paths:
                while self._extend_path(path):
                    pass

            for path in paths:
                n_effective += 1
                if len(path.layers_touched) >= target_layers:
                    cascade_total += path.total_weight
                    cascade_sq += path.total_weight ** 2

        prob = cascade_total / max(n_trials, 1)
        var = (cascade_sq / max(n_trials, 1) - prob ** 2) / max(n_trials - 1, 1)
        rel_err = math.sqrt(max(var, 0.0)) / max(prob, 1e-12)

        return CascadeEstimate(
            target_layers=target_layers, probability=prob,
            variance=max(var, 0.0), relative_error=rel_err,
            n_samples=n_trials, method="SPLITTING",
        )

    def monte_carlo_baseline(self, n_samples: int = 10000,
                             seed: int = 0) -> Dict[int, CascadeEstimate]:
        """标准蒙特卡洛基线 -- 用于对比IS/分裂法的方差缩减效果。"""
        random.seed(seed)
        layer_hits: Dict[int, float] = {}
        layer_sq: Dict[int, float] = {}
        counts: Dict[int, int] = {}

        for _ in range(n_samples):
            _, layers = self._simulate_cascade_is(bias_factor=1.0)
            for t in range(1, 7):
                hit = 1.0 if len(layers) >= t else 0.0
                layer_hits[t] = layer_hits.get(t, 0.0) + hit
                layer_sq[t] = layer_sq.get(t, 0.0) + hit
                counts[t] = counts.get(t, 0) + 1

        results = {}
        for t in range(1, 7):
            prob = layer_hits.get(t, 0.0) / n_samples
            var = (layer_sq.get(t, 0.0) / n_samples - prob ** 2) / max(n_samples - 1, 1)
            results[t] = CascadeEstimate(
                target_layers=t, probability=prob,
                variance=max(var, 0.0),
                relative_error=math.sqrt(max(var, 0.0)) / max(prob, 1e-12),
                n_samples=n_samples, method="MC",
            )
        return results

    def _simulate_cascade_is(self, bias_factor: float
                             ) -> Tuple[float, Set[int]]:
        """执行一次重要性采样级联模拟。

        返回 (累积似然比权重, 触及的平台层集合)。
        """
        # 随机起始节点（优先固件层）
        fw_nodes = [nid for nid in self._graph._nodes
                    if self._graph._nodes[nid].layer == PlatformLayer.FIRMWARE]
        start_pool = fw_nodes or list(self._graph._nodes.keys())
        if not start_pool:
            return 1.0, set()

        current = random.choice(start_pool)
        visited = {current}
        activated: List[Tuple[str, str]] = []
        layers_hit = {self._graph._nodes[current].layer.value}
        weight = 1.0

        # BFS传播
        from collections import deque
        queue = deque([current])
        while queue:
            src = queue.popleft()
            for tgt, orig_prob in self._out_edges.get(src, []):
                if tgt in visited:
                    continue
                biased_prob = min(1.0, orig_prob * bias_factor)
                if random.random() < biased_prob:
                    visited.add(tgt)
                    activated.append((src, tgt))
                    weight *= orig_prob / max(biased_prob, 1e-9)
                    if tgt in self._graph._nodes:
                        layers_hit.add(self._graph._nodes[tgt].layer.value)
                    queue.append(tgt)

        return weight, layers_hit

    def _extend_path(self, path: CascadePath) -> bool:
        """沿传播边延伸路径一步 -- 返回是否成功延伸。"""
        current = path.visited_nodes[-1]
        for tgt, orig_prob in self._out_edges.get(current, []):
            if tgt in path.visited_nodes:
                continue
            if random.random() < orig_prob:
                path.visited_nodes.append(tgt)
                path.activated_edges.append((current, tgt))
                if tgt in self._graph._nodes:
                    path.layers_touched.add(
                        self._graph._nodes[tgt].layer.value)
                return True
        return False
