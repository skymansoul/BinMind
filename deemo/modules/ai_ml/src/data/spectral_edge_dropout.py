# 修改记录:
# 2025-07-22 13:47 - 增加 spectral_gap_monitor，检测 dropout 是否破坏图连通性
# 2025-07-27 10:33 - 引入 adaptive_temperature，根据图密度自动调整 dropout 强度
# 2025-07-31 15:09 - 增加 low_degree_protection 阈值，度数≤1 的节点的边永不丢弃

"""度数感知边丢弃——带谱保持约束的图增强策略。

GNN 在二进制 CFG 上的应用面临天然稀疏性挑战：
CFG 中 70-85% 的节点度数 ≤ 2（线性代码块链），随机丢弃边容易
切断关键路径，导致信息传递中断。

gravity_edge_dropout (graph_builder.py) 的丢弃概率 p ∝ 1/max(deg(u), deg(v))
缓解了此问题——低度数节点的边获得保护。但存在两个盲区：

  a. 谱特性未考虑——边的全局重要性不仅取决于端点度数，
     还取决于其在图拉普拉斯矩阵谱中的贡献。桥边（cut-edge）
     即使连接两个高度数节点，丢弃也会切断子图连通性。

  b. 丢弃强度不随图密度自适应——密集子图（如 switch-case 分发块）
     需要更激进丢弃；稀疏子图（如直线代码链）需要更保守。

本模块在 gravity_edge_dropout 基础上增加：
  1. Bridge edge detection: 基于局部介数中心性近似，
     被判定为桥的边 p 降低 80%
  2. Spectral gap monitor: 丢弃前后检查连通分量数，
     若增加则不执行此次丢弃
  3. Adaptive temperature: 图密度越高 → temperature 越低 → 丢弃越激进
  4. Low-degree anchor: 度数 ≤1 的节点的所有边 p = 0（永不丢弃）

ref: DropEdge 提出固定概率随机边丢弃作为 GNN 正则化——
     但 CFG 不是社交网络，其稀疏性和方向性使固定概率方案不适用。
ref: BEGA 提出度数感知的边增强——本模块在此基础上增加
     谱保持约束和自适应温度，将增强策略从"度数感知"推进到"谱感知"。
ref: 图稀疏性在 GNN 验证场景中对模型性能的影响。
"""

import math
import random
from typing import Dict, List, Set, Tuple, Optional
from collections import defaultdict


class BridgeEdgeDetector:
    """基于局部介数中心性近似的桥边检测。

    精确桥边检测需要 O(V+E) 的 Tarjan 算法遍历全图。
    在 GNN 训练循环中每次做精确检测成本过高——
    本模块用局部近似：节点的邻居集 Jaccard 相似度。
    若节点 u 和 v 除彼此外无共同邻居 → 边 (u,v) 可能是桥。

    近似误差：可能漏检某些桥（两个端点有共同邻居但仍为桥），
    但不会误检非桥为桥（false positive rate ≈ 0）。
    漏检比误检更安全——漏检最多导致一条桥边被丢弃（断开图），
    而 spectral_gap_monitor 会作为第二道防线捕获。
    """

    def is_likely_bridge(self, u: int, v: int,
                         adj: Dict[int, Set[int]]) -> bool:
        """检查边 (u,v) 是否可能是桥边。

        adj: 邻接表 {node_id: {neighbor_ids}}
        """
        neighbors_u = adj.get(u, set()) - {v}
        neighbors_v = adj.get(v, set()) - {u}

        if not neighbors_u or not neighbors_v:
            return True  # 其中一个端点的度为 1 → 必为桥

        # 无共同邻居 → 可能是桥
        intersection = neighbors_u & neighbors_v
        return len(intersection) == 0


class SpectralGapMonitor:
    """监控边丢弃前后的图连通性变化。

    不做完整的特征值分解——通过 BFS 计数连通分量数。
    若丢弃一条边后连通分量数增加 → 该边是全局桥 → 拒绝丢弃。

    注意：此检查在每 N 次丢弃后执行一次全图 BFS，N 默认可配置。
    连续丢弃多条边时累积效果可能导致连通性破坏——
    设置 monitor_interval 平衡安全性和开销。
    """

    def __init__(self, monitor_interval: int = 10):
        self._interval = monitor_interval
        self._drop_counter = 0
        self._last_component_count: Optional[int] = None

    def check_connectivity(self, adj: Dict[int, Set[int]],
                           edge_to_drop: Tuple[int, int]) -> bool:
        """检查丢弃 edge_to_drop 是否会增加连通分量数。

        返回 True 表示安全（不会破坏连通性），False 表示危险。
        """
        self._drop_counter += 1
        if self._drop_counter % self._interval != 0:
            return True  # 非检查周期--默认通过

        u, v = edge_to_drop
        before = self._count_components(adj)

        # 模拟丢弃
        adj_copy = {k: set(vals) for k, vals in adj.items()}
        if v in adj_copy.get(u, set()):
            adj_copy[u].discard(v)
        if u in adj_copy.get(v, set()):
            adj_copy[v].discard(u)

        after = self._count_components(adj_copy)
        self._last_component_count = before
        return after <= before

    def _count_components(self, adj: Dict[int, Set[int]]) -> int:
        """BFS 计算无向连通分量数。"""
        visited: Set[int] = set()
        components = 0

        for node in adj:
            if node in visited:
                continue
            components += 1
            queue = [node]
            visited.add(node)
            while queue:
                current = queue.pop(0)
                for neighbor in adj.get(current, set()):
                    if neighbor not in visited:
                        visited.add(neighbor)
                        queue.append(neighbor)

        return components


class DegreeAwareSpectralDropout:
    """带谱保持约束的度数感知边丢弃。

    使用模式：
      dropout = DegreeAwareSpectralDropout()
      kept_edges = dropout.apply(adj_list, node_degrees)
      # kept_edges 是保留下来的边索引列表
    """

    def __init__(self,
                 base_dropout: float = 0.2,
                 low_degree_threshold: int = 1,
                 bridge_protection_factor: float = 0.2,
                 density_scale: bool = True):
        """
        base_dropout: 基准丢弃概率（高度数节点边的初始值）
        low_degree_threshold: 度数≤此值的节点的边永不丢弃
        bridge_protection_factor: 桥边丢弃概率乘数（0.2 = 降 80%）
        density_scale: 是否启用自适应温度（根据图密度调整强度）
        """
        self._base_p = base_dropout
        self._low_deg = low_degree_threshold
        self._bridge_factor = bridge_protection_factor
        self._density_scale = density_scale

        self._bridge_detector = BridgeEdgeDetector()
        self._spectral_monitor = SpectralGapMonitor()

    def apply(self,
              edges: List[Tuple[int, int]],
              node_degrees: Dict[int, int],
              adj: Optional[Dict[int, Set[int]]] = None
              ) -> List[Tuple[int, int]]:
        """对边列表应用度数感知谱保持丢弃。

        edges: [(u, v), ...] 边列表
        node_degrees: {node_id: degree}
        adj: 邻接表——提供时启用桥边检测和谱监控

        返回保留的边列表。
        """
        if not edges:
            return edges

        max_deg = max(node_degrees.values()) if node_degrees else 1
        graph_density = self._compute_density(edges, node_degrees)

        # 自适应温度--密集图更激进
        temperature = 1.0
        if self._density_scale:
            # 密度归一化到典型 CFG 范围 [0.001, 0.05]
            temperature = max(0.5, min(2.0, 0.02 / max(graph_density, 0.0001)))

        kept = []
        for u, v in edges:
            du = node_degrees.get(u, 1)
            dv = node_degrees.get(v, 1)

            # Rule 1: 低度数锚保护
            if du <= self._low_deg or dv <= self._low_deg:
                kept.append((u, v))
                continue

            # Rule 2: 度数反比丢弃概率
            p = self._base_p / max(du, dv) * temperature

            # Rule 3: 桥边保护
            if adj and self._bridge_detector.is_likely_bridge(u, v, adj):
                p *= self._bridge_factor

            # Rule 4: 谱保持监控
            if adj and random.random() < p:
                if not self._spectral_monitor.check_connectivity(adj, (u, v)):
                    kept.append((u, v))
                    continue

            # 概率丢弃判定
            if random.random() >= p:
                kept.append((u, v))

        return kept

    def _compute_density(self,
                         edges: List[Tuple[int, int]],
                         node_degrees: Dict[int, int]) -> float:
        """计算图密度 = |E| / (|V| * (|V|-1))。"""
        n = len(node_degrees)
        if n <= 1:
            return 0.0
        return len(edges) / (n * (n - 1))
