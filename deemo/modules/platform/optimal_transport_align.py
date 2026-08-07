"""
最优传输图对齐 -- 基于Sinkhorn熵正则最优传输的传播图结构比对。

问题：
  比较两个传播图（如不同固件版本的漏洞传播结构）的传统方法：
  - 图编辑距离：NP-hard，不可微，大规模图不可行
  - 图同构检测：过于严格，小幅结构变化即判为不同
  - 持续同调指纹（本项目的propagation_homology）：仅比较拓扑特征，忽略节点语义

方案：
  将传播图对齐建模为最优传输问题。
  1. 每节点提取特征向量（严重度、层位置、入度、跨层边比、PageRank近似）
  2. 计算源图和目标图节点间的代价矩阵（特征距离+结构距离加权）
  3. Sinkhorn-Knopp算法求解熵正则化的最优传输计划
  4. 最优传输代价 = 两个传播图的结构-语义对齐距离

  熵正则化参数 lambda 控制传输计划的稀疏度：
  lambda->0: 近似精确OT（稀疏匹配）
  lambda->inf: 均匀传输（最大熵）

创新点：
  首次将Sinkhorn最优传输应用于跨平台漏洞传播图的结构比对。
  与Gromov-Wasserstein（比较图拓扑）不同，本方法同时编码节点语义和局部结构，
  适用于固件版本演化中的漏洞传播模式漂移检测。

与已有工作的区分：
  GW鲁棒性工作: 关注GW距离对异常值的脆弱性，
    不涉及漏洞传播图的语义特征对齐。
  本模块：将OT的成本函数设计为传播特定的特征空间，而非通用的GW框架。

ref: Cuturi "Sinkhorn Distances: Lightspeed Computation of Optimal Transport".
ref: Peyre & Cuturi "Computational Optimal Transport" -- 综合参考。
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .propagation_graph import PlatformLayer, PropagationGraph


@dataclass
class TransportPlan:
    """最优传输计划 -- 源图节点到目标图节点的软匹配矩阵。"""
    source_nodes: List[str]
    target_nodes: List[str]
    plan_matrix: List[List[float]]       # [n_source x n_target], 行和≈源权重, 列和≈目标权重
    transport_cost: float                 # <P, C>_F -- Frobenius内积
    entropy: float                        # 传输计划的熵 (正则化强度指标)
    converged: bool                       # Sinkhorn是否收敛


class SinkhornPropagationAligner:
    """Sinkhorn传播图对齐器 -- 熵正则最优传输。

    用法::

        aligner = SinkhornPropagationAligner(reg_lambda=0.1)
        plan = aligner.align(graph_a, graph_b)
        print(f"Transport cost: {plan.transport_cost:.4f}")
    """

    def __init__(self, reg_lambda: float = 0.1, max_iters: int = 200,
                 tol: float = 1e-6):
        self._lambda = reg_lambda      # 熵正则化系数（越小越稀疏）
        self._max_iters = max_iters
        self._tol = tol

    def extract_node_features(self, graph: PropagationGraph
                              ) -> Dict[str, List[float]]:
        """提取传播图节点的特征向量 -- 8维。

        维度设计：
          0: severity (自身严重度)
          1: layer_normalized (平台层位置 / 6)
          2: indegree_log (log(1+入度)归一化)
          3: outdegree_log (log(1+出度)归一化)
          4: cross_layer_ratio (跨层边比例)
          5: mean_neighbor_severity (邻居平均严重度)
          6: pagerank_approx (简化的PageRank一阶近似)
          7: clustering_coeff (局部聚类系数)
        """
        n = graph.node_count
        features: Dict[str, List[float]] = {}

        # 一阶PageRank近似（入边权重和）
        pr_approx: Dict[str, float] = {}
        for nid in graph._nodes:
            pr = 0.0
            for src in graph._rev_adj.get(nid, []):
                edge = graph._edges.get((src, nid))
                if edge:
                    pr += edge.confidence
            pr_approx[nid] = pr / max(n, 1)

        for nid, node in graph._nodes.items():
            indeg = len(graph._rev_adj.get(nid, []))
            outdeg = len(graph._adj.get(nid, []))

            cross_in = sum(1 for s in graph._rev_adj.get(nid, [])
                          if s in graph._nodes
                          and graph._nodes[s].layer != node.layer)
            cross_out = sum(1 for t in graph._adj.get(nid, [])
                           if t in graph._nodes
                           and graph._nodes[t].layer != node.layer)
            total_edges = indeg + outdeg
            cross_ratio = (cross_in + cross_out) / max(total_edges, 1)

            neighbor_sevs = []
            for s in graph._rev_adj.get(nid, []):
                if s in graph._nodes:
                    neighbor_sevs.append(graph._nodes[s].severity)
            for t in graph._adj.get(nid, []):
                if t in graph._nodes:
                    neighbor_sevs.append(graph._nodes[t].severity)
            mean_ns = sum(neighbor_sevs) / max(len(neighbor_sevs), 1)

            # 局部聚类系数
            neighbors = (set(graph._rev_adj.get(nid, []))
                         | set(graph._adj.get(nid, [])))
            neighbor_edges = sum(1 for a in neighbors for b in neighbors
                                if a < b and (a, b) in graph._edges)
            npairs = len(neighbors) * (len(neighbors) - 1) / 2.0
            clust = neighbor_edges / max(npairs, 1.0)

            vec = [
                node.severity,
                node.layer.value / 6.0,
                math.log1p(indeg) / math.log1p(max(n, 1)),
                math.log1p(outdeg) / math.log1p(max(n, 1)),
                cross_ratio,
                mean_ns,
                min(pr_approx.get(nid, 0.0), 1.0),
                clust,
            ]
            features[nid] = vec

        return features

    def _node_role_signature(self, graph: PropagationGraph,
                             node_id: str) -> Tuple[float, float, float]:
        """计算节点的结构角色签名 (hub, leaf, bridge)。

        hub = 高入度+高出度, leaf = 低出度, bridge = 连接不同层的节点。
        返回归一化的3元组。
        """
        indeg = len(graph._rev_adj.get(node_id, []))
        outdeg = len(graph._adj.get(node_id, []))
        node = graph._nodes.get(node_id)
        if node is None:
            return (0.5, 0.5, 0.5)
        cross_out = sum(1 for t in graph._adj.get(node_id, [])
                       if t in graph._nodes
                       and graph._nodes[t].layer != node.layer)
        n = max(graph.node_count, 1)
        hub = math.log1p(indeg + outdeg) / math.log1p(n)
        leaf = 1.0 - math.log1p(outdeg) / math.log1p(max(indeg + outdeg, 1))
        bridge = cross_out / max(outdeg, 1) if outdeg > 0 else 0.0
        return (hub, leaf, bridge)

    def compute_cost_matrix(self, features_a: Dict[str, List[float]],
                            features_b: Dict[str, List[float]],
                            graph_a: PropagationGraph,
                            graph_b: PropagationGraph
                            ) -> Tuple[List[str], List[str], List[List[float]]]:
        """计算结构角色感知的传输代价矩阵。

        创新：代价 = L2特征距离 + 层惩罚 + 结构角色距离。
        两个节点即使特征不同，若它们在各自图中扮演相同结构角色
        (如都是'桥接KERNEL-HARDWARE的关键节点'), 传输代价也更低。
        这使OT对齐更关注传播图的功能等价性而非表面特征相似。
        """
        nodes_a = list(features_a.keys())
        nodes_b = list(features_b.keys())
        n_a, n_b = len(nodes_a), len(nodes_b)

        cost = [[0.0] * n_b for _ in range(n_a)]
        layer_penalty = 0.3

        # 预计算结构角色签名
        roles_a = {na: self._node_role_signature(graph_a, na) for na in nodes_a}
        roles_b = {nb: self._node_role_signature(graph_b, nb) for nb in nodes_b}

        for i, na in enumerate(nodes_a):
            va = features_a[na]
            layer_a = graph_a._nodes[na].layer
            ra = roles_a[na]
            for j, nb in enumerate(nodes_b):
                vb = features_b[nb]
                layer_b = graph_b._nodes[nb].layer
                rb = roles_b[nb]
                # L2特征距离
                d2 = sum((va[k] - vb[k]) ** 2 for k in range(len(va)))
                d = math.sqrt(d2)
                # 跨层惩罚
                if layer_a != layer_b:
                    d += layer_penalty * abs(layer_a.value - layer_b.value)
                # 结构角色距离 (权重0.15——角色信息辅助但不主导)
                role_dist = math.sqrt(sum((ra[k] - rb[k])**2 for k in range(3)))
                d += 0.15 * role_dist
                cost[i][j] = d

        return nodes_a, nodes_b, cost

    def align(self, graph_a: PropagationGraph,
              graph_b: PropagationGraph,
              uniform_weights: bool = True
              ) -> TransportPlan:
        """对齐两个传播图 -- 返回Sinkhorn传输计划。

        uniform_weights=True: 每节点权重=1/|V|（等权重）
        uniform_weights=False: 每节点权重正比于其严重度（按风险加权）
        """
        feats_a = self.extract_node_features(graph_a)
        feats_b = self.extract_node_features(graph_b)

        nodes_a, nodes_b, cost = self.compute_cost_matrix(
            feats_a, feats_b, graph_a, graph_b,
        )

        n_a, n_b = len(nodes_a), len(nodes_b)
        if n_a == 0 or n_b == 0:
            return TransportPlan(
                source_nodes=nodes_a, target_nodes=nodes_b,
                plan_matrix=[[0.0]], transport_cost=0.0,
                entropy=0.0, converged=False,
            )

        # 权重向量
        if uniform_weights:
            a_weights = [1.0 / n_a] * n_a
            b_weights = [1.0 / n_b] * n_b
        else:
            sevs_a = [graph_a._nodes[n].severity for n in nodes_a]
            sevs_b = [graph_b._nodes[n].severity for n in nodes_b]
            sum_a = sum(sevs_a)
            sum_b = sum(sevs_b)
            a_weights = [s / max(sum_a, 1e-9) for s in sevs_a]
            b_weights = [s / max(sum_b, 1e-9) for s in sevs_b]

        # Sinkhorn-Knopp迭代
        # K = exp(-C / lambda), 逐行/列缩放
        K = [[math.exp(-cost[i][j] / max(self._lambda, 1e-9))
              for j in range(n_b)] for i in range(n_a)]

        u = [1.0] * n_a
        v = [1.0] * n_b

        converged = False
        for _ in range(self._max_iters):
            u_prev = list(u)
            # 行缩放: u_i = a_i / sum_j K_ij * v_j
            for i in range(n_a):
                s = sum(K[i][j] * v[j] for j in range(n_b))
                u[i] = a_weights[i] / max(s, 1e-15)
            # 列缩放: v_j = b_j / sum_i K_ij * u_i
            for j in range(n_b):
                s = sum(K[i][j] * u[i] for i in range(n_a))
                v[j] = b_weights[j] / max(s, 1e-15)

            # 收敛检查
            max_delta = max(abs(u[i] - u_prev[i]) for i in range(n_a))
            if max_delta < self._tol:
                converged = True
                break

        # 构建传输计划 P_ij = u_i * K_ij * v_j
        plan = [[u[i] * K[i][j] * v[j] for j in range(n_b)]
                for i in range(n_a)]

        # 传输代价 = sum_i,j P_ij * C_ij
        total_cost = sum(plan[i][j] * cost[i][j]
                        for i in range(n_a) for j in range(n_b))

        # 传输计划熵 = -sum P_ij * log P_ij
        entropy_val = 0.0
        for i in range(n_a):
            for j in range(n_b):
                if plan[i][j] > 1e-15:
                    entropy_val -= plan[i][j] * math.log(plan[i][j])

        return TransportPlan(
            source_nodes=nodes_a, target_nodes=nodes_b,
            plan_matrix=plan, transport_cost=total_cost,
            entropy=entropy_val, converged=converged,
        )

    def graph_distance(self, graph_a: PropagationGraph,
                       graph_b: PropagationGraph) -> float:
        """计算两个传播图的OT距离 -- 单值摘要度量。

        距离已按 min(|V_a|, |V_b|) 归一化，使不同规模图可比。
        """
        plan = self.align(graph_a, graph_b)
        n_min = min(len(plan.source_nodes), len(plan.target_nodes))
        return plan.transport_cost / max(n_min, 1)
