"""
Bootstrap传播置信区间 -- Efron重抽样估计传播图边置信度的经验分布。

问题：
  传播图中每条边的置信度来自有限的证据观测。
  当evidence_count很小时，点估计不可靠。
  共形预测(conformal_risk)提供分布无关的预测区间，
  Bootstrap提供基于数据重抽样的经验置信区间——两者互补。

方案：
  非参数Bootstrap (Efron 1979)：
  1. 将传播图的边置信度观测视为经验分布
  2. 有放回重抽样B次(B=1000), 每次构建一个bootstrap传播图
  3. 在每个bootstrap图上运行RiskScorer
  4. 对每个节点/边, 取B次估计的α/2和1-α/2分位数作为置信区间

  三种Bootstrap变体：
  (a) 边Bootstrap: 重抽样边集, 保持节点不变
  (b) 节点Bootstrap: 重抽样节点(保留其关联边), 用于节点级稳定性评估
  (c) 残差Bootstrap: 对边置信度加残差噪声后重抽样

创新点：
  首次将Bootstrap重抽样应用于传播图边置信度的经验分布估计。
  传播图的DAG约束在bootstrap过程中自动保持(边方向不变,
  仅权重变化)。为每个风险评分提供数据驱动的置信区间。

与已有模块的关系：
  conformal_risk: 分布无关保证, 需校准集
  adversarial_hardening: Beta后验HDI, 需贝叶斯先验
  本模块: 纯频率学派经验方法, 仅需原始数据, 无先验假设

ref: Efron & Tibshirani (1994) "An Introduction to the Bootstrap".
ref: Efron (1979) "Bootstrap Methods: Another Look at the Jackknife".
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from .propagation_graph import PlatformLayer, PropagationGraph, VulnNode


@dataclass
class BootstrapResult:
    """Bootstrap估计结果 -- 含点估计+置信区间。"""
    node_id: str
    point_estimate: float          # 原始数据上的估计值
    bootstrap_mean: float          # B次bootstrap估计的均值
    bootstrap_std: float           # B次bootstrap估计的标准差
    ci_lower: float                # (1-alpha)置信区间下界
    ci_upper: float                # (1-alpha)置信区间上界
    bias: float                    # bootstrap偏差 = mean_boot - point


class PropagationBootstrap:
    """传播图Bootstrap重抽样 -- 经验置信区间估计。

    用法::

        graph = PropagationGraph()
        boot = PropagationBootstrap(graph, n_bootstrap=500, seed=42)
        results = boot.bootstrap_edges(risk_scorer_fn)
        for nid, r in results.items():
            print(f"{nid}: {r.point_estimate:.3f} [{r.ci_lower:.3f}, {r.ci_upper:.3f}]")
    """

    def __init__(self, graph: PropagationGraph,
                 n_bootstrap: int = 500, alpha: float = 0.10,
                 seed: int = 0):
        self._graph = graph
        self._B = n_bootstrap
        self._alpha = alpha
        self._seed = seed

    def bootstrap_edges(self,
                        risk_fn: Callable[[PropagationGraph], Dict[str, float]]
                        ) -> Dict[str, BootstrapResult]:
        """边Bootstrap: 重抽样边集估计节点风险的置信区间。

        对每次bootstrap: 从原始边集中有放回抽样|E|条边，构建新图。
        """
        random.seed(self._seed)
        edge_list = list(self._graph._edges.items())  # [(key, edge)]
        n_edges = len(edge_list)
        node_ids = list(self._graph._nodes.keys())

        if n_edges == 0:
            return {}

        # 基准
        base_scores = risk_fn(self._graph)

        # 初始化累加器
        boot_samples: Dict[str, List[float]] = {nid: [] for nid in node_ids}

        for b in range(self._B):
            # 有放回抽样 |E| 条边
            sampled = [edge_list[random.randint(0, n_edges - 1)]
                      for _ in range(n_edges)]

            boot_graph = self._build_bootstrap_graph(sampled)
            try:
                scores = risk_fn(boot_graph)
            except Exception:
                continue

            for nid in node_ids:
                boot_samples[nid].append(scores.get(nid, base_scores.get(nid, 0.5)))

        return self._compute_results(node_ids, base_scores, boot_samples)

    def bootstrap_nodes(self,
                        risk_fn: Callable[[PropagationGraph], Dict[str, float]]
                        ) -> Dict[str, BootstrapResult]:
        """节点Bootstrap: 重抽样节点子集估计稳定性。"""
        random.seed(self._seed)
        node_list = list(self._graph._nodes.items())  # [(nid, node)]
        n_nodes = len(node_list)
        if n_nodes == 0:
            return {}

        base_scores = risk_fn(self._graph)
        node_ids = list(self._graph._nodes.keys())
        boot_samples: Dict[str, List[float]] = {nid: [] for nid in node_ids}

        for b in range(self._B):
            sampled_nodes = [node_list[random.randint(0, n_nodes - 1)]
                           for _ in range(n_nodes)]
            seen = set()
            unique_nodes = []
            for nid, node in sampled_nodes:
                if nid not in seen:
                    seen.add(nid)
                    unique_nodes.append((nid, node))

            boot_graph = PropagationGraph(max_nodes=self._graph._max_nodes)
            for nid, node in unique_nodes:
                boot_graph.add_node(VulnNode(
                    node_id=nid, layer=node.layer,
                    vuln_type=node.vuln_type, severity=node.severity,
                    entity_ref=node.entity_ref, metadata=dict(node.metadata),
                ))
            # 添加原始边(两端节点都存在时)
            for (src, tgt), edge in self._graph._edges.items():
                if src in seen and tgt in seen:
                    try:
                        boot_graph.add_edge(src, tgt, edge.confidence, edge.rule_name)
                    except (KeyError, ValueError):
                        pass

            try:
                scores = risk_fn(boot_graph)
            except Exception:
                continue
            for nid in node_ids:
                boot_samples[nid].append(scores.get(nid, base_scores.get(nid, 0.5)))

        return self._compute_results(node_ids, base_scores, boot_samples)

    def bootstrap_residual(self,
                           risk_fn: Callable[[PropagationGraph], Dict[str, float]],
                           residual_std: float = 0.05
                           ) -> Dict[str, BootstrapResult]:
        """残差Bootstrap: 保持图结构不变, 对边置信度加残差噪声。"""
        random.seed(self._seed)
        node_ids = list(self._graph._nodes.keys())
        base_scores = risk_fn(self._graph)

        if not node_ids:
            return {}

        boot_samples: Dict[str, List[float]] = {nid: [] for nid in node_ids}

        for b in range(self._B):
            boot_graph = PropagationGraph(max_nodes=self._graph._max_nodes)
            for nid, node in self._graph._nodes.items():
                boot_graph.add_node(VulnNode(
                    node_id=nid, layer=node.layer,
                    vuln_type=node.vuln_type, severity=node.severity,
                    entity_ref=node.entity_ref, metadata=dict(node.metadata),
                ))
            for (src, tgt), edge in self._graph._edges.items():
                noise = random.gauss(0, residual_std)
                noisy_conf = max(0.01, min(0.99, edge.confidence + noise))
                try:
                    boot_graph.add_edge(src, tgt, noisy_conf, edge.rule_name)
                except (KeyError, ValueError):
                    pass

            try:
                scores = risk_fn(boot_graph)
            except Exception:
                continue
            for nid in node_ids:
                boot_samples[nid].append(scores.get(nid, base_scores.get(nid, 0.5)))

        return self._compute_results(node_ids, base_scores, boot_samples)

    def bootstrap_path_blocks(self,
                              risk_fn: Callable[[PropagationGraph], Dict[str, float]],
                              max_paths_per_node: int = 3
                              ) -> Dict[str, BootstrapResult]:
        """路径块Bootstrap -- 以完整传播路径为抽样单元。

        与边Bootstrap的本质区别:
          边Bootstrap独立抽样每条边, 破坏传播路径的连续性。
          路径块Bootstrap提取所有极大路径, 整条路径作为一块抽样。
          这保持了同一条传播链上各边间的相关性结构——
          固件→内核→硬件的三跳路径不会在重抽样中被拆散。
        """
        random.seed(self._seed)
        node_ids = list(self._graph._nodes.keys())
        if not node_ids:
            return {}

        # 提取路径块: 每对(source, target)的最优路径
        path_blocks: List[Tuple[List[str], List[Tuple[str, str, float]]]] = []
        for src in node_ids:
            paths_found = 0
            for tgt in node_ids:
                if src == tgt or paths_found >= max_paths_per_node:
                    break
                raw = self._graph.find_propagation_paths(
                    src, tgt, max_paths=1, max_depth=5)
                if not raw:
                    continue
                path = raw[0]
                if len(path) < 2:
                    continue
                edges_in_path = []
                for k in range(len(path) - 1):
                    edge = self._graph._edges.get((path[k], path[k+1]))
                    if edge:
                        edges_in_path.append((path[k], path[k+1], edge.confidence))
                if edges_in_path:
                    path_blocks.append((path, edges_in_path))
                    paths_found += 1

        if not path_blocks:
            return self.bootstrap_edges(risk_fn)  # 回退到边Bootstrap

        base_scores = risk_fn(self._graph)
        boot_samples: Dict[str, List[float]] = {nid: [] for nid in node_ids}

        for b in range(self._B):
            # 有放回抽样路径块
            n_blocks = len(path_blocks)
            sampled_blocks = [path_blocks[random.randint(0, n_blocks - 1)]
                            for _ in range(max(1, n_blocks // 2))]

            boot_graph = PropagationGraph(max_nodes=self._graph._max_nodes)
            seen = set()
            for node_path, edge_list in sampled_blocks:
                for nid in node_path:
                    if nid not in seen and nid in self._graph._nodes:
                        node = self._graph._nodes[nid]
                        boot_graph.add_node(VulnNode(
                            node_id=nid, layer=node.layer,
                            vuln_type=node.vuln_type, severity=node.severity,
                            entity_ref=node.entity_ref,
                            metadata=dict(node.metadata),
                        ))
                        seen.add(nid)
                for src, tgt, conf in edge_list:
                    try:
                        boot_graph.add_edge(src, tgt, conf,
                            self._graph._edges.get((src, tgt),
                                type('E',(),{'rule_name':''})()).rule_name)
                    except (KeyError, ValueError):
                        pass

            try:
                scores = risk_fn(boot_graph)
            except Exception:
                continue
            for nid in node_ids:
                boot_samples[nid].append(scores.get(nid, base_scores.get(nid, 0.5)))

        return self._compute_results(node_ids, base_scores, boot_samples)

    def _build_bootstrap_graph(self,
                               sampled_edges: List[Tuple]) -> PropagationGraph:
        """从抽样边集构建bootstrap传播图。"""
        g = PropagationGraph(max_nodes=self._graph._max_nodes)
        seen_nodes = set()

        for (src, tgt), edge in sampled_edges:
            for nid in (src, tgt):
                if nid not in seen_nodes and nid in self._graph._nodes:
                    node = self._graph._nodes[nid]
                    g.add_node(VulnNode(
                        node_id=nid, layer=node.layer,
                        vuln_type=node.vuln_type, severity=node.severity,
                        entity_ref=node.entity_ref, metadata=dict(node.metadata),
                    ))
                    seen_nodes.add(nid)
            try:
                g.add_edge(src, tgt, edge.confidence, edge.rule_name)
            except (KeyError, ValueError):
                pass
        return g

    def _compute_results(self, node_ids: List[str],
                         base: Dict[str, float],
                         samples: Dict[str, List[float]]
                         ) -> Dict[str, BootstrapResult]:
        """从bootstrap样本计算CI和统计量。"""
        results = {}
        alpha_half = self._alpha / 2.0

        for nid in node_ids:
            vals = sorted(samples.get(nid, []))
            m = len(vals)
            if m < 10:
                results[nid] = BootstrapResult(
                    node_id=nid,
                    point_estimate=base.get(nid, 0.5),
                    bootstrap_mean=0.0, bootstrap_std=0.0,
                    ci_lower=0.0, ci_upper=1.0, bias=0.0,
                )
                continue

            mean_boot = sum(vals) / m
            var_boot = sum((v - mean_boot)**2 for v in vals) / max(m - 1, 1)
            std_boot = math.sqrt(max(var_boot, 0.0))

            lo_idx = max(0, int(alpha_half * m))
            hi_idx = min(m - 1, int((1.0 - alpha_half) * m))

            results[nid] = BootstrapResult(
                node_id=nid,
                point_estimate=base.get(nid, 0.5),
                bootstrap_mean=round(mean_boot, 4),
                bootstrap_std=round(std_boot, 4),
                ci_lower=round(vals[lo_idx], 4),
                ci_upper=round(vals[hi_idx], 4),
                bias=round(mean_boot - base.get(nid, 0.5), 4),
            )

        return results
