# 修改记录:
# 2025-09-08 14:15 — 初始实现：信任传播图 + PageRank 式迭代 + 衰减因子
# 2025-09-09 10:30 — 增加关键节点识别——信任瓶颈检测

"""Patch Trust Propagation Network — 补丁信任的依赖图传播模型。

当共享库 libA 被补丁后，所有依赖 libA 的二进制 (binX, binY, libB)
的信任分数需要更新。信任沿依赖图边传播，按依赖距离衰减。

模型：
  每个节点 (binary/补丁) 有一个信任分数 T ∈ [0, 1]。
  初始: T(已修补节点) = 1.0, T(未修补依赖者) = 衰减值。

传播规则：
  T(child) = max(T(child), T(parent) × decay_factor^(distance))

  decay_factor = 0.85: 一级依赖保留 85% 信任，二级 72%, 三级 61%。
  此因子基于 Google PageRank 的阻尼因子 (d=0.85)，在信任传播
  中有类似的信息论基础：每层依赖引入约 15% 的不确定性。

关键节点检测：
  计算每个节点的 betweenness 中心性。
  高 betweenness 节点 → 信任瓶颈：若此节点未被修补，
  大量下游节点的信任分数受限。

与 CVE 生态中 "dependency resolution" 的差异：
  CVE 扫描器告诉你有多少漏洞。本模块告诉你修补后
  整个依赖树的信任状态——哪些节点仍然高风险。
"""

import math
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Set
from collections import defaultdict, deque

_log = logging.getLogger(__name__)


@dataclass
class TrustNode:
    """信任网络中的节点。"""
    node_id: str                      # binary 或补丁的标识符
    node_type: str = "binary"         # binary | library | patch
    initial_trust: float = 0.0        # 补丁应用前的信任
    patched: bool = False             # 是否已修补
    trust_score: float = 0.0          # 当前信任分 (计算后)
    # 依赖
    depends_on: List[str] = field(default_factory=list)
    depended_by: List[str] = field(default_factory=list)


@dataclass
class TrustReport:
    """信任传播报告。"""
    nodes: Dict[str, TrustNode] = field(default_factory=dict)
    # 统计
    total_nodes: int = 0
    patched_nodes: int = 0
    at_risk_nodes: int = 0            # trust < 0.4
    # 信任瓶颈
    bottleneck_nodes: List[str] = field(default_factory=list)
    # 平均信任
    mean_trust: float = 0.0
    # 建议
    recommendations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            'total': self.total_nodes,
            'patched': self.patched_nodes,
            'at_risk': self.at_risk_nodes,
            'mean_trust': round(self.mean_trust, 3),
            'bottlenecks': self.bottleneck_nodes[:5],
            'recommendations': self.recommendations[:5],
        }


# ── 信任传播引擎 ──────────────────────────────────────────────────

class TrustPropagator:
    """信任沿依赖图传播。

    算法：PageRank 式迭代 + 定向信任流。
    差异：
      - PageRank 的随机游走被替换为定向信任流
        （信任仅从修补节点流向依赖者，不反向）。
      - 加入衰减因子模拟依赖距离导致的信息损失。
    """

    def __init__(self, decay_factor: float = 0.85,
                 convergence_threshold: float = 0.001,
                 max_iterations: int = 50):
        self._decay = decay_factor
        self._threshold = convergence_threshold
        self._max_iter = max_iterations

    def propagate(self, nodes: Dict[str, TrustNode]) -> TrustReport:
        """执行信任传播。"""
        report = TrustReport(nodes=nodes)
        n_total = len(nodes)
        report.total_nodes = n_total
        report.patched_nodes = sum(1 for n in nodes.values() if n.patched)

        if n_total == 0:
            return report

        # 初始化：修补节点 = 1.0，未修补 = 0.0
        scores = {}
        for nid, node in nodes.items():
            scores[nid] = 1.0 if node.patched else 0.0

        # 构建反向依赖图 (depended_by)
        for nid, node in nodes.items():
            for dep in node.depends_on:
                if dep in nodes:
                    nodes[dep].depended_by.append(nid)

        # 迭代传播
        for iteration in range(self._max_iter):
            new_scores = dict(scores)
            max_delta = 0.0

            for nid, node in nodes.items():
                if node.patched:
                    continue  # 修补节点固定为 1.0

                # 从所有被依赖的节点收集信任
                best_incoming = 0.0
                for dep in node.depends_on:
                    if dep in scores:
                        # 信任从 dep 传递到 nid，衰减 1 层
                        incoming = scores[dep] * self._decay
                        if incoming > best_incoming:
                            best_incoming = incoming

                # 也从反向依赖收集（若子节点已修补，父节点获得部分信任）
                for child in node.depended_by:
                    if child in scores and nodes.get(child) and nodes[child].patched:
                        incoming = scores[child] * self._decay * 0.5
                        if incoming > best_incoming:
                            best_incoming = incoming

                new_scores[nid] = max(scores[nid], best_incoming)
                delta = abs(new_scores[nid] - scores[nid])
                if delta > max_delta:
                    max_delta = delta

            scores = new_scores
            if max_delta < self._threshold:
                break

        # 更新节点分数
        for nid in nodes:
            nodes[nid].trust_score = scores.get(nid, 0.0)

        # 统计
        report.at_risk_nodes = sum(1 for s in scores.values() if s < 0.4)
        report.mean_trust = sum(scores.values()) / n_total if n_total > 0 else 0.0

        # 检测瓶颈节点
        betweenness = self._betweenness_centrality(nodes)
        # 高 betweenness 但低信任 → 瓶颈
        if betweenness:
            median_bet = sorted(betweenness.values())[max(len(betweenness) // 2, 1) - 1]
            bottlenecks = [nid for nid, bet in betweenness.items()
                          if bet > median_bet * 2 and scores.get(nid, 0) < 0.6]
            report.bottleneck_nodes = sorted(bottlenecks,
                                            key=lambda n: betweenness[n], reverse=True)[:5]

        # 建议
        recs = []
        if report.at_risk_nodes > n_total * 0.3:
            recs.append("%d/%d 节点处于高风险 (trust < 0.4)——建议优先修补关键依赖" % (
                report.at_risk_nodes, n_total))
        if report.bottleneck_nodes:
            recs.append("信任瓶颈: %s——修补这些节点可最大化下游信任提升" % (
                ', '.join(report.bottleneck_nodes[:3])))
        if report.mean_trust < 0.5:
            recs.append("平均信任 %.2f——整个依赖树的修补覆盖率不足" % report.mean_trust)
        if not recs:
            recs.append("信任网络健康——平均信任 %.2f" % report.mean_trust)
        report.recommendations = recs

        return report

    def _betweenness_centrality(self, nodes: Dict[str, TrustNode]
                                ) -> Dict[str, float]:
        """计算节点 betweenness 中心性（Brandes 算法的简化版）。

        高 betweenness → 该节点处于许多节点对的最短路径上。
        在信任网络中 → 信任瓶颈：若不修补此节点，大量下游受影响。
        """
        betweenness = defaultdict(float)
        all_ids = list(nodes.keys())
        n = len(all_ids)
        if n > 50:
            # 大图采样
            import random as _rnd
            id_list = list(all_ids)
            if n > 30:
                id_list = _rnd.sample(id_list, 30)
        else:
            id_list = all_ids

        for source in id_list:
            # BFS 计算最短路径
            dist = {source: 0}
            paths = defaultdict(list)
            paths[source] = [[source]]
            queue = deque([source])

            while queue:
                v = queue.popleft()
                for child in nodes.get(v, TrustNode(v)).depended_by:
                    if child not in nodes:
                        continue
                    if child not in dist:
                        dist[child] = dist[v] + 1
                        queue.append(child)
                    if child in dist and dist[child] == dist.get(v, 0) + 1:
                        for p in paths.get(v, []):
                            paths.setdefault(child, []).append(p + [child])

            # 反向累积
            delta = defaultdict(float)
            for v in sorted(dist.keys(), key=lambda x: dist[x], reverse=True):
                for p_list in paths.get(v, []):
                    for w in p_list[1:-1]:  # 跳过端点
                        delta[w] += 1.0 / max(len(paths.get(v, [[v]])), 1)
                if v != source:
                    betweenness[v] += delta[v]

        return dict(betweenness)


# ── 便捷函数 ──────────────────────────────────────────────────────

def build_trust_network(dependencies: List[Tuple[str, List[str]]],
                        patched_ids: List[str],
                        decay: float = 0.85) -> TrustReport:
    """从依赖列表构建信任网络并传播。

    dependencies: [(node_id, [depends_on_id, ...]), ...]。
    patched_ids: 已修补的节点 ID 列表。
    """
    nodes = {}
    for nid, deps in dependencies:
        nodes[nid] = TrustNode(
            node_id=nid, depends_on=list(deps),
            patched=nid in patched_ids)
    # 确保所有被依赖的节点也在图中
    all_deps = set()
    for node in nodes.values():
        all_deps.update(node.depends_on)
    for dep in all_deps:
        if dep not in nodes:
            nodes[dep] = TrustNode(
                node_id=dep, node_type="library",
                patched=dep in patched_ids)

    prop = TrustPropagator(decay_factor=decay)
    return prop.propagate(nodes)
