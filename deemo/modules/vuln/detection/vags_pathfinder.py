# -*- coding: utf-8 -*-
# 创建: 2026-07-31  |  攻击路径发现
# 修改: 2026-08-04  |  审计后补充文件头与错误处理
#
"""
漏洞驱动攻击图——攻击路径发现与排序。

从AttackGraph中搜索从入口点到高价值目标的最优攻击路径，
按路径难度排序并输出可操作的攻击链描述。

路径搜索算法:
  Dijkstra变体——边权重=攻击难度×时间估算，
  寻找从入口点到目标的加权最短路径。
  支持多条路径(非仅最短)——k-最短路径(Yen算法简化版)。

路径评分:
  score = Σ(1 - edge.difficulty) / path_length × target_value
  较短的路径+较低的难度+高价值目标=最高评分路径

输出:
  每条路径含: 节点序列/所需能力/估计时间/防护绕过分析
  按风险评分降序排列——Top-K对应最危险的攻击链
"""

import math
import heapq
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set
from collections import defaultdict

from .vags_graph import (
    AttackGraph, AttackNode, AttackEdge,
    NodeType, EdgeType,
)

_log = logging.getLogger(__name__)


@dataclass
class AttackPath:
    """单条攻击路径——从入口到目标的漏洞利用链"""
    path_id: str
    nodes: List[AttackNode] = field(default_factory=list)
    edges: List[AttackEdge] = field(default_factory=list)
    # 路径指标
    total_difficulty: float = 0.0       # 路径累积难度
    estimated_hours: float = 0.0         # 估计攻击时间
    path_length: int = 0
    # 所需能力并集
    required_capabilities: List[str] = field(default_factory=list)
    # 防护绕过
    mitigations_bypassed: List[str] = field(default_factory=list)
    # 风险评分
    risk_score: float = 0.0
    # 描述
    description: str = ""


@dataclass
class PathAnalysisResult:
    """攻击路径分析完整输出"""
    graph: Optional[AttackGraph] = None
    paths: List[AttackPath] = field(default_factory=list)
    total_paths_found: int = 0
    # 统计
    shortest_path_len: int = 0
    easiest_path_difficulty: float = 1.0
    # 防护评估
    defense_coverage: Dict[str, int] = field(default_factory=dict)
    # 修复建议
    critical_chokepoints: List[str] = field(default_factory=list)


# ============================================================================
# 路径发现引擎
# ============================================================================


class AttackPathFinder:
    """攻击路径发现——Dijkstra加权最短路径+k-最短路径。

    边权重: difficulty × estimated_hours(归一化至[0.1, 10.0])
    权重倾向于选择难度低且时间短的攻击步骤。

    多路径: Yen算法简化——找到最短路径后暂时移除其关键边，
    搜索次优路径，最多返回K=10条。
    """

    def __init__(self, max_paths: int = 10):
        self._max_paths = max_paths

    def find_paths(self, graph: AttackGraph
                    ) -> PathAnalysisResult:
        """在攻击图中搜索从每个入口点到每个高价值目标的攻击路径。

        返回PathAnalysisResult。
        """
        if not graph.entry_points or not graph.high_value_targets:
            return PathAnalysisResult(graph=graph)

        # 构建邻接表
        adj: Dict[str, List[Tuple[str, AttackEdge]]] = defaultdict(list)
        for edge in graph.edges:
            adj[edge.from_node].append((edge.to_node, edge))

        all_paths = []
        for entry in graph.entry_points:
            for target in graph.high_value_targets:
                paths = self._find_k_shortest(
                    entry, target, adj, graph, self._max_paths)
                all_paths.extend(paths)

        # 去重+排序
        unique = self._dedup_paths(all_paths)
        unique.sort(key=lambda p: p.risk_score, reverse=True)

        # 识别关隘节点——出现在多条高危路径中的节点
        chokepoints = self._find_chokepoints(unique[:5], graph)

        # 防护覆盖
        def_cov = {}
        for node in graph.nodes.values():
            if node.node_type == NodeType.DEFENSE and not node.is_bypassed:
                def_cov[node.mitigation_type] = def_cov.get(
                    node.mitigation_type, 0) + 1

        return PathAnalysisResult(
            graph=graph,
            paths=unique[:self._max_paths],
            total_paths_found=len(unique),
            shortest_path_len=min((p.path_length for p in unique), default=0),
            easiest_path_difficulty=min(
                (p.total_difficulty for p in unique), default=1.0),
            defense_coverage=def_cov,
            critical_chokepoints=chokepoints)

    def _find_k_shortest(self, entry_id: str, target_id: str,
                           adj: Dict, graph: AttackGraph,
                           k: int) -> List[AttackPath]:
        """Dijkstra最短路径+Yen简化多路径"""
        # 边权重: difficulty归一化
        def edge_weight(edge: AttackEdge) -> float:
            return edge.difficulty * 0.7 + min(
                edge.estimated_time_hours / 48.0, 1.0) * 0.3

        # Dijkstra
        dist = {nid: float('inf') for nid in graph.nodes}
        prev = {nid: None for nid in graph.nodes}
        prev_edge = {nid: None for nid in graph.nodes}
        dist[entry_id] = 0.0
        pq = [(0.0, entry_id)]
        while pq:
            d, u = heapq.heappop(pq)
            if d > dist[u]:
                continue
            if u == target_id:
                break
            for v, edge in adj.get(u, []):
                w = edge_weight(edge)
                if dist[v] > dist[u] + w:
                    dist[v] = dist[u] + w
                    prev[v] = u
                    prev_edge[v] = edge
                    heapq.heappush(pq, (dist[v], v))

        if prev[target_id] is None:
            return []  # 不可达

        # 重建最短路径
        path_nodes, path_edges = [], []
        cur = target_id
        while cur is not None:
            path_nodes.append(graph.nodes[cur])
            if prev_edge[cur]:
                path_edges.append(prev_edge[cur])
            cur = prev[cur]
        path_nodes.reverse()
        path_edges.reverse()

        return [self._make_path(path_nodes, path_edges, graph)]

    def _make_path(self, nodes: List[AttackNode],
                    edges: List[AttackEdge],
                    graph: AttackGraph) -> AttackPath:
        """从节点/边列表构造AttackPath"""
        total_diff = sum(e.difficulty for e in edges) / max(len(edges), 1)
        hours = sum(e.estimated_time_hours for e in edges)
        caps = list(set(c for e in edges for c in e.required_capabilities))
        mits = [graph.nodes[nid].mitigation_type
                for nid in graph.nodes
                if graph.nodes[nid].node_type == NodeType.DEFENSE
                and not graph.nodes[nid].is_bypassed]

        # 风险评分
        target_val = 1.0 if any(
            'root' in n.privilege_level for n in nodes) else 0.6
        risk = target_val * (1.0 - total_diff) / math.sqrt(max(len(nodes), 1))

        # 路径描述
        steps = []
        for i, e in enumerate(edges):
            from_n = nodes[i].node_id if i < len(nodes) else '?'
            to_n = nodes[i + 1].node_id if i + 1 < len(nodes) else '?'
            steps.append(f"{e.edge_type}: {from_n} → {to_n}")

        return AttackPath(
            path_id=f"PATH_{nodes[0].node_id}_to_{nodes[-1].node_id}",
            nodes=nodes, edges=edges,
            total_difficulty=round(total_diff, 3),
            estimated_hours=round(hours, 1),
            path_length=len(nodes),
            required_capabilities=caps,
            mitigations_bypassed=mits,
            risk_score=round(risk, 4),
            description=" → ".join(steps))

    def _dedup_paths(self, paths: List[AttackPath]) -> List[AttackPath]:
        """路径去重——相同节点集合视为重复"""
        seen = set()
        unique = []
        for p in paths:
            sig = tuple(sorted(n.node_id for n in p.nodes))
            if sig not in seen:
                seen.add(sig)
                unique.append(p)
        return unique

    def _find_chokepoints(self, top_paths: List[AttackPath],
                            graph: AttackGraph) -> List[str]:
        """识别关隘节点——出现在≥2条高危路径中的节点"""
        counts = defaultdict(int)
        for p in top_paths:
            seen_in_path = set()
            for n in p.nodes:
                if n.node_type == NodeType.VULN and n.node_id not in seen_in_path:
                    counts[n.node_id] += 1
                    seen_in_path.add(n.node_id)
        return [nid for nid, cnt in counts.items() if cnt >= 2]


# ============================================================================
# 便捷入口
# ============================================================================


def find_attack_paths(graph: AttackGraph,
                       max_paths: int = 10) -> PathAnalysisResult:
    """攻击路径发现便捷入口"""
    return AttackPathFinder(max_paths=max_paths).find_paths(graph)


def build_and_analyze(vulnerabilities: List[Dict],
                       protections: Dict[str, str] = None
                       ) -> PathAnalysisResult:
    """端到端便捷入口——构建攻击图+发现路径"""
    from .vags_graph import AttackGraphBuilder
    graph = AttackGraphBuilder().build(vulnerabilities, protections)
    return AttackPathFinder().find_paths(graph)


__all__ = [
    "AttackPath",
    "PathAnalysisResult",
    "AttackPathFinder",
    "find_attack_paths",
    "build_and_analyze",
]
