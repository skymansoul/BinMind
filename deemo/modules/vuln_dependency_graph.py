"""
漏洞依赖图与连锁利用分析模块

功能:
    1. 构建不同漏洞之间的前置依赖关系 (如需要先信息泄露才能利用堆溢出)
    2. 自动发现多种漏洞组合成的攻击路径
    3. 可视化展示
    4. 计算整体可达概率

核心技术:
    - 有向图: 漏洞 -> 漏洞 (依赖)
    - 拓扑排序
    - 概率传播 (贝叶斯条件概率)
    - 图搜索 (BFS/DFS) 找攻击路径
"""

import logging
import os
import json
import re
import math
from typing import Dict, Any, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque

logger = logging.getLogger(__name__)


class VulnRole(Enum):
    """漏洞在攻击路径中的角色"""
    ENTRY = "entry"             # 入口点
    INFO_LEAK = "info_leak"     # 信息泄露
    PRIMITIVE = "primitive"     # 写原语 / 控制流劫持
    ESCALATION = "escalation"   # 提权 / 沙箱逃逸
    TARGET = "target"           # 目标
    INDEPENDENT = "independent"


@dataclass
class VulnNode:
    """漏洞节点"""
    vuln_id: str
    vuln_type: str
    exploitability: float = 0.5
    role: VulnRole = VulnRole.INDEPENDENT
    description: str = ""
    produces: List[str] = field(default_factory=list)   # 提供的"能力"
    requires: List[str] = field(default_factory=list)   # 需要的"能力"


@dataclass
class VulnEdge:
    """漏洞间依赖边"""
    src: str           # 提供方
    dst: str           # 依赖方
    weight: float      # 依赖强度 0-1
    reason: str = ""


@dataclass
class AttackPath:
    """一条攻击路径"""
    nodes: List[str]
    edges: List[Tuple[str, str]]
    probability: float
    description: str = ""


@dataclass
class DependencyGraph:
    """漏洞依赖图"""
    nodes: Dict[str, VulnNode] = field(default_factory=dict)
    edges: List[VulnEdge] = field(default_factory=list)
    adj: Dict[str, List[int]] = field(default_factory=lambda: defaultdict(list))   # src -> [edge_idx]
    rev: Dict[str, List[int]] = field(default_factory=lambda: defaultdict(list))   # dst -> [edge_idx]
    metadata: Dict[str, Any] = field(default_factory=dict)

    def add_node(self, node: VulnNode):
        self.nodes[node.vuln_id] = node

    def add_edge(self, edge: VulnEdge):
        idx = len(self.edges)
        self.edges.append(edge)
        self.adj[edge.src].append(idx)
        self.rev[edge.dst].append(idx)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'node_count': len(self.nodes),
            'edge_count': len(self.edges),
            'nodes': [
                {
                    'vuln_id': n.vuln_id,
                    'vuln_type': n.vuln_type,
                    'exploitability': n.exploitability,
                    'role': n.role.value,
                    'produces': n.produces,
                    'requires': n.requires
                }
                for n in self.nodes.values()
            ],
            'edges': [
                {
                    'src': e.src, 'dst': e.dst,
                    'weight': e.weight, 'reason': e.reason
                }
                for e in self.edges
            ]
        }


class DependencyGraphBuilder:
    """依赖图构建器"""

    ROLE_RULES = {
        "info_leak": VulnRole.INFO_LEAK,
        "format_string": VulnRole.INFO_LEAK,
        "use_after_free": VulnRole.PRIMITIVE,
        "buffer_overflow": VulnRole.PRIMITIVE,
        "heap_overflow": VulnRole.PRIMITIVE,
        "command_injection": VulnRole.TARGET,
        "path_traversal": VulnRole.TARGET,
        "race_condition": VulnRole.ESCALATION,
        "type_confusion": VulnRole.PRIMITIVE,
        "integer_overflow": VulnRole.PRIMITIVE
    }

    def __init__(self):
        self.graph = DependencyGraph()

    def add_vuln(self, vuln_id: str, vuln_type: str,
                 exploitability: float = 0.5,
                 produces: Optional[List[str]] = None,
                 requires: Optional[List[str]] = None,
                 description: str = "") -> VulnNode:
        role = self.ROLE_RULES.get(vuln_type.lower(), VulnRole.INDEPENDENT)
        node = VulnNode(
            vuln_id=vuln_id,
            vuln_type=vuln_type,
            exploitability=exploitability,
            role=role,
            description=description,
            produces=produces or [],
            requires=requires or []
        )
        self.graph.add_node(node)
        return node

    def auto_link(self):
        """基于 produces/requires 自动建立依赖边"""
        # 索引: capability -> [vuln_id 提供者]
        providers: Dict[str, List[str]] = defaultdict(list)
        for n in self.graph.nodes.values():
            for p in n.produces:
                providers[p].append(n.vuln_id)
        for n in self.graph.nodes.values():
            for req in n.requires:
                for prov in providers.get(req, []):
                    if prov == n.vuln_id:
                        continue
                    self.graph.add_edge(VulnEdge(
                        src=prov, dst=n.vuln_id,
                        weight=0.7, reason=f"requires {req}"
                    ))

    def to_dict(self) -> Dict[str, Any]:
        return self.graph.to_dict()


class AttackPathFinder:
    """攻击路径搜索"""

    def __init__(self, graph: DependencyGraph):
        self.graph = graph

    def find_paths_to(self, target: str, max_depth: int = 6) -> List[AttackPath]:
        """找到达 target 的所有路径"""
        if target not in self.graph.nodes:
            return []
        paths: List[AttackPath] = []
        # DFS 收集路径
        def dfs(cur: str, path: List[str], edges: List[Tuple[str, str]],
                visited: Set[str], depth: int):
            if depth > max_depth:
                return
            if cur == target and len(path) > 1:
                paths.append(AttackPath(
                    nodes=list(path),
                    edges=list(edges),
                    probability=self._compute_path_probability(path, edges)
                ))
                return
            # 找以 cur 为 dst 的边 (即能产出 cur 所需能力的)
            for ei in self.graph.rev.get(cur, []):
                e = self.graph.edges[ei]
                if e.src in visited:
                    continue
                visited.add(e.src)
                path.append(e.src)
                edges.append((e.src, cur))
                dfs(e.src, path, edges, visited, depth + 1)
                path.pop()
                edges.pop()
                visited.remove(e.src)
        dfs(target, [target], [], {target}, 0)
        paths.sort(key=lambda p: p.probability, reverse=True)
        return paths

    def _compute_path_probability(self, nodes: List[str],
                                  edges: List[Tuple[str, str]]) -> float:
        prob = 1.0
        for n in nodes:
            node = self.graph.nodes.get(n)
            if node:
                prob *= max(0.01, min(0.99, node.exploitability))
        for s, d in edges:
            for e in self.graph.edges:
                if e.src == s and e.dst == d:
                    prob *= max(0.1, min(1.0, e.weight))
                    break
        return prob

    def find_chain_exploits(self, top_n: int = 10) -> List[AttackPath]:
        """寻找最高概率的连锁利用链"""
        all_paths: List[AttackPath] = []
        for n in self.graph.nodes.values():
            if n.role == VulnRole.TARGET:
                all_paths.extend(self.find_paths_to(n.vuln_id))
        all_paths.sort(key=lambda p: p.probability, reverse=True)
        return all_paths[:top_n]


class GraphVisualizer:
    """图可视化 (DOT)"""

    @staticmethod
    def to_dot(graph: DependencyGraph,
               highlight_paths: Optional[List[AttackPath]] = None) -> str:
        lines = ["digraph vuln_dep {",
                 "  rankdir=LR;",
                 '  node [shape=box, style="rounded,filled"];']
        # 节点
        for vid, n in graph.nodes.items():
            color_map = {
                VulnRole.ENTRY: "#ffcccc",
                VulnRole.INFO_LEAK: "#cce5ff",
                VulnRole.PRIMITIVE: "#ffffcc",
                VulnRole.ESCALATION: "#ffccff",
                VulnRole.TARGET: "#ccffcc",
                VulnRole.INDEPENDENT: "#f0f0f0"
            }
            color = color_map.get(n.role, "#f0f0f0")
            label = f"{vid}\\n{n.vuln_type}\\nexp={n.exploitability:.2f}"
            lines.append(f'  "{vid}" [label="{label}", fillcolor="{color}"];')
        # 边
        for e in graph.edges:
            lines.append(
                f'  "{e.src}" -> "{e.dst}" '
                f'[label="{e.weight:.2f}"];'
            )
        # 高亮路径
        if highlight_paths:
            lines.append("  edge [color=red, penwidth=2.0];")
            for i, p in enumerate(highlight_paths[:3]):
                for a, b in p.edges:
                    lines.append(f'  "{a}" -> "{b}" '
                                 f'[label="path{i+1} p={p.probability:.2f}"];')
        lines.append("}")
        return "\n".join(lines)


def build_vuln_dependency_graph(
    vulns: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """便捷入口"""
    builder = DependencyGraphBuilder()
    for v in vulns:
        builder.add_vuln(
            vuln_id=v['id'],
            vuln_type=v.get('type', 'other'),
            exploitability=float(v.get('exploitability', 0.5)),
            produces=v.get('produces', []),
            requires=v.get('requires', []),
            description=v.get('description', '')
        )
    builder.auto_link()
    finder = AttackPathFinder(builder.graph)
    chains = finder.find_chain_exploits(top_n=10)
    return {
        'success': True,
        'graph': builder.to_dict(),
        'chains': [
            {
                'nodes': c.nodes,
                'edges': c.edges,
                'probability': c.probability
            }
            for c in chains
        ],
        'dot': GraphVisualizer.to_dot(builder.graph, chains)
    }
