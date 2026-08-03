# 漏洞链分析器——程序依赖图中多步利用路径发现。
# 基于HGAT图建模（Cascaded Vulnerability Attacks, arXiv:2601.20158）。
#
# 核心逻辑:
#   单点低危漏洞危害有限，但经由调用图与数据流图组合多个漏洞
#   形成利用链，可达高危甚至严重级效果。
#
# 执行流程:
#   1. 漏洞标记为图节点（属性: CWE类型、CVSS评分、位置）
#   2. 节点间建边——基于调用可达性（A的崩溃可控制B的输入）
#   3. 图遍历寻找入口点到高价值目标（敏感函数、特权操作）的路径
#   4. 路径评分 = 累乘可达概率 × 目标节点影响权重
#   5. 输出Top-K最危险漏洞链
#
# 初版实现——调用图BFS + 可达性分析

import os, json, logging, heapq, math
from typing import Dict, List, Optional, Any, Tuple, Set, Iterator
from dataclasses import dataclass, field
from collections import defaultdict, deque
from itertools import combinations

logger = logging.getLogger(__name__)


@dataclass
class VulnNode:
    """漏洞节点——图中单点漏洞实体。"""
    node_id: str
    vuln_type: str                    # CWE类型标识
    cve_id: str = ""
    function_name: str = ""
    address: int = 0
    severity: str = "MEDIUM"
    cvss_score: float = 5.0
    # 节点角色标记
    is_entry_point: bool = False      # 外部输入入口
    is_high_value_target: bool = False  # 高价值目标（特权操作、密钥访问等）
    prerequisites: List[str] = field(default_factory=list)  # 触发前置条件
    effects: List[str] = field(default_factory=list)        # 利用后产生效果
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ChainEdge:
    """链边——前驱漏洞到后继漏洞的可达路径。"""
    from_node: str
    to_node: str
    edge_type: str = "call_reachable"  # 边类型: call_reachable / data_flow / shared_state
    distance: int = 1                  # 调用距离（直接调用 = 1）
    confidence: float = 1.0            # 边存在置信度
    intermediate_nodes: List[str] = field(default_factory=list)


@dataclass
class VulnChain:
    """漏洞利用链——从入口到目标的漏洞节点有序序列。"""
    chain_id: str
    nodes: List[VulnNode] = field(default_factory=list)
    edges: List[ChainEdge] = field(default_factory=list)
    total_score: float = 0.0
    chain_length: int = 0
    entry_function: str = ""
    target_function: str = ""
    combined_cvss: float = 0.0
    exploitation_complexity: str = "UNKNOWN"


@dataclass
class ChainAnalysisResult:
    """链分析输出——所有利用链及统计信息聚合体。"""
    chains: List[VulnChain] = field(default_factory=list)
    total_nodes: int = 0
    total_edges: int = 0
    entry_points: List[VulnNode] = field(default_factory=list)
    high_value_targets: List[VulnNode] = field(default_factory=list)
    max_chain_depth: int = 0
    statistics: Dict[str, Any] = field(default_factory=dict)


class VulnChainAnalyzer:
    """漏洞链分析器——程序依赖图中多步利用路径发掘。

    算法:
        1. 构建漏洞图（VulnNode + 调用图可达性边 = ChainEdge）
        2. 每个入口点BFS遍历至所有可达的高价值目标
        3. 路径评分 = Π(节点利用概率) × 目标影响权重
        4. Top-K排序返回最危险链

    复杂度: O(|V|×(|V|+|E|)) = O(n²)，每入口点一次BFS。
    大型程序（>10K函数）启用depth=5截断BFS。
    """

    def __init__(self, max_chain_depth: int = 5,
                  min_chain_score: float = 0.01):
        self.max_depth = max_chain_depth
        self.min_score = min_chain_score

    def analyze(self, vulnerabilities: List[VulnNode],
                call_graph: Dict[str, List[str]] = None,
                data_flow_edges: Dict[str, List[str]] = None) -> ChainAnalysisResult:
        """执行漏洞链分析。

        参数:
            vulnerabilities: 漏洞节点列表
            call_graph: {调用者函数: [被调用者函数列表]} 调用图
            data_flow_edges: {源函数: [目标函数列表]} 数据流边

        返回ChainAnalysisResult。
        """
        call_graph = call_graph or {}
        data_flow_edges = data_flow_edges or {}

        # 建立函数名到VulnNode的索引
        vuln_by_func: Dict[str, VulnNode] = {}
        entry_pts = []
        targets = []
        for vn in vulnerabilities:
            key = vn.function_name or vn.node_id
            vuln_by_func[key] = vn
            if vn.is_entry_point:
                entry_pts.append(vn)
            if vn.is_high_value_target:
                targets.append(vn)

        # 自动标记：无入边的函数归类为潜在入口点
        all_callers = set()
        for callees in call_graph.values():
            all_callers.update(callees)
        for func in call_graph:
            if func not in all_callers and func in vuln_by_func:
                vn = vuln_by_func[func]
                if not vn.is_entry_point:
                    vn.is_entry_point = True
                    entry_pts.append(vn)

        # 可达性闭包计算——每函数其可达函数集合
        reachable = self._compute_reachability(call_graph, self.max_depth)

        # 基于可达性构建漏洞间边
        edges = self._build_vuln_edges(vuln_by_func, reachable, call_graph,
                                        data_flow_edges)

        # 从每个入口BFS发掘漏洞链
        all_chains = []
        for entry in entry_pts:
            chains_from_entry = self._find_chains_from(
                entry, targets, vuln_by_func, reachable, edges,
                call_graph, self.max_depth)
            all_chains.extend(chains_from_entry)

        # 无明确入口/目标时回退至全节点对
        if not all_chains and len(vulnerabilities) >= 2:
            for vn_a, vn_b in combinations(vulnerabilities, 2):
                key_a = vn_a.function_name or vn_a.node_id
                key_b = vn_b.function_name or vn_b.node_id
                if key_b in reachable.get(key_a, set()):
                    chain = self._make_chain([vn_a, vn_b],
                        [ChainEdge(from_node=vn_a.node_id, to_node=vn_b.node_id,
                                   distance=1, confidence=0.5)])
                    all_chains.append(chain)

        # 去重并降序排序
        all_chains = self._deduplicate_chains(all_chains)
        all_chains.sort(key=lambda c: c.total_score, reverse=True)

        return ChainAnalysisResult(
            chains=all_chains,
            total_nodes=len(vulnerabilities),
            total_edges=len(edges),
            entry_points=entry_pts,
            high_value_targets=targets,
            max_chain_depth=max((c.chain_length for c in all_chains), default=0),
            statistics={
                'total_chains': len(all_chains),
                'avg_chain_length': (sum(c.chain_length for c in all_chains)
                                     / max(len(all_chains), 1)),
                'top_score': all_chains[0].total_score if all_chains else 0.0,
            })

    def _compute_reachability(self, call_graph: Dict[str, List[str]],
                               max_depth: int) -> Dict[str, Set[str]]:
        """调用图可达性闭包——每节点BFS限max_depth步。"""
        reachable = {}
        all_funcs = set(call_graph.keys())
        for callers in call_graph.values():
            all_funcs.update(callers)

        for func in all_funcs:
            visited = set()
            q = deque([(func, 0)])
            while q:
                curr, depth = q.popleft()
                if depth > max_depth:
                    continue
                if curr in visited:
                    continue
                visited.add(curr)
                if curr != func:
                    reachable.setdefault(func, set()).add(curr)
                for callee in call_graph.get(curr, []):
                    if callee not in visited:
                        q.append((callee, depth + 1))
            reachable.setdefault(func, set())

        return reachable

    def _build_vuln_edges(self, vuln_by_func, reachable, call_graph,
                           data_flow_edges) -> List[ChainEdge]:
        """构建漏洞边——前驱所在函数可达后继所在函数时建立连接。"""
        edges = []
        funcs = list(vuln_by_func.keys())

        for i, fa in enumerate(funcs):
            for fb in funcs[i + 1:]:
                # A可达B则建A→B边，B可达A则建B→A边
                if fb in reachable.get(fa, set()):
                    dist = self._estimate_call_distance(fa, fb, call_graph)
                    edges.append(ChainEdge(
                        from_node=vuln_by_func[fa].node_id,
                        to_node=vuln_by_func[fb].node_id,
                        edge_type="call_reachable", distance=dist))

                if fa in reachable.get(fb, set()):
                    dist = self._estimate_call_distance(fb, fa, call_graph)
                    edges.append(ChainEdge(
                        from_node=vuln_by_func[fb].node_id,
                        to_node=vuln_by_func[fa].node_id,
                        edge_type="call_reachable", distance=dist))

        return edges

    def _estimate_call_distance(self, src, dst, call_graph, max_d=10) -> int:
        """调用距离估计——BFS最短路径长度。"""
        if src == dst:
            return 0
        visited = {src}
        q = deque([(src, 0)])
        while q:
            curr, dist = q.popleft()
            if dist >= max_d:
                continue
            for callee in call_graph.get(curr, []):
                if callee == dst:
                    return dist + 1
                if callee not in visited:
                    visited.add(callee)
                    q.append((callee, dist + 1))
        return max_d

    def _find_chains_from(self, entry: VulnNode, targets: List[VulnNode],
                           vuln_by_func, reachable, edges, call_graph,
                           max_depth) -> List[VulnChain]:
        """从指定入口点寻找所有可达目标的漏洞链。"""
        chains = []
        entry_key = entry.function_name or entry.node_id

        for target in targets:
            target_key = target.function_name or target.node_id
            # 入口必须可直接或间接到达目标
            if target_key not in reachable.get(entry_key, set()):
                continue

            # 路径上定位中间漏洞节点
            path_nodes = self._find_intermediate_vulns(
                entry, target, vuln_by_func, reachable, call_graph, max_depth)

            if len(path_nodes) < 2:
                continue

            # 按序构造链边
            chain_edges = []
            for i in range(len(path_nodes) - 1):
                a_key = path_nodes[i].function_name or path_nodes[i].node_id
                b_key = path_nodes[i + 1].function_name or path_nodes[i + 1].node_id
                dist = self._estimate_call_distance(a_key, b_key, call_graph)
                chain_edges.append(ChainEdge(
                    from_node=path_nodes[i].node_id,
                    to_node=path_nodes[i + 1].node_id,
                    distance=dist, confidence=1.0 / max(dist, 1)))

            chain = self._make_chain(path_nodes, chain_edges)
            if chain.total_score >= self.min_score:
                chains.append(chain)

        return chains

    def _find_intermediate_vulns(self, entry, target, vuln_by_func,
                                   reachable, call_graph, max_depth):
        """入口到目标路径上的中间漏洞集——取同时可达入口且可达目标的节点。"""
        entry_key = entry.function_name or entry.node_id
        target_key = target.function_name or target.node_id
        intermediates = [entry]

        for key, vn in vuln_by_func.items():
            if vn.node_id in (entry.node_id, target.node_id):
                continue
            from_entry = key in reachable.get(entry_key, set())
            to_target = target_key in reachable.get(key, set())
            if from_entry and to_target:
                intermediates.append(vn)

        intermediates.append(target)
        return intermediates

    def _make_chain(self, nodes, edges):
        """从节点及边列表构造VulnChain并计算综合评分。"""
        score = 1.0
        # 节点分数: CVSS归一化 × 利用概率
        for vn in nodes:
            exploit_prob = self._cwe_exploit_prob(vn.vuln_type)
            score *= (vn.cvss_score / 10.0) * exploit_prob

        for e in edges:
            score *= e.confidence

        # 链长度惩罚——路径越长不确定性越大
        length_penalty = 1.0 / math.sqrt(max(len(nodes), 1))
        score *= length_penalty

        combined_cvss = math.sqrt(
            sum(vn.cvss_score ** 2 for vn in nodes) / len(nodes))

        return VulnChain(
            chain_id=f"CHAIN_{nodes[0].node_id}_to_{nodes[-1].node_id}",
            nodes=nodes, edges=edges, total_score=round(score, 4),
            chain_length=len(nodes),
            entry_function=nodes[0].function_name,
            target_function=nodes[-1].function_name,
            combined_cvss=round(combined_cvss, 1),
            exploitation_complexity=self._assess_complexity(len(nodes),
                                                             combined_cvss))

    @staticmethod
    def _cwe_exploit_prob(cwe_type: str) -> float:
        """CWE类型利用概率估计——基于CISA KEV统计先验。"""
        probs = {
            'CWE-787': 0.85, 'CWE-79': 0.90, 'CWE-89': 0.92,
            'CWE-416': 0.75, 'CWE-78': 0.88, 'CWE-20': 0.60,
            'CWE-125': 0.70, 'CWE-22': 0.85, 'CWE-119': 0.72,
            'CWE-502': 0.70, 'CWE-77': 0.82, 'CWE-94': 0.75,
            'buffer_overflow': 0.72, 'use_after_free': 0.75,
            'format_string': 0.60, 'integer_overflow': 0.55,
        }
        return probs.get(cwe_type, probs.get(cwe_type.replace('_', ' '), 0.50))

    @staticmethod
    def _assess_complexity(length, cvss):
        if length <= 2 and cvss >= 7.0:
            return "LOW"
        elif length <= 3 and cvss >= 5.0:
            return "MEDIUM"
        return "HIGH"

    def _deduplicate_chains(self, chains):
        """链去重——同节点集合不同排列视为重复。"""
        seen = set()
        unique = []
        for chain in chains:
            sig = tuple(sorted(vn.node_id for vn in chain.nodes))
            if sig not in seen:
                seen.add(sig)
                unique.append(chain)
        return unique


# ---- 便捷入口 ----

def analyze_vulnerability_chains(vulnerabilities: List[VulnNode],
                                  call_graph: Dict[str, List[str]] = None,
                                  max_depth: int = 5) -> ChainAnalysisResult:
    """漏洞链分析便捷调用入口。"""
    return VulnChainAnalyzer(max_chain_depth=max_depth).analyze(
        vulnerabilities, call_graph)


def build_vuln_node(vuln_type: str, function_name: str = "",
                      cve_id: str = "", cvss: float = 5.0,
                      severity: str = "MEDIUM", address: int = 0,
                      is_entry: bool = False,
                      is_target: bool = False) -> VulnNode:
    """VulnNode构造工厂函数。"""
    return VulnNode(
        node_id=f"VULN_{function_name or vuln_type}_{address or '0'}",
        vuln_type=vuln_type, cve_id=cve_id,
        function_name=function_name, address=address,
        severity=severity, cvss_score=cvss,
        is_entry_point=is_entry, is_high_value_target=is_target)
