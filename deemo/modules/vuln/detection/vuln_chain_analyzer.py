# 漏洞链分析器——在程序依赖图中发现多步漏洞利用路径。
# 参考Cascaded Vulnerability Attacks (arXiv:2601.20158) 的HGAT图建模
# 和多步CVE链预测方法。
#
# 核心思想:
#   单个低危漏洞可能自身危害有限，但通过程序调用图和数据流图
#   组合多个漏洞形成利用链，最终效果相当于高危甚至严重漏洞。
#
# 方法:
#   1. 将每个漏洞标记为图中的节点（属性: CWE类型、CVSS评分、位置）
#   2. 构建节点间的边——基于调用可达性（A的崩溃可控制B的输入）
#   3. 遍历图寻找从入口点到高价值目标（敏感函数、特权操作）的路径
#   4. 路径评分: 累乘可达概率 × 目标节点的影响权重
#   5. 报告Top-K最危险的漏洞链
#
# 2026-07-29 —— 初版，调用图BFS+可达性分析

import os, json, logging, heapq, math
from typing import Dict, List, Optional, Any, Tuple, Set, Iterator
from dataclasses import dataclass, field
from collections import defaultdict, deque
from itertools import combinations

logger = logging.getLogger(__name__)


@dataclass
class VulnNode:
    """图中的单个漏洞节点。"""
    node_id: str
    vuln_type: str                    # CWE类型
    cve_id: str = ""
    function_name: str = ""
    address: int = 0
    severity: str = "MEDIUM"
    cvss_score: float = 5.0
    # 节点属性
    is_entry_point: bool = False      # 是否为外部输入入口
    is_high_value_target: bool = False  # 是否为高价值目标（特权操作、密钥访问等）
    prerequisites: List[str] = field(default_factory=list)  # 触发此漏洞的前置条件
    effects: List[str] = field(default_factory=list)        # 利用后的效果
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ChainEdge:
    """漏洞链中的边——表示从前驱漏洞到后继漏洞的可达路径。"""
    from_node: str
    to_node: str
    edge_type: str = "call_reachable"  # call_reachable / data_flow / shared_state
    distance: int = 1                  # 调用距离（直接调用=1）
    confidence: float = 1.0            # 边存在置信度
    intermediate_nodes: List[str] = field(default_factory=list)


@dataclass
class VulnChain:
    """一条漏洞利用链——从入口点到目标的一系列漏洞节点。"""
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
    """漏洞链分析的总产出。"""
    chains: List[VulnChain] = field(default_factory=list)
    total_nodes: int = 0
    total_edges: int = 0
    entry_points: List[VulnNode] = field(default_factory=list)
    high_value_targets: List[VulnNode] = field(default_factory=list)
    max_chain_depth: int = 0
    statistics: Dict[str, Any] = field(default_factory=dict)


class VulnChainAnalyzer:
    """漏洞链分析器——在程序依赖图中发现多步漏洞利用路径。

    算法:
        1. 构建漏洞图（VulnNode + call graph可达性 = ChainEdge）
        2. 从每个入口点BFS遍历到所有可达的高价值目标
        3. 路径评分 = Π(节点利用概率) × 目标影响权重
        4. Top-K排序返回最危险链

    复杂度: O(|V|×(|V|+|E|)) = O(n²) —— 每个入口点一次BFS
    对大型程序（>10K函数）使用限制depth=5的截断BFS。
    """

    def __init__(self, max_chain_depth: int = 5,
                  min_chain_score: float = 0.01):
        self.max_depth = max_chain_depth
        self.min_score = min_chain_score

    def analyze(self, vulnerabilities: List[VulnNode],
                call_graph: Dict[str, List[str]] = None,
                data_flow_edges: Dict[str, List[str]] = None) -> ChainAnalysisResult:
        """分析漏洞链。

        参数:
            vulnerabilities: 漏洞节点列表
            call_graph: {caller_func: [callee_func, ...]} 调用图
            data_flow_edges: {src_func: [dst_func, ...]} 数据流边

        返回ChainAnalysisResult。
        """
        call_graph = call_graph or {}
        data_flow_edges = data_flow_edges or {}

        # 索引: function_name → VulnNode
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

        # 自动标记: 无入边的函数可能为入口点
        all_callers = set()
        for callees in call_graph.values():
            all_callers.update(callees)
        for func in call_graph:
            if func not in all_callers and func in vuln_by_func:
                vn = vuln_by_func[func]
                if not vn.is_entry_point:
                    vn.is_entry_point = True
                    entry_pts.append(vn)

        # 构建可达性闭包——每个函数的可达函数集合
        reachable = self._compute_reachability(call_graph, self.max_depth)

        # 构建漏洞间边
        edges = self._build_vuln_edges(vuln_by_func, reachable, call_graph,
                                        data_flow_edges)

        # 寻找漏洞链——从每个入口BFS
        all_chains = []
        for entry in entry_pts:
            chains_from_entry = self._find_chains_from(
                entry, targets, vuln_by_func, reachable, edges,
                call_graph, self.max_depth)
            all_chains.extend(chains_from_entry)

        # 如果没有明确入口/目标，使用全节点对
        if not all_chains and len(vulnerabilities) >= 2:
            for vn_a, vn_b in combinations(vulnerabilities, 2):
                key_a = vn_a.function_name or vn_a.node_id
                key_b = vn_b.function_name or vn_b.node_id
                if key_b in reachable.get(key_a, set()):
                    chain = self._make_chain([vn_a, vn_b],
                        [ChainEdge(from_node=vn_a.node_id, to_node=vn_b.node_id,
                                   distance=1, confidence=0.5)])
                    all_chains.append(chain)

        # 去重&排序
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
        """计算调用图的可达性闭包。

        每节点BFS限max_depth步——避免在深调用栈中过度展开。
        """
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
        """构建漏洞间的边——如果前驱所在函数可达后继所在函数。"""
        edges = []
        funcs = list(vuln_by_func.keys())

        for i, fa in enumerate(funcs):
            for fb in funcs[i + 1:]:
                # A可达B则A→B，B可达A则B→A
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
        """估计调用距离——BFS最短路径长度。"""
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
        """从给定入口点出发寻找所有到目标的漏洞链。"""
        chains = []
        entry_key = entry.function_name or entry.node_id

        for target in targets:
            target_key = target.function_name or target.node_id
            # 入口必须可达目标
            if target_key not in reachable.get(entry_key, set()):
                continue

            # 寻找路径上的中间漏洞节点
            path_nodes = self._find_intermediate_vulns(
                entry, target, vuln_by_func, reachable, call_graph, max_depth)

            if len(path_nodes) < 2:
                continue

            # 构建链边
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
        """在入口到目标的路径上寻找中间漏洞。"""
        # 简化: 取所有同时可达入口和目标的漏洞
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
        """从节点和边列表构建VulnChain。"""
        score = 1.0
        # 节点分数: cvss归一化 × 利用概率
        for vn in nodes:
            exploit_prob = self._cwe_exploit_prob(vn.vuln_type)
            score *= (vn.cvss_score / 10.0) * exploit_prob

        for e in edges:
            score *= e.confidence

        # 链长度惩罚——越长越不确定
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
        """CWE类型的估计利用概率——基于CISA KEV统计的先验。"""
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
        """去重——同一组节点集合的不同排列视为重复。"""
        seen = set()
        unique = []
        for chain in chains:
            sig = tuple(sorted(vn.node_id for vn in chain.nodes))
            if sig not in seen:
                seen.add(sig)
                unique.append(chain)
        return unique


# ---- 便捷函数 ----

def analyze_vulnerability_chains(vulnerabilities: List[VulnNode],
                                  call_graph: Dict[str, List[str]] = None,
                                  max_depth: int = 5) -> ChainAnalysisResult:
    """分析漏洞链的便捷入口。"""
    return VulnChainAnalyzer(max_chain_depth=max_depth).analyze(
        vulnerabilities, call_graph)


def build_vuln_node(vuln_type: str, function_name: str = "",
                      cve_id: str = "", cvss: float = 5.0,
                      severity: str = "MEDIUM", address: int = 0,
                      is_entry: bool = False,
                      is_target: bool = False) -> VulnNode:
    """构建VulnNode的工厂函数。"""
    return VulnNode(
        node_id=f"VULN_{function_name or vuln_type}_{address or '0'}",
        vuln_type=vuln_type, cve_id=cve_id,
        function_name=function_name, address=address,
        severity=severity, cvss_score=cvss,
        is_entry_point=is_entry, is_high_value_target=is_target)
