# 漏洞传播路径分析器——基于程序依赖图DFS可达性传播。
# 参考ReposVul(ASE'22)依赖传播模型：CVE从源函数沿调用边传播，
# 置信度沿边累积衰减，<0.1时剪枝控制状态空间膨胀。
# nx.all_simple_paths以cutoff限制路径深度，防止大型图组合爆炸。

import os, logging
from typing import Dict, List, Any, Set, Optional
from dataclasses import dataclass, field
import networkx as nx

logger = logging.getLogger(__name__)


@dataclass
class VulnerabilityNode:
    node_id: str
    node_type: str
    name: str
    description: str = ""
    severity: str = 'medium'
    is_source: bool = False
    is_sink: bool = False


@dataclass
class PropagationEdge:
    source: str
    target: str
    edge_type: str
    confidence: float = 1.0


@dataclass
class PropagationResult:
    vulnerability_id: str
    source_node: str
    propagation_graph: nx.DiGraph
    affected_nodes: List[str]
    critical_paths: List[List[str]]
    summary: str


class VulnPropagationAnalyzer:
    def __init__(self, binary_path: str = ""):
        self.binary_path = binary_path
        self.propagation_graph = nx.DiGraph()
        self.vulnerability_nodes: Dict[str, VulnerabilityNode] = {}
        self.affected_functions: Set[str] = set()

    def build_dependency_graph(self, binary_analysis: Dict) -> None:
        self.propagation_graph.clear()
        if 'functions' in binary_analysis:
            for func_name, func_info in binary_analysis['functions'].items():
                self._add_function_node(func_name, func_info)
                if 'calls' in func_info:
                    for called_func in func_info['calls']:
                        self.propagation_graph.add_edge(
                            func_name, called_func,
                            edge_type='call', confidence=1.0)
        if 'data_flows' in binary_analysis:
            for flow in binary_analysis['data_flows']:
                self.propagation_graph.add_edge(
                    flow['source'], flow['target'],
                    edge_type='data_flow',
                    confidence=flow.get('confidence', 1.0))
        if 'memory_regions' in binary_analysis:
            for region in binary_analysis['memory_regions']:
                self._add_memory_node(region)

    def _add_function_node(self, name: str, info: Dict) -> None:
        node = VulnerabilityNode(
            node_id=f"func_{name}", node_type='function',
            name=name,
            description=info.get('description', f"函数: {name}"),
            severity='low')
        self.vulnerability_nodes[node.node_id] = node
        self.propagation_graph.add_node(node.node_id, **node.__dict__)

    def _add_memory_node(self, region: Dict) -> None:
        node_id = f"mem_{region.get('name', 'unknown')}"
        node = VulnerabilityNode(
            node_id=node_id, node_type='memory',
            name=region.get('name', 'unknown'),
            description=region.get('description', "内存区域"),
            severity='low')
        self.vulnerability_nodes[node_id] = node
        self.propagation_graph.add_node(node_id, **node.__dict__)

    def add_vulnerability_source(self, vuln_info: Dict) -> str:
        node_id = f"vuln_{vuln_info.get('id', 'unknown')}"
        node = VulnerabilityNode(
            node_id=node_id, node_type='vulnerability',
            name=vuln_info.get('name', '未知漏洞'),
            description=vuln_info.get('description', ''),
            severity=vuln_info.get('severity', 'medium'),
            is_source=True)
        self.vulnerability_nodes[node_id] = node
        self.propagation_graph.add_node(node_id, **node.__dict__)
        if 'location' in vuln_info:
            location = vuln_info['location']
            if location.startswith('0x'):
                location = f"func_{location}"
            self.propagation_graph.add_edge(
                node_id, location, edge_type='data_flow', confidence=0.95)
        return node_id

    def propagate_vulnerability(self, source_node_id: str) -> List[List[str]]:
        affected_nodes = set()
        visited = set()

        def dfs(node_id, path, confidence):
            if node_id in visited or confidence < 0.1:
                return
            visited.add(node_id)
            if node_id != source_node_id:
                affected_nodes.add(node_id)
            for _, target, data in self.propagation_graph.out_edges(node_id, data=True):
                edge_confidence = data.get('confidence', 1.0)
                dfs(target, path + [target], confidence * edge_confidence)

        dfs(source_node_id, [source_node_id], 1.0)
        self.affected_functions = {n for n in affected_nodes if n.startswith('func_')}
        return self._find_critical_paths(source_node_id)

    def _find_critical_paths(self, source_node_id: str) -> List[List[str]]:
        critical_paths = []
        sink_nodes = [
            n for n in self.propagation_graph.nodes
            if self.propagation_graph.nodes[n].get('node_type') == 'memory' or
               self.propagation_graph.out_degree(n) == 0]
        # cutoff=8限制路径深度，防止组合爆炸。
        for sink in sink_nodes[:5]:
            try:
                for path in nx.all_simple_paths(
                    self.propagation_graph, source_node_id, sink, cutoff=8):
                    if len(path) >= 2:
                        critical_paths.append(path)
            except nx.NetworkXNoPath:
                continue
        return sorted(critical_paths, key=len, reverse=True)[:10]

    def analyze(self, vuln_info: Dict, binary_analysis: Dict) -> PropagationResult:
        self.build_dependency_graph(binary_analysis)
        source_node_id = self.add_vulnerability_source(vuln_info)
        critical_paths = self.propagate_vulnerability(source_node_id)
        summary = self._generate_summary(vuln_info, critical_paths)
        return PropagationResult(
            vulnerability_id=vuln_info.get('id', 'unknown'),
            source_node=source_node_id,
            propagation_graph=self.propagation_graph,
            affected_nodes=list(self.affected_functions),
            critical_paths=critical_paths, summary=summary)

    def _generate_summary(self, vuln_info: Dict,
                           critical_paths: List[List[str]]) -> str:
        parts = []
        parts.append(f"漏洞: {vuln_info.get('name', 'Unknown')}")
        parts.append(f"严重度: {vuln_info.get('severity', 'medium').upper()}")
        parts.append(f"受影响函数: {len(self.affected_functions)}")
        parts.append(f"关键传播路径: {len(critical_paths)}")
        if critical_paths:
            parts.append("\n主要传播路径:")
            for i, path in enumerate(critical_paths[:3], 1):
                path_desc = " -> ".join(self._retrieve_node_name(n) for n in path)
                parts.append(f"{i}. {path_desc}")
        return '\n'.join(parts)

    def _retrieve_node_name(self, node_id: str) -> str:
        if node_id in self.vulnerability_nodes:
            return self.vulnerability_nodes[node_id].name
        return node_id.replace('func_', '').replace('mem_', '')

    def generate_report(self, result: PropagationResult) -> str:
        lines = [
            "漏洞传播路径分析报告", "====================", "",
            f"漏洞ID: {result.vulnerability_id}",
            f"源节点: {result.source_node}",
            f"受影响函数数: {len(result.affected_nodes)}",
            f"关键路径数: {len(result.critical_paths)}",
            "", "摘要:", "-----", result.summary, ""]
        if result.affected_nodes:
            lines.append("受影响函数:")
            lines.append("------------")
            for func in sorted(result.affected_nodes):
                func_name = func.replace('func_', '')
                lines.append(f"- {func_name}")
        if result.critical_paths:
            lines.append("")
            lines.append("关键传播路径:")
            lines.append("-------------")
            for i, path in enumerate(result.critical_paths, 1):
                path_str = " -> ".join([self._retrieve_node_name(n) for n in path])
                lines.append(f"{i}. {path_str}")
        return '\n'.join(lines)


def analyze_vuln_propagation(vuln_info: Dict,
                               binary_analysis: Dict) -> PropagationResult:
    analyzer = VulnPropagationAnalyzer()
    return analyzer.analyze(vuln_info, binary_analysis)


def build_program_dependency_graph(functions: Dict[str, Any],
                                     data_flows: List[Dict[str, Any]],
                                     memory_regions: List[Dict[str, Any]] = None
                                     ) -> nx.DiGraph:
    analyzer = VulnPropagationAnalyzer()
    analyzer.build_dependency_graph({
        'functions': functions, 'data_flows': data_flows,
        'memory_regions': memory_regions or []})
    return analyzer.propagation_graph


def find_affected_functions(graph: nx.DiGraph, source_node: str) -> List[str]:
    affected = set()

    def dfs(node):
        if node in affected:
            return
        affected.add(node)
        for _, target in graph.out_edges(node):
            dfs(target)

    dfs(source_node)
    return [n for n in affected if n.startswith('func_')]
