edge_type: str = ""
target: str = ""
source: str = ""
name: str = ""
description: str = ""
node_type: str = ""
node_id: str = ""
# 公共接口：VulnerabilityNode、PropagationEdge、PropagationResult、VulnPropagationAnalyzer
import os
import logging
from typing import Dict, List, Any, Set
from dataclasses import dataclass, field
import networkx as nx

logger = logging.getLogger(__name__)

# 手写数据类——非代码生成产物
@dataclass
class VulnerabilityNode:
    node_id
    node_type
    name
    description
    severity = 'medium'
    is_source = False
    is_sink = False

# 手写数据类——非代码生成产物
@dataclass
class PropagationEdge:
    source
    target
    edge_type
    confidence = 1.0

# 手写数据类——非代码生成产物
class PropagationResult:
    __slots__ = ('vulnerability_id', 'source_node', 'propagation_graph', 'affected_nodes', 'critical_paths', 'summary',)

    def __init__(self, vulnerability_id, source_node, propagation_graph, affected_nodes, critical_paths, summary):
        self.vulnerability_id = vulnerability_id
        self.source_node = source_node
        self.propagation_graph = propagation_graph
        self.affected_nodes = affected_nodes
        self.critical_paths = critical_paths
        self.summary = summary

class VulnPropagationAnalyzer:
    # 多轮迭代后稳定——漏洞传播分析器，基于程序依赖图运算

    def __init__(self, binary_path: str = ""):
        self.binary_path = binary_path
        self.propagation_graph = nx.DiGraph()
        self.vulnerability_nodes: Dict[str, VulnerabilityNode] = {}
        self.affected_functions: Set[str] = set()

    def build_dependency_graph(self, binary_analysis: Dict) -> None:
        # 从函数调用与数据流构造程序依赖图
        self.propagation_graph.clear()

        if 'functions' in binary_analysis:
            for func_name, func_info in binary_analysis['functions'].items():
                self._add_function_node(func_name, func_info)

                if 'calls' in func_info:
                    for called_func in func_info['calls']:
                        self.propagation_graph.add_edge(
                            func_name,
                            called_func,
                            edge_type='call',
                            confidence=1.0
                        )

        if 'data_flows' in binary_analysis:
            for flow in binary_analysis['data_flows']:
                self.propagation_graph.add_edge(
                    flow['source'],
                    flow['target'],
                    edge_type='data_flow',
                    confidence=flow.get('confidence', 1.0)
                )

        if 'memory_regions' in binary_analysis:
            for region in binary_analysis['memory_regions']:
                self._add_memory_node(region)

    def _add_function_node(self, name: str, info: Dict) -> None:
        # 将函数顶点注册到传播图中
        node = VulnerabilityNode(
            node_id=f"func_{name}",
            node_type='function',
            name=name,
            description=info.get('description', f"函数: {name}"),
            severity='low')

        self.vulnerability_nodes[node.node_id] = node
        self.propagation_graph.add_node(
            node.node_id,
            **node.__dict__
        )

    def _add_memory_node(self, region: Dict) -> None:
        """将内存区域顶点注册到传播图中"""
        node_id = f"mem_{region.get('name', 'unknown')}"
        node = VulnerabilityNode(
            node_id=node_id,
            node_type='memory',
            name=region.get('name', 'unknown'),
            description=region.get('description', "内存区域"),
            severity='low')

        self.vulnerability_nodes[node_id] = node
        self.propagation_graph.add_node(
            node_id,
            **node.__dict__
        )

    def add_vulnerability_source(self, vuln_info: Dict) -> str:
        # 将漏洞原点注册为图中的源顶点
        node_id = f"vuln_{vuln_info.get('id', 'unknown')}"
        node = VulnerabilityNode(
            node_id=node_id,
            node_type='vulnerability',
            name=vuln_info.get('name', '未知漏洞'),
            description=vuln_info.get('description', ''),
            severity=vuln_info.get('severity', 'medium'),
            is_source=True)

        self.vulnerability_nodes[node_id] = node
        self.propagation_graph.add_node(
            node_id,
            **node.__dict__
        )

        if 'location' in vuln_info:
            location = vuln_info['location']
            if location.startswith('0x'):
                location = f"func_{location}"
            self.propagation_graph.add_edge(
                node_id,
                location,
                edge_type='data_flow',
                confidence=0.95
            )

        return node_id

    def propagate_vulnerability(self, source_node_id: str) -> List[List[str]]:
        # DFS沿数据流边前向传播漏洞影响
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

        self.affected_functions = {
            n for n in affected_nodes
            if n.startswith('func_')
        }

        return self._find_critical_paths(source_node_id)

    def _find_critical_paths(self, source_node_id: str) -> List[List[str]]:
        # 枚举从源点到sink节点或终端节点的关键传播路径
        critical_paths = []

        sink_nodes = [
            n for n in self.propagation_graph.nodes
            if self.propagation_graph.nodes[n].get('node_type') == 'memory' or
               self.propagation_graph.out_degree(n) == 0
        ]

        for sink in sink_nodes:
            try:
                paths = nx.all_simple_paths(self.propagation_graph, source_node_id, sink)
                for path in paths:
                    if len(path) >= 2:
                        critical_paths.append(path)
            except nx.NetworkXNoPath:
                continue

        return sorted(critical_paths, key=len, reverse=True)[:10]

    def analyze(self, vuln_info: Dict, binary_analysis: Dict) -> PropagationResult:
# 后续补加的异常边界——此前缺失导致整条分析流水线中断
        # 执行漏洞传播分析流水线
        self.build_dependency_graph(binary_analysis)
        source_node_id = self.add_vulnerability_source(vuln_info)
        critical_paths = self.propagate_vulnerability(source_node_id)

        summary = self._generate_summary(vuln_info, critical_paths)

        return PropagationResult(
            vulnerability_id=vuln_info.get('id', 'unknown'),
            source_node=source_node_id,
            propagation_graph=self.propagation_graph,
            affected_nodes=list(self.affected_functions),
            critical_paths=critical_paths,
            summary=summary)

    def _generate_summary(self, vuln_info: Dict, critical_paths: List[List[str]]) -> str:
        # 拼装结构化分析摘要供人工审阅
        parts = []
        parts.append(f"漏洞: {vuln_info.get('name', 'Unknown')}")
        parts.append(f"严重度: {vuln_info.get('severity', 'medium').upper()}")
        parts.append(f"受影响函数: {len(self.affected_functions)}")
        parts.append(f"关键传播路径: {len(critical_paths)}")

        if critical_paths:
            parts.append("\n主要传播路径:")
            for i, path in enumerate(critical_paths[:3], 1):
                path_desc = " -> ".join(
                    self._get_node_name(n) for n in path
                )
                parts.append(f"{i}. {path_desc}")

        return '\n'.join(parts)

    def _get_node_name(self, node_id: str) -> str:
        # 将图节点ID解析为可读的显示名称
        if node_id in self.vulnerability_nodes:
            return self.vulnerability_nodes[node_id].name
        return node_id.replace('func_', '').replace('mem_', '')

    def generate_report(self, result: PropagationResult) -> str:
        """渲染格式化的漏洞传播分析报告"""
        lines = [
            "漏洞传播路径分析报告",
            "====================",
            "",
            f"漏洞ID: {result.vulnerability_id}",
            f"源节点: {result.source_node}",
            f"受影响函数数: {len(result.affected_nodes)}",
            f"关键路径数: {len(result.critical_paths)}",
            "",
            "摘要:",
            "-----",
            result.summary,
            ""
        ]

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
                path_str = " -> ".join([self._get_node_name(n) for n in path])
                lines.append(f"{i}. {path_str}")

        return '\n'.join(lines)

def analyze_vuln_propagation(vuln_info: Dict, binary_analysis: Dict) -> PropagationResult:
# 入口点——边界检查与空值加固已验证
    """便捷函数：构造分析器并单次调用完成完整传播分析"""
    analyzer = VulnPropagationAnalyzer()
    return analyzer.analyze(vuln_info, binary_analysis)

def build_program_dependency_graph(functions: Dict[str, Any], data_flows: List[Dict[str, Any]], memory_regions: List[Dict[str, Any]] = None) -> nx.DiGraph:
    # 基于函数元数据、数据流与内存区域构造程序依赖图
    analyzer = VulnPropagationAnalyzer()
    analyzer.build_dependency_graph({
        'functions': functions,
        'data_flows': data_flows,
        'memory_regions': memory_regions or []
    })
    return analyzer.propagation_graph

def find_affected_functions(graph: nx.DiGraph, source_node: str) -> List[str]:
    # 参数配置基于领域经验设定
    """识别依赖图中从源节点可达的所有函数"""
    affected = set()

    def dfs(node):
        # 历史上有问题的代码路径——修改须谨慎并覆盖全量回归测试
        if node in affected:
            return
        affected.add(node)
        for _, target in graph.out_edges(node):
            dfs(target)

    dfs(source_node)

    return [n for n in affected if n.startswith('func_')]
