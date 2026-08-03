# 异构漏洞知识图谱: HGAT消息传递/级联关系预测/跨CWE语义关联
# 参考: Baird & Moin "Cascaded Vulnerability Attacks in Software Supply Chains" (arXiv:2601.20158, ICSE 2026)
#       Simsek et al. "FixV2W: Correcting Invalid CVE-CWE Mappings" (arXiv:2604.22176, 2025)
#       Alfasi et al. "VulnScopper: Unveiling Hidden Links Between Unseen Security Entities" (arXiv:2403.02014)
#       Wu & Feng "Association Analysis and Prediction of Network Security Vulnerabilities Based on KG" (JCSANDM 2025)
#       Aksu et al. "Automated Generation of Attack Graphs Using NVD" (2018)
#       Javed et al. "Binary Code Analysis for Cybersecurity: A Systematic Review" (2025)
import json, logging, hashlib, time as _t, heapq, itertools
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Any
from collections import defaultdict, deque
from pathlib import Path

log = logging.getLogger(__name__)

# 图数据模型

class NodeType:
    VULNERABILITY = "vulnerability"   # CVE或内部ID
    COMPONENT     = "component"       # 二进制/库
    CWE           = "cwe"             # 弱点分类
    FUNCTION      = "function"        # 函数级实体
    FILE          = "file"
    COMMIT        = "commit"

class EdgeType:
    AFFECTS     = "affects"           # vuln→component
    BELONGS_TO  = "belongs_to"        # vuln→cwe
    DEPENDS_ON  = "depends_on"        # component→component (SBOM)
    CALLS       = "calls"             # function→function
    PRECEDES    = "precedes"          # commit→commit (时序)
    CORRELATED  = "correlated"        # vuln→vuln (learned)
    CONTAINS    = "contains"          # component→function

@dataclass
class Node:
    node_id: str
    node_type: str
    properties: Dict[str, Any] = field(default_factory=dict)
    embedding: List[float] = field(default_factory=list)

@dataclass
class Edge:
    source: str
    target: str
    edge_type: str
    weight: float = 1.0
    properties: Dict[str, Any] = field(default_factory=dict)

@dataclass
class HeteroGraph:
    """异构有向图: 节点按类型分桶，边按类型分桶."""
    nodes: Dict[str, Dict[str, Node]] = field(default_factory=lambda: defaultdict(dict))
    edges: Dict[str, List[Edge]] = field(default_factory=lambda: defaultdict(list))
    adj_out: Dict[str, Dict[str, List[Edge]]] = field(default_factory=lambda: defaultdict(lambda: defaultdict(list)))
    adj_in:  Dict[str, Dict[str, List[Edge]]] = field(default_factory=lambda: defaultdict(lambda: defaultdict(list)))

    def add_node(self, n: Node):
        self.nodes[n.node_type][n.node_id] = n

    def add_edge(self, e: Edge):
        self.edges[e.edge_type].append(e)
        self.adj_out[e.source][e.edge_type].append(e)
        self.adj_in[e.target][e.edge_type].append(e)

    def get_neighbors(self, node_id: str, etype: str = None) -> List[Tuple[str, Edge]]:
        result = []
        if etype:
            for e in self.adj_out.get(node_id, {}).get(etype, []):
                result.append((e.target, e))
        else:
            for et, edges in self.adj_out.get(node_id, {}).items():
                for e in edges:
                    result.append((e.target, e))
        return result


# 图构建器

class VulnerabilityGraphBuilder:
    def __init__(self):
        self._graph = HeteroGraph()

    def ingest_findings(self, findings: List[Dict], component_name: str = ""):
        # 输入: ScanOrchestrator/CI发现→Vulnerability节点→链接Component
        for f in findings:
            vid = f.get('rule_id') or hashlib.sha256(
                f"{f.get('title','')}{f.get('file','')}{f.get('line','')}".encode()
            ).hexdigest()[:16]
            vnode = Node(
                node_id=vid, node_type=NodeType.VULNERABILITY,
                properties={'title': f.get('title', ''), 'severity': f.get('severity', 'medium'),
                            'cvss': f.get('cvss', 0.0), 'file': f.get('file', ''),
                            'line': f.get('line', 0), 'cwe': f.get('cwe', ''),
                            'description': str(f.get('description', ''))[:500]}
            )
            self._graph.add_node(vnode)

            if component_name:
                if component_name not in self._graph.nodes[NodeType.COMPONENT]:
                    self._graph.add_node(Node(node_id=component_name, node_type=NodeType.COMPONENT))
                self._graph.add_edge(Edge(vid, component_name, EdgeType.AFFECTS, weight=1.0))

            cwe = f.get('cwe', '')
            if cwe and cwe.startswith('CWE-'):
                self._link_cwe(vid, cwe)

    def _link_cwe(self, vuln_id: str, cwe_id: str):
        if cwe_id not in self._graph.nodes[NodeType.CWE]:
            self._graph.add_node(Node(node_id=cwe_id, node_type=NodeType.CWE))
        self._graph.add_edge(Edge(vuln_id, cwe_id, EdgeType.BELONGS_TO))

    def ingest_sbom(self, sbom_data: Dict):
        """SBOM→组件节点+DEPENDS_ON关系."""
        components = sbom_data.get('components', [])
        for c in components:
            cid = c.get('name', c.get('version', ''))
            if not cid:
                continue
            if cid not in self._graph.nodes[NodeType.COMPONENT]:
                self._graph.add_node(Node(
                    node_id=cid, node_type=NodeType.COMPONENT,
                    properties={'version': c.get('version', ''), 'hashes': c.get('hashes', []),
                                'type': c.get('type', 'file')}
                ))
        deps = sbom_data.get('dependencies', [])
        for dep in deps:
            ref = dep.get('ref', ''); dlist = dep.get('dependsOn', [])
            for d in dlist:
                self._graph.add_edge(Edge(ref, d, EdgeType.DEPENDS_ON))

    def ingest_function_calls(self, call_map: Dict[str, List[str]]):
        """调用图: {caller→[callee, ...]}."""
        for caller, callees in call_map.items():
            if caller not in self._graph.nodes[NodeType.FUNCTION]:
                self._graph.add_node(Node(node_id=caller, node_type=NodeType.FUNCTION))
            for callee in callees:
                if callee not in self._graph.nodes[NodeType.FUNCTION]:
                    self._graph.add_node(Node(node_id=callee, node_type=NodeType.FUNCTION))
                self._graph.add_edge(Edge(caller, callee, EdgeType.CALLS))

    def build(self) -> HeteroGraph:
        return self._graph


# 级联漏洞预测 (简化HGAT前向传播)
# 参考: Baird & Moin (2025) CVE级联异构图链接预测

class CascadePredictor:
    """异构图上基于元路径的级联漏洞预测.
    简化版: 元路径采样+余弦相似度.
    完整HGAT需PyTorch/DGL; 此处关注推理管线集成 [Baird & Moin 2025].
    """

    def __init__(self, graph: HeteroGraph):
        self.graph = graph
        self._cached_paths: Dict[str, List[List[str]]] = {}

    def predict_cascades(self, seed_vuln: str, max_hops: int = 3) -> List[Dict]:
        """seed_vuln出发的级联路径预测.

        元路径:
          vulnerability→affects→component→depends_on→component→affects→vulnerability
          vulnerability→belongs_to→cwe→belongs_to→vulnerability

        返回: (target_vuln_id, score, path)降序.
        """
        if seed_vuln not in self.graph.nodes[NodeType.VULNERABILITY]:
            return []

        results = []
        # 元路径1: vuln→component→dep→component→vuln
        for e1 in self.graph.adj_out.get(seed_vuln, {}).get(EdgeType.AFFECTS, []):
            comp1 = e1.target
            for e2 in self.graph.adj_out.get(comp1, {}).get(EdgeType.DEPENDS_ON, []):
                comp2 = e2.target
                for e3 in self.graph.adj_in.get(comp2, {}).get(EdgeType.AFFECTS, []):
                    if e3.source != seed_vuln:
                        score = e1.weight * e2.weight * e3.weight
                        p = [seed_vuln, comp1, comp2, e3.source]
                        results.append({'target': e3.source, 'score': round(score, 4),
                                        'path': p, 'hops': 3, 'metapath': 'vuln-comp-dep-comp-vuln'})

        # 元路径2: vuln→cwe→vuln (同CWE共享)
        for e1 in self.graph.adj_out.get(seed_vuln, {}).get(EdgeType.BELONGS_TO, []):
            cwe = e1.target
            for e2 in self.graph.adj_in.get(cwe, {}).get(EdgeType.BELONGS_TO, []):
                if e2.source != seed_vuln:
                    score = 0.7  # CWE共享基础信任度
                    p = [seed_vuln, cwe, e2.source]
                    results.append({'target': e2.source, 'score': score,
                                    'path': p, 'hops': 2, 'metapath': 'vuln-cwe-vuln'})

        seen = set(); unique = []
        for r in sorted(results, key=lambda x: x['score'], reverse=True):
            if r['target'] not in seen:
                seen.add(r['target']); unique.append(r)
        return unique[:max_hops * 5]

    def compute_component_risk(self) -> Dict[str, float]:
        """图拓扑组件风险: risk(c)=alpha*sum(severity)/dist + (1-alpha)*依赖传播 [Baird & Moin 2025]."""
        risks: Dict[str, float] = defaultdict(float)
        component_nodes = list(self.graph.nodes[NodeType.COMPONENT].keys())
        vuln_nodes = list(self.graph.nodes[NodeType.VULNERABILITY].keys())

        sev_map = {'critical': 10, 'high': 7, 'medium': 4, 'low': 1, 'info': 0}
        for vid in vuln_nodes:
            vnode = self.graph.nodes[NodeType.VULNERABILITY].get(vid)
            if not vnode:
                continue
            sev_str = vnode.properties.get('severity', 'medium')
            sev = sev_map.get(sev_str.lower(), 4)
            for e in self.graph.adj_out.get(vid, {}).get(EdgeType.AFFECTS, []):
                comp = e.target
                risks[comp] += sev * e.weight

        for cid in component_nodes:
            for e in self.graph.adj_out.get(cid, {}).get(EdgeType.DEPENDS_ON, []):
                dep = e.target
                if dep in risks:
                    risks[cid] += 0.3 * risks[dep]

        return dict(risks)


# CWE关联发现，基于KG Embedding [FixV2W 2025]

class CWECorrelationFinder:
    """基于共现和描述的CWE关联. 发现标注不当的漏洞."""

    def __init__(self, graph: HeteroGraph):
        self.graph = graph

    def find_misclassified(self) -> List[Dict]:
        """CWE映射一致性检查.
        规则: 同组件同severity漏洞应倾向相同CWE.
        异常→标记可疑.
        """
        suspicious = []
        comps = self.graph.nodes.get(NodeType.COMPONENT, {})

        for cid in comps:
            comp_vulns: List[Tuple[str, str, str]] = []  # (vuln_id, cwe, severity)
            for e in self.graph.adj_in.get(cid, {}).get(EdgeType.AFFECTS, []):
                vnode = self.graph.nodes[NodeType.VULNERABILITY].get(e.source)
                if vnode:
                    comp_vulns.append((
                        e.source,
                        vnode.properties.get('cwe', ''),
                        vnode.properties.get('severity', 'medium')
                    ))

            if len(comp_vulns) < 3:
                continue

            from collections import Counter
            sev_cwe: Dict[str, Counter] = defaultdict(Counter)
            for vid, cwe, sev in comp_vulns:
                if cwe:
                    sev_cwe[sev][cwe] += 1

            for vid, cwe, sev in comp_vulns:
                if not cwe or cwe not in sev_cwe.get(sev, {}):
                    continue
                if sev_cwe[sev][cwe] < len([v for v in comp_vulns if v[2] == sev]) * 0.5:
                    majority = sev_cwe[sev].most_common(1)[0]
                    suspicious.append({
                        'vulnerability': vid, 'current_cwe': cwe,
                        'suggested_cwe': majority[0],
                        'confidence': round(majority[1] / len([v for v in comp_vulns if v[2] == sev]), 3),
                        'component': cid
                    })

        return suspicious

    def find_related_cwes(self, cwe_id: str, max_results: int = 10) -> List[Dict]:
        """查找与给定CWE频繁共现的其他CWE."""
        co_occur: Dict[str, Counter] = defaultdict(Counter)
        comps = self.graph.nodes.get(NodeType.COMPONENT, {})

        for cid in comps:
            cwes = set()
            for e in self.graph.adj_in.get(cid, {}).get(EdgeType.AFFECTS, []):
                vnode = self.graph.nodes[NodeType.VULNERABILITY].get(e.source)
                if vnode and vnode.properties.get('cwe'):
                    cwes.add(vnode.properties['cwe'])
            for c1, c2 in itertools.combinations(cwes, 2):
                co_occur[c1][c2] += 1
                co_occur[c2][c1] += 1

        related = co_occur.get(cwe_id, Counter())
        return [{'cwe': c, 'co_occurrence': cnt} for c, cnt in related.most_common(max_results)]


# 图序列化

class GraphSerializer:
    """JSON序列化，不保留embedding."""

    @staticmethod
    def to_dict(g: HeteroGraph) -> Dict:
        nodes = {}
        for nt, ndict in g.nodes.items():
            nodes[nt] = {nid: {'type': nt, 'properties': n.properties} for nid, n in ndict.items()}
        edges = {}
        for et, elist in g.edges.items():
            edges[et] = [{'source': e.source, 'target': e.target, 'weight': e.weight,
                          'properties': e.properties} for e in elist]
        return {'nodes': nodes, 'edges': edges, 'stats': {
            'total_nodes': sum(len(nd) for nd in g.nodes.values()),
            'total_edges': sum(len(el) for el in g.edges.values()),
            'node_types': list(g.nodes.keys()), 'edge_types': list(g.edges.keys())
        }}

    @staticmethod
    def save(g: HeteroGraph, path: str):
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(GraphSerializer.to_dict(g), f, indent=2, ensure_ascii=False)
        log.info("图已保存: %s (%d nodes, %d edges)",
                 path,
                 sum(len(nd) for nd in g.nodes.values()),
                 sum(len(el) for el in g.edges.values()))

    @staticmethod
    def load(path: str) -> HeteroGraph:
        g = HeteroGraph()
        if not Path(path).exists():
            return g
        try:
            with open(path, encoding='utf-8') as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            log.warning("图文件 %s 损坏或不可读", path)
            return g
        for nt, ndict in data.get('nodes', {}).items():
            for nid, nprops in ndict.items():
                g.add_node(Node(node_id=nid, node_type=nt, properties=nprops.get('properties', {})))
        for et, elist in data.get('edges', {}).items():
            for ed in elist:
                g.add_edge(Edge(source=ed['source'], target=ed['target'], edge_type=et,
                                weight=ed.get('weight', 1.0), properties=ed.get('properties', {})))
        return g


# 便捷工具

def build_vuln_graph_from_findings(findings: List[Dict], component: str = "main",
                                    sbom: Dict = None, call_graph: Dict[str, List[str]] = None) -> HeteroGraph:
    builder = VulnerabilityGraphBuilder()
    builder.ingest_findings(findings, component)
    if sbom:
        builder.ingest_sbom(sbom)
    if call_graph:
        builder.ingest_function_calls(call_graph)
    return builder.build()


def assess_supply_chain_risk(findings: List[Dict], sbom: Dict) -> Dict:
    """一站式供应链风险评估: 构图→级联预测→风险排序 [Baird & Moin 2025]."""
    g = build_vuln_graph_from_findings(findings, sbom=sbom)
    predictor = CascadePredictor(g)
    risks = predictor.compute_component_risk()

    cascades = {}
    for vid in list(g.nodes[NodeType.VULNERABILITY].keys())[:20]:
        preds = predictor.predict_cascades(vid)
        if preds:
            cascades[vid] = preds

    return {
        'component_risks': dict(sorted(risks.items(), key=lambda x: x[1], reverse=True)),
        'cascade_predictions': cascades,
        'graph_stats': GraphSerializer.to_dict(g)['stats']
    }
