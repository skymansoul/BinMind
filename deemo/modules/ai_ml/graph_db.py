# 2026-07-17: preserved; minor optimizations applied.
# 2026-07-23: 持久化支持、子图提取、综合图统计指标，数据生命周期才算闭环
import logging
import json
import hashlib
import os
import gzip
from typing import Dict, Any, List, Optional, Tuple, Set

__log = logging.getLogger(__name__)

try:
    import networkx as nx
    NX_AVAILABLE = True
except ImportError:
    NX_AVAILABLE = False

class GraphDB:
    def __init__(self, backend: str = "networkx", neo4j_uri: str = "bolt://localhost:7687"):
        self.backend = backend
        self.neo4j_uri = neo4j_uri
        self._nx_graph = None
        self._checksum = ""  # 文件持久化校验，写入后更新
        if NX_AVAILABLE and backend == "networkx":
            self._nx_graph = nx.DiGraph()

    # ---------- 持久化：保存/加载 ---------- {{{

    def save(self, filepath: str, compress: bool = True) -> str:
        """将图序列化到磁盘。compress=True 时用 gzip 压缩，返回 sha256 校验和。"""
        if self._nx_graph is None:
            __log.warning("Graph backend not initialized, nothing to save.")
            return ""
        raw = json.dumps(self.to_dict(), ensure_ascii=False, indent=2)
        payload = gzip.compress(raw.encode('utf-8')) if compress else raw.encode('utf-8')
        with open(filepath, 'wb') as fh:
            fh.write(payload)
        self._checksum = hashlib.sha256(payload).hexdigest()
        __log.info("Graph saved to %s (checksum=%s, compressed=%s)", filepath, self._checksum, compress)
        return self._checksum

    @classmethod
    def load(cls, filepath: str, compressed: Optional[bool] = None) -> "GraphDB":
        """从磁盘文件反序列化图。compressed=None 自动嗅探 gzip 魔数头 1f8b。"""
        if not os.path.isfile(filepath):
            raise FileNotFoundError(f"Graph snapshot not found: {filepath}")
        with open(filepath, 'rb') as fh:
            header = fh.read(2)
            fh.seek(0)
            raw_bytes = fh.read()
        is_gz = (header[:2] == b'\x1f\x8b')
        if compressed is False or (compressed is None and not is_gz):
            payload = raw_bytes
        else:
            payload = gzip.decompress(raw_bytes)
        data = json.loads(payload.decode('utf-8'))
        instance = cls()
        for node in data.get('nodes', []):
            props = {k: v for k, v in node.items() if k != 'id'}
            instance.add_node(node['id'], **props)
        for edge in data.get('edges', []):
            props = {k: v for k, v in edge.items() if k not in ('source', 'target')}
            instance.add_edge(edge['source'], edge['target'], **props)
        instance._checksum = hashlib.sha256(raw_bytes).hexdigest()
        __log.info("Graph loaded from %s (%d nodes, %d edges)", filepath,
                    data.get('node_count', 0), data.get('edge_count', 0))
        return instance

    @property
    def checksum(self) -> str:
        return self._checksum

    # }}}

    def add_node(self, node_id: str, **properties):
        if self._nx_graph is not None:
            self._nx_graph.add_node(node_id, **properties)

    def add_edge(self, source: str, target: str, **properties):
        if self._nx_graph is not None:
            self._nx_graph.add_edge(source, target, **properties)

    def get_neighbors(self, node_id: str) -> List[str]:
        if self._nx_graph is not None:
            return list(self._nx_graph.neighbors(node_id))
        return []

    def get_predecessors(self, node_id: str) -> List[str]:
        if self._nx_graph is not None:
            return list(self._nx_graph.predecessors(node_id))
        return []

    def find_paths(self, source: str, target: str, max_len: int = 5) -> List[List[str]]:
        if self._nx_graph is not None:
            try:
                return list(nx.all_simple_paths(self._nx_graph, source, target, cutoff=max_len))
            except (nx.NodeNotFound, nx.NetworkXNoPath):
                pass
        return []

    def shortest_path(self, source: str, target: str) -> Optional[List[str]]:
        if self._nx_graph is not None:
            try:
                return nx.shortest_path(self._nx_graph, source, target)
            except (nx.NodeNotFound, nx.NetworkXNoPath):
                pass
        return None

    def centrality(self, top_n: int = 10) -> List[Tuple[str, float]]:
        if self._nx_graph is not None and len(self._nx_graph) > 0:
            try:
                dc = nx.degree_centrality(self._nx_graph)
                return sorted(dc.items(), key=lambda x: x[1], reverse=True)[:top_n]
            except Exception:
                pass
        return []

    # ---------- 子图提取：k-hop 邻域 ---------- {{{

    def subgraph_around(self, center: str, radius: int = 2) -> Optional["GraphDB"]:
        """提取以 center 为源的 k-hop 子图，拷贝属性。孤点返回空子图。"""
        if self._nx_graph is None or center not in self._nx_graph:
            return None
        # 用 bfs_tree 控制邻域范围，保持有向边
        sub: Set[str] = {center}
        frontier: Set[str] = {center}
        for _ in range(radius):
            nxt: Set[str] = set()
            for node in frontier:
                nxt.update(self._nx_graph.successors(node))
                nxt.update(self._nx_graph.predecessors(node))
            if not nxt:
                break
            sub |= nxt
            frontier = nxt - sub  # 仅处理新增的节点，避免重复 bfs
        sg = GraphDB()
        for n in sub:
            sg.add_node(n, **self._nx_graph.nodes[n])
        for u, v in self._nx_graph.edges():
            if u in sub and v in sub:
                sg.add_edge(u, v, **self._nx_graph.edges[u, v])
        __log.info("Extracted %d-node subgraph around '%s' (radius=%d)", len(sub), center, radius)
        return sg

    # }}}

    # ---------- 综合图统计指标 ---------- {{{

    def stats(self) -> Dict[str, Any]:
        """返回图级别统计：节点/边数、密度、弱/强连通分量数、孤立点计数。"""
        if self._nx_graph is None:
            return {}
        n_nodes = self._nx_graph.number_of_nodes()
        n_edges = self._nx_graph.number_of_edges()
        # 密度 = |E| / (|V|*(|V|-1))，空图/单节点图密度为 0
        density = 0.0
        if n_nodes > 1:
            density = n_edges / (n_nodes * (n_nodes - 1))
        # 连通分量 — 有向图用 weak 计数；子图粒度较大时仅统计数量，不展开节点列表
        wcc_count = 0
        scc_count = 0
        isolates = 0
        try:
            wcc_count = nx.number_weakly_connected_components(self._nx_graph)
            scc_count = nx.number_strongly_connected_components(self._nx_graph)
            # out_degree + in_degree == 0 就是孤立点
            isolates = sum(1 for n in self._nx_graph.nodes()
                           if self._nx_graph.degree(n) == 0)
        except Exception:
            __log.exception("stats computation failed for connected components")
        return {
            'node_count': n_nodes,
            'edge_count': n_edges,
            'density': round(density, 6),
            'weakly_connected_components': wcc_count,
            'strongly_connected_components': scc_count,
            'isolates': isolates,
        }

    # }}}

    def to_dict(self) -> Dict[str, Any]:
        if self._nx_graph is not None:
            return {
                'nodes': [{'id': n, **self._nx_graph.nodes[n]} for n in self._nx_graph.nodes()],
                'edges': [{'source': s, 'target': t, **self._nx_graph.edges[s, t]} for s, t in self._nx_graph.edges()],
                'node_count': self._nx_graph.number_of_nodes(),
                'edge_count': self._nx_graph.number_of_edges(),
            }
        return {'nodes': [], 'edges': []}

    def to_cypher(self) -> str:
        lines = []
        data = self.to_dict()
        for node in data['nodes']:
            props = ', '.join(f'{k}: "{v}"' for k, v in node.items() if k != 'id')
            lines.append(f"CREATE (:{node.get('type', 'Unknown')} {{id: '{node['id']}', {props}}});")
        for edge in data['edges']:
            lines.append(f"MATCH (a {{id: '{edge['source']}'}}), (b {{id: '{edge['target']}'}}) CREATE (a)-[:DEPENDS_ON]->(b);")
        return "\n".join(lines)

def create_graph_db(backend: str = "networkx") -> GraphDB:
    return GraphDB(backend=backend)
