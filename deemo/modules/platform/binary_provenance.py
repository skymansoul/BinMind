# 修改记录:
# 2025-07-30 10:44 - 增加 SBOM 节点到格节点的自动映射逻辑
# 2025-08-01 13:52 - 修复跨版本漏洞传递的传递闭包计算溢出

"""
二进制来源追踪——传递漏洞分析。

SBOM依赖图嵌入VersionLattice时间维。每个二进制实体同时持有
空间来源（编译者、依赖链）和时间来源（版本、引入时刻）。交叉查询：
  "此漏洞经哪个依赖的哪个版本引入？"

核心结构：
  ProvenanceNode — SBOM组件节点
  ProvenanceGraph — 有向依赖图（组件→依赖）
  ProvenanceLatticeIntegrator — 桥接层

权衡：
  依赖图可有环（A→B, B→A）。不消环——以SCC压缩将强连通分量坍缩为超节点，
  在超节点级做传递闭包。

ref: CVE-2024-3094 (XZ backdoor) — 恶意代码经构建依赖注入，仅SBOM不足，
     需版本格追踪依赖演化。
ref: (Cascaded CVE prediction via heterogeneous SBOM graphs) —
     将HGAT图结构简化为可增量维护的邻接表，偏重可操作性。
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, Iterator, List, Optional, Set, Tuple

from .version_lattice import VersionLattice, VersionNode

@dataclass
class ProvenanceNode:
    """SBOM组件节点——对应一个二进制或库。"""
    purl: str                      # Package URL (pkg:type/namespace/name@version)
    name: str
    version: str
    supplier: str = ""             # 编译者/分发者
    binary_hash: str = ""          # 内容 hash（关联到 VersionNode）
    metadata: Dict[str, Any] = field(default_factory=dict)
    vuln_ids: Set[str] = field(default_factory=set)  # 直接关联的 CVE/Vuln ID

    @property
    def node_id(self) -> str:
        return self.purl

    def __hash__(self) -> int:
        return hash(self.purl)

@dataclass
class DependencyEdge:
    """依赖方→被依赖方的有向边。"""
    source_purl: str
    target_purl: str
    dependency_type: str = "runtime"  # runtime / build / test / optional
    version_constraint: str = ""      # >=1.0,<2.0

class ProvenanceGraph:
    """SBOM依赖图——组件间依赖关系的有向图。

    SCC压缩处理循环依赖（A→B→A）。
    传递闭包：Floyd-Warshall，超节点级别。
    """

    MAX_SCC_NODES = 500  # 超节点数量上限

    def __init__(self):
        self._nodes: Dict[str, ProvenanceNode] = {}     # purl → node
        self._edges: Dict[Tuple[str, str], DependencyEdge] = {}
        self._adj: Dict[str, List[str]] = defaultdict(list)
        self._rev_adj: Dict[str, List[str]] = defaultdict(list)
        self._scc_dag: Optional[Dict[int, Set[int]]] = None  # SCC → 可达 SCC 集合
        self._node_to_scc: Dict[str, int] = {}          # purl → scc_id

    def add_component(self, node: ProvenanceNode) -> None:
        self._nodes[node.purl] = node

    def add_dependency(self, edge: DependencyEdge) -> None:
        if edge.source_purl not in self._nodes:
            return
        if edge.target_purl not in self._nodes:
            # 自动创建缺失的依赖节点——信息不完整但保留拓扑
            self._nodes[edge.target_purl] = ProvenanceNode(
                purl=edge.target_purl, name=edge.target_purl, version="unknown",
            )
        key = (edge.source_purl, edge.target_purl)
        if key not in self._edges:
            self._edges[key] = edge
            self._adj[edge.source_purl].append(edge.target_purl)
            self._rev_adj[edge.target_purl].append(edge.source_purl)

    def transitive_dependencies(self, purl: str) -> FrozenSet[str]:
        """返回某组件的全部传递依赖（含自身）。"""
        if purl not in self._nodes:
            return frozenset()
        scc_id = self._node_to_scc.get(purl)
        if scc_id is None or self._scc_dag is None:
            self._build_scc_dag()
            scc_id = self._node_to_scc.get(purl)

        if scc_id is None or self._scc_dag is None:
            return frozenset({purl})

        reachable_sccs = self._scc_dag.get(scc_id, {scc_id})
        result: Set[str] = set()
        for sid in reachable_sccs:
            for pid, sid2 in self._node_to_scc.items():
                if sid2 == sid:
                    result.add(pid)
        return frozenset(result)

    def transitive_vulnerabilities(self, purl: str) -> Set[str]:
        """某组件的传递漏洞——自身及所有传递依赖的漏洞 ID 的并集。"""
        vulns: Set[str] = set()
        for dep_purl in self.transitive_dependencies(purl):
            node = self._nodes.get(dep_purl)
            if node:
                vulns.update(node.vuln_ids)
        return vulns

    def _build_scc_dag(self) -> None:
        """Kosaraju算法做SCC分解，超节点级建DAG。

        SCC数超MAX_SCC_NODES时终止——大规模图可走外部图数据库（Neo4j等）。
        """
        n = len(self._nodes)
        if n == 0:
            return

        # 第一遍 DFS——计算结束时间
        visited: Set[str] = set()
        order: List[str] = []

        def _dfs1(v: str) -> None:
            visited.add(v)
            for w in self._adj.get(v, []):
                if w not in visited:
                    _dfs1(w)
            order.append(v)

        for v in self._nodes:
            if v not in visited:
                _dfs1(v)

        # 第二遍 DFS——在反向图上按结束时间逆序遍历
        scc_id = 0
        scc_members: Dict[int, Set[str]] = defaultdict(set)
        visited.clear()

        def _dfs2(v: str, sid: int) -> None:
            visited.add(v)
            self._node_to_scc[v] = sid
            scc_members[sid].add(v)
            for w in self._rev_adj.get(v, []):
                if w not in visited:
                    _dfs2(w, sid)

        for v in reversed(order):
            if v not in visited:
                if scc_id >= self.MAX_SCC_NODES:
                    break
                _dfs2(v, scc_id)
                scc_id += 1

        # 构建 SCC 级 DAG 的传递闭包
        self._scc_dag = defaultdict(set)
        for (src, tgt) in self._edges:
            sid_s = self._node_to_scc.get(src)
            sid_t = self._node_to_scc.get(tgt)
            if sid_s is not None and sid_t is not None and sid_s != sid_t:
                self._scc_dag[sid_s].add(sid_t)

        # Floyd-Warshall 风格的传递闭包（SCC 级别，规模可控）
        scc_list = list(range(scc_id))
        for k in scc_list:
            for i in scc_list:
                if k in self._scc_dag.get(i, set()):
                    self._scc_dag[i].update(self._scc_dag.get(k, set()))

    # 此段后续可微调，当前先保证正确性
    def summary(self) -> Dict[str, Any]:
        scc_count = len(set(self._node_to_scc.values())) if self._node_to_scc else 0
        return {
            "components": len(self._nodes),
            "dependencies": len(self._edges),
            "scc_count": scc_count,
            "has_transitive_closure": self._scc_dag is not None,
        }

class ProvenanceLatticeIntegrator:
    """桥接ProvenanceGraph（空间依赖）与VersionLattice（时间演化）。

    跨维查询：
      - 组件+版本 → 其依赖在哪个版本引入某漏洞
      - 漏洞 → 受影响组件的版本范围（格祖先链）
    """

    def __init__(self, provenance: ProvenanceGraph, lattice: VersionLattice):
        self._pg = provenance
        self._lattice = lattice
        # hash → purl 反向索引
        self._hash_to_purl: Dict[str, str] = {}
        for node in provenance._nodes.values():
            if node.binary_hash:
                self._hash_to_purl[node.binary_hash] = node.purl

    def affected_version_range(self, vuln_hash: str) -> Dict[str, List[str]]:
        """受某漏洞影响的所有组件及版本范围。

        {purl: [version_tag, ...]}，按时间序。
        """
        affected: Dict[str, List[str]] = defaultdict(list)
        versions = self._lattice._vuln_to_versions.get(vuln_hash, [])
        for _, binary_hash in sorted(versions, key=lambda x: x[0]):
            purl = self._hash_to_purl.get(binary_hash)
            if purl:
                node = self._lattice._nodes.get(binary_hash)
                if node:
                    affected[purl].append(node.version_tag)
        return dict(affected)

    def dependency_introduction_chain(
        self, root_purl: str, vuln_hash: str,
    ) -> List[Tuple[str, Optional[str]]]:
        """追踪漏洞沿依赖链的传播路径。

        从root_purl出发沿依赖边遍历，找每条路径引入vuln_hash的最早组件。
        返回 [(purl, version_tag_or_None)]。None=该组件不受此漏洞影响。
        """
        deps = self._pg.transitive_dependencies(root_purl)
        chain: List[Tuple[str, Optional[str]]] = []

        for dep_purl in sorted(deps):
            pnode = self._pg._nodes.get(dep_purl)
            if pnode is None:
                continue
            witness = self._lattice.find_introduction_point(vuln_hash)
            if witness is None:
                chain.append((dep_purl, None))
                continue

            # 检查此组件是否在引入点或之后受影响的版本线上
            affected = self.affected_version_range(vuln_hash)
            if dep_purl in affected:
                chain.append((dep_purl, affected[dep_purl][0] if affected[dep_purl] else None))
            else:
                chain.append((dep_purl, None))

        return chain

    def find_vulnerable_dependency_paths(
        self, root_purl: str, vuln_hash: str, max_depth: int = 5,
    ) -> List[List[str]]:
        """BFS搜索从root_purl到受影响依赖的漏洞传播路径。

        返回按路径长度排序的前几条最短路径。
        """
        affected = set(self.affected_version_range(vuln_hash).keys())
        if not affected:
            return []

        all_paths: List[List[str]] = []
        queue: deque[Tuple[str, List[str]]] = deque([(root_purl, [root_purl])])

        while queue and len(all_paths) < 10:
            current, path = queue.popleft()
            if len(path) > max_depth:
                continue
            if current in affected and current != root_purl:
                all_paths.append(list(path))
                continue
            for neighbor in self._pg._adj.get(current, []):
                if neighbor not in path:
                    queue.append((neighbor, path + [neighbor]))

        all_paths.sort(key=len)
        return all_paths[:10]
