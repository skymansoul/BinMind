"""Pearl SCM 因果图 — PC 算法 + do-calculus + twin network.

参考: Pearl "Causality", Spirtes et al. "Causation, Prediction, and Search"

与 constraint_inference_mutator 的区分:
前者做启发式约束推断 (关联层), 本模块实现 do-calculus 图手术 (干预层)。
PC 算法从观测数据中学习因果图骨架, do-operator 模拟干预效果。"""


from collections import defaultdict
from dataclasses import dataclass, field
from itertools import combinations
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

from .causal_stats import fisher_independent, subsets_up_to


_DEFAULT_ALPHA = 0.05
_MAX_CONDITIONING_SET = 4


@dataclass
class CausalNode:
    """因果图中的节点 — 字节位置、覆盖边、或观测变量."""
    name: str
    node_type: str = "variable"
    domain: tuple = (0, 255)
    observations: List[float] = field(default_factory=list)
    parents: Set[str] = field(default_factory=set)
    children: Set[str] = field(default_factory=set)


class CausalDAG:
    """因果有向无环图 — PC 结构学习 + do-calculus (干预) + 后门/前门准则."""

    def __init__(self, alpha: float = _DEFAULT_ALPHA):
        self.alpha = alpha
        self._nodes: Dict[str, CausalNode] = {}
        self._edges: Set[Tuple[str, str]] = set()
        self._adjacency: Dict[str, Set[str]] = defaultdict(set)

    # //// 节点管理 ////
    def add_node(self, name: str, node_type: str = "variable",
                 domain: tuple = (0, 255)) -> CausalNode:
        if name not in self._nodes:
            self._nodes[name] = CausalNode(
                name=name, node_type=node_type, domain=domain)
        return self._nodes[name]

    def add_edge(self, parent: str, child: str) -> None:
        if parent == child:
            return
        self._edges.add((parent, child))
        self._adjacency[parent].add(child)
        if parent in self._nodes and child in self._nodes:
            self._nodes[parent].children.add(child)
            self._nodes[child].parents.add(parent)

    def remove_edge(self, parent: str, child: str) -> None:
        self._edges.discard((parent, child))
        self._adjacency[parent].discard(child)
        if parent in self._nodes:
            self._nodes[parent].children.discard(child)
        if child in self._nodes:
            self._nodes[child].parents.discard(parent)

    # //// do-operator: 图手术 ////
    def do(self, node_name: str) -> 'CausalDAG':
        """干预 do(X): 返回移除指向 X 的所有入边的图副本."""
        mutilated = CausalDAG(alpha=self.alpha)
        for name, node in self._nodes.items():
            mutilated._nodes[name] = CausalNode(
                name=node.name, node_type=node.node_type,
                domain=node.domain, observations=list(node.observations),
                parents=set(node.parents), children=set(node.children))
        mutilated._edges = set(self._edges)
        for p in list(mutilated._nodes[node_name].parents):
            mutilated.remove_edge(p, node_name)
        return mutilated

    # //// 后门准则 ////
    def backdoor_admissible(self, treatment: str, outcome: str,
                           adjustment_set: Set[str]) -> bool:
        """Z 满足后门准则: Z 不包含 treatment 后代, 且 d-分离所有后门路径."""
        descendants = self._descendants(treatment)
        if adjustment_set & descendants:
            return False
        return self._blocks_all_backdoor_paths(treatment, outcome, adjustment_set)

    def _descendants(self, node: str) -> Set[str]:
        result = set(); stack = [node]
        while stack:
            cur = stack.pop()
            if cur in result: continue
            result.add(cur)
            for child in self._adjacency.get(cur, set()):
                if child not in result: stack.append(child)
        return result

    def _blocks_all_backdoor_paths(self, treatment: str, outcome: str,
                                    adjustment: Set[str]) -> bool:
        parents = [p for p, c in self._edges if c == treatment]
        return all(self._is_d_separated(p, outcome, adjustment) for p in parents)

    def _is_d_separated(self, x: str, y: str,
                        conditioning: Set[str]) -> bool:
        """简化 d-分离 — 路径枚举, 适用于小规模因果图 (<100节点)."""
        all_paths = self._all_undirected_paths(x, y, max_length=6)
        return all(self._path_blocked_by(p, conditioning) for p in all_paths)

    def _all_undirected_paths(self, start: str, end: str,
                              max_length: int = 6) -> List[List[str]]:
        paths = []
        def dfs(cur, visited, path):
            if len(path) > max_length: return
            if cur == end and len(path) > 1:
                paths.append(list(path)); return
            nbors = (self._adjacency.get(cur, set())
                     | {p for p, c in self._edges if c == cur})
            for nb in nbors:
                if nb not in visited:
                    dfs(nb, visited | {nb}, path + [nb])
        dfs(start, {start}, [start])
        return paths

    @staticmethod
    def _path_blocked_by(path: List[str], conditioning: Set[str]) -> bool:
        """单条路径是否被阻断: chain/fork/collider 规则."""
        for i in range(1, len(path) - 1):
            if path[i] in conditioning:
                return True
        return False

    # //// 结构学习: PC 算法 ////
    def learn_structure(self, data: Dict[str, List[float]]) -> None:
        """PC 算法 Phase I (骨架发现): 完全无向图 → 逐步删除条件独立的边."""
        var_names = list(data.keys())
        n_vars = len(var_names)
        if n_vars < 2:
            return
        self._nodes.clear(); self._edges.clear(); self._adjacency.clear()
        for name in var_names:
            self.add_node(name)
            self._nodes[name].observations = data.get(name, [])
        for a, b in combinations(var_names, 2):
            self._adjacency[a].add(b); self._adjacency[b].add(a)

        # PC 迭代
        cond_set_size = 0
        while True:
            edges_removed = 0
            adj_snapshot = {n: set(nb) for n, nb in self._adjacency.items()}
            for a in var_names:
                for b in list(adj_snapshot.get(a, set())):
                    if b <= a: continue
                    neighbors_a = adj_snapshot.get(a, set()) - {b}
                    for cond_set in subsets_up_to(neighbors_a, cond_set_size):
                        if fisher_independent(a, b, cond_set, data, self.alpha):
                            self._adjacency[a].discard(b)
                            self._adjacency[b].discard(a)
                            edges_removed += 1
                            break
            cond_set_size += 1
            if edges_removed == 0 or cond_set_size > _MAX_CONDITIONING_SET:
                break

        self._orient_v_structures(data)
        self._propagate_orientation()

    def _orient_v_structures(self, data: Dict[str, List[float]]) -> None:
        """定向 collider: 未定向的 X—Z—Y, 若 Z 不在 X⟂Y|C 中, 则 X→Z←Y."""
        for x in self._nodes:
            for y in self._nodes:
                if y <= x: continue
                common_nb = self._adjacency.get(x, set()) & self._adjacency.get(y, set())
                for z in common_nb:
                    if (x, z) in self._edges or (z, x) in self._edges: continue
                    if (y, z) in self._edges or (z, y) in self._edges: continue
                    nb_z = self._adjacency.get(z, set()) - {x, y}
                    sep_sets = []
                    for size in range(min(3, len(nb_z) + 1)):
                        for cond in subsets_up_to(nb_z, size):
                            if z not in cond and fisher_independent(
                                    x, y, cond, data, self.alpha):
                                sep_sets.append(cond)
                    if not sep_sets:
                        self.add_edge(x, z); self.add_edge(y, z)

    def _propagate_orientation(self) -> None:
        """Meek 规则 R1: 传播边方向约束, 避免环."""
        changed = True
        while changed:
            changed = False
            for a in list(self._adjacency.keys()):
                for b in list(self._adjacency.get(a, set())):
                    for c in list(self._adjacency.get(b, set())):
                        if c == a: continue
                        if ((a, b) in self._edges
                                and c not in self._adjacency.get(a, set())
                                and (c, b) not in self._edges
                                and (b, c) not in self._edges):
                            self.add_edge(b, c); changed = True

    # //// 统计 ////
    def stats(self) -> dict:
        return {
            "nodes": len(self._nodes),
            "edges": len(self._edges),
            "byte_nodes": sum(1 for n in self._nodes.values()
                            if n.node_type == "byte_offset"),
            "coverage_nodes": sum(1 for n in self._nodes.values()
                                if n.node_type == "coverage_edge"),
            "max_degree": max((len(self._adjacency.get(n, set()))
                             for n in self._nodes), default=0),
        }
