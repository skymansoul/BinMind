# Tarjan SCC detection for loop_structure_recovery.py
from typing import Dict, List, Set

class TarjanSCC:
    """Tarjan强连通分量检测-在CFG中找循环候选"""
    def __init__(self, adjacency: Dict[int, List[int]]):
        self._adj = adjacency
        self._index = 0
        self._stack: List[int] = []
        self._on_stack: Set[int] = set()
        self._indices: Dict[int, int] = {}
        self._lowlinks: Dict[int, int] = {}
        self._sccs: List[List[int]] = []

    def find_sccs(self) -> List[List[int]]:
        for node in self._adj:
            if node not in self._indices:
                self._strongconnect(node)
        return [scc for scc in self._sccs if len(scc) >= 2]

    def _strongconnect(self, v: int):
        self._indices[v] = self._index
        self._lowlinks[v] = self._index
        self._index += 1
        self._stack.append(v)
        self._on_stack.add(v)
        for w in self._adj.get(v, []):
            if w not in self._indices:
                self._strongconnect(w)
                self._lowlinks[v] = min(self._lowlinks[v], self._lowlinks[w])
            elif w in self._on_stack:
                self._lowlinks[v] = min(self._lowlinks[v], self._indices[w])
        if self._lowlinks[v] == self._indices[v]:
            scc = []
            while True:
                w = self._stack.pop()
                self._on_stack.discard(w)
                scc.append(w)
                if w == v:
                    break
            self._sccs.append(scc)
