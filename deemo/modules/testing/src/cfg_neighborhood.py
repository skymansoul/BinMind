# CFG邻域子图提取与结构签名计算
#
# 从 vuln_pattern_extractor.py 拆分的底层工具模块:
#   - CFGNeighborhoodExtractor: BFS邻域提取
#   - NeighborhoodSignatureBuilder: 12维结构签名计算
# 两者均无外部依赖, 可独立用于其他CFG分析任务。

from __future__ import annotations

import math
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple


class CFGNeighborhoodExtractor:
    """从CFG中提取指定基本块周围的局部邻域子图。

    沿前驱和后继方向做BFS遍历 radius 步。
    """

    def __init__(self, radius: int = 3):
        self._radius = radius

    def extract(self,
                cfg_adjacency: Dict[int, List[int]],
                center_addr: int,
                block_sizes: Optional[Dict[int, int]] = None,
                ) -> Tuple[Dict[int, List[int]], Set[int]]:
        """返回 (subgraph_adjacency, neighborhood_blocks_set)。"""
        if center_addr not in cfg_adjacency:
            return {}, set()

        reverse_adj: Dict[int, List[int]] = defaultdict(list)
        for src, succs in cfg_adjacency.items():
            for dst in succs:
                reverse_adj[dst].append(src)

        neighborhood: Set[int] = {center_addr}
        frontier = {center_addr}

        for _ in range(self._radius):
            next_frontier: Set[int] = set()
            for block in frontier:
                for succ in cfg_adjacency.get(block, []):
                    if succ not in neighborhood:
                        next_frontier.add(succ)
                for pred in reverse_adj.get(block, []):
                    if pred not in neighborhood:
                        next_frontier.add(pred)
            if not next_frontier:
                break
            neighborhood |= next_frontier
            frontier = next_frontier

        subgraph: Dict[int, List[int]] = {}
        for block in neighborhood:
            all_succs = cfg_adjacency.get(block, [])
            subgraph[block] = [s for s in all_succs if s in neighborhood]

        return subgraph, neighborhood

    @staticmethod
    def subgraph_block_sizes(subgraph: Dict[int, List[int]],
                              full_block_sizes: Dict[int, int]
                              ) -> Dict[int, int]:
        return {b: full_block_sizes.get(b, 1) for b in subgraph}


class NeighborhoodSignatureBuilder:
    """计算CFG邻域子图的12维结构签名。

    前9维: 标准CFG熵特征 (与 cfg_entropy_fingerprint.py 对齐)
      F1: 出度分布熵  F2: 入度分布熵  F3: 块大小熵
      F4: 循环块比率  F5: 分支块比率  F6: 平均出度
      F7: 最大出度    F8: 出口块比率  F9: 孤立块比率

    后3维: 邻域特有特征
      F10: center块到最近入口的归一化距离
      F11: center块的前驱/后继不对称比
      F12: 邻域内回边密度
    """

    @staticmethod
    def compute(subgraph: Dict[int, List[int]],
                center_block: int,
                block_sizes: Optional[Dict[int, int]] = None,
                radius: int = 3,
                ) -> List[float]:
        if not subgraph:
            return [0.0] * 12

        blocks = list(subgraph.keys())
        n = len(blocks)
        sizes = block_sizes or {b: 1 for b in blocks}

        outdeg: Dict[int, int] = defaultdict(int)
        indeg: Dict[int, int] = defaultdict(int)
        for b in blocks:
            outdeg[len(subgraph.get(b, []))] += 1
            in_count = sum(1 for src, succs in subgraph.items()
                          if b in succs)
            indeg[in_count] += 1

        ot = sum(outdeg.values()) or 1
        it = sum(indeg.values()) or 1
        sz = [sizes.get(b, 1) for b in blocks]
        st = sum(sz) or 1

        f1 = _shannon([c / ot for c in outdeg.values()])
        f2 = _shannon([c / it for c in indeg.values()])
        f3 = _shannon([s / st for s in sz])
        f4 = sum(1 for b in blocks
                 if len(subgraph.get(b, [])) >= 2
                 or sum(1 for src in subgraph if b in subgraph[src]) >= 2) / n
        f5 = sum(1 for b in blocks if len(subgraph.get(b, [])) >= 2) / n
        f6 = sum(len(subgraph.get(b, [])) for b in blocks) / n
        f7 = float(max((len(subgraph.get(b, [])) for b in blocks), default=0))
        f8 = sum(1 for b in blocks if len(subgraph.get(b, [])) == 0) / max(1, n)
        f9 = sum(1 for b in blocks
                 if sum(1 for src in subgraph if b in subgraph[src]) == 0
                 and len(subgraph.get(b, [])) == 0) / max(1, n)

        # F10: center到入口(入度最小)的BFS距离 / max_dist
        entries = [b for b in blocks
                   if sum(1 for src in subgraph if b in subgraph[src]) == 0]
        if not entries:
            entries = [blocks[0]]
        min_dist = NeighborhoodSignatureBuilder._bfs_distance(
            subgraph, entries[0], center_block)
        f10 = min(min_dist, radius * 3) / max(1, radius * 3)

        # F11: center块前驱/后继不对称比
        vuln_preds = sum(1 for src in subgraph
                        if center_block in subgraph[src])
        vuln_succs = len(subgraph.get(center_block, []))
        f11 = abs(vuln_preds - vuln_succs) / max(
            1, vuln_preds + vuln_succs)

        # F12: 回边密度
        back_edges = NeighborhoodSignatureBuilder._count_back_edges(subgraph)
        total_edges = sum(len(s) for s in subgraph.values())
        f12 = back_edges / max(1, total_edges)

        return [f1, f2, f3, f4, f5, f6, f7, f8, f9, f10, f11, f12]

    @staticmethod
    def _bfs_distance(subgraph: Dict[int, List[int]],
                       start: int, target: int) -> int:
        if start == target:
            return 0
        dist: Dict[int, int] = {start: 0}
        q = [start]
        while q:
            u = q.pop(0)
            for v in subgraph.get(u, []):
                if v not in dist:
                    dist[v] = dist[u] + 1
                    if v == target:
                        return dist[v]
                    q.append(v)
        return 999

    @staticmethod
    def _count_back_edges(subgraph: Dict[int, List[int]]) -> int:
        visited: Set[int] = set()
        in_stack: Set[int] = set()
        count = 0

        def dfs(u: int) -> None:
            nonlocal count
            visited.add(u)
            in_stack.add(u)
            for v in subgraph.get(u, []):
                if v in in_stack:
                    count += 1
                elif v not in visited:
                    dfs(v)
            in_stack.discard(u)

        for node in subgraph:
            if node not in visited:
                try:
                    dfs(node)
                except RecursionError:
                    pass
        return count


def _shannon(probs: List[float]) -> float:
    ent = 0.0
    for p in probs:
        if p > 0:
            ent -= p * math.log2(p)
    return ent
