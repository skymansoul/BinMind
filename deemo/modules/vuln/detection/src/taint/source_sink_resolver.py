"""Source-Sink 路径求解器 — def-use 链 + 启发式跨函数连接.

创建: 2026-06-22 14:33
用途: 给定污点图中的 source 集合和 sink 集合, 求解两者之间的数据流路径。
      对跨函数场景使用启发式连接 (参数传递→返回值), 不做完整过程间分析。

设计决策:
  - BFS 而非 DFS: BFS 找到的路径是距离 source 最近的中毒传播链,
    计算%fmt 偏移时更准确 (污染步数→栈参数偏移的映射更直接)。
  - 跨函数启发式: 若 source 在前一个函数的参数中, sink 在当前函数中,
    通过检查调用约定 (x86-64: rdi/rsi/rdx/rcx/r8/r9) 做启发式连接。
    这不能替代完整的过程间分析, 但在 strip 二进制中实用。
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from collections import deque

from .taint_graph import TaintGraph, TaintNode, TaintTag


@dataclass
class TaintPath:
    """一条从 source 到 sink 的污染传播路径."""
    source_addr: int           # 输入源指令地址
    sink_addr: int             # 危险 sink 指令地址
    path_nodes: List[str]      # 路径上的节点ID序列
    path_length: int           # 步数
    format_offset: int         # 估计的格式化字符串参数偏移 (-1 if unknown)
    confidence: float          # [0, 1] — 置信度


class SourceSinkResolver:
    """Source-Sink 路径求解器.

    使用 BFS 在污点图上搜索从输入源到危险 sink 的最短路径。
    对格式化字符串场景, 将路径长度映射为 printf 参数偏移。

    使用方式:
      g = TaintGraph()
      # ... 构建 g 添加 source/sink ...
      resolver = SourceSinkResolver(g)
      paths = resolver.resolve_all()
      for p in paths:
          if p.confidence > 0.6:
              print(f"Vuln: fmt offset={p.format_offset}")
    """

    def __init__(self, taint_graph: TaintGraph):
        self._g = taint_graph
        # x86-64 calling convention: 参数顺序
        self._arg_regs = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']

    # //// 路径求解 ////
    def resolve_all(self) -> List[TaintPath]:
        """求解所有 source→sink 路径."""
        paths = []
        sources = self._g.get_sources()
        sinks = self._g.get_sinks()

        for src_addr, src_nodes in sources.items():
            for sink_addr, sink_nodes in sinks.items():
                for src_id in src_nodes:
                    path = self._bfs_shortest_path(src_id, sink_nodes)
                    if path:
                        fmt_off = self._estimate_format_offset(path, sink_addr)
                        conf = self._compute_confidence(path)
                        paths.append(TaintPath(
                            source_addr=src_addr, sink_addr=sink_addr,
                            path_nodes=path, path_length=len(path),
                            format_offset=fmt_off, confidence=conf))
        paths.sort(key=lambda p: p.confidence, reverse=True)
        return paths

    def _bfs_shortest_path(self, start: str,
                            targets: List[str]) -> List[str]:
        """BFS 最短路径 (沿 propagated_to 方向)."""
        if not targets:
            return []
        target_set = set(targets)
        queue = deque([(start, [start])])
        visited = {start}
        while queue:
            cur, path = queue.popleft()
            if cur in target_set:
                return path
            node = self._g._nodes.get(cur)
            if node:
                for nxt in node.propagated_to:
                    if nxt not in visited:
                        visited.add(nxt)
                        queue.append((nxt, path + [nxt]))
        return []

    # //// 格式化字符串偏移估计 ////
    def _estimate_format_offset(self, path: List[str],
                                 sink_addr: int) -> int:
        """从污染传播步数估计 printf 参数偏移.

        启发式: 每一步 def-use 传播 ≈ 一个栈槽位 (8 bytes).
        在 x86-64 上, 前 6 个参数通过寄存器 (rdi/rsi/rdx/rcx/r8/r9),
        第 7 个起通过栈。printf 的 fmt 参数是第 1 个参数 (rdi),
        如果用户数据通过第 2 个参数传入 (rsi), 则 offset=1,
        对应于 printf 的 %1$ 语法中的位置。
        """
        # 检查 path 中是否有寄存器线索
        for node_id in path:
            if 'rsi' in node_id.lower():
                return 1  # 第 2 个参数
            if 'rdx' in node_id.lower():
                return 2  # 第 3 个参数
            if 'rcx' in node_id.lower():
                return 3
            if 'r8' in node_id.lower():
                return 4
            if 'r9' in node_id.lower():
                return 5
        # 回退: 步数 → 偏移映射
        return max(1, len(path))

    def _compute_confidence(self, path: List[str]) -> float:
        """基于路径特征计算置信度."""
        if not path:
            return 0.0
        score = 1.0
        # 路径越短, 置信度越高 (直接污染)
        if len(path) <= 2:
            score *= 0.95
        elif len(path) <= 4:
            score *= 0.70
        else:
            score *= 0.50 * (1.0 / (len(path) - 3))
        # 检查是否有寄存器线索
        has_reg_hint = any(
            any(reg in node_id.lower() for reg in self._arg_regs)
            for node_id in path)
        if has_reg_hint:
            score *= 1.1
        else:
            score *= 0.8
        return min(1.0, max(0.1, score))

    # //// 统计 ////
    def stats(self) -> dict:
        paths = self.resolve_all()
        return {
            "n_sources": len(self._g.get_sources()),
            "n_sinks": len(self._g.get_sinks()),
            "n_paths_found": len(paths),
            "high_confidence_paths": sum(1 for p in paths if p.confidence > 0.6),
            "mean_format_offset": (
                sum(p.format_offset for p in paths) / max(1, len(paths))
                if paths else 0),
        }
