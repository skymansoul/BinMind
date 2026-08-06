"""
格式化字符串调用图分析 —— 跨函数追踪格式化参数的传播路径。

现有 format_string_detector 的 Level 1 正则匹配仅在单函数内搜索
printf(user_input) 模式。若 user_input 经过函数封装:
  void log_msg(char *s) { printf(s); }
  log_msg(argv[1]);
正则匹配无法跨越 log_msg 的调用边界追踪到 argv[1]。

本模块在调用图上做 BFS 传播:
1. 识别 printf 系列调用点为 sink
2. 反向沿调用图追踪每个 sink 的格式化参数直到找到外部输入源
3. BFS 深度限制 ≤ 5 层以避免全程序分析

与非跨函数方法的互补: 本模块捕获间接调用路径, 原有静态匹配覆盖直接调用,
两者结果取并集。
"""

from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class CallEdge:
    caller: str        # 调用方函数名
    callee: str        # 被调函数名
    arg_index: int     # 参数在调用方参数列表中的位置 (0-indexed)
    call_site: str = ""


@dataclass
class FormatSink:
    func_name: str     # 包含 printf 调用的函数
    sink_type: str     # printf/fprintf/sprintf/snprintf/syslog
    fmt_arg_pos: int   # 格式化参数在函数签名中的位置


@dataclass
class TaintPath:
    """一条从外部输入到格式化 sink 的传播路径。"""
    source_desc: str          # "argv[1]" / "recv()" / "getenv()"
    path_functions: List[str]  # [caller, ..., callee_with_sink]
    depth: int
    confidence: float


class FormatStringCallgraphAnalyzer:
    """
    格式化字符串调用图分析器。

    在调用图上从 sink 反向 BFS, 搜索到外部输入的路径。
    BFS 深度限制：5 层调用。理由：在实测二进制中，
    超过 5 层的封装极少见（日志库通常 ≤ 2 层）。
    """

    MAX_BFS_DEPTH = 5

    # 外部输入源函数
    _SOURCE_FUNCS = {
        'main', 'thread_main', 'callback', 'handler',
        'recv', 'read', 'fgets', 'scanf', 'getenv',
    }

    def __init__(self):
        self._call_graph: List[CallEdge] = []
        self._sinks: List[FormatSink] = []

    def add_call_edge(self, caller: str, callee: str, arg_index: int = 0) -> None:
        self._call_graph.append(CallEdge(caller, callee, arg_index))

    def add_sink(self, func_name: str, sink_type: str = "printf", fmt_arg_pos: int = 0) -> None:
        self._sinks.append(FormatSink(func_name, sink_type, fmt_arg_pos))

    def build_graph_from_disasm(self, call_pairs: List[Tuple[str, str]]) -> None:
        """
        从反汇编结果批量构建调用图。
        call_pairs: [(caller_func, callee_func), ...]
        """
        for caller, callee in call_pairs:
            self.add_call_edge(caller, callee, 0)

    def analyze(self) -> List[TaintPath]:
        """从所有 sink 反向 BFS 搜索到外部输入的路径。"""
        callee_to_callers: Dict[str, List[CallEdge]] = {}
        for edge in self._call_graph:
            if edge.callee not in callee_to_callers:
                callee_to_callers[edge.callee] = []
            callee_to_callers[edge.callee].append(edge)

        paths: List[TaintPath] = []
        for sink in self._sinks:
            found = self._bfs_from_sink(sink, callee_to_callers)
            paths.extend(found)
        return paths

    def _bfs_from_sink(
        self, sink: FormatSink,
        callee_to_callers: Dict[str, List[CallEdge]],
    ) -> List[TaintPath]:
        """从单个 sink 反向 BFS。"""
        queue: deque = deque()
        queue.append((sink.func_name, [sink.func_name], 0))
        paths: List[TaintPath] = []
        visited: Set[str] = {sink.func_name}

        while queue:
            current, path, depth = queue.popleft()
            if depth >= self.MAX_BFS_DEPTH:
                continue

            # 检查是否为外部输入源
            if current in self._SOURCE_FUNCS or any(
                s in current for s in ['main', 'handler', 'callback']
            ):
                paths.append(TaintPath(
                    source_desc=current,
                    path_functions=list(reversed(path)),
                    depth=depth,
                    confidence=0.80 - depth * 0.10,
                ))
                continue

            # 继续反向搜索
            callers = callee_to_callers.get(current, [])
            for edge in callers:
                if edge.caller in visited:
                    continue
                visited.add(edge.caller)
                new_path = path + [edge.caller]
                queue.append((edge.caller, new_path, depth + 1))

        return paths


__all__ = [
    'CallEdge', 'FormatSink', 'TaintPath',
    'FormatStringCallgraphAnalyzer',
]
