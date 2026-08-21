"""
UAF 跨函数CFG数据类型 — FunctionNode 和 CallGraph.
"""


from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple


@dataclass
class FunctionNode:
    """调用图中的函数节点."""
    name: str
    start_line: int = 0
    end_line: int = 0
    calls: Set[str] = field(default_factory=set)     # 此函数调用了谁
    called_by: Set[str] = field(default_factory=set)  # 谁调用了此函数
    alloc_sites: List[int] = field(default_factory=list)    # malloc行号
    free_sites: List[int] = field(default_factory=list)     # free行号
    use_sites: List[int] = field(default_factory=list)      # 解引用行号
    is_alloc_wrapper: bool = False   # 是否 malloc 包装函数
    is_free_wrapper: bool = False    # 是否 free 包装函数


@dataclass
class CallGraph:
    """跨函数调用图."""
    nodes: Dict[str, FunctionNode] = field(default_factory=dict)
    edges: List[Tuple[str, str]] = field(default_factory=list)  # (caller,callee)

    def has_path(self, src_func: str, dst_func: str) -> bool:
        """BFS 判定从 src_func 到 dst_func 是否存在调用路径."""
        if src_func == dst_func:
            return True
        if src_func not in self.nodes or dst_func not in self.nodes:
            return False
        visited = {src_func}
        queue = deque([src_func])
        while queue:
            current = queue.popleft()
            node = self.nodes.get(current)
            if not node:
                continue
            for callee in node.calls:
                if callee == dst_func:
                    return True
                if callee not in visited:
                    visited.add(callee)
                    queue.append(callee)
        return False

    def reachable_from(self, func_name: str) -> Set[str]:
        """返回从 func_name 出发可到达的所有函数."""
        reachable = set()
        if func_name not in self.nodes:
            return reachable
        queue = deque([func_name])
        while queue:
            current = queue.popleft()
            if current in reachable:
                continue
            reachable.add(current)
            node = self.nodes.get(current)
            if node:
                for callee in node.calls:
                    if callee not in reachable:
                        queue.append(callee)
        return reachable
