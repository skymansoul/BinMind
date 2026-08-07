"""
HOIG 路径敏感 CFG 构建 — 从伪代码提取控制流图.

下沉到独立模块, 使 PathSensitiveHOIG 聚焦状态传播.
"""

import re
from typing import List

_RE_IF = re.compile(r'\bif\s*\(')
_RE_ELSE = re.compile(r'\belse\b')
_RE_FOR = re.compile(r'\bfor\s*\(')
_RE_WHILE = re.compile(r'\bwhile\s*\(')


class CFGNode:
    """CFG节点: 连续代码行序列."""
    __slots__ = ('start', 'end', 'kind', 'succs')

    def __init__(self, start: int, end: int, kind: str = 'block'):
        self.start = start
        self.end = end
        self.kind = kind
        self.succs: List[int] = []


def build_cfg(lines: List[str]) -> List[CFGNode]:
    """从伪代码构建简化CFG.

    if/else 各生成独立 branch 节点, 使路径敏感分析能正确
    判定双分支全覆盖. else 检测覆盖同行和独立行.
    """
    nodes: List[CFGNode] = []
    i = 0
    n = len(lines)
    current_start = 1

    while i < n:
        line = lines[i].strip()
        if not line or line.startswith('//'):
            i += 1
            continue

        is_branch = (_RE_IF.search(line) or _RE_FOR.search(line)
                     or _RE_WHILE.search(line))
        if is_branch:
            if current_start <= i:
                nodes.append(CFGNode(current_start, i, 'block'))
            branch_start = i + 1
            branch_end = find_block_end(lines, i)
            nodes.append(CFGNode(branch_start, branch_end, 'branch'))
            current_start = branch_end + 1
            else_end = find_else_end(lines, branch_end)
            if else_end:
                nodes.append(CFGNode(branch_end + 1, else_end, 'branch'))
                current_start = else_end + 1
                i = else_end
            else:
                i = branch_end
        elif _RE_ELSE.search(line):
            if current_start <= i:
                nodes.append(CFGNode(current_start, i, 'block'))
            branch_start = i + 1
            branch_end = find_block_end(lines, i)
            nodes.append(CFGNode(branch_start, branch_end, 'branch'))
            current_start = branch_end + 1
            i = branch_end
        i += 1

    if current_start <= n:
        nodes.append(CFGNode(current_start, n, 'block'))

    return nodes if nodes else [CFGNode(1, n, 'block')]


def find_block_end(lines: List[str], idx: int) -> int:
    """找代码块结束行 (匹配 {})."""
    n = len(lines)
    if idx >= n:
        return idx + 1
    brace = lines[idx].find('{')
    if brace == -1:
        for j in range(idx + 1, min(idx + 3, n)):
            if lines[j].strip().startswith('{'):
                brace, idx = 0, j
                break
        if brace == -1:
            return next((j for j in range(idx + 1, n)
                         if lines[j].strip()), n)
    depth = 0
    for j in range(idx, n):
        for ch in lines[j]:
            if ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
                if depth == 0:
                    return j + 1
    return n


def find_else_end(lines: List[str], if_end1: int) -> int:
    """if 块结束后检测 else 块, 返回 else 块结束行, 0 表示无 else."""
    n = len(lines)
    idx = if_end1 - 1
    if idx >= n:
        return 0
    ep = lines[idx].find('else')
    if ep == -1:
        return 0
    bp = lines[idx].find('{', ep)
    if bp == -1:
        for j in range(idx + 1, min(idx + 3, n)):
            bp = lines[j].find('{')
            if bp != -1:
                idx = j
                break
        else:
            return 0
    depth = 1
    for j in range(idx, n):
        seg = lines[idx][bp + 1:] if j == idx else lines[j]
        for ch in seg:
            if ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
                if depth == 0:
                    return j + 1
    return n


__all__ = ['CFGNode', 'build_cfg', 'find_block_end', 'find_else_end']
