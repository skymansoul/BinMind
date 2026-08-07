"""
反编译代码的CFG解析 — 将伪代码分割为基本块, 识别条件分支。

供 path_sensitive_vrf.py 使用。不依赖其他项目模块。
"""


import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class BasicBlock:
    """基本块: 线性指令序列 + 控制流连接。"""
    id: int
    lines: List[str] = field(default_factory=list)
    start_lineno: int = 0
    end_lineno: int = 0
    successors: List[int] = field(default_factory=list)
    is_conditional: bool = False
    condition_var: str = ""
    condition_op: str = ""
    condition_val: int = 0
    fallthrough: int = -1
    branch_taken: int = -1


_RE_IF = re.compile(r'if\s*\(\s*(\w+)\s*(<|>|<=|>=|==|!=)\s*(\d+)\s*\)')


def split_into_blocks(code: str) -> List[BasicBlock]:
    """将反编译伪代码按控制流分割为基本块。

    简化策略: 每个 if 语句是条件块, 其他为顺序块。
    不处理 while/for/goto——这些较罕见且保守处理不会引入误报。
    """
    lines = code.split('\n')
    blocks: List[BasicBlock] = []
    cur_lines: List[str] = []
    cur_start = 1
    bid = 0

    def flush():
        nonlocal cur_lines, cur_start, bid
        if cur_lines:
            blocks.append(BasicBlock(
                id=bid, lines=list(cur_lines),
                start_lineno=cur_start,
                end_lineno=cur_start + len(cur_lines) - 1,
            ))
            bid += 1
            cur_lines = []
            cur_start = -1

    for i, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped:
            continue
        if cur_start < 0:
            cur_start = i

        m_if = _RE_IF.search(stripped)
        if m_if:
            flush()
            blocks.append(BasicBlock(
                id=bid, lines=[stripped],
                start_lineno=i, end_lineno=i,
                is_conditional=True,
                condition_var=m_if.group(1),
                condition_op=m_if.group(2),
                condition_val=int(m_if.group(3)),
                fallthrough=bid + 1,
                branch_taken=bid + 2,
            ))
            blocks[-1].successors = [bid + 1, bid + 2]
            bid += 1
            cur_start = -1
            continue

        cur_lines.append(stripped)

    flush()

    # 链接顺序块的后继
    for i in range(len(blocks)):
        b = blocks[i]
        if not b.successors and i + 1 < len(blocks):
            b.successors = [i + 1]

    return blocks
