"""
分配器感知过滤 提取层 — 分配点与写点解析.

从伪 IR 行中提取:
  - 分配点: vN = malloc(size_expr) (括号平衡解析 size)
  - 写点:   memcpy(dst, src, size) / store vN + off
写点按变量名关联到分配 (全局别名), 不受块序限制.
本模块只做语法提取, 不做判定 — 判定由 alloc_aware_engine 完成.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional

from .alloc_aware_allocator import AllocKind, alloc_bound
from .alloc_aware_interval import Interval, simplify_expr
from .alloc_aware_taint import TaintState

_RE_ALLOC = re.compile(
    r'(\w+)\s*=\s*(malloc|calloc|realloc)\s*\(', re.IGNORECASE)
_RE_ALLOC_CPP = re.compile(
    r'(?:malloc|calloc|realloc)\s*\(\s*([^)]*)\)', re.IGNORECASE)
_RE_COPY_CALL = re.compile(
    r'(memcpy|memset|strcpy|strncpy|memmove)\s*\(\s*(\w+)\s*,',
    re.IGNORECASE)
_RE_STORE_LINE = re.compile(
    r'store\s+(\w+)\s+\+\s+(0x[0-9a-fA-F]+|\d+)(?:\s*=\s*\d+)?'
    r'(?:\s*#\s*loop)?\s*$', re.IGNORECASE)


@dataclass
class HfpAlloc:
    """分配点事实."""
    pc: int
    var: str
    kind: AllocKind
    size_expr: str
    bound: 'AllocBound' = None

    def resolve_bound(self, env: dict) -> None:
        """用污点环境解析常量变量, 构造分配边界."""
        iv, _ = simplify_expr(self.size_expr, env)
        req = iv.lo if iv.lo == iv.hi and iv.lo > 0 else 0
        self.bound = alloc_bound(req, self.kind)


@dataclass
class HfpWrite:
    """写点事实."""
    pc: int
    base_var: str
    offset: int
    write_iv: Interval
    call_fn: str = ''
    size_expr: str = ''


def mk_alloc_expr(line: str) -> str:
    """从 'v = malloc(...)' 行提取括号平衡的 size 表达式."""
    m = re.search(r'\b(malloc|calloc|realloc)\s*\(', line, re.IGNORECASE)
    if not m:
        return ''
    start = m.end()
    depth = 0
    for j in range(start, len(line)):
        c = line[j]
        if c == '(':
            depth += 1
        elif c == ')':
            if depth == 0:
                return line[start:j].strip()
            depth -= 1
    return ''


def extract_alloc(line: str, pc: int) -> Optional[HfpAlloc]:
    """从单行提取分配点, 无匹配返回 None."""
    m = _RE_ALLOC.search(line)
    if not m:
        return None
    return HfpAlloc(pc=pc, var=m.group(1), kind=AllocKind(
        m.group(2).lower().split('.')[-1]),
        size_expr=mk_alloc_expr(line))


def extract_alloc_exprs(ir_lines: List[str]) -> dict:
    """全文件分配表: var -> HfpAlloc (跨块, 供写点关联)."""
    out = {}
    for i, line in enumerate(ir_lines):
        alloc = extract_alloc(line, i)
        if alloc and alloc.var:
            out[alloc.var] = alloc
    return out


def last_top_level_arg(line: str) -> str:
    """提取调用行最后一个顶层 (括号外) 参数.

    从行尾回溯: 最后 ')' 是调用闭括号, 其前最近的顶层逗号
    分隔了最后一个参数.
    """
    depth = 0
    last_comma = -1
    for i in range(len(line) - 1, -1, -1):
        c = line[i]
        if c == ')':
            depth += 1
        elif c == '(':
            depth -= 1
            if depth < 0:
                break
        elif c == ',' and depth == 1:
            last_comma = i
            break
    if last_comma < 0:
        return ''
    tail = line[last_comma + 1:].strip()
    return tail.rstrip(')').strip()


def extract_call_size(ir_lines: List[str]) -> str:
    """从 memcpy(p, src, size) 调用行提取 size 表达式.

    src 可能是元组 repr (lea 参数), 含逗号/括号 — 从行尾回溯
    找最后一个顶层逗号后的 token 作为 size.
    """
    for line in ir_lines:
        m = _RE_COPY_CALL.search(line)
        if not m:
            continue
        size = last_top_level_arg(line)
        if re.fullmatch(r'[\w?]+', size):
            return size
    return ''


def extract_write(line: str, pc: int, alloc_by_var: dict,
                  taint: TaintState, env: dict) -> Optional[HfpWrite]:
    """从单行提取写点并按变量关联到分配, 无匹配返回 None."""
    m = _RE_STORE_LINE.search(line)
    if m:
        var = m.group(1)
        if var not in alloc_by_var:
            return None
        off = int(m.group(2), 0)
        return HfpWrite(pc=pc, base_var=var, offset=off,
                        write_iv=Interval(1, 1))
    m = _RE_COPY_CALL.search(line)
    if m:
        var = m.group(2)
        if var not in alloc_by_var:
            return None
        fn = m.group(1).lower()
        size_expr = extract_call_size([line])
        size_iv, _ = simplify_expr(size_expr, env)
        return HfpWrite(pc=pc, base_var=var, offset=0,
                        write_iv=size_iv, call_fn=fn,
                        size_expr=size_expr)
    return None