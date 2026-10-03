"""
堆缓冲区值范围边界检查器 — 从代码中提取分配点和堆写入,
用区间传播判断写入偏移是否超出分配边界.

设计决策:
  - 区间用 [lo, hi] 闭区间表示, hi 为 INF 时表示无上界
  - 只追踪整型变量 (size 相关), 不追踪指针
  - 守卫条件 if (var <= N) → 传播 var 上界
  - 外部输入变量默认 [0, INF] (保守)
  - 与 value_range.py 的差异: 本模块提供 AllocSite/HeapWrite/BoundsViolation
    数据类和 check_bounds 主接口, 面向 _exports_heap.py 的调用方
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

INF = 0x7FFFFFFF


@dataclass
class Interval:
    """整数区间 [lo, hi]."""
    lo: int = 0
    hi: int = INF

    @property
    def is_const(self) -> bool:
        return self.lo == self.hi and self.hi < INF

    @property
    def is_unknown(self) -> bool:
        return self.hi >= INF

    def contains(self, val: int) -> bool:
        return self.lo <= val <= self.hi

    def __repr__(self):
        hi_str = 'INF' if self.hi >= INF else str(self.hi)
        return f'[{self.lo}, {hi_str}]'


@dataclass
class AllocSite:
    """堆分配点."""
    var: str
    size_expr: str
    size_range: Interval = field(default_factory=Interval)
    line: int = 0


@dataclass
class HeapWrite:
    """堆写入操作."""
    dest_var: str
    offset_expr: str = '0'
    size_expr: str = ''
    offset_range: Interval = field(default_factory=Interval)
    size_range: Interval = field(default_factory=Interval)
    line: int = 0


@dataclass
class BoundsViolation:
    """边界违规: 写入超出分配范围."""
    alloc: AllocSite
    write: HeapWrite
    overflow_bytes: int = 0
    is_definite: bool = False


# 正则
_ALLOC_RE = re.compile(
    r'(\w+)\s*=\s*(?:malloc|calloc|realloc)\s*\(\s*([^)]+)\s*\)'
)

_WRITE_RE = re.compile(
    r'(?:memcpy|memmove|memset|strcpy|strncpy|strcat|strncat|read|fread|recv)\s*'
    r'\(\s*([^,]+)\s*(?:,\s*[^,]+)?(?:,\s*([^)]+))?\s*\)'
)

_ASSIGN_RE = re.compile(r'(\w+)\s*=\s*(\d+)\s*;')

_GUARD_RE = re.compile(
    r'if\s*\(\s*(\w+)\s*(<=?|>=?)\s*(\d+)\s*\)'
)

_NUM_RE = re.compile(r'^-?\d+$')


def _eval_expr(expr: str, consts: Dict[str, int]) -> Interval:
    """评估表达式到区间."""
    expr = expr.strip()
    if _NUM_RE.match(expr):
        v = int(expr)
        return Interval(v, v)
    # 变量引用
    if re.match(r'^\w+$', expr):
        if expr in consts:
            return Interval(consts[expr], consts[expr])
        return Interval(0, INF)  # 未知变量保守处理
    # n * k 形式
    m = re.match(r'(\w+)\s*\*\s*(\d+)', expr)
    if m:
        var, k = m.group(1), int(m.group(2))
        if var in consts:
            v = consts[var] * k
            return Interval(v, v)
        return Interval(0, INF)
    # n + k 形式
    m = re.match(r'(\w+)\s*\+\s*(\d+)', expr)
    if m:
        var, k = m.group(1), int(m.group(2))
        if var in consts:
            v = consts[var] + k
            return Interval(v, v)
        return Interval(k, INF)
    return Interval(0, INF)


def _collect_consts(code: str) -> Dict[str, int]:
    """收集常量赋值."""
    consts: Dict[str, int] = {}
    for m in _ASSIGN_RE.finditer(code):
        consts[m.group(1)] = int(m.group(2))
    return consts


def _apply_guards(code: str, consts: Dict[str, int]) -> Dict[str, Interval]:
    """从守卫条件提取变量上界."""
    ranges: Dict[str, Interval] = {}
    for m in _GUARD_RE.finditer(code):
        var, op, val = m.group(1), m.group(2), int(m.group(3))
        if op == '<':
            ranges[var] = Interval(0, val - 1)
        elif op == '<=':
            ranges[var] = Interval(0, val)
        elif op == '>':
            ranges[var] = Interval(val + 1, INF)
        elif op == '>=':
            ranges[var] = Interval(val, INF)
    return ranges


def extract_alloc_sites(code: str) -> List[AllocSite]:
    """从代码中提取堆分配点."""
    consts = _collect_consts(code)
    guards = _apply_guards(code, consts)
    lines = code.split('\n')
    sites: List[AllocSite] = []
    for i, line in enumerate(lines):
        for m in _ALLOC_RE.finditer(line):
            var = m.group(1)
            size_expr = m.group(2).strip()
            size_range = _eval_expr(size_expr, consts)
            if var in guards:
                size_range = guards[var]
            sites.append(AllocSite(
                var=var, size_expr=size_expr,
                size_range=size_range, line=i + 1,
            ))
    return sites


def extract_heap_writes(code: str) -> List[HeapWrite]:
    """从代码中提取堆写入操作."""
    consts = _collect_consts(code)
    lines = code.split('\n')
    writes: List[HeapWrite] = []
    for i, line in enumerate(lines):
        for m in _WRITE_RE.finditer(line):
            dest = m.group(1).strip()
            size = m.group(2).strip() if m.group(2) else ''
            size_range = _eval_expr(size, consts) if size else Interval(0, INF)
            writes.append(HeapWrite(
                dest_var=dest, size_expr=size,
                size_range=size_range, line=i + 1,
            ))
    return writes


def analyze_heap_bounds(code: str) -> List[BoundsViolation]:
    """分析堆写入是否超出分配边界.

    对每个 (alloc, write) 对:
      - write.size_range.hi > alloc.size_range.hi → 可能溢出
      - write.size_range.lo > alloc.size_range.hi → 确定溢出
    """
    allocs = extract_alloc_sites(code)
    writes = extract_heap_writes(code)
    violations: List[BoundsViolation] = []

    alloc_map = {a.var: a for a in allocs}
    for w in writes:
        base_var = re.sub(r'[\[\(].*$', '', w.dest_var).strip()
        base_var = re.sub(r'^[*&]', '', base_var).strip()
        alloc = alloc_map.get(base_var)
        if not alloc:
            continue
        write_hi = w.size_range.hi
        alloc_hi = alloc.size_range.hi
        write_lo = w.size_range.lo
        if write_lo > alloc_hi and alloc_hi < INF:
            violations.append(BoundsViolation(
                alloc=alloc, write=w,
                overflow_bytes=write_lo - alloc_hi,
                is_definite=True,
            ))
        elif write_hi > alloc_hi and alloc_hi < INF:
            violations.append(BoundsViolation(
                alloc=alloc, write=w,
                overflow_bytes=write_hi - alloc_hi,
                is_definite=False,
            ))
    return violations


def check_bounds(
    allocs: List[AllocSite],
    writes: List[HeapWrite],
) -> List[BoundsViolation]:
    """边界检查主函数: 对给定的分配点和写入列表做交叉检查."""
    violations: List[BoundsViolation] = []
    alloc_map = {a.var: a for a in allocs}
    for w in writes:
        base_var = re.sub(r'[\[\(].*$', '', w.dest_var).strip()
        base_var = re.sub(r'^[*&]', '', base_var).strip()
        alloc = alloc_map.get(base_var)
        if not alloc:
            continue
        write_hi = w.size_range.hi
        alloc_hi = alloc.size_range.hi
        write_lo = w.size_range.lo
        if write_lo > alloc_hi and alloc_hi < INF:
            violations.append(BoundsViolation(
                alloc=alloc, write=w,
                overflow_bytes=write_lo - alloc_hi,
                is_definite=True,
            ))
        elif write_hi > alloc_hi and alloc_hi < INF:
            violations.append(BoundsViolation(
                alloc=alloc, write=w,
                overflow_bytes=write_hi - alloc_hi,
                is_definite=False,
            ))
    return violations
