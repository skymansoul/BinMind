"""
区间域与约束简化 — 堆溢出误报抑制的第二阶段。

决策逻辑:
  二进制级 size 表达式无法精确求值, 但可保守地收窄为区间 [lo, hi]。
  区间域提供 meet(约束) / join(汇合) / 乘法缩放 等运算, 供写大小
  与分配大小的比较使用。约束简化负责把 sizeof(T)*n 类表达式展开为
  可计算的线性形式, 并消去与判定无关的常量项。

设计约束:
  区间运算保持 sound: 结果必包含真实值。无法推导时返回 (0, INF),
  由三态判定引擎按保守策略处理 (宁保留告警, 不漏报)。
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional, Tuple

INF = 1 << 62

_SIZEOF_MAP = {
    'char': 1, 'int': 4, 'unsigned': 4, 'long': 8, 'unsigned long': 8,
    'size_t': 8, 'short': 2, 'double': 8, 'float': 4, 'pointer': 8,
    'void*': 8, 'char*': 8, 'int*': 8, 'uint8_t': 1, 'uint16_t': 2,
    'uint32_t': 4, 'uint64_t': 8, 'long long': 8,
}


@dataclass(frozen=True)
class Interval:
    """闭区间 [lo, hi], 空区间用 lo > hi 表示."""
    lo: int
    hi: int

    @staticmethod
    def top() -> 'Interval':
        return Interval(0, INF)

    @staticmethod
    def bottom() -> 'Interval':
        return Interval(1, 0)

    @staticmethod
    def point(v: int) -> 'Interval':
        return Interval(v, v)

    def is_top(self) -> bool:
        return self.lo == 0 and self.hi == INF

    def is_bottom(self) -> bool:
        return self.lo > self.hi

    def meet(self, other: 'Interval') -> 'Interval':
        """约束交集 — 收窄区间."""
        lo, hi = max(self.lo, other.lo), min(self.hi, other.hi)
        return Interval(lo, hi)

    def join(self, other: 'Interval') -> 'Interval':
        """汇合并集 — 放宽区间."""
        return Interval(min(self.lo, other.lo), max(self.hi, other.hi))

    def scale(self, k: int) -> 'Interval':
        if k == 0:
            return Interval(0, 0)
        if k > 0:
            return Interval(self.lo * k, self.hi * k)
        return Interval(self.hi * k, self.lo * k)

    def shift(self, k: int) -> 'Interval':
        return Interval(self.lo + k, self.hi + k)

    def add(self, other: 'Interval') -> 'Interval':
        return Interval(self.lo + other.lo, self.hi + other.hi)

    def __contains__(self, v: int) -> bool:
        return self.lo <= v <= self.hi

    def __str__(self) -> str:
        if self.is_top():
            return '[0,INF]'
        if self.is_bottom():
            return '[EMPTY]'
        return f'[{self.lo},{self.hi}]'


def simplify_expr(expr: str, env: Optional[dict] = None) -> Tuple[Interval, bool]:
    """约束简化: 将 size 表达式转换为区间 + 是否完全确定.

    支持: 常量, sizeof(T), 变量(查 env), a*b, a+b, a-b, (expr) 括号。
    返回 (区间, 是否常量确定)。
    """
    if env is None:
        env = {}
    expr = expr.strip()
    if not expr:
        return Interval.top(), False

    m = re.fullmatch(r'0x[0-9a-fA-F]+|\d+', expr)
    if m:
        return Interval.point(int(expr, 0)), True

    m = _RE_SIZEOF_SIMPLE.fullmatch(expr)
    if m:
        tname = m.group(1)
        if tname in _SIZEOF_MAP:
            return Interval.point(_SIZEOF_MAP[tname]), True
        return Interval.top(), False

    # 拆最外层 +/-/* (按最后一个运算符, 避免优先级错误)
    for op in ('+', '-', '*'):
        idx = _find_top_level_op(expr, op)
        if idx >= 0:
            left, right = expr[:idx].strip(), expr[idx + 1:].strip()
            il, cl = simplify_expr(left, env)
            ir, cr = simplify_expr(right, env)
            if op == '+':
                return il.add(ir), cl and cr
            if op == '-':
                return Interval(il.lo - ir.hi, il.hi - ir.lo), cl and cr
            return il.scale(ir.lo) if il.hi == il.lo else Interval.top(), False

    if expr in env:
        return env[expr], False
    if re.fullmatch(r'\w+', expr):
        return Interval.top(), False
    return Interval.top(), False


_RE_SIZEOF_SIMPLE = re.compile(r'sizeof\s*\(\s*(\w+)\s*\)')


def _find_top_level_op(expr: str, op: str) -> int:
    """寻找最外层 (括号外) 的运算符位置, 无则返回 -1."""
    depth = 0
    for i in range(len(expr) - 1, -1, -1):
        c = expr[i]
        if c == ')':
            depth += 1
        elif c == '(':
            depth -= 1
        elif depth == 0 and c == op:
            return i
    return -1


def bound_scale(base: Interval, scale_k: int) -> Interval:
    """写大小缩放: 循环次数 × 单次写大小."""
    return base.scale(scale_k)


def clamp_nonneg(iv: Interval) -> Interval:
    """负数截断为 0 — 分配大小与写大小均非负."""
    return Interval(max(0, iv.lo), max(0, iv.hi))
