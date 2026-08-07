"""
SGAV 值范围传播器 — 区间域抽象解释 + 守卫精化.
从赋值/守卫推断每个变量在每行的值范围.
"""
import re
from typing import Dict, List, Optional, Tuple
from analysis.sgav_types import ValueRange, GuardConstraint

# 赋值 var = expr
_ASSIGN = re.compile(r'(\w[\w]*)\s*=\s*([^;]+);')
# 常量赋值
_CONST_ASSIGN = re.compile(r'(\w[\w]*)\s*=\s*(\d+)\s*;')
# sizeof 赋值
_SIZEOF_ASSIGN = re.compile(r'(\w[\w]*)\s*=\s*sizeof\s*\(\s*(\w[\w]*)\s*\)\s*;')
# 算术赋值 var = a op b
_ARITH = re.compile(
    r'(\w[\w]*)\s*=\s*(\w[\w]*)\s*([+\-*/])\s*(\w[\w]*|\d+)\s*;')
# atoi 赋值
_ATOI = re.compile(r'(\w[\w]*)\s*=\s*atoi\s*\(')
# argc 赋值
_ARGC_COND = re.compile(r'argc\s*>\s*(\d+)')


class RangePropagator:
    """区间域值范围传播 + 守卫精化."""

    def propagate(self, lines: List[str],
                  guards: Dict[int, List[GuardConstraint]]
                  ) -> Dict[int, Dict[str, ValueRange]]:
        """返回 {line: {var: range}} 每行每变量的值范围."""
        result: Dict[int, Dict[str, ValueRange]] = {}
        ranges: Dict[str, ValueRange] = {}
        for i, line in enumerate(lines, start=1):
            text = line.strip()
            if text.startswith(('//', '/*')): continue
            # 守卫精化: 进入 if 块后约束变量范围
            line_guards = guards.get(i, [])
            for g in line_guards:
                if g.var in ranges:
                    ranges[g.var] = self._refine(ranges[g.var], g)
                else:
                    ranges[g.var] = self._from_guard(g)
            # 记录当前行快照
            result[i] = {k: ValueRange(lo=v.lo, hi=v.hi, is_const=v.is_const)
                         for k, v in ranges.items()}
            # 处理赋值
            self._process_assign(text, ranges)
        return result

    def _process_assign(self, text: str,
                        ranges: Dict[str, ValueRange]) -> None:
        # sizeof(buf) = N
        m = _SIZEOF_ASSIGN.search(text)
        if m:
            var = m.group(1)
            buf_name = m.group(2)
            # sizeof 是编译期常量，但不能在纯源码层面知道确切值
            # 标记为有界但值未知 → 给定一个合理上界
            ranges[var] = ValueRange(lo=1, hi=4096, is_const=False)
            return
        # 常量赋值
        m = _CONST_ASSIGN.search(text)
        if m:
            val = int(m.group(2))
            ranges[m.group(1)] = ValueRange(lo=val, hi=val, is_const=True)
            return
        # atoi → 用户输入，范围无界
        m = _ATOI.search(text)
        if m:
            ranges[m.group(1)] = ValueRange(
                lo=-2147483648, hi=2147483647, is_const=False)
            return
        # 算术赋值: c = a op b
        m = _ARITH.search(text)
        if m:
            dst, lhs, op, rhs_str = m.group(1), m.group(2), m.group(3), m.group(4)
            lhs_r = ranges.get(lhs, ValueRange())
            rhs_r: ValueRange
            if rhs_str.isdigit():
                val = int(rhs_str)
                rhs_r = ValueRange(lo=val, hi=val, is_const=True)
            else:
                rhs_r = ranges.get(rhs_str, ValueRange())
            ranges[dst] = self._compute(lhs_r, op, rhs_r)
            return
        # argc 在 main 中 > 1 → argc 无界
        m = _ARGC_COND.search(text)
        if m:
            pass  # argc 本身不传播

    @staticmethod
    def _compute(a: ValueRange, op: str, b: ValueRange) -> ValueRange:
        if op == '+':
            lo = a.lo + b.lo
            hi = a.hi + b.hi
        elif op == '-':
            lo = a.lo - b.hi
            hi = a.hi - b.lo
        elif op == '*':
            vals = [a.lo * b.lo, a.lo * b.hi, a.hi * b.lo, a.hi * b.hi]
            lo = min(vals)
            hi = max(vals)
        elif op == '/':
            if b.lo <= 0 <= b.hi:
                lo = -2147483648
                hi = 2147483647
            elif b.lo > 0:
                lo = a.lo // b.hi
                hi = a.hi // b.lo
            else:
                lo = a.hi // b.lo
                hi = a.lo // b.hi
        else:
            return ValueRange()
        # 截断到合理范围
        lo = max(lo, -2147483648)
        hi = min(hi, 2147483647)
        return ValueRange(lo=lo, hi=hi, is_const=False)

    @staticmethod
    def _refine(r: ValueRange, g: GuardConstraint) -> ValueRange:
        """用守卫约束精化值范围."""
        if g.bound < 0:
            return r  # sizeof 特殊情况
        if g.op == '<':
            return ValueRange(lo=r.lo, hi=min(r.hi, g.bound - 1))
        if g.op == '<=':
            return ValueRange(lo=r.lo, hi=min(r.hi, g.bound))
        if g.op == '>':
            return ValueRange(lo=max(r.lo, g.bound + 1), hi=r.hi)
        if g.op == '>=':
            return ValueRange(lo=max(r.lo, g.bound), hi=r.hi)
        if g.op == '==':
            return ValueRange(lo=g.bound, hi=g.bound, is_const=True)
        return r

    @staticmethod
    def _from_guard(g: GuardConstraint) -> ValueRange:
        if g.bound < 0:
            return ValueRange()
        if g.op == '<':
            return ValueRange(lo=0, hi=g.bound - 1)
        if g.op == '<=':
            return ValueRange(lo=0, hi=g.bound)
        if g.op == '>':
            return ValueRange(lo=g.bound + 1, hi=2147483647)
        if g.op == '>=':
            return ValueRange(lo=g.bound, hi=2147483647)
        if g.op == '==':
            return ValueRange(lo=g.bound, hi=g.bound, is_const=True)
        return ValueRange()


__all__ = ['RangePropagator']
