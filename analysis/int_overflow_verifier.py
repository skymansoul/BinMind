"""
整数溢出验证器 — 值范围传播 + I-GUARD 六阶段 FP 削减。
  1.值范围传播 2.溢出可行性 3.守卫检测 4.abort守卫 5.符号域 6.批量验证
与 int_overflow_detector.py 互补: detector广度扫描(高召回), verifier深度过滤(高精度)
参考: Dietz et al., IOC, CWE-190
"""

from __future__ import annotations

import logging, re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

_log = logging.getLogger(__name__)

_ABORT_GUARD_RE = re.compile(
    r'if\s*\(\s*(\w+)\s*\*\s*(\w+)\s*<\s*\1\s*\)\s*(?:abort|assert|exit)\s*\(',
    re.IGNORECASE)
_BUILTIN_OVERFLOW_RE = re.compile(
    r'__builtin_(?:[su])?(?:add|sub|mul)l?_overflow\s*\(')
_UNSIGNED_DECL_RE = re.compile(
    r'(?:unsigned|size_t|uint\d+_t|uintptr_t)\s+(\w+)')
# 显式溢出守卫: if (a > INT_MAX / b) return error;
_OVERFLOW_DIV_GUARD_RE = re.compile(
    r'if\s*\(\s*(\w+)\s*>\s*(?:INT_MAX|INT32_MAX|UINT_MAX|SIZE_MAX|'
    r'(?:\d+))\s*/\s*(\w+)\s*\)', re.IGNORECASE)


@dataclass
class ValueRange:
    """整数值范围."""
    lo: int = 0
    hi: int = 2**31 - 1
    is_top: bool = False
    is_bottom: bool = False

    @staticmethod
    def const(v: int) -> "ValueRange":
        return ValueRange(lo=v, hi=v)

    @staticmethod
    def top() -> "ValueRange":
        return ValueRange(is_top=True)

    def mul(self, other: "ValueRange") -> "ValueRange":
        """乘法: 取四个角的极值."""
        if self.is_top or other.is_top:
            return ValueRange.top()
        vals = [self.lo * other.lo, self.lo * other.hi,
                self.hi * other.lo, self.hi * other.hi]
        return ValueRange(lo=min(vals), hi=max(vals))

    def add(self, other: "ValueRange") -> "ValueRange":
        if self.is_top or other.is_top:
            return ValueRange.top()
        return ValueRange(lo=self.lo + other.lo, hi=self.hi + other.hi)

    def may_overflow(self, bits: int = 32) -> bool:
        """是否可能超过 bit 位有符号/无符号上限."""
        if self.is_top:
            return True
        max_val = (1 << bits) - 1
        return self.hi > max_val or self.lo < 0

    def refine_by_guard(self, op: str, bound: int) -> "ValueRange":
        """用守卫条件精化范围."""
        if self.is_top:
            return self
        if op == 'lt':  # <
            return ValueRange(lo=self.lo, hi=min(self.hi, bound - 1))
        elif op == 'le':  # <=
            return ValueRange(lo=self.lo, hi=min(self.hi, bound))
        elif op == 'gt':  # >
            return ValueRange(lo=max(self.lo, bound + 1), hi=self.hi)
        elif op == 'ge':  # >=
            return ValueRange(lo=max(self.lo, bound), hi=self.hi)
        return self

    def __repr__(self) -> str:
        if self.is_top:
            return "TOP"
        return f"[{self.lo}, {self.hi}]"


@dataclass
class IntOverflowVerdict:
    """整数溢出判定."""
    expr: str
    func_name: str
    call_site: int
    range_before_guard: ValueRange
    range_after_guard: ValueRange
    may_overflow: bool
    is_guarded: bool
    confidence: float
    reason: str


class IntOverflowVerifier:
    """基于值范围传播的整数溢出验证."""

    # 守卫模式
    _GUARD_PATS = [
        (r'if\s*\(\s*(\w+)\s*<\s*(\d+)\s*\)', 'lt'),
        (r'if\s*\(\s*(\w+)\s*<=\s*(\d+)\s*\)', 'le'),
        (r'if\s*\(\s*(\w+)\s*>\s*(\d+)\s*\)', 'gt'),
        (r'if\s*\(\s*(\w+)\s*>=\s*(\d+)\s*\)', 'ge'),
        (r'(\w+)\s*=\s*min\s*\(\s*\w+\s*,\s*(\d+)\s*\)', 'le'),
        (r'(\w+)\s*=\s*max\s*\(\s*\w+\s*,\s*(\d+)\s*\)', 'ge'),
    ]

    def __init__(self):
        self._var_ranges: Dict[str, ValueRange] = {}
        self._guards: Dict[str, List[Tuple[str, int]]] = {}

    def clear(self):
        self._var_ranges.clear()
        self._guards.clear()

    def propagate(self, insns: List[Tuple[int, str]]):
        """在伪代码行上做值范围正向传播."""
        for addr, text in insns:
            tl = text.strip()
            # var = const
            m = re.match(r'(\w+)\s*=\s*(\d+)\s*;?$', tl)
            if m:
                self._var_ranges[m.group(1)] = ValueRange.const(int(m.group(2)))
                continue
            # var = other
            m = re.match(r'(\w+)\s*=\s*(\w+)\s*;?$', tl)
            if m:
                src = self._var_ranges.get(m.group(2))
                if src: self._var_ranges[m.group(1)] = ValueRange(lo=src.lo, hi=src.hi)
                continue
            # var = a * b
            m = re.match(r'(\w+)\s*=\s*(\w+)\s*\*\s*(\w+)\s*;?$', tl)
            if m:
                a = self._var_ranges.get(m.group(2), ValueRange.top())
                b = self._var_ranges.get(m.group(3), ValueRange.top())
                self._var_ranges[m.group(1)] = a.mul(b)
                continue
            # var = a + const
            m = re.match(r'(\w+)\s*=\s*(\w+)\s*\+\s*(\d+)\s*;?$', tl)
            if m:
                a = self._var_ranges.get(m.group(2), ValueRange.top())
                self._var_ranges[m.group(1)] = a.add(ValueRange.const(int(m.group(3))))
                continue

            # 守卫模式
            for pat, op in self._GUARD_PATS:
                gm = re.match(pat, tl)
                if gm:
                    var, val = gm.group(1), int(gm.group(2))
                    self._guards.setdefault(var, []).append((op, val))
                    break

    def verify(self, expr: str, func_name: str = "",
               call_site: int = 0) -> IntOverflowVerdict:
        """验证 a*b 或 a 是否可能溢出 (含守卫精化)."""
        # 解析表达式: a * b 或 a
        mul_m = re.match(r'(\w+)\s*\*\s*(\w+)', expr)
        if mul_m:
            a_name, b_name = mul_m.group(1), mul_m.group(2)
            a_range = self._var_ranges.get(a_name, ValueRange.top())
            b_range = self._var_ranges.get(b_name, ValueRange.top())
            raw_range = a_range.mul(b_range)
        else:
            raw_range = self._var_ranges.get(expr, ValueRange.top())

        # 应用守卫
        guarded_range = raw_range
        is_guarded = False
        if expr in self._guards or mul_m:
            target_var = expr if expr in self._guards else (
                mul_m.group(1) if mul_m and mul_m.group(1) in self._guards else None)
            if target_var:
                for op, bound in self._guards[target_var]:
                    guarded_range = guarded_range.refine_by_guard(op, bound)
                    is_guarded = True

        may_ovf = guarded_range.may_overflow()

        if not may_ovf and not raw_range.is_top:
            confidence = 0.05
            reason = f"值范围 {guarded_range} 在安全边界内"
        elif may_ovf and is_guarded:
            confidence = 0.40
            reason = f"被守卫但范围 {guarded_range} 仍可能溢出"
        elif may_ovf and not raw_range.is_top:
            confidence = 0.75
            reason = f"值范围 {guarded_range} 可能溢出 {2**31-1}"
        else:
            confidence = 0.35
            reason = "值范围未知"

        return IntOverflowVerdict(
            expr=expr, func_name=func_name, call_site=call_site,
            range_before_guard=raw_range,
            range_after_guard=guarded_range,
            may_overflow=may_ovf,
            is_guarded=is_guarded,
            confidence=confidence,
            reason=reason,
        )

    # Stage A: Abort 守卫 ─────────────────────────

    def check_abort_guard(self, code: str, ops: List[str]) -> bool:
        """if(a*b < a) abort() | __builtin_*_overflow → 运行时崩溃而非可利用溢出."""
        return bool(_ABORT_GUARD_RE.search(code) or
                    _BUILTIN_OVERFLOW_RE.search(code) or
                    _OVERFLOW_DIV_GUARD_RE.search(code))

    # Stage D: Domain Narrowing ──────────────────

    def is_unsigned_domain(self, code: str, ops: List[str]) -> bool:
        """检测操作数是否均为无符号类型 (unsigned wrap 是定义行为)."""
        unsigned_vars: Set[str] = set()
        for m in _UNSIGNED_DECL_RE.finditer(code):
            unsigned_vars.add(m.group(1))
        for m in re.finditer(r'(?:size_t|uintptr_t)\s+(\w+)', code):
            unsigned_vars.add(m.group(1))
        return bool(ops and all(
            op in unsigned_vars for op in ops if op and not op.isdigit()))

    # 批量验证 ───────────────────────────────────

    def verify_candidates(self, findings: List[dict], code: str = ""
                          ) -> Tuple[List[dict], Dict[str, int]]:
        """批量验证检测器候选: 值范围+abort+domain → 综合判定。"""
        stats = {'safe_guarded': 0, 'safe_bounded': 0,
                 'safe_domain': 0, 'confirmed': 0, 'uncertain': 0}
        refined = []
        for f in findings:
            expr = f.get('expr', f.get('expression', ''))
            ops = re.findall(r'[a-zA-Z_]\w*', expr) if expr else []
            v = self.verify(expr, f.get('function', ''))
            has_abort = self.check_abort_guard(code, ops)
            is_unsigned = self.is_unsigned_domain(code, ops)
            desc = str(f.get('description', ''))
            in_alloc = any(op in desc for op in ['malloc','calloc','realloc'])

            if not v.may_overflow:
                f['severity']='Info'; f['confidence']=0.05
                f['iov_verdict']='safe_bounded'; f['iov_reason']=v.reason
                stats['safe_bounded']+=1
            elif has_abort:
                f['severity']='Low'; f['confidence']=0.25
                f['iov_verdict']='safe_guarded'
                f['iov_reason']='abort/builtin overflow guard'
                stats['safe_guarded']+=1
            elif is_unsigned and not in_alloc:
                f['severity']='Low'; f['confidence']=0.30
                f['iov_verdict']='safe_domain'
                f['iov_reason']='unsigned domain: wrap is defined'
                stats['safe_domain']+=1
            elif v.may_overflow and not v.is_guarded:
                f['severity']='Critical'; f['confidence']=0.85
                f['iov_verdict']='confirmed'; f['iov_reason']=v.reason
                stats['confirmed']+=1
            else:
                f['iov_verdict']='uncertain'; f['iov_reason']=v.reason
                stats['uncertain']+=1
            refined.append(f)
        return refined, stats


def verify_int_overflow_candidates(findings: List[dict], code: str = ""
                                   ) -> Tuple[List[dict], Dict[str, int]]:
    """I-GUARD 整数溢出验证便捷入口。"""
    return IntOverflowVerifier().verify_candidates(findings, code)
