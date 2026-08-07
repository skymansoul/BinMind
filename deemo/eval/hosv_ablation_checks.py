"""

包含循环写入/有界写入/变长分配/指针写入/双变量检查逻辑.
"""
from __future__ import annotations
from typing import Optional, List

from analysis.heap_overflow_types import HoResult, HoVerdict
from analysis.heap_overflow_src_patterns import _ptmalloc2_usable
from analysis.heap_overflow_src_checks import is_tainted_input
from analysis.heap_overflow_src_guards import (
    find_loop_bound_const, find_guard_bounds, infer_stride)
from analysis.heap_overflow_src_apas import struct_write_check


def _vuln(a, w, ac, ws, detail, conf=0.85) -> HoResult:
    return HoResult(
        verdict=HoVerdict.VULN, alloc_line=a.line, write_line=w.line,
        var_name=a.var, alloc_size=ac, write_size=ws,
        confidence=conf,
        reason=f"'{a.var}': malloc({ac})@L{a.line} + {detail}@L{w.line}")


def _safe(a, w, ac, ws, detail, conf=0.90) -> HoResult:
    return HoResult(
        verdict=HoVerdict.SAFE, alloc_line=a.line, write_line=w.line,
        var_name=a.var, alloc_size=ac, write_size=ws, confidence=conf,
        reason=f"'{a.var}': malloc({ac}) + {detail} — safe")


def _uncertain(a, w, ac, detail, conf=0.50) -> HoResult:
    return HoResult(
        verdict=HoVerdict.UNCERTAIN, alloc_line=a.line, write_line=w.line,
        var_name=a.var, alloc_size=ac, write_size=-1, confidence=conf,
        reason=f"'{a.var}': {detail}@L{w.line} — needs further analysis")


class AblationChecksMixin:
    """AblationVerifier的详细检查方法, 拆出为mixin."""

    def _loop_write(self, a, w, lines, sc) -> Optional[HoResult]:
        import re
        lb = None
        if hasattr(w, 'loop_bound') and w.loop_bound > 0:
            lb = w.loop_bound
        if lb is None and self._guard:
            lb = find_loop_bound_const(lines, w.line, w.target)
        if lb is None and sc > 0:
            sz_var = a.size_expr.strip()
            if sz_var and re.search(
                    r'for\s*\([^;]*;\s*\w+\s*<\s*'
                    + re.escape(sz_var) + r'\s*[;]',
                    '\n'.join(lines[max(0, w.line - 5):w.line])):
                stride = infer_stride(a, lines)
                we = sc * stride
                if we <= sc:
                    return _safe(a, w, sc, we,
                                 f"loop_var={sz_var}=alloc({sc})*stride({stride})")
        if lb is not None and lb > 0:
            stride = infer_stride(a, lines)
            we = lb * stride
            if we <= sc:
                return _safe(a, w, sc, we,
                             f"loop_bound({lb})*stride({stride})")
            return HoResult(
                verdict=HoVerdict.VULN, alloc_line=a.line,
                write_line=w.line, var_name=a.var, alloc_size=sc,
                write_size=we, overflow_bytes=we - sc,
                confidence=0.85,
                reason=f"'{a.var}': malloc({sc}), "
                       f"loop_bound({lb})*stride({stride})={we} > {sc}")
        return _vuln(a, w, sc, -1, "unbounded loop_write")

    def _bounded(self, a, w, sc, ag) -> Optional[HoResult]:
        if self._alloc:
            usable = _ptmalloc2_usable(sc)
        else:
            usable = sc
        if w.offset + w.write_size <= usable:
            return _safe(a, w, sc, w.write_size, f"{w.kind} {w.write_size}B")
        conf = 0.55 if ag else 0.90
        return HoResult(
            verdict=HoVerdict.VULN, alloc_line=a.line, write_line=w.line,
            var_name=a.var, alloc_size=sc, write_size=w.write_size,
            overflow_bytes=w.offset + w.write_size - usable,
            confidence=conf, stage_guard=not ag,
            reason=f"'{a.var}': malloc({sc}) usable={usable}, "
                   f"{w.kind} writes {w.write_size}B@offset {w.offset}@L{w.line}"
                   + (" (guarded but oversized)" if ag else ""))

    def _var_alloc(self, a, w, ag, au) -> Optional[HoResult]:
        if self._guard and ag and au > 0 and w.write_size > au:
            return HoResult(
                verdict=HoVerdict.VULN, alloc_line=a.line,
                write_line=w.line, var_name=a.var, alloc_size=-1,
                write_size=w.write_size,
                overflow_bytes=w.write_size - au,
                confidence=0.80, stage_guard=False,
                reason=f"'{a.var}': malloc({a.size_expr}) guarded≤{au} "
                       f"+ {w.kind}({w.write_size}B)@L{w.line} "
                       f"— write exceeds guard bound")
        if self._cgraph_en and self._cgraph.may_overflow(
                a.size_expr.strip(), 0, w.write_size, w.target):
            return _uncertain(a, w, -1, f"variable alloc({a.size_expr})")
        if not self._cgraph_en:
            return _uncertain(a, w, -1, f"variable alloc({a.size_expr})")
        return None

    def _ptr_write(self, a, w, lines, sc) -> Optional[HoResult]:
        if self._alloc:
            usable = _ptmalloc2_usable(sc)
        else:
            usable = sc
        if w.offset < 0 and hasattr(w, 'src_var') and w.src_var:
            return self._var_offset_ptr(a, w, lines, sc, usable)
        woff = w.offset if w.offset >= 0 else 0
        if woff + w.write_size > usable:
            return _vuln(a, w, sc, w.write_size,
                         f"ptr+{woff} write {w.write_size}B")
        return _safe(a, w, sc, w.write_size,
                     f"ptr+{woff} write {w.write_size}B")

    def _var_offset_ptr(self, a, w, lines, sc, usable) -> HoResult:
        vn = w.src_var
        if self._guard:
            lo, hi = find_guard_bounds(vn, lines, w.line)
        else:
            lo, hi = None, None
        if lo is not None and lo + w.write_size > usable:
            return HoResult(
                verdict=HoVerdict.VULN, alloc_line=a.line,
                write_line=w.line, var_name=a.var, alloc_size=sc,
                write_size=w.write_size,
                overflow_bytes=lo + w.write_size - usable,
                confidence=0.80,
                reason=f"'{a.var}': ptr+{vn}(>={lo}) write {w.write_size}B"
                       f"@L{w.line} — guard proves overflow")
        if hi is not None and hi + w.write_size <= usable:
            return _safe(a, w, sc, w.write_size,
                         f"ptr+{vn}(<={hi}) write {w.write_size}B")
        return _uncertain(a, w, sc, f"ptr+{vn}(var offset)")

    def _double_var(self, a, w, lines, ag, au) -> HoResult:
        if self._guard and ag and a.size_expr.strip() == w.target:
            return _safe(a, w, -1, -1,
                         f"guard≤{au} + {w.kind}({a.size_expr})")
        if self._guard and ag:
            return _uncertain(a, w, -1,
                              f"guarded≤{au} + {w.kind}", conf=0.40)
        taint = is_tainted_input(a.size_expr, lines, a.line) or \
            is_tainted_input(w.target, lines, w.line)
        if taint:
            return HoResult(
                verdict=HoVerdict.VULN, alloc_line=a.line,
                write_line=w.line, var_name=a.var,
                alloc_size=-1, write_size=-1, confidence=0.75,
                reason=f"'{a.var}': malloc({a.size_expr})@L{a.line} + "
                       f"{w.kind}@{w.line} — both sizes tainted, unbounded")
        return _uncertain(a, w, -1, "variable sizes", conf=0.45)


__all__ = [
    'AblationChecksMixin', '_vuln', '_safe', '_uncertain',
]
