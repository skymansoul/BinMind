"""
堆溢出源级验证器 (堆写模式验证 (Heap Write Verification)). 5阶段管线 — 分配→写入→边界检查→约束闭包→APAS增强.

▎正则模式+分配器模型 → analysis.heap_overflow_src_patterns
▎Phase 1+2 → analysis.heap_overflow_src_phases
▎累积/循环/chunk/struct_array检查 → analysis.heap_overflow_src_checks
▎循环边界/guard约束/stride推断 → analysis.heap_overflow_src_guards
▎APAS别名传播+偏移求解 → analysis.heap_overflow_src_apas
"""

import re
from typing import List, Optional, Set, Tuple

from analysis.heap_overflow_types import (
    HoVerdict, HeapAllocSite, HeapWriteSite, HoResult)
from analysis.heap_size_constraint_graph import HeapSizeConstraintGraph
from analysis.heap_overflow_src_patterns import _ptmalloc2_usable
from analysis.heap_overflow_src_phases import find_allocs, find_writes
from analysis.heap_overflow_src_checks import (
    targets_same_heap_obj, alloc_has_guard, is_tainted_input,
    check_strcat_accumulation, check_loop_accumulation,
    check_chunk_relation, check_struct_array_oob)
from analysis.heap_overflow_src_guards import (
    find_loop_bound_const, find_guard_bounds, infer_stride)
from analysis.heap_overflow_src_interproc import (
    resolve_factory_allocs, resolve_cross_func_writes)
from analysis.heap_overflow_src_apas import (
    build_alias_closure, resolve_alias,
    resolve_write_offset, struct_write_check)
from analysis.heap_overflow_src_apas_writes import (
    find_alias_writes, find_struct_field_writes)
from analysis.heap_overflow_src_verifier_helpers import (
    vuln as _vuln, safe as _safe, uncertain as _uncertain)


class HeapOverflowSrcVerifier:
    """堆溢出源级验证 — 5阶段管线 + 差异约束图 + APAS."""

    def __init__(self):
        self._cgraph = HeapSizeConstraintGraph()

    def verify(self, source: str) -> List[HoResult]:
        """主入口: 运行5阶段管线 (Phase 1-4 + APAS增强)."""
        from analysis.heap_overflow_src_patterns import _skip_block_comments
        raw = source.splitlines()
        valid = {ln for ln, _ in _skip_block_comments(raw)}
        lines = raw
        results: List[HoResult] = []

        allocs = find_allocs(lines, valid)
        allocs.extend(resolve_factory_allocs(lines, allocs))
        if not allocs:
            return results

        # APAS Phase 5: 多跳别名闭包
        alloc_vars = {a.var for a in allocs}
        alias_map = build_alias_closure(lines, alloc_vars)
        for a in allocs:
            alias_map.setdefault(a.var, a.var)

        writes = find_writes(lines, allocs, valid)
        for w in writes:
            w.target = resolve_alias(w.target, alias_map)
        writes.extend(find_alias_writes(lines, alias_map, alloc_vars, valid))
        writes.extend(find_struct_field_writes(lines, alloc_vars, valid))
        writes.extend(resolve_cross_func_writes(lines, allocs, writes))

        # APAS: memcpy偏移解析 (buf+expr → root+offset)
        for w in writes:
            if w.kind == 'memcpy' and w.offset == 0:
                w.offset = resolve_write_offset(w, lines)

        self._cgraph.clear()
        self._cgraph.extract_from_source(lines)
        self._cgraph.build_closure()

        rgrows = {a.var: (a.line, a.size_const) for a in allocs
                  if a.kind == 'realloc' and a.size_const > 0}

        for a in allocs:
            ag, au = alloc_has_guard(a, lines)
            for w in writes:
                if not self._targets_match(a, w, alias_map, lines):
                    continue
                if w.kind == 'loop_write' and w.line < a.line:
                    continue
                es = self._eff_size(a, w, rgrows)
                if es == -998:
                    continue
                r = self._check(a, w, lines, ag, au, es)
                if r:
                    results.append(r)

        results.extend(check_strcat_accumulation(allocs, writes, lines))
        results.extend(check_loop_accumulation(allocs, writes, lines))
        results.extend(check_chunk_relation(allocs, writes, lines))
        return self._dedup(results)

    @staticmethod
    def _targets_match(a, w, alias_map, lines) -> bool:
        """APAS增强的写入-分配匹配: 使用别名闭包."""
        if w.target == a.var:
            return True
        root = alias_map.get(w.target)
        if root == a.var:
            return True
        return targets_same_heap_obj(a, w, lines)

    def _check(self, a, w, lines, ag, au, sc=-999) -> Optional[HoResult]:
        """主分发: 检查分配-写入对是否构成溢出."""
        sz = sc if sc != -999 else a.size_const

        r = check_struct_array_oob(a, w, lines, sz)
        if r:
            return r

        if w.kind == 'struct_write':
            return struct_write_check(a, w, lines, sz)
        if w.write_size == -1 and w.kind in ('strcpy', 'strcat', 'sprintf'):
            if sz >= 0:
                return _vuln(a, w, sz, -1, f"unbounded {w.kind}")
        if w.write_size == -1 and w.kind == 'loop_write' and sz >= 0:
            r = self._loop_write(a, w, lines, sz)
            if r:
                return r
        if w.write_size >= 0 and sz >= 0 and not (
                w.kind == 'ptr_write' and w.offset < 0):
            return self._bounded(a, w, sz, ag)
        if a.size_const < 0 and w.write_size >= 0:
            r = self._var_alloc(a, w, ag, au)
            if r:
                return r
        if a.size_const >= 0 and w.write_size == -2:
            return _uncertain(a, w, a.size_const, "expression write size")
        if sz >= 0 and w.write_size < 0 and w.kind in (
                'memcpy', 'memset', 'read', 'fread', 'ptr_write'):
            return _vuln(a, w, sz, -1, f"{w.kind}(unknown size)")
        if w.kind == 'ptr_write' and sz >= 0:
            return self._ptr_write(a, w, lines, sz)
        if a.size_const < 0 and w.write_size < 0:
            return self._double_var(a, w, lines, ag, au)
        return None

    @staticmethod
    def _eff_size(a, w, rgrows):
        """计算有效分配大小, -998表示跳过."""
        if a.kind != 'malloc' or a.var not in rgrows:
            return a.size_const
        rl, rsz = rgrows[a.var]
        if w.line > rl and rsz < a.size_const:
            return -998
        if w.line > rl and rsz >= a.size_const:
            return rsz
        return a.size_const

    @staticmethod
    def _dedup(results):
        """去重: 同键保留最严重verdict (VULN > UNCERTAIN > SAFE)."""
        sev = {HoVerdict.VULN: 0, HoVerdict.UNCERTAIN: 1, HoVerdict.SAFE: 2}
        seen: Set[Tuple[int, int, str]] = set()
        out = []
        for r in sorted(results,
                        key=lambda x: (sev.get(x.verdict, 9), -x.confidence)):
            k = (r.alloc_line, r.write_line, r.var_name)
            if k not in seen:
                seen.add(k)
                out.append(r)
        return out

    def _loop_write(self, a, w, lines, sc) -> HoResult:
        """loop_write: 用循环上界×stride判定."""
        lb = None
        if hasattr(w, 'loop_bound') and w.loop_bound > 0:
            lb = w.loop_bound
        if lb is None:
            lb = find_loop_bound_const(lines, w.line, w.target)
        if lb is None and sc > 0:
            sz_var = a.size_expr.strip()
            if sz_var and re.search(
                    r'for\s*\([^;]*;\s*\w+\s*<\s*'
                    + re.escape(sz_var) + r'\s*[;]',
                    '\n'.join(lines[max(0, w.line-5):w.line])):
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

    def _bounded(self, a, w, sc, ag) -> HoResult:
        """有界写入: offset+write_size vs usable."""
        usable = _ptmalloc2_usable(sc)
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
        """变量大小分配 + 已知写入大小."""
        if ag and au > 0 and w.write_size > au:
            return HoResult(
                verdict=HoVerdict.VULN, alloc_line=a.line,
                write_line=w.line, var_name=a.var, alloc_size=-1,
                write_size=w.write_size,
                overflow_bytes=w.write_size - au,
                confidence=0.80, stage_guard=False,
                reason=f"'{a.var}': malloc({a.size_expr}) guarded≤{au} "
                       f"+ {w.kind}({w.write_size}B)@L{w.line} "
                       f"— write exceeds guard bound")
        if self._cgraph.may_overflow(a.size_expr.strip(), 0,
                                      w.write_size, w.target):
            return _uncertain(a, w, -1, f"variable alloc({a.size_expr})")
        return None

    def _ptr_write(self, a, w, lines, sc) -> Optional[HoResult]:
        """指针偏移写入 — 含变量偏移guard分析."""
        usable = _ptmalloc2_usable(sc)
        if w.offset < 0 and hasattr(w, 'src_var') and w.src_var:
            return self._var_offset_ptr(a, w, lines, sc, usable)
        woff = w.offset if w.offset >= 0 else 0
        if woff + w.write_size > usable:
            return _vuln(a, w, sc, w.write_size,
                         f"ptr+{woff} write {w.write_size}B")
        return _safe(a, w, sc, w.write_size,
                     f"ptr+{woff} write {w.write_size}B")

    def _var_offset_ptr(self, a, w, lines, sc, usable) -> HoResult:
        """变量偏移指针写入: *(ptr + var) = ... — 用guard约束判定."""
        vn = w.src_var
        lo, hi = find_guard_bounds(vn, lines, w.line)
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
        """双变量: 分配大小和写入大小均为变量."""
        if ag and a.size_expr.strip() == w.target:
            return _safe(a, w, -1, -1,
                         f"guard≤{au} + {w.kind}({a.size_expr})")
        if ag:
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


__all__ = ['HeapOverflowSrcVerifier']
