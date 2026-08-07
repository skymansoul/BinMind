"""堆溢出源级验证 — 累积/循环/chunk关联检查 + 辅助判定函数。"""

from __future__ import annotations
import re
from typing import Dict, List, Optional, Tuple

from analysis.heap_overflow_types import (
    HoVerdict, HeapAllocSite, HeapWriteSite, HoResult)
from analysis.heap_overflow_src_patterns import (
    _GUARD_RE, _SIZE_CHECK_RE, _FOR_LOOP_RE, _LOOP_WRITE_RE,
    _CLAMP_GUARD_RE, _is_comment_or_empty, _ptmalloc2_usable,
    _resolve_sizeof, _infer_struct_type)
from analysis.heap_overflow_src_guards import find_loop_bound_const, infer_stride


def targets_same_heap_obj(a: HeapAllocSite, w: HeapWriteSite,
                           lines: List[str]) -> bool:
    """检查写入目标是否指向该分配 (含别名追踪)."""
    if w.target == a.var:
        return True
    for i in range(a.line, w.line):
        text = lines[i].strip()
        if _is_comment_or_empty(text): continue
        if re.search(rf'\b{re.escape(w.target)}\s*=\s*{re.escape(a.var)}\s*;', text):
            return True
        if re.search(rf'\b{re.escape(w.target)}\s*=\s*{re.escape(a.var)}\s*\+', text):
            return True
    return False


def alloc_has_guard(a: HeapAllocSite, lines: List[str]) -> Tuple[bool, int]:
    """检查分配点前是否有guard条件限制大小参数.

    支持两种guard模式:
      1. early-return guard: if(n>100) return/exit → continuation: n<=99
      2. clamp guard: if(n>200) n=200 → continuation: n<=200
    """
    search_var = a.size_expr.strip() if a.size_expr.strip() else a.var
    for i in range(max(0, a.line - 10), min(len(lines), a.line + 5)):
        text = lines[i].strip()
        if _is_comment_or_empty(text): continue
        cm = _CLAMP_GUARD_RE.search(text)
        if cm:
            var = cm.group(1)
            op = cm.group(2)
            threshold = int(cm.group(3))
            clamp_val = int(cm.group(4))
            if var == search_var:
                return True, clamp_val
        gm = _GUARD_RE.search(text)
        if gm:
            var = gm.group(1)
            if var == search_var:
                return True, int(gm.group(3))
        sm = _SIZE_CHECK_RE.search(text)
        if sm:
            var_a, op, var_b = sm.group(1), sm.group(2), sm.group(3)
            if (var_a == search_var and op == '<='):
                return True, -1
    return False, -1


def is_tainted_input(var: str, lines: List[str], around_line: int) -> bool:
    """检查变量是否来自用户输入 (argv, scanf, read, recv, fgets等)."""
    for i in range(max(0, around_line - 15), min(len(lines), around_line)):
        text = lines[i].strip()
        if _is_comment_or_empty(text): continue
        if re.search(rf'\b{re.escape(var)}\s*=\s*atoi\s*\(', text):
            return True
        if re.search(rf'\b{re.escape(var)}\s*=\s*atol\s*\(', text):
            return True
        if re.search(rf'\b(?:scanf|read|recv|fgets|fread)\s*\(.*\b{re.escape(var)}\b', text):
            return True
        if 'argv[' in text and var in text:
            return True
    return False


def check_strcat_accumulation(allocs: List[HeapAllocSite],
                               writes: List[HeapWriteSite],
                               lines: List[str]) -> List[HoResult]:
    """strcat累积: 多次strcat小buf → 累积溢出."""
    results = []
    strcat_writes = [w for w in writes if w.kind == 'strcat']
    if len(strcat_writes) < 2:
        return results
    target_counts: Dict[str, List[HeapWriteSite]] = {}
    for w in strcat_writes:
        target_counts.setdefault(w.target, []).append(w)
    for target, ws in target_counts.items():
        if len(ws) < 2:
            continue
        for a in allocs:
            if a.var != target or a.size_const < 0:
                continue
            min_cumulative = len(ws)
            usable = _ptmalloc2_usable(a.size_const)
            if min_cumulative > usable:
                results.append(HoResult(
                    verdict=HoVerdict.VULN,
                    alloc_line=a.line, write_line=ws[-1].line,
                    var_name=a.var, alloc_size=a.size_const,
                    confidence=0.75,
                    reason=f"'{a.var}[{a.size_const}]': {len(ws)} strcat "
                           f"calls → cumulative overflow"))
    return results


def check_loop_accumulation(allocs: List[HeapAllocSite],
                              writes: List[HeapWriteSite],
                              lines: List[str]) -> List[HoResult]:
    """循环内索引写入: for(i=0; i<user_ctrl; i++) buf[i]=...

    仅处理 loop_write 类型 — 索引随循环变量变化的写入.
    memcpy/memset 到固定基址的写入由 _bounded 单独判定, 不在此重复.

    FIXME: loop_accumulate 对3个样本仍漏检 — 循环边界推断仅处理
    for(i=0;i<N;i++) 常量模式, 未处理 while(i--)、指针追赶等变体.
    改进方向: 在 SCEV 层统一循环解析, 替代当前的逐模式尝试.
    """
    results = []
    for a in allocs:
        for w in writes:
            if w.target != a.var:
                continue
            if w.kind != 'loop_write':
                continue
            if w.line < a.line:
                continue
            if hasattr(w, 'loop_bound') and w.loop_bound > 0:
                lb = w.loop_bound
                if a.size_const > 0:
                    stride = infer_stride(a, lines)
                    if lb * stride > a.size_const:
                        results.append(HoResult(
                            verdict=HoVerdict.VULN, alloc_line=a.line,
                            write_line=w.line, var_name=a.var,
                            alloc_size=a.size_const, confidence=0.70,
                            reason=f"'{a.var}[{a.size_const}]': loop write@L{w.line} "
                                   f"(bound={lb})"))
                continue
            if _enclosed_in_loop(w.line, lines):
                lb_const = find_loop_bound_const(lines, w.line, w.target)
                loop_bound = lb_const if lb_const is not None else \
                    _find_loop_bound(w.line, lines)
                if a.size_const > 0:
                    stride = infer_stride(a, lines)
                    write_end = loop_bound * stride if loop_bound > 0 else -1
                    usable = _ptmalloc2_usable(a.size_const)
                    if loop_bound < 0 or write_end > usable:
                        results.append(HoResult(
                            verdict=HoVerdict.VULN, alloc_line=a.line,
                            write_line=w.line, var_name=a.var,
                            alloc_size=a.size_const, confidence=0.70,
                            reason=f"'{a.var}[{a.size_const}]': loop write@L{w.line} "
                                   f"(bound={'unbounded' if loop_bound<0 else loop_bound})"))
                elif a.size_const < 0 and a.size_expr:
                    resolved_expr = _resolve_size_expr(a.size_expr, lines, a.line)
                    mm = re.search(r'(\w+)\s*\*\s*sizeof', resolved_expr)
                    if mm:
                        size_var = mm.group(1)
                        if loop_bound < 0 or size_var == str(loop_bound):
                            results.append(HoResult(
                                verdict=HoVerdict.VULN, alloc_line=a.line,
                                write_line=w.line, var_name=a.var,
                                alloc_size=-1, confidence=0.65,
                                reason=f"'{a.var}': malloc({resolved_expr})@L{a.line} "
                                       f"+ loop bound={size_var}@L{w.line} "
                                       f"— integer overflow in size calc"))
    return results


def _resolve_size_expr(expr: str, lines: List[str], line: int) -> str:
    """追踪size_expr变量的实际赋值表达式 (如 alloc_size = count * sizeof(int))."""
    e = expr.strip()
    if not re.match(r'^\w[\w]*$', e):
        return e
    for j in range(line - 2, -1, -1):
        t = lines[j].strip()
        if t.startswith(('//', '/*')): continue
        am = re.search(rf'\b{re.escape(e)}\s*=\s*(.+?);', t)
        if am:
            return am.group(1).strip()
    return e


def check_chunk_relation(allocs: List[HeapAllocSite],
                           writes: List[HeapWriteSite],
                           lines: List[str]) -> List[HoResult]:
    """多chunk关联: free(a); b=malloc(N); memcpy(b,...) 若a→b相邻则越界写可能破坏b."""
    results = []
    free_lines = []
    for i, line in enumerate(lines, start=1):
        text = line.strip()
        if _is_comment_or_empty(text): continue
        fm = re.search(r'free\s*\(\s*(\w[\w]*)\s*\)', text)
        if fm:
            free_lines.append((i, fm.group(1)))
    for fline, fvar in free_lines:
        for a in allocs:
            if a.line <= fline:
                continue
            for w in writes:
                if w.target != fvar or w.line >= fline:
                    continue
                results.append(HoResult(
                    verdict=HoVerdict.UNCERTAIN,
                    alloc_line=a.line, write_line=w.line,
                    var_name=a.var,
                    confidence=0.40,
                    reason=f"'{fvar}' free@L{fline} → '{a.var}' alloc@L{a.line} "
                           f"— chunk reuse risk"))
    return results


def _enclosed_in_loop(line: int, lines: List[str]) -> bool:
    """检查行是否在循环体内."""
    depth = 0
    for i in range(line - 2, -1, -1):
        t = lines[i].strip()
        if _is_comment_or_empty(t): continue
        depth += t.count('}') - t.count('{')
        if _LOOP_WRITE_RE.search(t) or re.search(r'\b(for|while)\s*\(', t):
            if depth <= 0:
                return True
    return False


def _find_loop_bound(line: int, lines: List[str]) -> int:
    """找到包围行的循环上界.

    支持常量上界和变量上界(通过clamp guard推断).
    返回上界值, 或-1表示无上界.
    """
    depth = 0
    for i in range(line - 2, -1, -1):
        t = lines[i].strip()
        if _is_comment_or_empty(t): continue
        depth += t.count('}') - t.count('{')
        if depth > 0:
            continue
        # 常量上界: for(...; i < N; ...) 或 for(...; i <= N; ...)
        fm = _FOR_LOOP_RE.search(t)
        if fm:
            bound_str = fm.group(1)
            try:
                return int(bound_str, 0)
            except ValueError:
                pass
            # 变量上界: 查找clamp guard
            from analysis.heap_overflow_src_guards import _find_clamp_bound
            cb = _find_clamp_bound(lines, i, bound_str)
            if cb is not None:
                return cb
        fm = re.search(
            r'for\s*\(\s*(?:\w+\s+)?\w+\s*=\s*0\s*;\s*\w+\s*<=\s*(\d+)', t)
        if fm:
            try:
                return int(fm.group(1), 0) + 1
            except ValueError:
                return -1
    return -1


def check_struct_array_oob(
        a, w, lines: List[str], size_const: int) -> Optional[HoResult]:
    """struct array常量索引越界: arr[8].val = ... — offset=idx*elem_sz."""
    if w.kind != 'struct_array' or size_const < 0:
        return None
    usable = _ptmalloc2_usable(size_const)
    elem_sz = _resolve_sizeof(
        _infer_struct_type(a, lines), lines, a.line)
    if elem_sz <= 0:
        elem_sz = 16
    offset = w.offset * elem_sz
    if offset + elem_sz > usable:
        return HoResult(
            verdict=HoVerdict.VULN,
            alloc_line=a.line, write_line=w.line,
            var_name=a.var, alloc_size=size_const,
            write_size=elem_sz,
            overflow_bytes=offset + elem_sz - usable,
            confidence=0.85,
            reason=f"'{a.var}': malloc({size_const}) usable={usable}, "
                   f"arr[{w.offset}] offset={offset} "
                   f"+ {elem_sz}B@L{w.line} — OOB")
    return HoResult(
        verdict=HoVerdict.SAFE,
        alloc_line=a.line, write_line=w.line,
        var_name=a.var, alloc_size=size_const,
        write_size=elem_sz, confidence=0.90,
        reason=f"'{a.var}': arr[{w.offset}] offset={offset} "
               f"< usable({size_const})={usable} — safe")
