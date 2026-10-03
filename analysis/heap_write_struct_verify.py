"""
结构体数组索引写入越界判定. 含结构性 off-by-one 证明与常量/变量索引比较.

与 heap_write_struct_idx.py 同族, 负责对已收集的写入候选做最终判定.
类型大小解析/边界推断在 heap_write_struct_idx.py, 候选收集在
heap_write_struct_collect.py.

判定规则:
  - 结构 off-by-one: 循环上界 (经调用点实参回溯/守卫推断) == 分配元素数,
    且比较符 <= → 写 count+1 个元素恒越界 (与 n 取值无关)
  - 常量索引: arr[8] → write_end = (8+1)*elem_size
  - 变量索引: 上界 × elem_size 与可用容量比较
  - 无法定界 → UNCERTAIN (保守, 不产生误报)
"""

import re
from typing import Optional

from analysis.heap_write_ext_types import ExtAlloc, ExtResult
from analysis.heap_write_struct_idx import (
    _ELEM_ALLOC_RE, _loop_bound_var, _extract_index_bound,
    _bound_int, resolve_elem_size,
)


def verify_struct_idx(alloc: ExtAlloc, line: int, idx_expr: str,
                      lines) -> Optional[ExtResult]:
    """验证结构体数组变量索引写是否越界.

    alloc.size_expr 形如 `n * sizeof(T)` 时:
      elem_size = sizeof(T)
      索引上界 bound (i<=n → n+1)
      写量字节 = bound * elem_size

    结构性 off-by-one: 分配元素数与循环上界为同一变量 n, 比较符 <= 时,
    写元素数 = n+1 > 分配 n, 恒越界 (与 n 取值无关).
    """
    m = _ELEM_ALLOC_RE.search(
        lines[alloc.line - 1].strip()) if 0 < alloc.line <= len(lines) else None
    elem_size = 1
    alloc_count: Optional[int] = None
    alloc_count_var: Optional[str] = None
    if m:
        alloc_count_var = m.group(2)
        elem_size = resolve_elem_size(m.group(3), lines, alloc.line)
        if elem_size <= 0:
            elem_size = 8
        if re.match(r'^\d+$', alloc_count_var):
            alloc_count = int(alloc_count_var)
    # 结构性 off-by-one: 循环上界 == 分配元素数, 且 i<=bound → 越界 1 元素
    idx_var = idx_expr.strip()
    if re.match(r'^[a-zA-Z_]\w*$', idx_var) and alloc_count_var:
        bv = _loop_bound_var(line, idx_var, lines)
        bound_is_count = False
        if bv is not None:
            if bv[0] == alloc_count_var:
                bound_is_count = True
            elif alloc_count is not None and _bound_int(bv[0], lines, line) == alloc_count:
                bound_is_count = True
        if bv is not None and (bound_is_count or idx_var == alloc_count_var):
            is_le = bv[1]
            if is_le is True:
                # 写 count+1 个元素, 分配 count 个 → 恒越界一个元素
                write_bytes = (alloc_count + 1) * elem_size if alloc_count is not None \
                    else -1
                usable = alloc.usable if alloc.usable > 0 else alloc.size_const
                if alloc_count is not None and write_bytes > usable:
                    return ExtResult(
                        verdict="VULN", alloc_line=alloc.line, write_line=line,
                        var_name=alloc.var, alloc_size=alloc.size_const,
                        write_size=write_bytes, overflow_bytes=write_bytes - usable,
                        confidence=0.90, kind="struct_idx_off_by_one",
                        reason=("'%s': arr[%s] with %s<=%s writes %d+1 elems "
                                "× %dB = %dB > usable %d (structural OOB)"
                                % (alloc.var, idx_var, idx_var, alloc_count_var,
                                   alloc_count, elem_size, write_bytes, usable)))
                if alloc_count is None:
                    return ExtResult(
                        verdict="VULN", alloc_line=alloc.line, write_line=line,
                        var_name=alloc.var, alloc_size=alloc.size_const,
                        write_size=-1, confidence=0.85,
                        kind="struct_idx_off_by_one",
                        reason=("'%s': arr[%s] with %s<=count → writes count+1 "
                                "elems, allocates count → structural OOB"
                                % (alloc.var, idx_var, idx_var)))
            if is_le is False and alloc_count is not None:
                write_bytes = alloc_count * elem_size
                usable = alloc.usable if alloc.usable > 0 else alloc.size_const
                if usable > 0 and write_bytes <= usable:
                    return ExtResult(
                        verdict="SAFE", alloc_line=alloc.line, write_line=line,
                        var_name=alloc.var, alloc_size=alloc.size_const,
                        write_size=write_bytes, confidence=0.92,
                        kind="struct_idx",
                        reason=("'%s': arr[%s] with %s<%s writes %d elems "
                                "× %dB = %dB <= usable %d"
                                % (alloc.var, idx_var, idx_var, alloc_count_var,
                                   alloc_count, elem_size, write_bytes, usable)))
    bound = _extract_index_bound(idx_expr, line, lines)
    if re.match(r'^\d+$', idx_expr.strip()):
        # 常量索引: arr[8] 写第 8 个元素, write_end = (8+1)*elem_size
        const_idx = int(idx_expr.strip())
        bound = const_idx + 1
    if bound is None or bound <= 0:
        return ExtResult(
            verdict="UNCERTAIN", alloc_line=alloc.line, write_line=line,
            var_name=alloc.var, alloc_size=alloc.size_const,
            write_size=-1, confidence=0.35, kind="struct_idx",
            reason="'%s': index '%s' bound unknown"
                   % (alloc.var, idx_expr))
    write_bytes = bound * elem_size
    usable = alloc.usable if alloc.usable > 0 else alloc.size_const
    if usable <= 0 and alloc_count is not None and elem_size > 0:
        # malloc(count*sizeof(T)) 结构推断容量
        usable = alloc_count * elem_size
    if usable <= 0:
        return ExtResult(
            verdict="UNCERTAIN", alloc_line=alloc.line, write_line=line,
            var_name=alloc.var, alloc_size=alloc.size_const,
            write_size=-1, confidence=0.35, kind="struct_idx",
            reason="'%s': alloc size unknown, cannot compare bound %d"
                   % (alloc.var, bound))
    if write_bytes > usable:
        return ExtResult(
            verdict="VULN", alloc_line=alloc.line, write_line=line,
            var_name=alloc.var, alloc_size=alloc.size_const,
            write_size=write_bytes, overflow_bytes=write_bytes - usable,
            confidence=0.85, kind="struct_idx",
            reason=("'%s': malloc(%d) usable=%d, arr[%s] bound=%d "
                    "elem=%dB → %dB write > usable"
                    % (alloc.var, alloc.size_const, usable, idx_expr,
                       bound, elem_size, write_bytes)))
    return ExtResult(
        verdict="SAFE", alloc_line=alloc.line, write_line=line,
        var_name=alloc.var, alloc_size=alloc.size_const,
        write_size=write_bytes, confidence=0.92, kind="struct_idx",
        reason=("'%s': arr[%s] bound=%d elem=%dB → %dB write <= usable %d"
                % (alloc.var, idx_expr, bound, elem_size,
                   write_bytes, usable)))


__all__ = ['verify_struct_idx']
