"""
指针游走写判定. 含渐近系数比较与有界循环写量计算.

与 heap_write_walk_write.py 同族, 负责对已收集的游走写候选做最终判定.
候选收集在 heap_write_walk_write.py.

判定优先级:
  1. 渐近溢出 (strlen 驱动 + 系数比较) — 循环上界未知时
  2. 有界循环: max_write = bound*steps + trailing 与 usable 比较
  3. 无法定界 → UNCERTAIN (保守, 不产生误报)
"""

import re
from typing import List, Optional

from analysis.heap_write_ext_types import ExtAlloc, ExtResult, WalkWrite
from analysis.heap_overflow_src_patterns import _is_comment_or_empty


def _find_strlen_var(size_expr: str, lines: Optional[List[str]],
                     alloc_line: int) -> Optional[str]:
    """从分配表达式定位 strlen 源变量.

    a) 表达式直接含 strlen(X) → 返回 X
    b) 表达式为变量 l, 且前文 l=strlen(X) → 返回 X
    c) 表达式为变量 l, 且前文 l=expr 含 strlen(X) → 返回 X
    d) 多级中间变量: size_needed = arg_len+1; arg_len = strlen(s) → 返回 s
    """
    if not size_expr:
        return None
    dm = re.search(r'strlen\s*\(\s*(\w[\w]*)\s*\)', size_expr)
    if dm:
        return dm.group(1)
    if not lines:
        return None
    var = size_expr.strip()
    vm = re.search(r'\b([a-zA-Z_]\w*)\b', var)
    cand = vm.group(1) if vm else None
    if cand is None:
        return None
    return _trace_strlen_var(cand, lines, alloc_line, 0)


def _trace_strlen_var(name: str, lines: List[str], alloc_line: int,
                      depth: int) -> Optional[str]:
    """递归追踪变量赋值链, 定位 strlen 源变量. 限 3 层防环."""
    if depth > 3:
        return None
    for j in range(max(0, alloc_line - 10), alloc_line):
        t = lines[j].strip()
        if _is_comment_or_empty(t):
            continue
        am = re.search(
            rf'\b{re.escape(name)}\s*=\s*strlen\s*\(\s*(\w[\w]*)\s*\)',
            t)
        if am:
            return am.group(1)
        am2 = re.search(rf'\b{re.escape(name)}\s*=\s*([^;]+);', t)
        if am2:
            rhs = am2.group(1)
            dm2 = re.search(r'strlen\s*\(\s*(\w[\w]*)\s*\)', rhs)
            if dm2:
                return dm2.group(1)
            # rhs 中的变量继续追踪
            vm2 = re.search(r'\b([a-zA-Z_]\w*)\b', rhs)
            if vm2 and vm2.group(1) != name:
                return _trace_strlen_var(vm2.group(1), lines, j + 1,
                                         depth + 1)
    return None


def _strlen_coef(size_expr: str, lines: Optional[List[str]],
                 alloc_line: int, strlen_var: str) -> int:
    """解析分配表达式中 strlen_var 对应变量的系数.

    l+1    (l=strlen(s)) → 1
    l*2+2  (l=strlen(s)) → 2
    l*l    → 2 (平方, 保守按 2 计 — 分配增长快)
    strlen(s)+1 直接 → 1
    """
    if 'strlen' in size_expr:
        dm = re.search(
            r'strlen\s*\(\s*' + re.escape(strlen_var) + r'\s*\)\s*(\*)',
            size_expr)
        if dm:
            m2 = re.search(r'\*', size_expr)
            if m2:
                return 1  # 保守: strlen(s)*N 至少线性
        return 1
    if not lines:
        return 1
    vm = re.search(r'\b([a-zA-Z_]\w*)\b', size_expr)
    var = vm.group(1) if vm else size_expr.strip()
    for j in range(max(0, alloc_line - 8), alloc_line):
        t = lines[j].strip()
        if _is_comment_or_empty(t):
            continue
        am2 = re.search(rf'\b{re.escape(var)}\s*=\s*([^;]+);', t)
        if am2:
            rhs = am2.group(1)
            cm = re.search(rf'\b{re.escape(var)}\s*\*\s*(\d+)', size_expr)
            if cm:
                return int(cm.group(1))
            cm2 = re.search(rf'(\d+)\s*\*\s*{re.escape(var)}', size_expr)
            if cm2:
                return int(cm2.group(1))
            break
    return 1


def asymptotic_check(w: WalkWrite, alloc: ExtAlloc,
                     lines: Optional[List[str]] = None) -> Optional[ExtResult]:
    """渐近溢出判定 — 循环上界未知时比较分配/写入的增长系数.

    适用形态:
      a) 分配直接含 strlen: malloc(strlen(s)+1)
      b) 中间变量: l=strlen(s); malloc(l+1)
      c) 循环指针为 driver: for(q=s;*q;q++) 扫描 s, 分配基于 strlen(s)
    """
    if not w.is_str_loop:
        return None
    write_coef = w.max_steps_per_iter
    if alloc.size_const > 0:
        return None
    strlen_var = _find_strlen_var(alloc.size_expr, lines, alloc.line)
    if strlen_var is None:
        return None
    alloc_coef = _strlen_coef(alloc.size_expr, lines, alloc.line, strlen_var)
    if write_coef <= alloc_coef:
        # 分配增长不慢于写入增长, 结构性安全
        return ExtResult(
            verdict="SAFE", alloc_line=alloc.line,
            write_line=w.write_line, var_name=alloc.var,
            alloc_size=-1, write_size=-1, confidence=0.90,
            kind="walk_write_asymptotic",
            reason=("'%s': malloc(%s) alloc_coef=%d >= "
                    "ptr-walk write_coef=%d (steps/iter, strlen(%s)-driven) "
                    "→ no asymptotic overflow"
                    % (alloc.var, alloc.size_expr, alloc_coef, write_coef,
                       strlen_var)))
    return ExtResult(
        verdict="VULN", alloc_line=alloc.line,
        write_line=w.write_line, var_name=alloc.var,
        alloc_size=-1, write_size=-1, confidence=0.85,
        kind="walk_write_asymptotic",
        reason=("'%s': malloc(%s) alloc_coef=%d vs "
                "ptr-walk write_coef=%d (steps/iter, strlen(%s)-driven) "
                "→ asymptotic overflow for long input"
                % (alloc.var, alloc.size_expr, alloc_coef, write_coef,
                   strlen_var)))


def verify_walk(w: WalkWrite, alloc: Optional[ExtAlloc],
                lines: List[str]) -> Optional[ExtResult]:
    """对单个游走写验证溢出.

    判定优先级:
      1. 渐近溢出判定 (strlen 驱动 + 系数比较)
      2. 有界循环: max_write = bound*steps + trailing vs usable
      3. 无法定界 → UNCERTAIN (不产生误报)
    """
    if alloc is None or alloc.size_const <= 0:
        if alloc is not None and alloc.size_const < 0:
            return asymptotic_check(w, alloc, lines)
        return None
    asym = asymptotic_check(w, alloc, lines)
    if asym:
        return asym
    usable = alloc.usable if alloc.usable > 0 else alloc.size_const
    if w.loop_bound < 0:
        return ExtResult(
            verdict="UNCERTAIN", alloc_line=alloc.line,
            write_line=w.write_line, var_name=alloc.var,
            alloc_size=alloc.size_const, write_size=-1,
            confidence=0.35,
            reason="walk-write with unbounded loop: conservatively kept")
    max_write = (w.loop_bound * w.max_steps_per_iter * w.elem_size
                 + w.trailing_write)
    if max_write > usable:
        return ExtResult(
            verdict="VULN", alloc_line=alloc.line,
            write_line=w.write_line, var_name=alloc.var,
            alloc_size=alloc.size_const, write_size=max_write,
            overflow_bytes=max_write - usable, confidence=0.82,
            kind="walk_write",
            reason=("'%s': malloc(%d) usable=%d, ptr-walk write "
                    "%d iters * %d steps + %d trailing = %d > %d"
                    % (alloc.var, alloc.size_const, usable, w.loop_bound,
                       w.max_steps_per_iter, w.trailing_write,
                       max_write, usable)))
    return ExtResult(
        verdict="SAFE", alloc_line=alloc.line,
        write_line=w.write_line, var_name=alloc.var,
        alloc_size=alloc.size_const, write_size=max_write,
        confidence=0.90, kind="walk_write",
        reason=("'%s': ptr-walk write %d <= usable %d"
                % (alloc.var, max_write, usable)))


__all__ = [
    'verify_walk', 'asymptotic_check', '_find_strlen_var', '_strlen_coef',
]
