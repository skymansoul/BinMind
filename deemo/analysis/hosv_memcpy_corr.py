"""
memcpy 变量长度符号关联检测. 目标模式:

  size_t len = read_int();            # 或 strlen(s) / 外部输入
  char* buf = malloc(len + 8);        # 分配 = f(len)
  memcpy(buf, src, len * 2);          # 写入 = g(len)

原 HOSV 对 memcpy 变量长度 + 变量分配判 UNCERTAIN (漏报).
memcpy 到堆基址 + 变量长度是常见写形态. 本模块构建 alloc/write
的符号表达式 (见 hosv_sym_expr.py), 比较共享变量的系数与常量差:

  判定规则:
  1. alloc 常量, write 变量无上界 → 溢出 VULN
  2. alloc 常量, write 变量有守卫上界 <= usable → SAFE
  3. 共享符号变量: write_coef > alloc_coef → 渐近溢出 VULN
  4. 共享符号变量: write_coef <= alloc_coef 且 write_end <=
     usable → SAFE
  5. 无法关联 → UNCERTAIN (保守, 不产生误报)
"""

import re
from typing import Dict, List, Optional, Tuple

from analysis.hosv_ext_types import ExtAlloc, ExtResult
from analysis.heap_overflow_src_patterns import (
    _is_comment_or_empty, _base_var,
)
from analysis.hosv_sym_expr import SymExpr, trace_expr


_MEMCPY_RE = re.compile(
    r'memcpy\s*\(\s*([^,]+)\s*,\s*([^,]+)\s*,\s*([^)]+)\s*\)')
_MEMSET_RE = re.compile(
    r'memset\s*\(\s*([^,]+)\s*,\s*[^,]+,\s*([^)]+)\s*\)')
_PTR_ALIAS_RE = re.compile(
    r'(\w[\w]*)\s*=\s*(\w[\w]*)\s*\+\s*(\d+)\s*;')


def _alloc_symexpr(alloc: ExtAlloc, lines: List[str]) -> Optional[SymExpr]:
    """构建分配大小的符号表达式."""
    if alloc.size_const > 0:
        return SymExpr.const_expr(alloc.size_const)
    if alloc.size_expr:
        return trace_expr(alloc.size_expr, lines, alloc.line)
    return None


def _write_symexpr(third_arg: str, write_line: int,
                   lines: List[str]) -> Optional[SymExpr]:
    """构建 memcpy 第三参数 (长度) 的符号表达式."""
    return trace_expr(third_arg, lines, write_line)


def _has_guard_upper(write_line: int, usable: int,
                     lines: List[str]) -> Optional[int]:
    """在写入行前查找守卫钳制 write 长度的比较."""
    for i in range(max(0, write_line - 12), write_line):
        t = lines[i].strip()
        if _is_comment_or_empty(t):
            continue
        m = re.search(r'if\s*\(\s*\w+\s*<\s*(\d+)\s*\)', t)
        if m:
            n = int(m.group(1))
            if n <= usable:
                return n
        m = re.search(r'if\s*\(\s*\w+\s*<=\s*(\d+)\s*\)', t)
        if m:
            n = int(m.group(1))
            if n <= usable:
                return n
    return None


def verify_memcpy(alloc: ExtAlloc, write_line: int, dst: str,
                  third_arg: str, lines: List[str],
                  offset: int = 0) -> Optional[ExtResult]:
    """验证 memcpy 到堆缓冲的变量长度是否越界."""
    if alloc is None:
        return None
    usable = alloc.usable if alloc.usable > 0 else alloc.size_const
    aexpr = _alloc_symexpr(alloc, lines)
    wexpr = _write_symexpr(third_arg, write_line, lines)

    # 写长度为常量
    if wexpr is not None and not wexpr.coeffs and wexpr.const >= 0:
        end = wexpr.const + offset
        if usable > 0 and end > usable:
            return ExtResult(
                verdict="VULN", alloc_line=alloc.line, write_line=write_line,
                var_name=alloc.var, alloc_size=alloc.size_const,
                write_size=wexpr.const, overflow_bytes=end - usable,
                confidence=0.85, kind="memcpy_const",
                reason="'%s': memcpy %dB@off%d end=%d > usable %d"
                       % (alloc.var, wexpr.const, offset, end, usable))
        if usable > 0:
            return ExtResult(
                verdict="SAFE", alloc_line=alloc.line, write_line=write_line,
                var_name=alloc.var, alloc_size=alloc.size_const,
                write_size=wexpr.const, confidence=0.90,
                kind="memcpy_const",
                reason="'%s': memcpy %dB@off%d end=%d <= usable %d"
                       % (alloc.var, wexpr.const, offset, end, usable))

    # 分配常量, 写变量
    if aexpr is not None and not aexpr.coeffs and wexpr is not None:
        if usable <= 0:
            return None
        # 写变量无系数 (纯常量差) 或含未知变量
        if wexpr.coeffs:
            # 守卫上界检查
            gu = _has_guard_upper(write_line, usable, lines)
            if gu is not None:
                return ExtResult(
                    verdict="SAFE", alloc_line=alloc.line,
                    write_line=write_line, var_name=alloc.var,
                    alloc_size=alloc.size_const, write_size=gu,
                    confidence=0.88, kind="memcpy_guard",
                    reason="'%s': memcpy guarded ≤ %dB <= usable %d"
                           % (alloc.var, gu, usable))
            return ExtResult(
                verdict="VULN", alloc_line=alloc.line, write_line=write_line,
                var_name=alloc.var, alloc_size=alloc.size_const,
                write_size=-1, confidence=0.78, kind="memcpy_var",
                reason="'%s': malloc(%d) + memcpy(var) → overflow possible"
                       % (alloc.var, alloc.size_const))

    # 共享符号变量: 系数比较
    if aexpr is not None and wexpr is not None and wexpr.coeffs:
        shared = set(aexpr.coeffs) & set(wexpr.coeffs)
        if shared:
            for v in shared:
                ac, wc = aexpr.coeffs[v], wexpr.coeffs[v]
                if wc > ac:
                    return ExtResult(
                        verdict="VULN", alloc_line=alloc.line,
                        write_line=write_line, var_name=alloc.var,
                        alloc_size=-1, write_size=-1, confidence=0.85,
                        kind="memcpy_coef",
                        reason=("'%s': alloc_coef(%s)=%d vs "
                                "memcpy_coef=%d → asymptotic overflow"
                                % (alloc.var, v, ac, wc)))
            # 系数相等: 比较常量差
            if usable > 0:
                aw = _worst_write_end(aexpr, wexpr, offset)
                if aw is not None and aw > usable:
                    return ExtResult(
                        verdict="VULN", alloc_line=alloc.line,
                        write_line=write_line, var_name=alloc.var,
                        alloc_size=alloc.size_const, write_size=aw,
                        overflow_bytes=aw - usable, confidence=0.80,
                        kind="memcpy_coef",
                        reason="'%s': memcpy write_end %s > usable %d"
                               % (alloc.var, aw, usable))
                if aw is not None:
                    return ExtResult(
                        verdict="SAFE", alloc_line=alloc.line,
                        write_line=write_line, var_name=alloc.var,
                        alloc_size=alloc.size_const, write_size=aw,
                        confidence=0.88, kind="memcpy_coef",
                        reason="'%s': memcpy write_end %s <= usable %d"
                               % (alloc.var, aw, usable))
    return None


def _worst_write_end(aexpr: SymExpr, wexpr: SymExpr,
                     offset: int = 0) -> Optional[int]:
    """计算写入终点上界: 若共享变量系数相等, write_end 相对 alloc
    的差 = const_diff + offset. 仅当 write 无非共享正系数且常量
    可解析时返回数值."""
    nonshared_w = {v: c for v, c in wexpr.coeffs.items()
                   if v not in aexpr.coeffs}
    if any(c > 0 for c in nonshared_w.values()):
        return None
    const_diff = wexpr.const - aexpr.const
    if aexpr.const >= 0 and wexpr.const >= 0:
        return aexpr.const + const_diff + offset
    return None


def collect_memcpy_writes(alloc_vars: set, lines: List[str],
                          valid_lines: Optional[set] = None
                          ) -> List[Tuple[int, str, str, int]]:
    """收集 memcpy/memset 到堆缓冲的写入: (line, dst_base, size_arg, offset).

    dst 若是堆基址的指针别名 (name_dst = buf + K), 归一为 (buf, K).
    """
    alias_off = _build_alias_offsets(lines, alloc_vars, valid_lines)
    out: List[Tuple[int, str, str, int]] = []
    for i, line in enumerate(lines, start=1):
        if valid_lines and i not in valid_lines:
            continue
        text = line.strip()
        if _is_comment_or_empty(text):
            continue
        m = _MEMCPY_RE.search(text)
        if m:
            dst = _base_var(m.group(1))
            base, off = _resolve_alias(dst, alias_off, alloc_vars)
            if base in alloc_vars:
                out.append((i, base, m.group(3).strip(), off))
            continue
        m = _MEMSET_RE.search(text)
        if m:
            dst = _base_var(m.group(1))
            base, off = _resolve_alias(dst, alias_off, alloc_vars)
            if base in alloc_vars:
                out.append((i, base, m.group(2).strip(), off))
    return out


def _build_alias_offsets(lines: List[str], alloc_vars: set,
                         valid_lines: Optional[set]
                         ) -> Dict[str, Tuple[str, int]]:
    """提取 `name_dst = buf + K` 别名偏移: {name_dst: (base, offset)}."""
    offs: Dict[str, Tuple[str, int]] = {}
    for i, t in enumerate(lines):
        ts = t.strip()
        if _is_comment_or_empty(ts):
            continue
        m = _PTR_ALIAS_RE.search(ts)
        if m:
            offs[m.group(1)] = (m.group(2), int(m.group(3)))
    return offs


def _resolve_alias(name: str, alias_off: Dict[str, Tuple[str, int]],
                   alloc_vars: set) -> Tuple[str, int]:
    """解析别名链到堆基址: q = p + 2; p = buf + 3 → (buf, 5)."""
    cur = name
    total = 0
    seen = set()
    while cur in alias_off and cur not in seen:
        seen.add(cur)
        base, off = alias_off[cur]
        total += off
        cur = base
        if cur in alloc_vars:
            return cur, total
    return cur, total


__all__ = [
    'collect_memcpy_writes', 'verify_memcpy',
    '_alloc_symexpr', '_write_symexpr',
]
