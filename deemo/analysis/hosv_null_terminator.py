"""
Null 终止符 off-by-one 检测. 目标模式:

  size_t l = strlen(s);
  char* d = malloc(l);
  memcpy(d, s, l);
  d[l] = 0;       # 写入下标 == 分配大小 → 越界 1 字节

CWE-193. malloc(strlen(s)) 缺 +1 空间, d[l]=0 写入恰好越界.
原 HOSV 对 `d[l]=0` (变量下标 ptr_write) 判 UNCERTAIN.

判定:
  1. 识别 `d[len] = 0` / `d[len] = '\0'` 终止符写入
  2. 分配大小 len == strlen(s) (无 +1) → off-by-one VULN
  3. 分配大小 len+1 或 len+2 → SAFE
  4. d[l]=0 下标与分配大小相等且写 1 字节 → 越界
"""

from __future__ import annotations

import re
from typing import List, Optional, Tuple

from analysis.hosv_ext_types import ExtAlloc, ExtResult
from analysis.heap_overflow_src_patterns import _is_comment_or_empty

# d[len] = 0 / d[len] = '\0' — 变量下标终止符写
_TERM_IDX_WRITE_RE = re.compile(
    r'(\w[\w]*)\s*\[\s*(\w[\w]*)\s*\]\s*=\s*(?:0|\'\\0\'|"\\0")\s*;')
# 分配大小 = strlen(...) 或无 +1
_ALLOC_STRLE_RE = re.compile(
    r'malloc\s*\(\s*strlen\s*\(\s*(\w[\w]*)\s*\)\s*\+?\s*(\d*)\s*\)')
# 分配大小 = 变量 (需从上方 strlen 追踪) 或 var+const
_ALLOC_VAR_RE = re.compile(
    r'malloc\s*\(\s*(\w[\w]*)(?:\s*\+\s*(\d+))?\s*\)')


def collect_terminator_writes(lines: List[str], valid_lines: set
                              ) -> List[Tuple[int, str, str]]:
    """收集终止符写入: (line, buf, idx_var)."""
    out = []
    for i, line in enumerate(lines, start=1):
        if valid_lines and i not in valid_lines:
            continue
        text = line.strip()
        if _is_comment_or_empty(text):
            continue
        m = _TERM_IDX_WRITE_RE.search(text)
        if m:
            out.append((i, m.group(1), m.group(2)))
    return out


def _alloc_expr_for(lines: List[str], alloc_line: int) -> str:
    """返回分配行的 malloc 大小表达式原文.

    支持 malloc(strlen(s)) / malloc(l) / malloc(l+1) 三种形态.
    返回值统一: strlen(...) 形式或 var 或 var+K.
    """
    if 0 < alloc_line <= len(lines):
        t = lines[alloc_line - 1].strip()
        m = _ALLOC_STRLE_RE.search(t)
        if m:
            src = m.group(1)
            plus = m.group(2)
            return "strlen(%s)+%s" % (src, plus) if plus else "strlen(%s)" % src
        m = _ALLOC_VAR_RE.search(t)
        if m:
            if m.group(2):
                return "%s+%s" % (m.group(1), m.group(2))
            return m.group(1)
    return ""


def _alloc_offset_from_strlen(lines: List[str], alloc_line: int,
                              idx_var: str) -> Optional[int]:
    """判定分配大小相对 idx_var 的偏移.

    分配大小 = strlen(idx_var) + K → 返回 K
    分配大小 = idx_var + K (idx_var 由 strlen 赋值) → 返回 K
    分配大小 = idx_var (且 idx_var 由 strlen 赋值) → 返回 0
    无法关联 → None
    """
    expr = _alloc_expr_for(lines, alloc_line)
    if not expr:
        return None
    # strlen(idx_var) 直接形式
    m = re.match(r'strlen\s*\(\s*(\w[\w]*)\s*\)(?:\s*\+\s*(\d+))?', expr)
    if m and m.group(1) == idx_var:
        return int(m.group(2)) if m.group(2) else 0
    # var / var+K 形式
    m2 = re.match(r'(\w[\w]*)(?:\s*\+\s*(\d+))?', expr)
    if m2 and m2.group(1) == idx_var:
        base_off = int(m2.group(2)) if m2.group(2) else 0
        # 验证 idx_var 由 strlen 赋值
        for j in range(max(0, alloc_line - 6), alloc_line):
            t = lines[j].strip()
            am = re.search(
                rf'\b{re.escape(idx_var)}\s*=\s*strlen\s*\(\s*(\w[\w]*)\s*\)',
                t)
            if am:
                return base_off
        return None
    return None


def verify_terminator(alloc: ExtAlloc, line: int, idx_var: str,
                      lines: List[str]) -> Optional[ExtResult]:
    """验证终止符 off-by-one.

    write_end = idx + 1 (单字节终止符), 与分配大小比较:
      alloc = strlen(idx_var) + K:
        K == 0 → write_end = strlen+1 > usable(strlen) → VULN
        K >= 1 → SAFE
      无法关联 → UNCERTAIN (保守)
    """
    off = _alloc_offset_from_strlen(lines, alloc.line, idx_var)
    if off is None:
        return None
    # 分配大小可解析时直接数值比较
    if alloc.size_const > 0:
        write_end = alloc.size_const + 1 if off == 0 else alloc.size_const
        usable = alloc.usable if alloc.usable > 0 else alloc.size_const
        if off == 0 and write_end > usable:
            return ExtResult(
                verdict="VULN", alloc_line=alloc.line, write_line=line,
                var_name=alloc.var, alloc_size=alloc.size_const,
                write_size=1, overflow_bytes=1, confidence=0.88,
                kind="null_terminator",
                reason=("'%s': malloc(strlen(%s)) no +1, '%s[%s]=0' "
                        "writes 1B past end (off-by-one)"
                        % (alloc.var, idx_var, alloc.var, idx_var)))
        if off == 0 and usable >= write_end:
            return ExtResult(
                verdict="SAFE", alloc_line=alloc.line, write_line=line,
                var_name=alloc.var, alloc_size=alloc.size_const,
                write_size=1, confidence=0.90, kind="null_terminator",
                reason="'%s': terminator write within bounds" % alloc.var)
    if off == 0:
        return ExtResult(
            verdict="VULN", alloc_line=alloc.line, write_line=line,
            var_name=alloc.var, alloc_size=-1, write_size=1,
            overflow_bytes=1, confidence=0.85, kind="null_terminator",
            reason=("'%s': malloc(strlen(%s)) = %s bytes, '%s[%s]=0' "
                    "writes 1B past end (off-by-one)"
                    % (alloc.var, idx_var, idx_var, alloc.var, idx_var)))
    if off >= 1:
        return ExtResult(
            verdict="SAFE", alloc_line=alloc.line, write_line=line,
            var_name=alloc.var, alloc_size=alloc.size_const,
            write_size=1, confidence=0.92, kind="null_terminator",
            reason=("'%s': malloc(strlen(%s)+%d) reserves terminator byte"
                    % (alloc.var, idx_var, off)))
    return None


__all__ = [
    'collect_terminator_writes', 'verify_terminator',
    '_alloc_expr_for', '_alloc_offset_from_strlen',
]
