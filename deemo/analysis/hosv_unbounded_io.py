"""
无界输入写入检测. 目标模式:

  char* b = malloc(32); scanf("%s", b);
  char* b = malloc(64); gets(b);

原 HOSV 的 find_writes 未覆盖 scanf("%s")/gets 等无界输入. 同时需
区分受控输入:
  scanf("%32s", b) — 字段宽度受限, 安全
  fgets(b, n, fp)  — 有界, 安全
本模块按格式化字符串字面量中的转换宽度精确判定.

判定规则:
  1. 提取 scanf/fgets/gets 的目标缓冲 (堆分配变量或别名)
  2. scanf: 解析第 1 参数格式串, 提取 %s 的宽度修饰符
     - 无宽度 %s → 无界 VULN
     - %<N>s → 有界 SAFE (N <= alloc_size 时)
  3. gets → 恒无界 VULN
  4. 目标为函数参数时交由 factory_bind 关联, 此处仅处理直接堆变量
"""


import re
from typing import List, Optional, Tuple

from analysis.hosv_ext_types import ExtAlloc, ExtResult
from analysis.heap_overflow_src_patterns import _is_comment_or_empty, _base_var

_SCANF_RE = re.compile(r'scanf\s*\(\s*("[^"]*"|[^,]+)')
_GETS_RE = re.compile(r'\bgets\s*\(\s*(\w[\w]*)\s*\)')
_FGETS_RE = re.compile(
    r'fgets\s*\(\s*(\w[\w]*)\s*,\s*(\d+)\s*,')

# scanf 格式串: %[flags][width][len]specifier
_FORMAT_WIDTH_RE = re.compile(r'%[0-9]*')
# 提取 %s 及宽度
_PERCENT_S_RE = re.compile(r'%(?:(\d+))?s')


def _parse_scanf_width(fmt_literal: str) -> Optional[int]:
    """从 scanf 第 1 参数字面量提取 %s 宽度; None=无界 %s."""
    if not fmt_literal.startswith('"'):
        return None  # 格式串非常量 — 保守无界
    inner = fmt_literal.strip('"')
    hits = _PERCENT_S_RE.findall(inner)
    if not hits:
        return None  # 无 %s, 不构成写入风险
    # 若存在未加宽度 %s → 无界
    for w in hits:
        if not w:
            return None
    widths = [int(w) for w in hits if w]
    return min(widths) if widths else None


def collect_unbounded_io(lines: List[str], valid_lines: set
                         ) -> List[Tuple[int, str, int, str]]:
    """收集输入写入候选: (line, target, max_io, kind).

    max_io = -1 表示无界;  >=0 表示受限写入量.
    """
    out: List[Tuple[int, str, int, str]] = []
    for i, line in enumerate(lines, start=1):
        if valid_lines and i not in valid_lines:
            continue
        text = line.strip()
        if _is_comment_or_empty(text):
            continue
        sm = _SCANF_RE.search(text)
        if sm:
            target = _find_target(lines, i, 'scanf')
            if target is None:
                continue
            fmt = sm.group(1)
            width = _parse_scanf_width(fmt)
            out.append((i, target, -1 if width is None else width, 'scanf'))
            continue
        gm = _GETS_RE.search(text)
        if gm:
            target = _base_var(gm.group(1))
            out.append((i, target, -1, 'gets'))
            continue
        fm = _FGETS_RE.search(text)
        if fm:
            target = _base_var(fm.group(1))
            out.append((i, target, int(fm.group(2)), 'fgets'))
    return out


def _find_target(lines: List[str], call_line: int, kind: str) -> Optional[str]:
    """定位调用参数中的目标缓冲变量."""
    text = lines[call_line - 1].strip()
    # scanf("%s", b) — 找 %s 之后的第一个实参
    m = re.search(r'%\s*s\s*,\s*&?\s*([^,)]+)\s*\)', text)
    if m:
        return _base_var(m.group(1))
    # 通配: 取所有实参, 找堆指针 (交给调用方验证, 此处返回最后实参)
    args = re.search(r'scanf\s*\(([^)]*)\)', text)
    if args:
        parts = [p.strip().lstrip('&') for p in args.group(1).split(',')]
        if len(parts) > 1:
            return _base_var(parts[1])
    return None


def verify_unbounded_io(alloc: ExtAlloc, line: int, max_io: int,
                        kind: str,
                        lines: Optional[List[str]] = None) -> Optional[ExtResult]:
    """验证输入写入是否溢出."""
    if alloc.size_const <= 0:
        return None
    usable = alloc.usable if alloc.usable > 0 else alloc.size_const
    if max_io < 0:
        # 无界输入前可能存在守卫钳制 (如 if(len<n) 限制读取长度),
        # 守卫上界不超过 usable 时判 SAFE, 否则按无界处理.
        guard_hi = _guard_upper_bound(line, alloc.size_const,
                                      alloc.size_expr, lines)
        if guard_hi is not None and guard_hi <= usable:
            return ExtResult(
                verdict="SAFE", alloc_line=alloc.line, write_line=line,
                var_name=alloc.var, alloc_size=alloc.size_const,
                write_size=guard_hi, confidence=0.88, kind=kind,
                reason="'%s': %s guarded ≤ %dB <= usable %d"
                       % (alloc.var, kind, guard_hi, usable))
        return ExtResult(
            verdict="VULN", alloc_line=alloc.line, write_line=line,
            var_name=alloc.var, alloc_size=alloc.size_const,
            write_size=-1, confidence=0.80, kind=kind,
            reason="'%s': malloc(%d) + unbounded %s → overflow possible"
                   % (alloc.var, alloc.size_const, kind))
    if max_io > usable:
        return ExtResult(
            verdict="VULN", alloc_line=alloc.line, write_line=line,
            var_name=alloc.var, alloc_size=alloc.size_const,
            write_size=max_io, overflow_bytes=max_io - usable,
            confidence=0.78, kind=kind,
            reason="'%s': malloc(%d) usable=%d, %s limit %dB > usable"
                   % (alloc.var, alloc.size_const, usable, kind, max_io))
    return ExtResult(
        verdict="SAFE", alloc_line=alloc.line, write_line=line,
        var_name=alloc.var, alloc_size=alloc.size_const,
        write_size=max_io, confidence=0.90, kind=kind,
        reason="'%s': %s limit %dB <= usable %d"
               % (alloc.var, kind, max_io, usable))


def _guard_upper_bound(call_line: int, alloc_size: int,
                       size_expr: str, lines: Optional[List[str]]
                       ) -> Optional[int]:
    """在调用行之前查找对输入长度的守卫钳制.

    守卫必须满足: 比较的变量出现在分配大小表达式中 (即该变量是
    输入长度控制变量). 例如 malloc(len+1) + if(len<32) → 守卫上界 32.
    若守卫比较的变量与分配无关, 不采纳, 避免误判.
    """
    if not lines:
        return None
    # 提取分配大小表达式中的控制变量
    ctrl_var = None
    if size_expr:
        vm = re.search(r'\b([a-zA-Z_]\w*)\b', size_expr.strip())
        if vm:
            ctrl_var = vm.group(1)
    if ctrl_var is None:
        return None
    for i in range(max(0, call_line - 12), call_line):
        t = lines[i].strip()
        if _is_comment_or_empty(t):
            continue
        m = re.search(
            r'if\s*\(\s*' + re.escape(ctrl_var) + r'\s*<\s*(\d+)\s*\)', t)
        if m:
            n = int(m.group(1))
            if n <= alloc_size:
                return n
        m = re.search(
            r'if\s*\(\s*' + re.escape(ctrl_var) + r'\s*<=\s*(\d+)\s*\)', t)
        if m:
            n = int(m.group(1))
            if n <= alloc_size:
                return n
    return None


__all__ = [
    'collect_unbounded_io', 'verify_unbounded_io',
    '_parse_scanf_width', '_find_target', '_guard_upper_bound',
]
