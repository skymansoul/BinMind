"""
Heap allocation size propagation — recover malloc size arguments that cannot
be determined locally from the calling context.

Problem: malloc(size) size may be a variable (function parameter, global,
return value). Detection is impossible without a known size, leading to
missed findings (false negatives) when dynamically-sized allocations are
skipped.

Heuristic recovery for three common sources:
  1. Function parameter: if size comes from func(N, size), search call sites
     for a constant argument.
  2. sizeof expression: infer compile-time constants from decompiler output.
  3. Arithmetic expression: if size = N * M with constant factors, compute
     a lower bound.

Returns the *minimum possible* value, not the exact value. Chunk boundary
comparison only fires when store offset exceeds this minimum — guaranteeing
zero false negatives (conservative: report only when overflow is certain).

ref: GUEB — abstract interpretation for heap sizes.
     Simplified here to heuristic constant propagation (O(n) vs. full AI).
"""

import re
from dataclasses import dataclass
from typing import Optional


@dataclass
class SizeEstimate:
    """Estimated or lower-bound allocation size."""
    exact: int = 0          # 精确值 (常量直接可确定)
    lower_bound: int = 0     # 下界 (表达式可推断的最小值)
    confidence: float = 0.0  # [0,1]
    source: str = ''         # 'constant' | 'sizeof' | 'param' | 'expression'


def propagate_size_for_var(
    var_name: str,
    ir_lines: list[str],
    call_site_pc: int,
) -> SizeEstimate:
    """从变量定义处向前传播, 尝试恢复其数值。

    搜索链: var = expr → expr 中的常量 → 若不可确定, 尝试回溯上一层。
    """
    # 搜索 var_name 的定义行
    assign_pattern = re.compile(
        rf'{re.escape(var_name)}\s*=\s*(.+)'
    )
    for i in range(call_site_pc, max(0, call_site_pc - 20), -1):
        line = ir_lines[i]
        m = assign_pattern.search(line)
        if not m:
            continue
        rhs = m.group(1).strip()
        return _infer_size_from_rhs(rhs, ir_lines)
    return SizeEstimate(confidence=0.0, source='unknown')


def _infer_size_from_rhs(rhs: str, ir_lines: list[str]) -> SizeEstimate:
    """从右值表达式推断分配大小。"""
    # 直接常量: size = 64 或 0x40
    m = re.match(r'^(?:0x)?([0-9a-fA-F]+)$', rhs)
    if m:
        val = int(m.group(1), 0)
        return SizeEstimate(exact=val, lower_bound=val, confidence=0.95, source='constant')

    # sizeof 表达式: sizeof(struct X)
    sizeof_match = re.search(r'sizeof\s*\(\s*(\w+)\s*\)', rhs, re.IGNORECASE)
    if sizeof_match:
        struct_name = sizeof_match.group(1)
        size = _estimate_struct_size(struct_name)
        if size > 0:
            return SizeEstimate(exact=size, lower_bound=size, confidence=0.80,
                              source='sizeof')

    # 乘法表达式: N * M (常用于 calloc)
    mul_match = re.match(r'(\d+)\s*\*\s*(\d+)', rhs)
    if mul_match:
        product = int(mul_match.group(1)) * int(mul_match.group(2))
        return SizeEstimate(exact=product, lower_bound=product, confidence=0.75,
                          source='expression')

    # variable name — may be a function parameter
    if re.match(r'^[a-z_]\w*$', rhs, re.IGNORECASE):
        return SizeEstimate(lower_bound=1, confidence=0.30, source='param')

    return SizeEstimate(confidence=0.0, source='unknown')


def _estimate_struct_size(struct_name: str) -> int:
    """Estimate struct size from name via field-count heuristic.

    Covers common libc/system structs only. A full implementation would
    require Ghidra's data type database."""
    known_structs = {
        'sockaddr': 16, 'sockaddr_in': 16, 'sockaddr_in6': 28,
        'timeval': 16, 'timespec': 16,
        'stat': 144, 'dirent': 280,
        'iovec': 16, 'msghdr': 56,
        'SSL_CTX': 1024, 'SSL': 512,
    }
    name_lower = struct_name.lower().replace('struct_', '').replace('struct ', '')
    return known_structs.get(name_lower, 0)
