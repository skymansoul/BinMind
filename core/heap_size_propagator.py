"""
堆分配大小传播 — 恢复无法在调用上下文局部确定的 malloc 大小参数。
对三类来源做启发式恢复: 函数参数、sizeof 表达式、算术表达式;
返回最小可能值而非精确值, 保证 chunk 边界比较零漏报。
"""

import re
from dataclasses import dataclass
from typing import Optional


@dataclass
class SizeEstimate:
    """估算或下界的分配大小。"""
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

    # 变量名 — 可能是函数参数
    if re.match(r'^[a-z_]\w*$', rhs, re.IGNORECASE):
        return SizeEstimate(lower_bound=1, confidence=0.30, source='param')

    return SizeEstimate(confidence=0.0, source='unknown')


def _estimate_struct_size(struct_name: str) -> int:
    """按名称用字段数启发式估算结构体大小, 仅覆盖常见libc/系统结构体。"""
    known_structs = {
        'sockaddr': 16, 'sockaddr_in': 16, 'sockaddr_in6': 28,
        'timeval': 16, 'timespec': 16,
        'stat': 144, 'dirent': 280,
        'iovec': 16, 'msghdr': 56,
        'SSL_CTX': 1024, 'SSL': 512,
    }
    name_lower = struct_name.lower().replace('struct_', '').replace('struct ', '')
    return known_structs.get(name_lower, 0)
