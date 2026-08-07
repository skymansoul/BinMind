"""内联拷贝检测工具函数 — 栈槽提取/地址解析/立即数追踪.

创建: 2026-05-29
"""

from __future__ import annotations

import re as _re
from typing import List, Optional, Tuple

from .malloc_size_inferrer import MallocSite


def extract_stack_slot(mem_op: str) -> Optional[str]:
    """从 [rbp-0x8] 提取规范栈槽标识 'rbp-0x8'."""
    m = _re.search(r'rbp\s*([-+])\s*(0x[0-9a-f]+|\d+)', mem_op)
    if m:
        return f'rbp{m.group(1)}{m.group(2)}'
    return None


def extract_addr(instr: str) -> Optional[int]:
    """从 objdump 行提取指令地址."""
    m = _re.match(r'\s*([0-9a-f]+):', instr.strip())
    return int(m.group(1), 16) if m else None


def usable_from_site(site: MallocSite) -> Tuple[int, int]:
    """从 MallocSite 提取可用区间."""
    lo = site.size_interval.min_possible()
    hi = site.size_interval.max_possible()
    if hi == 0 or hi > 0x100000:
        hi = lo
    return lo, hi


def trace_immediate_arg(instructions: List[str],
                        call_idx: int, arg_reg: str
                        ) -> Tuple[Optional[int], str]:
    """后向追踪函数调用的立即数参数值 — MS64+SystemV 双尝试."""
    result = _backward_find_imm(instructions, call_idx, arg_reg)
    if result is not None:
        return result, f'{arg_reg}=0x{result:x}'
    # System V 映射: r8→rcx, rdx→rsi
    sysv_map = {'r8': 'rcx', 'rdx': 'rsi'}
    if arg_reg in sysv_map:
        result = _backward_find_imm(instructions, call_idx, sysv_map[arg_reg])
    if result is not None:
        return result, 'sysv'
    return None, ''


def _backward_find_imm(instructions: List[str],
                       call_idx: int, reg: str) -> Optional[int]:
    """后向查找 mov reg, imm — 处理 r8d/r8w 等宽度别名."""
    # 构建寄存器匹配模式: r8 → r8[dwb]? , ecx → ecx|rcx
    reg_aliases = {reg}
    if reg.startswith('r') and reg[1:].isdigit():
        reg_aliases.add(reg + 'd')  # r8 → r8d
        reg_aliases.add(reg + 'w')  # r8 → r8w
    reg_pattern = '|'.join(sorted(reg_aliases, key=len, reverse=True))
    for j in range(call_idx - 1, max(0, call_idx - 15) - 1, -1):
        il = instructions[j].strip().lower()
        if not il or il.startswith(';'):
            continue
        m = _re.match(rf'mov\s+({reg_pattern}),\s*(0x[0-9a-f]+|\d+)', il)
        if m:
            try:
                return int(m.group(2), 0)
            except ValueError:
                return None
        m = _re.match(r'push\s+(0x[0-9a-f]+|\d+)', il)
        if m:
            try:
                return int(m.group(1), 0)
            except ValueError:
                return None
        if _re.match(rf'(mov|lea|xor|add|sub)\s+({reg_pattern}),', il):
            return None
    return None
