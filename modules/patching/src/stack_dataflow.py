# 栈溢出数据流追踪 — memcpy call分析 + 寄存器值回溯
"""栈溢出数据流辅助 — 从memcpy/memset等调用回溯dst缓冲区和size参数。

MS x64 ABI: memcpy(rcx=dst, rdx=src, r8=size)
System V:   memcpy(rdi=dst, rsi=src, rdx=size)
"""

import re
from typing import List, Optional, Tuple


# memcpy/memset/strcpy等 — 栈溢出的主要来源
MEMCPY_CALLS = re.compile(
    r'\bcall\s+(?:[0-9a-f]+\s+<)?(memcpy|memmove|memset|strcpy|strncpy|'
    r'sprintf|snprintf|gets|strcat|wcscpy|mbscpy|CopyMemory|'
    r'__builtin_memcpy|__memcpy_chk)(?:@plt)?>?\b', re.I)

# 寄存器→栈偏移的lea模式
LEA_STACK = re.compile(
    r'\blea\s+(\w+),?\s*\[(rbp|rsp)\s*-\s*(0x[0-9a-f]+|\d+)\]', re.I)


def resolve_reg_value(lowered: List[str], from_idx: int, reg: str
                      ) -> Tuple[int, bool]:
    """回溯寄存器值来源。返回 (value, is_tainted)。"""
    for j in range(from_idx - 1, max(from_idx - 12, -1), -1):
        l = lowered[j]
        # 直接mov reg, imm
        m = re.search(r'\bmov\s+' + re.escape(reg) + r',?\s*(0x[0-9a-f]+|\d+)', l)
        if m:
            v = int(m.group(1), 16) if m.group(1).lower().startswith('0x') else int(m.group(1))
            return v, False
        # movsxd reg, eax → 符号扩展, 继续追溯eax
        m = re.search(r'\bmovsxd\s+' + re.escape(reg) + r',?\s*(\w+)', l)
        if m:
            src = m.group(1)
            for k in range(j - 1, max(j - 5, -1), -1):
                m2 = re.search(r'\bmov\s+' + re.escape(src) + r',?\s*\[rbp[+\-]', lowered[k])
                if m2:
                    return 0, True  # 来自栈上的参数 → 外部控制
            return 0, True  # 来自寄存器 → 保守认为是外部控制
        # mov reg, src_reg — 继续追溯
        m = re.search(r'\bmov\s+' + re.escape(reg) + r',?\s*(\w+)', l)
        if m and m.group(1) not in ('rbp', 'rsp', 'rip'):
            return resolve_reg_value(lowered, j, m.group(1))
    return 0, False


def find_dst_offset(lowered: List[str], call_idx: int) -> int:
    """从memcpy调用回溯dst寄存器，找到对应的[rbp-N]偏移。

    支持: lea rcx/rdi, [rbp-N]; mov rcx/rdi, reg → lea reg, [rbp-N]
    """
    for j in range(call_idx - 1, max(call_idx - 8, -1), -1):
        l = lowered[j]
        # 直接 lea rcx/rdi, [rbp-N]
        m = re.search(r'\blea\s+(rcx|rdi),?\s*\[(rbp|rsp)\s*-\s*'
                      r'(0x[0-9a-f]+|\d+)\]', l)
        if m:
            return int(m.group(3), 16) if m.group(3).lower().startswith('0x') else int(m.group(3))
        # mov rcx/rdi, reg → 再回溯一层
        m = re.search(r'\bmov\s+(rcx|rdi),?\s*(\w+)', l)
        if m:
            mid_reg = m.group(2)
            for k in range(j - 1, max(j - 5, -1), -1):
                m2 = re.search(r'\blea\s+' + re.escape(mid_reg) +
                               r',?\s*\[(rbp|rsp)\s*-\s*(0x[0-9a-f]+|\d+)\]',
                               lowered[k])
                if m2:
                    return int(m2.group(2), 16) if m2.group(2).lower().startswith('0x') else int(m2.group(2))
            break
        # lea reg, [rbp-N] → 检查后续是否有 mov rcx/rdi, reg
        m = re.search(r'\blea\s+(\w+),?\s*\[(rbp|rsp)\s*-\s*(0x[0-9a-f]+|\d+)\]', l)
        if m:
            mid_reg = m.group(1)
            off = int(m.group(3), 16) if m.group(3).lower().startswith('0x') else int(m.group(3))
            for k in range(j + 1, min(j + 4, len(lowered))):
                if re.search(r'\bmov\s+(rcx|rdi),?\s*' + re.escape(mid_reg), lowered[k]):
                    return off
    return 0
