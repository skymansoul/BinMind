# x86_64: first 6 args in registers (rdi,rsi,rdx,rcx,r8,r9), stack from 7th.
# Format string = 1st arg (rdi); stack offset counted from caller's rsp+0.
# i386: all args on stack, format string at esp+4 (above return address).
# Offset affects %n write exploitability: offset<=0 means format string itself
# is on the stack, allowing direct control of the write target.

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class FormatOffsetEstimate:
    """Format-string stack offset estimate."""
    call_addr: int
    format_func: str
    estimated_offset: int      # 栈上偏移(以%p参数位置计), -1表示未知
    arch_bits: int             # 32 or 64
    calling_convention: str    # "x86_64_sysv" / "i386_cdecl"
    confidence: float
    note: str = ""


def estimate_format_offset(
    disasm_lines: List[str],
    call_idx: int,
    arch_bits: int = 64,
) -> FormatOffsetEstimate:
    """估计格式化字符串在栈上的参数偏移位置。

    对于x86_64: rdi=格式字符串自身, 栈上参数从第7个位置开始。
    若格式字符串通过lea rdi,[rsp+X]加载→字符串在栈上→栈偏移可用。
    """
    if call_idx < 0 or call_idx >= len(disasm_lines):
        return FormatOffsetEstimate(call_idx, "", -1, arch_bits, "", 0.0)

    line = disasm_lines[call_idx].strip().lower()
    m = re.search(r'call.*<(\w+)', line)
    fmt_func = m.group(1) if m else "printf"

    if arch_bits == 64:
        # x86_64: 默认偏移=6(前5个寄存器参数+格式字符串自身=第6个位置以后)
        offset = 6
        convention = "x86_64_sysv"

        # 检查格式字符串是否在栈上(lea rdi, [rsp+N])
        for i in range(call_idx - 1, max(-1, call_idx - 10), -1):
            prev = disasm_lines[i].strip().lower()
            m = re.search(r'lea\s+(?:rdi|edi),\s*\[rsp\s*[+\-]\s*(0x[0-9a-fA-F]+|\d+)\]', prev)
            if m:
                try:
                    sp_offset = int(m.group(1), 0)
                    # 栈偏移 = sp_offset / 8 (每个栈槽8字节)+ 前6个寄存器参数
                    stack_pos = sp_offset // 8 + 6
                    offset = max(1, stack_pos)
                    return FormatOffsetEstimate(
                        call_idx, fmt_func, offset, arch_bits, convention,
                        0.75, f"格式字符串在rsp+{sp_offset}→栈偏移={offset}")
                except ValueError:
                    pass

            # 检查是否通过push传递(32位风格)
            if 'push' in prev:
                offset = 1
                return FormatOffsetEstimate(
                    call_idx, fmt_func, offset, arch_bits, convention,
                    0.60, "通过push传递→偏移=1")

        return FormatOffsetEstimate(
            call_idx, fmt_func, offset, arch_bits, convention,
            0.40, "默认x86_64偏移(无栈上格式字符串)")
    else:
        # i386: 所有参数在栈上, 格式字符串在返回地址之上
        return FormatOffsetEstimate(
            call_idx, fmt_func, 1, arch_bits, "i386_cdecl",
            0.50, "i386: 格式字符串=栈上第一个参数")


__all__ = ["FormatOffsetEstimate", "estimate_format_offset"]
