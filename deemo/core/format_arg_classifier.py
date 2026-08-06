# Classifies the first argument of printf-like calls into four categories.
# Static pattern matching flags every printf(foo) occurrence as vulnerable,
# but foo may be: (a) global .rodata constant, (b) stack buffer written after
# format, (c) caller-supplied constant string, (d) genuine user input.
# Only (d) is a vulnerability; (a)(b)(c) should be filtered.
# Uses disassembly heuristics to distinguish the four cases.

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class FormatArgClass:
    """格式参数分类"""
    call_addr: int
    format_func: str
    arg_class: str       # "rodata_const"/"stack_buffer"/"caller_const"/"user_input"/"unknown"
    confidence: float
    evidence: str = ""


# rodata段特征: lea rdi, [rip+offset] → 全局常量地址
_RODATA_PATTERN = re.compile(r'lea\s+(?:rdi|edi),\s*\[rip\s*[+\-]\s*(0x[0-9a-fA-F]+|\d+)\]', re.IGNORECASE)

# 栈缓冲区特征: lea rdi, [rbp-offset] 或 lea rdi, [rsp+offset]
_STACK_BUF_PATTERN = re.compile(r'lea\s+(?:rdi|edi),\s*\[(?:rbp|rsp)\s*[+\-]\s*(0x[0-9a-fA-F]+|\d+)\]', re.IGNORECASE)

# 来自寄存器(可能是参数传递)
_REG_ARG_PATTERN = re.compile(r'mov\s+(?:rdi|edi),\s*(r\w+)', re.IGNORECASE)

# 用户输入函数调用结果
_INPUT_CALL_PATTERN = re.compile(r'call.*<(?:read|recv|fgets|gets|scanf)\b', re.IGNORECASE)


def classify_format_arg(
    disasm_lines: List[str],
    call_idx: int,
) -> FormatArgClass:
    """分类printf调用的第一个参数来源。

    从call指令反向搜索参数准备指令(rdi/edi赋值), 分类为四种来源之一。
    """
    if call_idx < 0 or call_idx >= len(disasm_lines):
        return FormatArgClass(call_idx, "", "unknown", 0.0)

    # 提取格式函数名
    call_line = disasm_lines[call_idx].strip().lower()
    m = re.search(r'call.*<(\w+)', call_line)
    fmt_func = m.group(1) if m else "printf"

    # 反向搜索参数准备
    for i in range(call_idx - 1, max(-1, call_idx - 15), -1):
        line = disasm_lines[i].strip().lower()
        if not line or line.startswith(';'):
            continue

        # 分类1: lea rdi, [rip+offset] → rodata常量
        if _RODATA_PATTERN.search(line):
            return FormatArgClass(call_idx, fmt_func, "rodata_const",
                                  0.92, f"全局常量字符串(rip相对)@{hex(i)}")

        # 分类2: lea rdi, [rbp/rsp+offset] → 栈上缓冲区
        if _STACK_BUF_PATTERN.search(line):
            # 检查栈缓冲区是否从用户输入填充
            for j in range(i - 1, max(-1, i - 10), -1):
                prev = disasm_lines[j].strip().lower()
                if _INPUT_CALL_PATTERN.search(prev):
                    return FormatArgClass(call_idx, fmt_func, "user_input",
                                          0.78, f"栈缓冲区+用户输入@{hex(j)}→{hex(i)}")
            return FormatArgClass(call_idx, fmt_func, "stack_buffer",
                                  0.55, f"栈缓冲区(未确认用户输入)@{hex(i)}")

        # 分类3: mov rdi, reg → 来自参数
        m = _REG_ARG_PATTERN.search(line)
        if m:
            src_reg = m.group(1)
            if src_reg in ('rsi', 'rdx', 'rcx', 'r8', 'r9'):
                return FormatArgClass(call_idx, fmt_func, "caller_const",
                                      0.60, f"来自调用者参数({src_reg})@{hex(i)}")
            return FormatArgClass(call_idx, fmt_func, "user_input",
                                  0.50, f"来自寄存器{src_reg}(可能用户可控)@{hex(i)}")

        # 分类4: mov rdi, imm → 常量地址
        m = re.search(r'mov\s+(?:rdi|edi),\s*(0x[0-9a-fA-F]+|\d+)', line)
        if m:
            return FormatArgClass(call_idx, fmt_func, "rodata_const",
                                  0.88, f"常量地址{hex(int(m.group(1),0))}@{hex(i)}")

    return FormatArgClass(call_idx, fmt_func, "unknown", 0.20, "无法分类")


__all__ = ["FormatArgClass", "classify_format_arg"]
