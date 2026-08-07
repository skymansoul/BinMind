"""检测模式: 分配大小相关 — LARGE_IMM64 / TRUNCATION / SUSPICIOUS_SIZE.

创建: 2026-07-25

三个模式共享核心逻辑: 指令中的分配大小 → 是否超出安全边界.
"""
from __future__ import annotations

from typing import Dict, List, Optional, Tuple, Callable

from ._types import (
    IntOverflowFinding, OverflowType,
    _MAX_UINT32, _SUSPICIOUS_VALS,
    MOVABS64, MOV_STACK_EAX, MOV_R64_IMM64,
    MOV_REG_IMM, MOV_REG_FROM_STACK,
)


def detect_large_imm64(
    instructions: List[str],
    function_name: str,
    addrs: Optional[List[int]] = None,
) -> List[IntOverflowFinding]:
    """movabs rax, 0xNNNN (>2^32) → rcx=rax → call alloc.

    编译器的 movabs 指令直接暴露了 64-bit 立即数,
    如果该值 > 2^32 且流向 alloc, 几乎确定是溢出.
    """
    findings: List[IntOverflowFinding] = []
    for i, instr in enumerate(instructions):
        il = instr.strip().lower()
        m = MOVABS64.match(il)
        if not m:
            continue
        val = int(m.group(2), 0)
        if val <= _MAX_UINT32:
            continue

        call_target = _find_next_alloc_call(instructions, i)
        if call_target is None:
            continue

        alloc_func, call_idx = call_target
        call_addr = (addrs[call_idx]
                     if (addrs and call_idx < len(addrs)) else call_idx)
        truncated = val & _MAX_UINT32

        findings.append(IntOverflowFinding(
            insn_addr=i, function_name=function_name,
            description=(
                f'integer overflow: 64-bit immediate 0x{val:x} '
                f'(> 2^32) passed to {alloc_func}() '
                f'at {function_name}:0x{call_addr:x}'),
            overflow_type=OverflowType.LARGE_IMM64,
            alloc_site=call_idx,
            alloc_size=val,
            computed_size=truncated,
            confidence=0.80,
            size_source=f'movabs 0x{val:x} → {alloc_func}',
        ))
    return findings


def detect_truncation(
    instructions: List[str],
    function_name: str,
    addrs: Optional[List[int]] = None,
) -> List[IntOverflowFinding]:
    """movabs rax, >2^32 → mov [rbp-X], eax → ... → call alloc.

    编译器将对 64-bit 值的 32-bit 截断显式化为 mov [...] eax,
    该存储只有 32-bit → 高位丢失.
    """
    findings: List[IntOverflowFinding] = []
    for i, instr in enumerate(instructions):
        il = instr.strip().lower()
        m = MOVABS64.match(il)
        if not m:
            continue
        val64 = int(m.group(2), 0)
        if val64 <= _MAX_UINT32:
            continue

        # 查找后序的 mov [rbp-X], eax (截断存储)
        trunc_idx = None
        for j in range(i + 1, min(i + 15, len(instructions))):
            jl = instructions[j].strip().lower()
            if MOV_STACK_EAX.match(jl):
                trunc_idx = j
                break
            if 'call' in jl:
                break
        if trunc_idx is None:
            continue

        # 从截断点继续查找 alloc call
        call_target = _find_next_alloc_call(instructions, trunc_idx)
        if call_target is None:
            continue

        alloc_func, call_idx = call_target
        call_addr = (addrs[call_idx]
                     if (addrs and call_idx < len(addrs)) else call_idx)
        truncated = val64 & _MAX_UINT32

        findings.append(IntOverflowFinding(
            insn_addr=i, function_name=function_name,
            description=(
                f'integer overflow: truncation 0x{val64:x} '
                f'→ 0x{truncated:x} (32-bit) '
                f'→ {alloc_func}(size={truncated}) '
                f'at {function_name}:0x{call_addr:x}'),
            overflow_type=OverflowType.TRUNCATION,
            alloc_site=call_idx,
            alloc_size=val64,
            computed_size=truncated,
            confidence=0.85,
            size_source=f'truncation 64→32: {val64:#x}→{truncated:#x}',
        ))
    return findings


def detect_suspicious_size(
    instructions: List[str],
    function_name: str,
    addrs: Optional[List[int]] = None,
    stack_vals: Optional[Dict[int, int]] = None,
    find_alloc: Optional[Callable] = None,
) -> List[IntOverflowFinding]:
    """检测可疑分配大小 — 直接立即数 + 栈传参.

    子模式 A: mov reg/r64, 0xFF... → call alloc (直接立即数)
    子模式 B: mov [rbp-X], 0xFF... → mov reg, [rbp-X] → call alloc (栈传参)
    """
    if find_alloc is None:
        find_alloc = _find_next_alloc_call
    if stack_vals is None:
        stack_vals = {}
    findings: List[IntOverflowFinding] = []

    # — 子模式 A: 直接立即数 —
    for i, instr in enumerate(instructions):
        il = instr.strip().lower()

        # 先检测 mov r64, imm64 (64-bit立即数 in 64-bit寄存器)
        m64 = MOV_R64_IMM64.match(il)
        if m64:
            val = int(m64.group(2), 0)
            call_target = find_alloc(instructions, i)
            if call_target:
                alloc_func, call_idx = call_target
                call_addr = (addrs[call_idx]
                             if (addrs and call_idx < len(addrs)) else call_idx)
                findings.append(IntOverflowFinding(
                    insn_addr=i, function_name=function_name,
                    description=(
                        f'integer overflow: suspicious 64-bit size '
                        f'0x{val:x} ({alloc_func}) '
                        f'at {function_name}:0x{call_addr:x}'),
                    overflow_type=OverflowType.SUSPICIOUS_SIZE,
                    alloc_site=call_idx,
                    alloc_size=val,
                    confidence=0.70,
                    size_source=f'imm64 0x{val:x} → {alloc_func}',
                ))
            continue

        # 常规 mov reg, imm32
        m = MOV_REG_IMM.match(il)
        if not m:
            continue
        val = int(m.group(2), 0)
        if val not in _SUSPICIOUS_VALS:
            continue
        call_target = find_alloc(instructions, i)
        if call_target is None:
            continue
        alloc_func, call_idx = call_target
        call_addr = (addrs[call_idx]
                     if (addrs and call_idx < len(addrs)) else call_idx)
        findings.append(IntOverflowFinding(
            insn_addr=i, function_name=function_name,
            description=(
                f'integer overflow: suspicious alloc size '
                f'0x{val:x} ({alloc_func}) '
                f'at {function_name}:0x{call_addr:x}'),
            overflow_type=OverflowType.SUSPICIOUS_SIZE,
            alloc_site=call_idx,
            alloc_size=val,
            confidence=0.65,
            size_source=f'suspicious size 0x{val:x} → {alloc_func}',
        ))

    # — 子模式 B: 栈传参 —
    for offset, val in stack_vals.items():
        if val not in _SUSPICIOUS_VALS:
            continue
        for i, instr in enumerate(instructions):
            il = instr.strip().lower()
            m = MOV_REG_FROM_STACK.match(il)
            if not m:
                continue
            sign = 1 if m.group(2) == '+' else -1
            stack_off = sign * int(m.group(3), 16 if '0x' in m.group(3) else 10)
            if stack_off != offset:
                continue
            call_target = find_alloc(instructions, i)
            if call_target is None:
                continue
            alloc_func, call_idx = call_target
            call_addr = (addrs[call_idx]
                         if (addrs and call_idx < len(addrs)) else call_idx)
            findings.append(IntOverflowFinding(
                insn_addr=i, function_name=function_name,
                description=(
                    f'integer overflow: suspicious alloc size '
                    f'0x{val:x} via stack (rbp{offset:+d}) → {alloc_func}() '
                    f'at {function_name}:0x{call_addr:x}'),
                overflow_type=OverflowType.SUSPICIOUS_SIZE,
                alloc_site=call_idx,
                alloc_size=val,
                confidence=0.60,
                size_source=f'stack[rbp{offset:+d}]={val:#x}',
            ))
    return findings


# 内置辅助

_ALLOC_FUNCS = {'malloc', 'calloc', 'realloc', '_malloc', 'HeapAlloc'}


def _find_next_alloc_call(instructions: List[str],
                           start_idx: int) -> Optional[Tuple[str, int]]:
    """从 start_idx 前向查找最近的 alloc 函数调用."""
    for j in range(start_idx + 1, min(start_idx + 30, len(instructions))):
        il = instructions[j].strip().lower()
        if 'call' not in il:
            continue
        for f in _ALLOC_FUNCS:
            if f in il:
                return (f, j)
    return None
