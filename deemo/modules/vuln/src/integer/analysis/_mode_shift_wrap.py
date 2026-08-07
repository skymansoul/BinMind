"""检测模式: SHL 溢出 + 16-bit 编译器提升意图.

创建: 2026-05-09

这两个模式处理编译器优化/提升导致的间接溢出:
  SHL_OVERFLOW: shl N (×2^N, N≥5) → cdqe → alloc — 跨函数参数场景
  16-bit intent: WORD store near 0xFFFF → movzx → 算术 → alloc — 编译器提升掩盖
"""
from __future__ import annotations

import re as _re
from typing import Dict, List, Optional, Tuple, Callable

from ._types import (
    IntOverflowFinding, OverflowType,
    MOV_REG_FROM_STACK,
)

# shl reg, const — 移位量 ≥ 此阈值视为潜在溢出 (×32 → 32-bit 变量有溢出风险)
_SHL_MIN_BITS = 5

# 16-bit WORD 存储值 ≥ 此阈值视为"近16-bit最大值"
_WORD_NEAR_MAX = 0xFFE0


def detect_shl_overflow(
    instructions: List[str],
    function_name: str,
    addrs: Optional[List[int]] = None,
    find_alloc: Optional[Callable] = None,
) -> List[IntOverflowFinding]:
    """shl reg, N (N≥5) → cdqe/movsxd → alloc → 潜在溢出.

    解决跨函数参数追踪问题: main 中的立即数通过寄存器传参到子函数,
    子函数内 shl → cdqe → malloc. 即使无法跨函数追踪具体值,
    shl + cdqe + alloc 的组合本身是溢出信号.
    (int-overflow-3: mov ecx,0xFFFFFFFF → call load → shl eax,7 → cdqe → malloc)
    """
    findings: List[IntOverflowFinding] = []
    _alloc_finder = find_alloc or _find_next_alloc_call

    for i, instr in enumerate(instructions):
        il = instr.strip().lower()
        m = _re.match(r'shl\s+(\w+),\s*(0x[0-9a-f]+|\d+)', il)
        if not m:
            continue
        shift_bits = int(m.group(2), 0)
        if shift_bits < _SHL_MIN_BITS:
            continue

        # shl 后 5 条指令内是否有 cdqe / movsxd
        has_sign_ext = False
        for j in range(i + 1, min(i + 6, len(instructions))):
            jl = instructions[j].strip().lower()
            if _re.match(r'(cdqe|movsxd\s+\w+,\s*\w+)', jl):
                has_sign_ext = True
                break

        call_target = _alloc_finder(instructions, i)
        if call_target is None:
            continue

        alloc_func, call_idx = call_target
        call_addr = (addrs[call_idx]
                     if (addrs and call_idx < len(addrs)) else call_idx)
        multiplier = 1 << shift_bits

        # 若从栈加载的值参与 shl, 置信度更高 (参数来源)
        confidence = 0.55
        size_source = f'shl ×{multiplier} → {alloc_func}'
        for k in range(max(0, i - 3), i):
            kl = instructions[k].strip().lower()
            if MOV_REG_FROM_STACK.match(kl):
                confidence = 0.65
                size_source = f'shl ×{multiplier} (stack-sourced) → {alloc_func}'
                break

        findings.append(IntOverflowFinding(
            insn_addr=i, function_name=function_name,
            description=(
                f'integer overflow: shl by {shift_bits} (×{multiplier}) '
                f'{"+sign-ext " if has_sign_ext else ""}'
                f'→ {alloc_func}() '
                f'at {function_name}:0x{call_addr:x}'),
            overflow_type=OverflowType.MUL_OVERFLOW,
            alloc_site=call_idx,
            alloc_size=multiplier,
            confidence=confidence,
            size_source=size_source,
        ))
    return findings


def detect_16bit_overflow_intent(
    instructions: List[str],
    function_name: str,
    addrs: Optional[List[int]] = None,
    stack_vals: Optional[Dict[int, int]] = None,
    find_alloc: Optional[Callable] = None,
) -> List[IntOverflowFinding]:
    """mov WORD PTR [rbp±N], near_max → movzx → 算术 → cdqe → alloc.

    编译器将 unsigned short 提升为 int (32-bit) 做运算,
    导致二进制级无溢出 (如 0xFFFF+1 = 0x10000 在32-bit中是合法的).
    但 WORD 存储 + movzx + 算术 + alloc 的组合暴露了程序员的 16-bit 回绕意图.
    (intof-8, int-overflow-1, integer-overflow-06)
    """
    if stack_vals is None:
        stack_vals = {}
    findings: List[IntOverflowFinding] = []
    _alloc_finder = find_alloc or _find_next_alloc_call

    for offset, val in stack_vals.items():
        if val < _WORD_NEAR_MAX:
            continue

        for i, instr in enumerate(instructions):
            il = instr.strip().lower()
            # movzx eax/reg, WORD PTR [rbp±N]
            m = _re.match(
                r'movzx\s+(\w+),\s*word\s+ptr\s+\[rbp\s*([+\-])\s*'
                r'(0x[0-9a-f]+|\d+)\]', il)
            if not m:
                continue
            sign = 1 if m.group(2) == '+' else -1
            load_off = sign * int(m.group(3), 16 if '0x' in m.group(3) else 10)
            if load_off != offset:
                continue

            # movzx 后是否有算术运算 (add/shl/imul/sub)
            has_arith = False
            for j in range(i + 1, min(i + 5, len(instructions))):
                jl = instructions[j].strip().lower()
                if _re.match(r'(add|sub|shl|imul)\s+\w+,', jl):
                    has_arith = True
                    break
            if not has_arith:
                continue

            call_target = _alloc_finder(instructions, i)
            if call_target is None:
                continue

            alloc_func, call_idx = call_target
            call_addr = (addrs[call_idx]
                         if (addrs and call_idx < len(addrs)) else call_idx)
            findings.append(IntOverflowFinding(
                insn_addr=i, function_name=function_name,
                description=(
                    f'integer overflow: 16-bit overflow intent '
                    f'WORD[rbp{offset:+d}]={val:#x} → movzx → arithmetic '
                    f'→ {alloc_func}() '
                    f'at {function_name}:0x{call_addr:x}'),
                overflow_type=OverflowType.SUSPICIOUS_SIZE,
                alloc_site=call_idx,
                alloc_size=val,
                confidence=0.45,
                size_source=f'16-bit intent WORD[rbp{offset:+d}]={val:#x}',
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
