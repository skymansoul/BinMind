"""检测模式: 算术溢出 — SIGNED_IDX / MUL_OVERFLOW / 16-bit wraparound.

创建: 2024-09-27

模式覆盖:
  SIGNED_IDX: 有符号加法突破 INT_MAX
  MUL_OVERFLOW: imul 结果 (via stack 或立即数) → alloc
  16-bit wraparound: ADD + mov WORD PTR [ax] 截断 (编译器显式截断)
"""
from __future__ import annotations

import re as _re
from typing import Dict, List, Optional, Tuple, Callable

from ._types import (
    IntOverflowFinding, OverflowType,
    _MAX_INT32,
    ADD_STACK_DWORD, IMUL_STACK, MOV_STACK_AX,
    IMUL_IMM,
)


def detect_signed_idx_overflow(
    instructions: List[str],
    function_name: str,
    addrs: Optional[List[int]] = None,
    stack_vals: Optional[Dict[int, int]] = None,
) -> List[IntOverflowFinding]:
    """mov [mem], INT_MAX → add [mem], const → signed overflow.

    INT_MAX + const 突破 32-bit 有符号上限, 后续 movsxd 产生负索引.
    检测逻辑: 栈上有接近 INT_MAX 的值, 且对该栈槽执行 add.
    """
    if stack_vals is None:
        stack_vals = {}
    findings: List[IntOverflowFinding] = []

    for i, instr in enumerate(instructions):
        il = instr.strip().lower()
        m = ADD_STACK_DWORD.match(il)
        if not m:
            continue
        add_val = int(m.group(3), 16 if '0x' in m.group(3) else 10)
        sign = 1 if m.group(1) == '+' else -1
        offset = sign * int(m.group(2), 16 if '0x' in m.group(2) else 10)
        base_val = stack_vals.get(offset)
        if base_val is None:
            continue

        result = base_val + add_val
        if result <= _MAX_INT32:
            continue
        addr = addrs[i] if (addrs and i < len(addrs)) else i
        insn_addr = addr
        findings.append(IntOverflowFinding(
            insn_addr=insn_addr, function_name=function_name,
            description=(
                f'integer overflow: signed index overflow '
                f'{base_val}+{add_val}={result} '
                f'(> INT_MAX) at {function_name}:0x{addr:x}'),
            overflow_type=OverflowType.SIGNED_IDX,
            alloc_site=i,
            computed_size=result,
            confidence=0.75,
            size_source=f'signed idx {base_val}+{add_val}',
        ))
    return findings


def detect_mul_overflow(
    instructions: List[str],
    function_name: str,
    addrs: Optional[List[int]] = None,
    stack_vals: Optional[Dict[int, int]] = None,
    find_alloc: Optional[Callable] = None,
) -> List[IntOverflowFinding]:
    """乘法溢出: imul via stack slot 或立即数 → alloc.

    子模式 A: imul reg, [rbp±N] — 从栈取乘数
    子模式 B: imul reg, reg, const — 立即数乘法
    两者都需确认乘法结果流向 alloc 调用.
    """
    if stack_vals is None:
        stack_vals = {}
    findings: List[IntOverflowFinding] = []
    _alloc_finder = find_alloc or _find_next_alloc_call

    for i, instr in enumerate(instructions):
        il = instr.strip().lower()

        # 子模式 A: imul reg, [rbp±N]
        m = IMUL_STACK.match(il)
        if m:
            sign = 1 if m.group(3) == '+' else -1
            offset = sign * int(m.group(4), 16 if '0x' in m.group(4) else 10)
            mult_val = stack_vals.get(offset)
            if mult_val is None or mult_val < 256:
                continue
            call_target = _alloc_finder(instructions, i)
            if call_target is None:
                continue
            alloc_func, call_idx = call_target
            call_addr = (addrs[call_idx]
                         if (addrs and call_idx < len(addrs)) else call_idx)
            insn_addr = addrs[i] if (addrs and i < len(addrs)) else i
            findings.append(IntOverflowFinding(
                insn_addr=insn_addr, function_name=function_name,
                description=(
                    f'integer overflow: multiplication via stack '
                    f'[rbp{offset:+d}]={mult_val} passed to {alloc_func}() '
                    f'at {function_name}:0x{call_addr:x}'),
                overflow_type=OverflowType.MUL_OVERFLOW,
                alloc_site=call_idx,
                alloc_size=mult_val,
                confidence=0.55,
                size_source=f'mul ×{mult_val} → {alloc_func}',
            ))
            continue

        # 子模式 B: imul reg, reg, const
        m = IMUL_IMM.match(il)
        if not m:
            continue
        const = int(m.group(3), 0)
        if const < 256:
            continue
        call_target = _alloc_finder(instructions, i)
        if call_target is None:
            continue
        alloc_func, call_idx = call_target
        call_addr = (addrs[call_idx]
                     if (addrs and call_idx < len(addrs)) else call_idx)
        insn_addr = addrs[i] if (addrs and i < len(addrs)) else i
        findings.append(IntOverflowFinding(
            insn_addr=insn_addr, function_name=function_name,
            description=(
                f'integer overflow: imul by {const} '
                f'passed to {alloc_func}() '
                f'at {function_name}:0x{call_addr:x}'),
            overflow_type=OverflowType.MUL_OVERFLOW,
            alloc_site=call_idx,
            alloc_size=const,
            confidence=0.60,
            size_source=f'imul ×{const} → {alloc_func}',
        ))
    return findings


def detect_16bit_wraparound(
    instructions: List[str],
    function_name: str,
    addrs: Optional[List[int]] = None,
    stack_vals: Optional[Dict[int, int]] = None,
    find_alloc: Optional[Callable] = None,
) -> List[IntOverflowFinding]:
    """unsigned short 溢出 → 16-bit 截断 → malloc.

    add eax,N → mov WORD PTR [...], ax (截断回16-bit).
    编译器将 unsigned short 提升到 32-bit 做运算,
    但 ax 存储截断回 16-bit — 这是二进制级唯一可见的溢出证据.
    """
    if stack_vals is None:
        stack_vals = {}
    findings: List[IntOverflowFinding] = []
    _alloc_finder = find_alloc or _find_next_alloc_call

    for i, instr in enumerate(instructions):
        il = instr.strip().lower()
        m = MOV_STACK_AX.match(il)
        if not m:
            continue

        sign = 1 if m.group(1) == '+' else -1
        offset = sign * int(m.group(2), 16 if '0x' in m.group(2) else 10)

        # 后向追踪: 截断前是否有 add eax/ax, const
        had_add = False
        for j in range(i - 1, max(0, i - 5) - 1, -1):
            jl = instructions[j].strip().lower()
            if _re.match(r'add\s+(eax|ax),\s*\d+', jl):
                had_add = True
                break
            if _re.match(r'(mov|call|ret|jmp|j\w+)\s', jl):
                break
        if not had_add:
            continue

        # 检查原始栈值是否接近 16-bit MAX
        base_val = stack_vals.get(offset)
        if base_val is None or base_val < 0xFFF0:
            continue

        # 前向: 是否有 movzx + call malloc/alloc
        call_target = _alloc_finder(instructions, i)
        if call_target is None:
            continue

        alloc_func, call_idx = call_target
        call_addr = (addrs[call_idx]
                     if (addrs and call_idx < len(addrs)) else call_idx)
        insn_addr = addrs[i] if (addrs and i < len(addrs)) else i
        findings.append(IntOverflowFinding(
            insn_addr=insn_addr, function_name=function_name,
            description=(
                f'integer overflow: 16-bit wraparound '
                f'0x{base_val:x} at rbp{offset:+d} truncated via '
                f'mov WORD PTR [ax] → {alloc_func}() '
                f'at {function_name}:0x{call_addr:x}'),
            overflow_type=OverflowType.SUSPICIOUS_SIZE,
            alloc_site=call_idx,
            alloc_size=base_val,
            confidence=0.68,
            size_source=f'16-bit wraparound rbp{offset:+d}',
        ))
    return findings


def detect_32bit_add_wraparound(
    instructions: List[str],
    function_name: str,
    addrs: Optional[List[int]] = None,
    stack_vals: Optional[Dict[int, int]] = None,
    find_alloc: Optional[Callable] = None,
) -> List[IntOverflowFinding]:
    """32-bit 无符号加法回绕: 双DWORD参数 → LEA偏移 + memcpy大小.

    malloc(const_small) + memcpy(buf + DWORD_off, data, DWORD_len)
    两个32-bit参数值相加可能超过UINT_MAX导致回绕. (int-overflow-2)
    """
    findings: List[IntOverflowFinding] = []
    _alloc_finder = find_alloc or _find_next_alloc_call

    # 第一遍: 收集 DWORD 参数槽 (正rbp偏移处的 mov DWORD PTR [rbp+off], r32)
    dword_params: Dict[int, str] = {}  # offset → source_reg
    DWORD_PARAM_STORE = _re.compile(
        r'mov\s+dword\s+ptr\s+\[rbp\s*([+\-])\s*(0x[0-9a-f]+|\d+)\]'
        r'\s*,\s*(e\w\w|r\w\w)', _re.I)
    for i, instr in enumerate(instructions):
        il = instr.strip().lower()
        m = DWORD_PARAM_STORE.match(il)
        if not m:
            continue
        sign = 1 if m.group(1) == '+' else -1
        offset = sign * int(m.group(2), 16 if '0x' in m.group(2) else 10)
        if offset > 0:  # 正偏移 = 参数区
            dword_params[offset] = m.group(3)

    if len(dword_params) < 2:
        return findings

    # 检查是否有 malloc 调用 (分配大小是常量)
    has_small_alloc = False
    alloc_size = 0
    for i, instr in enumerate(instructions):
        il = instr.strip().lower()
        m_imm = _re.match(r'mov\s+(e\w\w|r\w\w),\s*(0x[0-9a-f]+|\d+)', il)
        if not m_imm:
            continue
        const_val = int(m_imm.group(2), 0)
        if 0 < const_val <= 0x100000:
            call_target = _alloc_finder(instructions, i)
            if call_target:
                has_small_alloc = True
                alloc_size = const_val
                break

    if not has_small_alloc:
        return findings

    # 第二遍: 找 LEA [r32 + r64] 模式, 其中 r32 来自 DWORD 参数
    LEA_OFFSET = _re.compile(
        r'lea\s+(r\w\w),\s*\[(\w+)\s*\+\s*(r\w\w)\s*\*?\s*1?\]', _re.I)
    DWORD_LOAD = _re.compile(
        r'mov\s+(e\w\w|r\w\w),\s*dword\s+ptr\s+\[rbp\s*([+\-])\s*'
        r'(0x[0-9a-f]+|\d+)\]', _re.I)
    MEMCPY_CALL = _re.compile(r'call\s+.*(memcpy|memset|memmove)', _re.I)

    for i, instr in enumerate(instructions):
        il = instr.strip().lower()
        m = LEA_OFFSET.match(il)
        if not m:
            continue
        offset_reg = m.group(2)  # 偏移寄存器 (如 edx/rdx)
        # 基址寄存器不强制要求 = malloc 指针 (保守: 任何指针)
        base_reg = m.group(3)

        # 向前追踪 offset_reg: 是否来自 DWORD 参数加载
        offset_param = None
        for j in range(i - 1, max(0, i - 8) - 1, -1):
            jl = instructions[j].strip().lower()
            dm = DWORD_LOAD.match(jl)
            if not dm:
                # 若寄存器被重定义, 停止追踪
                if _re.match(rf'(mov|add|sub|lea|xor|imul|shl)\s+{offset_reg},', jl):
                    break
                continue
            loaded_reg = dm.group(1)
            sign = 1 if dm.group(2) == '+' else -1
            load_off = sign * int(dm.group(3), 16 if '0x' in dm.group(3) else 10)
            if load_off in dword_params:
                offset_param = load_off
                break

        if offset_param is None:
            continue

        # 确认前向有 memcpy 调用 (≤10条指令)
        has_memcpy = False
        for j in range(i + 1, min(i + 11, len(instructions))):
            if MEMCPY_CALL.search(instructions[j].strip().lower()):
                has_memcpy = True
                break

        if not has_memcpy:
            continue

        dword_addr = (addrs[i] if (addrs and i < len(addrs)) else i)
        # 计算置信度: 参数越多→越像 (函数签名包含多个无符号int)
        confidence = min(0.55 + 0.05 * len(dword_params), 0.75)
        findings.append(IntOverflowFinding(
            insn_addr=dword_addr, function_name=function_name,
            description=(
                f'integer overflow: 32-bit ADD wraparound '
                f'DWORD[rbp+{offset_param:#x}] used as pointer offset, '
                f'malloc({alloc_size}) + memcpy, '
                f'offset+size may wrap UINT32_MAX '
                f'at {function_name}:0x{dword_addr:x}'),
            overflow_type=OverflowType.SUSPICIOUS_SIZE,
            alloc_site=i,
            alloc_size=alloc_size,
            confidence=confidence,
            size_source=f'32-bit ADD wraparound DWORD[rbp+{offset_param:#x}]',
        ))
    return findings


# 内置辅助

_ALLOC_FUNCS = {'malloc', 'calloc', 'realloc', '_malloc', 'HeapAlloc'}


def _find_next_alloc_call(instructions: List[str],
                           start_idx: int) -> Optional[Tuple[str, int]]:
    """从 start_idx 前向查找最近的 alloc 函数调用 (≤15指令).

    数据流守卫: 中间非alloc的call可能破坏寄存器约定, 视为数据流中断.
    """
    for j in range(start_idx + 1, min(start_idx + 15, len(instructions))):
        il = instructions[j].strip().lower()
        if 'call' in il:
            for f in _ALLOC_FUNCS:
                if f in il:
                    return (f, j)
            return None
    return None
