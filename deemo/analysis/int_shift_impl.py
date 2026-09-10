# INT-SHIFT - 整数溢出 8 模式汇编检测管线 (x86-64 objdump 静态分析).
#
# 决策逻辑:
#   八模式正交管线 + 栈值预扫描 (第一遍线性收集 mov [rbp±N], imm):
#     LARGE_IMM64:  movabs rax, >2^32, alloc
#     TRUNCATION:   64-bit, mov [mem], eax, malloc
#     SIGNED_IDX:   INT_MAX + const, signed overflow
#     SUSPICIOUS_SIZE: 0xFF... 直接或栈传参
#     MUL_OVERFLOW: imul 结果, alloc
#     16-bit wraparound: add + mov WORD PTR [ax], alloc
#     SHL_OVERFLOW: shl N>=5, cdqe, alloc (跨函数参数场景)
#     16-bit intent: WORD near 0xFFFF, movzx, arithmetic, alloc
#     32-bit ADD wraparound: DWORD 参数, LEA 偏移 + memcpy 大小回绕
#
#   本文件实现 INT-SHIFT 八模式正交检测管线 + 栈值预扫描.


from __future__ import annotations

import re as _re
from dataclasses import dataclass
from enum import Enum, auto
from typing import Callable, Dict, List, Optional, Tuple


class OverflowType(Enum):
    """整数溢出子类型."""
    LARGE_IMM64 = auto()       # 64-bit 大立即数, alloc
    TRUNCATION = auto()         # 64->32bit 截断, alloc
    SIGNED_IDX = auto()         # 有符号索引溢出 (INT_MAX+const)
    SUSPICIOUS_SIZE = auto()    # 可疑分配大小 (0xFF...)
    MUL_OVERFLOW = auto()       # 乘法结果溢出


@dataclass
class IntOverflowFinding:
    """单次整数溢出发现."""
    insn_addr: int
    function_name: str
    description: str
    overflow_type: OverflowType
    alloc_site: int = 0
    alloc_size: int = 0
    computed_size: int = 0
    confidence: float = 0.5
    size_source: str = ""


# - 常量与预编译正则 -

_MAX_UINT32 = 0xFFFFFFFF
_MAX_INT32 = 0x7FFFFFFF

_SUSPICIOUS_VALS = {
    0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFF,
    0xFFFFFFFE, 0x7FFFFFFF, 0x3FFFFFFF,
    0xFFFFFFFFFFFF,
}

_ALLOC_FUNCS = {'malloc', 'calloc', 'realloc', '_malloc', 'HeapAlloc'}

MOVABS64 = _re.compile(r'movabs\s+(r\w\w),\s*(0x[0-9a-f]+)', _re.I)
MOV_STACK_DWORD = _re.compile(
    r'mov\s+dword\s+ptr\s+\[rbp\s*([+\-])\s*(0x[0-9a-f]+|\d+)\]'
    r'\s*,\s*(0x[0-9a-f]+|\d+)', _re.I)
MOV_STACK_WORD = _re.compile(
    r'mov\s+word\s+ptr\s+\[rbp\s*([+\-])\s*(0x[0-9a-f]+|\d+)\]'
    r'\s*,\s*(0x[0-9a-f]+|\d+)', _re.I)
ADD_STACK_DWORD = _re.compile(
    r'add\s+dword\s+ptr\s+\[rbp\s*([+\-])\s*(0x[0-9a-f]+|\d+)\]'
    r'\s*,\s*(0x[0-9a-f]+|\d+)', _re.I)
MOV_REG_FROM_STACK = _re.compile(
    r'mov\s+(e\w\w),\s*dword\s+ptr\s+\[rbp\s*([+\-])\s*(0x[0-9a-f]+|\d+)\]',
    _re.I)
MOV_REG_IMM = _re.compile(
    r'mov\s+(\w+),\s*(0x[0-9a-f]+|\d+)', _re.I)
MOV_R64_IMM64 = _re.compile(
    r'mov\s+(r\w\w),\s*(0x[0-9a-f]{8,16})', _re.I)
IMUL_STACK = _re.compile(
    r'imul\s+(\w+),\s*(dword|word)\s+ptr\s+\[rbp\s*([+\-])\s*(0x[0-9a-f]+|\d+)\]',
    _re.I)
MOV_STACK_EAX = _re.compile(
    r'mov\s+dword\s+ptr\s+\[rbp\s*([+\-])\s*(0x[0-9a-f]+|\d+)\]'
    r'\s*,\s*eax', _re.I)
MOV_STACK_AX = _re.compile(
    r'mov\s+word\s+ptr\s+\[rbp\s*([+\-])\s*(0x[0-9a-f]+|\d+)\]'
    r'\s*,\s*ax', _re.I)
IMUL_IMM = _re.compile(r'imul\s+(\w+),\s*(\w+),\s*(0x[0-9a-f]+|\d+)', _re.I)

_SHL_MIN_BITS = 5
_WORD_NEAR_MAX = 0xFFE0


# - 共享辅助 -

def _find_next_alloc_call(instructions: List[str],
                          start_idx: int) -> Optional[Tuple[str, int]]:
    """从 start_idx 前向查找最近的 alloc 函数调用 (≤30指令)."""
    for j in range(start_idx + 1, min(start_idx + 30, len(instructions))):
        il = instructions[j].strip().lower()
        if 'call' not in il:
            continue
        for f in _ALLOC_FUNCS:
            if f in il:
                return (f, j)
    return None


def _addr(addrs: Optional[List[int]], idx: int) -> int:
    return addrs[idx] if (addrs and idx < len(addrs)) else idx


# - 模式 1-3: 分配大小相关 -

def detect_large_imm64(
    instructions: List[str],
    function_name: str,
    addrs: Optional[List[int]] = None,
) -> List[IntOverflowFinding]:
    """movabs rax, 0xNNNN (>2^32): rcx=rax, call alloc.

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
        call_addr = _addr(addrs, call_idx)
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
    """movabs rax, >2^32: mov [rbp-X], eax, ..., call alloc.

    编译器将对 64-bit 值的 32-bit 截断显式化为 mov [...] eax,
    该存储只有 32-bit, 高位丢失.
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

        call_target = _find_next_alloc_call(instructions, trunc_idx)
        if call_target is None:
            continue

        alloc_func, call_idx = call_target
        call_addr = _addr(addrs, call_idx)
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
    """检测可疑分配大小 - 直接立即数 + 栈传参.

    子模式 A: mov reg/r64, 0xFF..., call alloc (直接立即数)
    子模式 B: mov [rbp-X], 0xFF..., mov reg, [rbp-X], call alloc (栈传参)
    """
    if find_alloc is None:
        find_alloc = _find_next_alloc_call
    if stack_vals is None:
        stack_vals = {}
    findings: List[IntOverflowFinding] = []

    for i, instr in enumerate(instructions):
        il = instr.strip().lower()

        m64 = MOV_R64_IMM64.match(il)
        if m64:
            val = int(m64.group(2), 0)
            call_target = find_alloc(instructions, i)
            if call_target:
                alloc_func, call_idx = call_target
                call_addr = _addr(addrs, call_idx)
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
        call_addr = _addr(addrs, call_idx)
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
            call_addr = _addr(addrs, call_idx)
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


# - 模式 4-6: 算术溢出 -

def detect_signed_idx_overflow(
    instructions: List[str],
    function_name: str,
    addrs: Optional[List[int]] = None,
    stack_vals: Optional[Dict[int, int]] = None,
) -> List[IntOverflowFinding]:
    """mov [mem], INT_MAX, add [mem], const, signed overflow.

    INT_MAX + const 突破 32-bit 有符号上限, 后续 movsxd 产生负索引.
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
        addr = _addr(addrs, i)
        findings.append(IntOverflowFinding(
            insn_addr=i, function_name=function_name,
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
    """乘法溢出: imul via stack slot 或立即数, alloc."""
    if stack_vals is None:
        stack_vals = {}
    findings: List[IntOverflowFinding] = []
    _alloc_finder = find_alloc or _find_next_alloc_call

    for i, instr in enumerate(instructions):
        il = instr.strip().lower()

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
            call_addr = _addr(addrs, call_idx)
            findings.append(IntOverflowFinding(
                insn_addr=i, function_name=function_name,
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
        call_addr = _addr(addrs, call_idx)
        findings.append(IntOverflowFinding(
            insn_addr=i, function_name=function_name,
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
    """unsigned short 溢出: 16-bit 截断, malloc.

    add eax,N, mov WORD PTR [...], ax (截断回16-bit).
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

        base_val = stack_vals.get(offset)
        if base_val is None or base_val < 0xFFF0:
            continue

        call_target = _alloc_finder(instructions, i)
        if call_target is None:
            continue

        alloc_func, call_idx = call_target
        call_addr = _addr(addrs, call_idx)
        findings.append(IntOverflowFinding(
            insn_addr=i, function_name=function_name,
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
    """32-bit 无符号加法回绕: 双DWORD参数 → LEA偏移 + memcpy大小."""
    findings: List[IntOverflowFinding] = []
    _alloc_finder = find_alloc or _find_next_alloc_call

    dword_params: Dict[int, str] = {}
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
        if offset > 0:
            dword_params[offset] = m.group(3)

    if len(dword_params) < 2:
        return findings

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
        offset_reg = m.group(2)
        base_reg = m.group(3)

        offset_param = None
        for j in range(i - 1, max(0, i - 8) - 1, -1):
            jl = instructions[j].strip().lower()
            dm = DWORD_LOAD.match(jl)
            if not dm:
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

        has_memcpy = False
        for j in range(i + 1, min(i + 11, len(instructions))):
            if MEMCPY_CALL.search(instructions[j].strip().lower()):
                has_memcpy = True
                break

        if not has_memcpy:
            continue

        dword_addr = _addr(addrs, i)
        confidence = min(0.55 + 0.05 * len(dword_params), 0.75)
        findings.append(IntOverflowFinding(
            insn_addr=i, function_name=function_name,
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


# - 模式 7-8: SHL 与 16-bit 意图 -

def detect_shl_overflow(
    instructions: List[str],
    function_name: str,
    addrs: Optional[List[int]] = None,
    find_alloc: Optional[Callable] = None,
) -> List[IntOverflowFinding]:
    """shl reg, N (N>=5): cdqe/movsxd, alloc, 潜在溢出.

    即使无法跨函数追踪具体值, shl + cdqe + alloc 的组合本身是溢出信号.
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
        call_addr = _addr(addrs, call_idx)
        multiplier = 1 << shift_bits

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
    """mov WORD PTR [rbp±N], near_max: movzx, 算术, cdqe, alloc.

    WORD 存储 + movzx + 算术 + alloc 的组合暴露了程序员的 16-bit 回绕意图.
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
            m = _re.match(
                r'movzx\s+(\w+),\s*word\s+ptr\s+\[rbp\s*([+\-])\s*'
                r'(0x[0-9a-f]+|\d+)\]', il)
            if not m:
                continue
            sign = 1 if m.group(2) == '+' else -1
            load_off = sign * int(m.group(3), 16 if '0x' in m.group(3) else 10)
            if load_off != offset:
                continue

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
            call_addr = _addr(addrs, call_idx)
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


# - 主入口 -

class IntOverflowDetector:
    """整数溢出检测器 - x86-64 objdump 静态分析.

    八模式检测管线:
      LARGE_IMM64: movabs rax, >2^32, alloc
      TRUNCATION: 64-bit, mov [mem], eax, malloc
      SIGNED_IDX: INT_MAX + const, signed overflow
      SUSPICIOUS_SIZE: 0xFF... 直接或栈传参
      MUL_OVERFLOW: imul 结果, alloc
      16-bit wraparound: add + mov WORD PTR [ax], alloc
      SHL_OVERFLOW: shl N>=5, cdqe, alloc
      16-bit intent: WORD near 0xFFFF, movzx, arithmetic, alloc
      32-bit ADD wraparound: DWORD params, LEA offset + memcpy size, wrap
    """

    def __init__(self):
        self._stack_vals: Dict[int, int] = {}  # slot_offset, value

    def analyze(self, instructions: List[str],
                function_name: str = "",
                addrs: Optional[List[int]] = None,
                ) -> List[IntOverflowFinding]:
        findings: List[IntOverflowFinding] = []
        self._stack_vals.clear()

        # 第一遍: 收集栈上存储的立即数值 (所有模式共用)
        self._collect_stack_vals(instructions)

        findings += detect_large_imm64(instructions, function_name, addrs)
        findings += detect_truncation(instructions, function_name, addrs)
        findings += detect_suspicious_size(
            instructions, function_name, addrs, self._stack_vals,
            self._find_next_alloc_call)
        findings += detect_signed_idx_overflow(
            instructions, function_name, addrs, self._stack_vals)
        findings += detect_mul_overflow(
            instructions, function_name, addrs, self._stack_vals,
            self._find_next_alloc_call)
        findings += detect_16bit_wraparound(
            instructions, function_name, addrs, self._stack_vals,
            self._find_next_alloc_call)
        findings += detect_32bit_add_wraparound(
            instructions, function_name, addrs, self._stack_vals,
            self._find_next_alloc_call)
        findings += detect_shl_overflow(
            instructions, function_name, addrs,
            self._find_next_alloc_call)
        findings += detect_16bit_overflow_intent(
            instructions, function_name, addrs, self._stack_vals,
            self._find_next_alloc_call)

        findings.sort(key=lambda f: -f.confidence)
        return findings

    def _collect_stack_vals(self, instructions: List[str]) -> None:
        """第一遍扫描: 收集栈上 DWORD/WORD 存储的常量值."""
        for instr in instructions:
            il = instr.strip().lower()
            m = MOV_STACK_DWORD.match(il)
            if m:
                self._stack_vals[self._offset(m.group(1), m.group(2))] = \
                    self._parse_int(m.group(3))
                continue
            m = MOV_STACK_WORD.match(il)
            if m:
                self._stack_vals[self._offset(m.group(1), m.group(2))] = \
                    self._parse_int(m.group(3))

    def _read_stack_val(self, instructions: List[str],
                         insn_idx: int) -> Optional[int]:
        """从 mov reg, [rbp±N] 指令中读取对应栈槽值."""
        il = instructions[insn_idx].strip().lower()
        m = MOV_REG_FROM_STACK.match(il)
        if not m:
            return None
        return self._stack_vals.get(
            self._offset(m.group(2), m.group(3)))

    def _find_next_alloc_call(self, instructions: List[str],
                               start_idx: int) -> Optional[Tuple[str, int]]:
        return _find_next_alloc_call(instructions, start_idx)

    def clear(self) -> None:
        """重置内部状态, 准备下一个函数."""
        self._stack_vals.clear()

    @staticmethod
    def _offset(sign_str: str, num_str: str) -> int:
        sign = 1 if sign_str == '+' else -1
        return sign * int(num_str, 16 if '0x' in num_str else 10)

    @staticmethod
    def _parse_int(s: str) -> int:
        return int(s, 16 if '0x' in s else 10)


__all__ = [
    "OverflowType", "IntOverflowFinding", "IntOverflowDetector",
    "detect_large_imm64", "detect_truncation", "detect_suspicious_size",
    "detect_signed_idx_overflow", "detect_mul_overflow",
    "detect_16bit_wraparound", "detect_32bit_add_wraparound",
    "detect_shl_overflow", "detect_16bit_overflow_intent",
]
