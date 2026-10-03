"""内存访问指令解析器 — .

创建: 2025-03-28
用途: 从汇编指令序列中识别堆分配调用和内存访问,
      提取 base/offset/access_size 用于越界检查。

设计决策:
  - 双语法兼容: 同时支持 Intel (mov QWORD PTR [rax+0x10], rdx)
    和 AT&T (mov %rdx, 0x10(%rax)) 两种汇编语法。
  - 访问大小推断优先级: 显式前缀 (qword/dword/...) > 寄存器大小 > 默认4字节。
    默认 DWORD 对 x86_64 堆访问偏保守, 但对多数 memcpy/memset 场景够用。
"""
import re
from typing import Dict, List, Optional, Tuple

from .interval_domain import SInterval


def identify_alloc_sites(instructions: List[str]) -> List[Tuple[int, str]]:
    """识别所有堆分配函数调用点, 返回 [(指令位置, 函数名), ...]."""
    sites = []
    for i, instr in enumerate(instructions):
        il = instr.strip().lower()
        for func in ('malloc', 'calloc', 'realloc',
                     '_malloc', 'kmalloc', 'kzalloc'):
            if func in il and ('call' in il or 'bl' in il[:4]):
                sites.append((i, func))
                break
        # PLT 跳转: jmp *malloc@GOTPCREL
        if 'malloc@' in il or 'calloc@' in il:
            for func in ('malloc', 'calloc', 'realloc'):
                if func in il:
                    sites.append((i, func))
                    break
    return sites


def parse_memory_access(idx: int, instr: str, fn: str,
                        mem_write_re: 're.Pattern',
                        mem_read_re: 're.Pattern') -> Optional[dict]:
    """解析内存操作指令, 返回 {'base','offset','access_size','is_write'} 或 None."""
    # 写操作: mov [base+offset], src
    m = mem_write_re.search(instr)
    if m:
        target = m.group(1)
        base, offset = split_mem_operand(target)
        return {
            'insn_addr': idx, 'base_ptr': base, 'offset_expr': offset,
            'access_size': infer_access_size(instr),
            'function_name': fn, 'is_write': True}

    # 读操作: mov dst, [base+offset]
    m = mem_read_re.search(instr)
    if m:
        source = m.group(2)
        base, offset = split_mem_operand(source)
        return {
            'insn_addr': idx, 'base_ptr': base, 'offset_expr': offset,
            'access_size': infer_access_size(instr),
            'function_name': fn, 'is_write': False}

    return None


def split_mem_operand(op: str) -> Tuple[str, str]:
    """拆分内存操作数 [base+offset] → (base, offset)."""
    op = op.strip()
    if '+' in op:
        parts = op.split('+', 1)
        return (parts[0].strip(),
                parts[1].split(']')[0].strip() if ']' in parts[1]
                else parts[1].strip())
    if '-' in op and not op.startswith('-'):
        parts = op.split('-', 1)
        return (parts[0].strip(),
                '-' + parts[1].split(']')[0].strip() if ']' in parts[1]
                else '-' + parts[1].strip())
    return op, '0x0'


def infer_access_size(instr: str) -> int:
    """从指令文本推断内存访问大小 (字节).

    优先级: 显式大小前缀 > 寄存器宽度 > 默认4.
    """
    il = instr.lower()
    if 'qword' in il or 'movsxd' in il:
        return 8
    if 'dword' in il:
        return 4
    if 'word' in il:
        return 2
    if 'byte' in il:
        return 1
    # 从目标寄存器推断
    if any(r in il for r in ('rax,', 'rbx,', 'rcx,', 'rdx,')):
        return 8
    return 4


def find_nearest_alloc(access_idx: int,
                       sites: Dict[int, 'MallocSite']) -> Optional[int]:
    """找到访问指令之前最近的分配点地址."""
    candidates = [addr for addr in sites if addr < access_idx]
    return max(candidates) if candidates else None


def parse_offset(expr: str) -> int:
    """解析偏移表达式为整数."""
    expr = expr.strip().replace('*', '')
    try:
        return int(expr, 0)
    except ValueError:
        return 0


def build_mem_regexes():
    """构建 Intel 语法内存操作正则 (写/读)."""
    mem_write_re = re.compile(
        r'mov\s+(?:(?:qword|dword|word|byte)\s+ptr\s+)?'
        r'\[([^\]]+)\],\s*(\S+)',
        re.IGNORECASE)
    mem_read_re = re.compile(
        r'mov\s+(\S+),\s*(?:(?:qword|dword|word|byte)\s+ptr\s+)?'
        r'\[([^\]]+)\]',
        re.IGNORECASE)
    return mem_write_re, mem_read_re


# 函数调用型内存写入检测
# 为什么需要: memcpy(buffer, src, 128) 这种溢出不会产生 mov [reg+128], val
# 指令, 而是通过 call memcpy 隐式写入。必须单独追踪函数调用参数。

# 常见的内存写入函数及其在 MS x64 / System V 下的目标/大小参数索引
_MEM_WRITE_FUNCS: Dict[str, Dict[str, int]] = {
    # func_name: {'dest_idx': N, 'size_idx': M}  (0-based arg index)
    'memcpy':     {'dest_idx': 0, 'size_idx': 2},
    'memset':     {'dest_idx': 0, 'size_idx': 2},
    '__memcpy_chk': {'dest_idx': 0, 'size_idx': 2},
    '__memset_chk': {'dest_idx': 0, 'size_idx': 2},
    'memmove':    {'dest_idx': 0, 'size_idx': 2},
    'strncpy':    {'dest_idx': 0, 'size_idx': 2},
    'strcpy':     {'dest_idx': 0, 'size_idx': -1},   # 隐式 strlen, 无显式 size
    'strcat':     {'dest_idx': 0, 'size_idx': -1},
    'snprintf':   {'dest_idx': 0, 'size_idx': 1},
    'read':       {'dest_idx': 1, 'size_idx': 2},
    'fread':      {'dest_idx': 0, 'size_idx': 1},
    'fgets':      {'dest_idx': 0, 'size_idx': 1},
    'recv':       {'dest_idx': 1, 'size_idx': 2},
    'recvfrom':   {'dest_idx': 1, 'size_idx': 2},
}

# MS x64 调用约定: arg0=rcx, arg1=rdx, arg2=r8, arg3=r9
_MS64_ARG_REGS = ['rcx', 'rdx', 'r8', 'r9']
# System V: arg0=rdi, arg1=rsi, arg2=rdx, arg3=rcx, arg4=r8, arg5=r9
_SYSV_ARG_REGS = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']

# 32-bit 别名 → 64-bit (方便匹配 mov ecx, 0x40)
_ARG_REG_ALIASES: Dict[str, str] = {
    'ecx': 'rcx', 'edx': 'rdx', 'r8d': 'r8', 'r9d': 'r9',
    'edi': 'rdi', 'esi': 'rsi',
}


def _canon_reg(r: str) -> str:
    return _ARG_REG_ALIASES.get(r.lower(), r.lower())


def identify_mem_write_calls(instructions: List[str]) -> List[Tuple[int, str]]:
    """识别所有内存写入函数调用点, 返回 [(指令位置, 函数名), ...]."""
    sites = []
    for i, instr in enumerate(instructions):
        il = instr.strip().lower()
        for func in _MEM_WRITE_FUNCS:
            if func in il and 'call' in il:
                sites.append((i, func))
                break
        # PLT 跳转
        for func in _MEM_WRITE_FUNCS:
            if f'{func}@' in il:
                sites.append((i, func))
                break
    return sites


def get_call_arg_reg(func_name: str, arg_idx: int,
                     convention: str = 'ms64') -> Optional[str]:
    """返回指定函数的第 arg_idx 个参数在调用约定下的寄存器名."""
    arg_regs = _MS64_ARG_REGS if convention == 'ms64' else _SYSV_ARG_REGS
    if 0 <= arg_idx < len(arg_regs):
        return arg_regs[arg_idx]
    return None


def trace_call_arg_value(instructions: List[str], call_idx: int,
                         target_reg: str) -> Tuple[bool, int, str]:
    """从 call 指令向前 (后向) 追踪参数寄存器的常量值.

    追踪 mov reg, const / mov reg, [rbp±N] → 进一步追踪栈槽来源.
    返回 (known, value, source_desc).

    为什么用后向追踪: call 指令前的参数准备通常是 call 前最后几条指令,
    追踪深度浅 (通常 ≤5 条), 比前向追踪高效得多.
    """
    canon_target = _canon_reg(target_reg)
    # 也尝试 32-bit 别名
    aliases = {canon_target}
    for k, v in _ARG_REG_ALIASES.items():
        if v == canon_target:
            aliases.add(k)

    # 栈槽位记录: 扫描 call 前指令, 记录栈溢出
    stack_slots: Dict[str, str] = {}  # offset_str → reg_name
    for i in range(max(0, call_idx - 20), call_idx):
        il = instructions[i].strip().lower()
        # mov [rbp±N], reg
        m = re.match(
            r'mov\s+(?:qword\s+ptr\s+)?\[rbp\s*([+\-])\s*(0x[0-9a-f]+|\d+)\],\s*(\w+)',
            il, re.I)
        if m:
            sign = 1 if m.group(1) == '+' else -1
            slot = sign * int(m.group(2), 16 if '0x' in m.group(2) else 10)
            stack_slots[str(slot)] = _canon_reg(m.group(3))

    for i in range(call_idx - 1, max(-1, call_idx - 20), -1):
        il = instructions[i].strip().lower()
        if not il or il.startswith(';'):
            continue
        if 'call' in il:
            break  # 遇到前一个 call → 停止

        # mov target_reg, imm
        for alias in aliases:
            m = re.match(r'mov\s+' + re.escape(alias) +
                         r'\s*,\s*(0x[0-9a-f]+|\d+)\s*$', il, re.I)
            if m:
                v = int(m.group(1), 16 if '0x' in m.group(1) else 10)
                return (True, v, f'const:{v}')

        # mov target_reg, other_reg → 继续追踪 other_reg
        for alias in aliases:
            m = re.match(r'mov\s+' + re.escape(alias) +
                         r'\s*,\s*(\w+)\s*$', il, re.I)
            if m:
                src = _canon_reg(m.group(1))
                # 检查 src 是否来自栈槽 (mov reg, [rbp±N])
                # 向后查: 是否在此之前有 mov [rbp±N], rax (malloc retval)
                # 这需要跨指令追踪, 简化处理: 直接递归追踪 src
                sub_known, sub_val, sub_desc = trace_call_arg_value(
                    instructions, i, src)
                if sub_known:
                    return (True, sub_val, f'{sub_desc}→{target_reg}')
                # 否则视为未知 (如 rax=TOP)
                return (False, 0, f'{target_reg}=unknown({src})')

        # mov target_reg, [rbp±N] → 查栈槽表
        for alias in aliases:
            m = re.match(
                r'mov\s+' + re.escape(alias) +
                r'\s*,\s*(?:qword\s+ptr\s+)?\[rbp\s*([+\-])\s*(0x[0-9a-f]+|\d+)\]',
                il, re.I)
            if m:
                sign = 1 if m.group(1) == '+' else -1
                slot = sign * int(m.group(2), 16 if '0x' in m.group(2) else 10)
                slot_key = str(slot)
                if slot_key in stack_slots:
                    spilled = stack_slots[slot_key]
                    # 栈槽内容来自 spilled_reg → 继续追踪
                    sub_known, sub_val, sub_desc = trace_call_arg_value(
                        instructions, i, spilled)
                    if sub_known:
                        return (True, sub_val,
                                f'stack:{slot_key}({spilled})→{target_reg}')
                return (False, 0, f'{target_reg}=stack[{slot_key}]')

    return (False, 0, f'{target_reg}=unknown')
