# coding: utf-8
# 创建: 2026-06-29  |  指令解析工具
# 修改: 2026-06-29  |  审计后补充文件头与错误处理
#
"""
DABSS指令解析工具——反汇编行解析、寄存器提取、约束识别。

从反汇编文本行中提取地址/助记符/操作数，识别约束操作，
为DataFlowSlicer提供结构化的指令表示。
"""

import re
from typing import Dict, List, Optional, Tuple, Set


def parse_insn(insn_str: str, arch: str = "x86_64") -> Tuple[int, str, List[str]]:
    """解析单行反汇编——返回(地址, 助记符, 操作数列表)。

    支持格式:
      "0x401000: mov rax, [rbp-0x8]"
      "0x401000: call memcpy@plt"
      "401000: push rbp"
    """
    parts = insn_str.strip().split(None, 1)
    if len(parts) < 2:
        return 0, '', []
    addr_str = parts[0].rstrip(':')
    try:
        addr = int(addr_str, 16)
    except ValueError:
        return 0, '', []
    rest = parts[1].strip()
    if ' ' in rest:
        mnem, ops_str = rest.split(None, 1)
        ops = [o.strip() for o in ops_str.split(',')]
    else:
        mnem, ops = rest, []
    return addr, mnem.lower(), ops


def extract_reg(operand: str) -> str:
    """从操作数提取基寄存器——去除偏移/缩放/段前缀。

    例: '[rbp-0x8]' → '', 'rax+8' → 'rax', 'eax' → 'eax'
    """
    op = operand.strip()
    if op.startswith('[') or op.startswith('*'):
        return ''
    if op.startswith('0x') or op.startswith('-') or op.isdigit():
        return ''
    for sep in ('+', '-', '*'):
        if sep in op:
            op = op.split(sep)[0]
    return op.strip()


def get_def_regs(mnem: str, ops: List[str]) -> Set[str]:
    """获取指令定义的寄存器集合——写入目标寄存器。

    不跟踪内存写入(mov [mem], reg→无寄存器定义)。
    """
    defs = set()
    m = mnem.lower()
    if ops and m not in ('cmp', 'test', 'jmp', 'je', 'jne', 'jg', 'jl',
                          'jge', 'jle', 'ja', 'jb', 'call', 'ret'):
        reg = extract_reg(ops[0])
        if reg:
            defs.add(reg)
    if m == 'pop' and ops:
        reg = extract_reg(ops[0])
        if reg:
            defs.add(reg)
    # lea: 目标寄存器一定被定义
    if m == 'lea' and ops:
        reg = extract_reg(ops[0])
        if reg:
            defs.add(reg)
    return defs


def parse_constraint_value(mnem: str, ops: List[str]) -> Tuple[str, int]:
    """解析比较指令的约束值——返回(操作符, 立即数)。

    例: "cmp eax, 0x100" → ("cmp", 256)
    注意: 操作符的实际方向(上界/下界)取决于后续条件跳转——
    此处保守提取数值，方向在BufferSlice汇总时补充。
    """
    if len(ops) < 2:
        return '', 0
    try:
        val = int(ops[1], 16) if '0x' in ops[1].lower() else int(ops[1])
        return 'cmp', val
    except ValueError:
        return '', 0


def infer_buffer_capacity(bounds: List[Tuple[str, int]],
                            size_operand: str) -> int:
    """从边界约束推断缓冲区容量(字节)。

    启发式优先级:
      1. size_operand是立即数→直接使用
      2. 边界中的最小上界→保守估计
      3. 无信息→0(标记为未知容量)
    """
    if size_operand:
        try:
            return int(size_operand, 16) if '0x' in size_operand else int(size_operand)
        except ValueError:
            pass
    uppers = [v for op, v in bounds if op in ('le', 'lt', 'cmp')]
    return min(uppers) if uppers else 0


# 敏感操作——DataFlowSlicer的sink目标
SINK_MNEMONICS = {
    'call': {'memcpy', 'strcpy', 'strncpy', 'strcat', 'strncat',
             'sprintf', 'snprintf', 'memmove', 'memset',
             'read', 'recv', 'fread', 'fgets', 'gets',
             'malloc', 'calloc', 'realloc', 'alloca',
             'mmap', 'mprotect'},
    'any': {'rep movs', 'rep stos'},
}

# 外部输入指示器——切片起点标记
SOURCE_INDICATORS = {
    'reg': {'rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9', 'edi', 'esi', 'edx',
            'ecx', 'r0', 'r1', 'r2', 'r3'},
    'mnem': {'mov', 'ldr', 'pop', 'ret'},
}


__all__ = [
    "parse_insn",
    "extract_reg",
    "get_def_regs",
    "parse_constraint_value",
    "infer_buffer_capacity",
    "SINK_MNEMONICS",
    "SOURCE_INDICATORS",
]
