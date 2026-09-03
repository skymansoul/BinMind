"""ACFPC 数据层 — 定义链的节点类型与常量.

DefKind 与 DefNode 承载身份键所需的全部元数据: 类型/立即数/寄存器/
栈槽/派生信息/返回值函数名. REG_BITS 覆盖 64/32/16/8 位寄存器宽度,
_BASE_OF 为 32→64 映射, _D32_OF 为 64→32 映射, 用于宽形式互查.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

class DefKind:
    IMM = 'IMM'          # 立即数
    REG = 'REG'          # 寄存器拷贝 (直通)
    SLOT = 'SLOT'        # 栈槽 (spill 读取)
    MEM = 'MEM'          # 全局/间接内存读取
    DERIVED = 'DERIVED'  # 经算术变换, 同源性断裂
    ARG = 'ARG'          # 函数入参寄存器 (无法跟踪来源)
    RETURN = 'RETURN'    # call 返回值 (身份=目标函数)
    UNKNOWN = 'UNKNOWN'


@dataclass
class DefNode:
    """一个数据定义点."""
    kind: str = DefKind.UNKNOWN
    imm: int = 0              # IMM 时的立即数值
    reg: str = ''             # REG 时的源寄存器
    slot: str = ''            # SLOT 时的栈槽名
    insn_idx: int = -1        # 定义指令位置
    derived_op: str = ''      # DERIVED 时的操作描述
    derived_base: str = ''    # DERIVED 时的基身份键
    derived_delta: int = 0    # DERIVED 时的立即数增量
    ret_name: str = ''        # RETURN 时的目标函数名

    def is_concrete(self) -> bool:
        return self.kind == DefKind.IMM

    def describe(self) -> str:
        if self.kind == DefKind.IMM:
            return f'imm({self.imm:#x})'
        if self.kind == DefKind.REG:
            return f'reg({self.reg})'
        if self.kind == DefKind.SLOT:
            return f'slot({self.slot})'
        if self.kind == DefKind.DERIVED:
            return f'derived({self.derived_op})'
        if self.kind == DefKind.RETURN:
            return f'ret({self.ret_name})'
        return self.kind


@dataclass
class CallSnapshot:
    """call 指令处的参数寄存器定义快照."""
    insn_idx: int
    callee: str = ''
    args: Dict[str, DefNode] = field(default_factory=dict)


REG_BITS = {
    'rax': 64, 'eax': 32, 'ax': 16, 'al': 8, 'ah': 8,
    'rbx': 64, 'ebx': 32, 'bx': 16, 'bl': 8, 'bh': 8,
    'rcx': 64, 'ecx': 32, 'cx': 16, 'cl': 8, 'ch': 8,
    'rdx': 64, 'edx': 32, 'dx': 16, 'dl': 8, 'dh': 8,
    'rsi': 64, 'esi': 32, 'si': 16, 'sil': 8,
    'rdi': 64, 'edi': 32, 'di': 16, 'dil': 8,
    'r8': 64, 'r8d': 32, 'r8w': 16, 'r8b': 8,
    'r9': 64, 'r9d': 32, 'r9w': 16, 'r9b': 8,
    'r10': 64, 'r10d': 32, 'r11': 64, 'r11d': 32,
    'r12': 64, 'r12d': 32, 'r13': 64, 'r13d': 32,
    'r14': 64, 'r14d': 32, 'r15': 64, 'r15d': 32,
    'rbp': 64, 'rsp': 64, 'rip': 64,
}
_BASE_OF = {'eax': 'rax', 'ax': 'rax', 'al': 'rax', 'ah': 'rax',
            'ebx': 'rbx', 'bx': 'rbx', 'bl': 'rbx', 'bh': 'rbx',
            'ecx': 'rcx', 'cx': 'rcx', 'cl': 'rcx', 'ch': 'rcx',
            'edx': 'rdx', 'dx': 'rdx', 'dl': 'rdx', 'dh': 'rdx',
            'esi': 'rsi', 'si': 'rsi', 'sil': 'rsi',
            'edi': 'rdi', 'di': 'rdi', 'dil': 'rdi',
            'r8d': 'r8', 'r8w': 'r8', 'r8b': 'r8',
            'r9d': 'r9', 'r9w': 'r9', 'r9b': 'r9'}
_D32_OF = {'rax': 'eax', 'rbx': 'ebx', 'rcx': 'ecx', 'rdx': 'edx',
           'rsi': 'esi', 'rdi': 'edi', 'r8': 'r8d', 'r9': 'r9d'}


def slot_name(operand: str) -> Optional[str]:
    """规范栈槽名: [rbp-0x8] → rbp-8, [rsp+0x10] → rsp+16."""
    op = operand.strip().strip('[]')
    parts = op.split('+') if '+' in op else op.split('-')
    if len(parts) != 2:
        return None
    base = parts[0].strip()
    if base not in ('rbp', 'rsp'):
        return None
    try:
        val = int(parts[1].strip(), 0)
    except ValueError:
        return None
    sign = '+' if '+' in op else '-'
    return f'{base}{sign}{val}'


def parse_int(text: str) -> Optional[int]:
    try:
        return int(text.strip(), 0)
    except ValueError:
        return None

