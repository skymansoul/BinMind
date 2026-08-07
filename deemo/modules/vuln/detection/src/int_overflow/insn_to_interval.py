"""指令→区间映射 — x86指令到区间抽象的解析器.

创建: 2026-06-30
      负责: 寄存器状态管理、立即数解析、寄存器规范化.

决策: 不下沉到 capstone 的 IR — 直接用 mnemonic + op_str 做模式匹配.
      精度足够应对整数溢出检测的主要模式 (mov/movabs/lea/arithmetic/shl).
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

try:
    from .interval_domain import (
        Interval, interval_add, interval_sub, interval_mul,
        interval_shl, interval_and_const,
    )
except ImportError:
    from interval_domain import (  # type: ignore[no-redef]
        Interval, interval_add, interval_sub, interval_mul,
        interval_shl, interval_and_const,
    )


@dataclass
class RegisterState:
    """一条指令处的抽象寄存器状态 — 寄存器名 → 区间."""
    regs: Dict[str, Interval] = field(default_factory=dict)

    def get(self, reg: str) -> Interval:
        return self.regs.get(reg.lower(), Interval.top())

    def set(self, reg: str, iv: Interval) -> None:
        self.regs[reg.lower()] = iv


# x86 算术指令 → 区间操作映射
_ARITH_HANDLERS = {
    'add': lambda a, b: interval_add(a, b),
    'sub': lambda a, b: interval_sub(a, b),
    'mul': lambda a, b: interval_mul(a, b),
    'imul': lambda a, b: interval_mul(a, b),
}

# 通用寄存器名 — 含所有宽度变体
_GPRS = {
    'rax', 'eax', 'ax', 'al', 'ah',
    'rbx', 'ebx', 'bx', 'bl', 'bh',
    'rcx', 'ecx', 'cx', 'cl', 'ch',
    'rdx', 'edx', 'dx', 'dl', 'dh',
    'rsi', 'esi', 'si', 'sil',
    'rdi', 'edi', 'di', 'dil',
    'r8', 'r8d', 'r8w', 'r8b',
    'r9', 'r9d', 'r9w', 'r9b',
    'r10', 'r10d', 'r10w', 'r10b',
    'r11', 'r11d', 'r11w', 'r11b',
    'r12', 'r12d', 'r12w', 'r12b',
    'r13', 'r13d', 'r13w', 'r13b',
    'r14', 'r14d', 'r14w', 'r14b',
    'r15', 'r15d', 'r15w', 'r15b',
    'rbp', 'ebp', 'bp', 'rsp', 'esp', 'sp',
}


def _reg_64bit(r: str) -> str:
    """宽寄存器名 → 64位形式: eax→rax, ax→rax."""
    m = {
        'eax': 'rax', 'ax': 'rax', 'al': 'rax', 'ah': 'rax',
        'ebx': 'rbx', 'bx': 'rbx', 'bl': 'rbx', 'bh': 'rbx',
        'ecx': 'rcx', 'cx': 'rcx', 'cl': 'rcx', 'ch': 'rcx',
        'edx': 'rdx', 'dx': 'rdx', 'dl': 'rdx', 'dh': 'rdx',
        'esi': 'rsi', 'si': 'rsi', 'sil': 'rsi',
        'edi': 'rdi', 'di': 'rdi', 'dil': 'rdi',
        'ebp': 'rbp', 'bp': 'rbp',
        'esp': 'rsp', 'sp': 'rsp',
    }
    return m.get(r, r)


def _parse_immediate(op_str: str) -> Optional[int]:
    """从操作数字符串中解析立即数."""
    m = re.search(r'(0x[0-9a-fA-F]+|\d+)', op_str)
    if m:
        return int(m.group(1), 0)
    return None


class InsnToInterval:
    """指令→区间状态转换器 — 对每条 x86 指令更新抽象寄存器状态.

    每调用一次 transfer(), 更新内部 _state 并返回变更摘要.
    """

    def __init__(self):
        self._state = RegisterState()
        self._alloc_regs: Set[str] = set()

    @property
    def state(self) -> RegisterState:
        return self._state

    def transfer(self, mnemonic: str, op_str: str,
                 insn_addr: int = 0,
                 mark_alloc_args: bool = False) -> Optional[str]:
        """处理单条指令, 返回改变的目的寄存器 (或 None)."""
        mnem = mnemonic.lower()
        ops = [o.strip() for o in op_str.split(',')]

        # mov reg, imm
        if mnem == 'mov' and len(ops) == 2:
            dst = ops[0]
            imm = _parse_immediate(ops[1])
            if imm is not None:
                self._state.set(dst, Interval.const(imm))
                return dst
            elif ops[1].lower() in _GPRS:
                self._state.set(dst, self._state.get(ops[1]))
                return dst

        # movabs rax, 0x...
        elif mnem == 'movabs' and len(ops) == 2:
            dst = ops[0]
            imm = _parse_immediate(ops[1])
            if imm is not None:
                self._state.set(dst, Interval.const(imm))
                return dst

        # lea reg, [base + offset]
        elif mnem == 'lea' and len(ops) == 2:
            dst = ops[0]
            m = re.search(r'\[(\w+)\s*\+\s*(0x[0-9a-fA-F]+|\d+)\]',
                         ops[1].lower())
            if m:
                base = m.group(1)
                off = int(m.group(2), 0)
                base_iv = self._state.get(base)
                if not base_iv.is_top:
                    self._state.set(dst, Interval(lo=base_iv.lo + off,
                                                  hi=base_iv.hi + off))
                    return dst

        # add/sub/mul/imul
        elif mnem in _ARITH_HANDLERS and len(ops) == 2:
            dst = ops[0]
            left = self._state.get(dst)
            if _parse_immediate(ops[1]) is not None:
                right = Interval.const(_parse_immediate(ops[1]))
            elif ops[1].lower() in _GPRS:
                right = self._state.get(ops[1])
            else:
                right = Interval.top()
            result = _ARITH_HANDLERS[mnem](left, right)
            self._state.set(dst, result)
            return dst

        # xor reg, reg → reg := 0
        elif mnem == 'xor' and len(ops) == 2:
            if ops[0].lower() == ops[1].lower():
                self._state.set(ops[0], Interval.const(0))
                return ops[0]

        # shl dst, imm
        elif mnem in ('shl', 'sal') and len(ops) == 2:
            dst = ops[0]
            shift = _parse_immediate(ops[1])
            if shift is not None:
                src_iv = self._state.get(dst)
                result = interval_shl(src_iv, shift)
                self._state.set(dst, result)
                return dst

        # and reg, imm
        elif mnem == 'and' and len(ops) == 2:
            dst = ops[0]
            mask = _parse_immediate(ops[1])
            if mask is not None:
                src_iv = self._state.get(dst)
                result = interval_and_const(src_iv, mask)
                self._state.set(dst, result)
                return dst

        # 标记 alloc 参数寄存器
        if mark_alloc_args and mnem == 'call':
            call_target = ops[0].lower() if ops else ''
            if any(a in call_target for a in
                   ('malloc', 'calloc', 'realloc', '_Znwm')):
                self._alloc_regs.add('rcx')
                self._alloc_regs.add('rdi')
                self._alloc_regs.add('ecx')
                self._alloc_regs.add('edi')

        return None

    def is_alloc_reg(self, reg: str) -> bool:
        return reg.lower() in self._alloc_regs

    def clear(self) -> None:
        self._state = RegisterState()
        self._alloc_regs.clear()
