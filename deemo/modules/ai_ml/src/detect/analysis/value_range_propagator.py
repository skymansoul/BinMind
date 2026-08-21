# 值范围传播器-在基本块内沿def-use链传播数值区间
# 与buffer_size_infer.py的区别:
#   buffer_size_infer: 只在call附近5条指令内查找立即数常量
#   本模块: 追踪完整的寄存器MOV链、算术运算的区间效应、跨基本块的保守传播
#
# 核心创新: 不依赖常量折叠-即使参数来自函数输入或非确定性源，
# 也通过区间收缩(如cmp约束)推导尽可能紧的范围
#
# 理论依据:
#   - 区间抽象解释
#   - 条件合并约束求解
# 本实现做的是"反向简化"而非完整抽象解释，旨在O(n)时间内得出有用结论

from __future__ import annotations

import re
import logging
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# x86-64寄存器宽度归一化: 32位写零扩展到64位, eax→rax
_REG_ALIAS = {'eax':'rax','ebx':'rbx','ecx':'rcx','edx':'rdx','esi':'rsi','edi':'rdi',
              'r8d':'r8','r9d':'r9','r10d':'r10','r11d':'r11'}
def _norm_reg(r: str) -> str:
    clean = r.lstrip('%')
    return _REG_ALIAS.get(clean, clean)


@dataclass
class ValueRange:
    """数值的区间表示 [lo, hi]-闭区间"""
    lo: int
    hi: int

    @staticmethod
    def exact(v: int) -> 'ValueRange':
        return ValueRange(v, v)

    @staticmethod
    def unknown() -> 'ValueRange':
        return ValueRange(0, 0xFFFFFFFF)

    @staticmethod
    def at_least(v: int) -> 'ValueRange':
        return ValueRange(v, 0xFFFFFFFF)

    @staticmethod
    def at_most(v: int) -> 'ValueRange':
        return ValueRange(0, v)

    @property
    def is_exact(self) -> bool:
        return self.lo == self.hi

    @property
    def is_unknown(self) -> bool:
        return self.lo == 0 and self.hi >= 0xFFFFFFFF

    def intersect(self, other: 'ValueRange') -> 'ValueRange':
        return ValueRange(max(self.lo, other.lo), min(self.hi, other.hi))

    def add(self, n: int) -> 'ValueRange':
        lo = self.lo + n if self.lo + n >= 0 else 0
        hi = self.hi + n if self.hi + n >= 0 else 0xFFFFFFFF
        return ValueRange(lo, min(hi, 0xFFFFFFFF))

    def mul(self, n: int) -> 'ValueRange':
        if n == 0:
            return ValueRange.exact(0)
        lo = self.lo * n if self.lo * n >= 0 else 0
        hi = self.hi * n if self.hi * n >= 0 else 0xFFFFFFFF
        if lo > hi:
            lo, hi = hi, lo
        return ValueRange(lo, min(hi, 0xFFFFFFFF))

    def __repr__(self) -> str:
        if self.is_exact:
            return f"[{self.lo}]"
        return f"[{self.lo},{self.hi}]"


@dataclass
class DefUseNode:
    """def-use链中的一个节点-记录哪个寄存器在哪个索引被定义"""
    reg: str
    instr_idx: int
    value: ValueRange
    source: str  # "immediate" | "memory_load" | "function_arg" | "arithmetic"


class ValueRangePropagator:
    """值范围传播器-指令序列中追踪寄存器值区间, 双ABI语法"""

    _PARAM_REGS = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9',
                   'edi', 'esi', 'edx', 'ecx', 'r8d', 'r9d']
    _NON_REG = {'qword', 'dword', 'word', 'byte', 'ptr', 'xmmword'}

    def __init__(self, max_steps: int = 30):
        self._max_steps = max_steps

    @staticmethod
    def _is_intel(instructions, idx):
        """检测Intel语法——无%寄存器前缀"""
        for j in range(max(0, idx - 5), min(len(instructions), idx + 2)):
            instr = instructions[j].strip().lower()
            if instr and not instr.startswith(';') and '%' in instr:
                return False
        return True

    @staticmethod
    def _parse_int(s):
        return int(s, 16) if '0x' in s.lower() else int(s)

    def _match_imm_op(self, instr, current_reg, mnemonic):
        """双ABI立即数运算: add/sub/imul/shl/cmp——AT&T: op $imm,%reg, Intel: op reg,imm"""
        m = re.match(rf'{mnemonic}\s+\$?(0x[0-9a-f]+|\d+),\s*%?(\w+)', instr)
        if m and _norm_reg(m.group(2)) == current_reg:
            return self._parse_int(m.group(1))
        m = re.match(rf'{mnemonic}\s+%?(\w+),\s*(0x[0-9a-f]+|\d+)', instr)
        if m and _norm_reg(m.group(1)) == current_reg:
            return self._parse_int(m.group(2))
        return None

    def trace_backward(self, start_idx, target_reg, instructions):
        """从start_idx向函数开头追踪target_reg的值来源——双ABI语法
        立即数→exact / 寄存器链→继续追踪 / 内存加载→unknown / call→停止"""
        current_reg = target_reg.lower()
        cmp_lo, cmp_hi = None, None

        for i in range(start_idx, max(-1, start_idx - self._max_steps), -1):
            if i < 0 or i >= len(instructions):
                break
            instr = instructions[i].strip().lower()
            if not instr or instr.startswith((';', '.')):
                continue

            # 立即数赋值——双ABI: AT&T mov $imm,%reg / Intel mov reg,imm
            m = re.match(r'mov\s+\$?(0x[0-9a-f]+|\d+),\s*%?(\w+)', instr)
            if m and _norm_reg(m.group(2)) == current_reg:
                return self._apply_cmp(ValueRange.exact(self._parse_int(m.group(1))), cmp_lo, cmp_hi)
            m = re.match(r'mov\s+%?(\w+),\s*(0x[0-9a-f]+|\d+)', instr)
            if m and _norm_reg(m.group(1)) == current_reg and m.group(1) not in self._NON_REG:
                return self._apply_cmp(ValueRange.exact(self._parse_int(m.group(2))), cmp_lo, cmp_hi)

            # 寄存器间mov——双ABI: group1/group2角色取决于语法
            m = re.match(r'mov\s+%?(\w+),\s*%?(\w+)', instr)
            if m:
                r1, r2 = _norm_reg(m.group(1)), _norm_reg(m.group(2))
                # AT&T: mov %src,%dst → r1=src,r2=dst / Intel: mov dst,src → r1=dst,r2=src
                if r2 == current_reg and r1 not in self._NON_REG and not r1[0].isdigit():
                    current_reg = r1; continue  # AT&T: 源=r1
                if r1 == current_reg and r2 not in self._NON_REG and not r2[0].isdigit():
                    current_reg = r2; continue  # Intel: 源=r2

            # 内存加载——双ABI: AT&T mov (...),%reg / Intel mov reg,[...]
            if re.search(rf'mov\s+.*[\[(].*[\]\)]\s*,\s*%?{current_reg}\b', instr):
                return self._apply_cmp(ValueRange.unknown(), cmp_lo, cmp_hi)
            if re.search(rf'mov\s+%?{current_reg}\s*,\s*(?:\w+\s+ptr\s+)?\[', instr):
                return self._apply_cmp(ValueRange.unknown(), cmp_lo, cmp_hi)

            # lea——双ABI: AT&T lea offset(%base),%dst / Intel lea dst,[base+offset]
            m = re.match(r'lea\s+([+-]?(?:0x[0-9a-f]+|\d+))\s*\(\s*%?(\w+)\s*\)\s*,\s*%?(\w+)', instr)
            if m and _norm_reg(m.group(3)) == current_reg and _norm_reg(m.group(2)) not in ('rip','eip'):
                off = self._parse_int(m.group(1)); base = _norm_reg(m.group(2))
                inner = self.trace_backward(i - 1, base, instructions)
                return self._apply_cmp(ValueRange(inner.lo + off, inner.hi + off), cmp_lo, cmp_hi)
            m = re.match(rf'lea\s+%?{current_reg}\s*,\s*\[(\w+)(?:[+\-]\w+)?\]', instr)
            if m and m.group(1) not in ('rip','eip'):
                inner = self.trace_backward(i - 1, _norm_reg(m.group(1)), instructions)
                return self._apply_cmp(inner, cmp_lo, cmp_hi)

            # 算术运算——双ABI: _match_imm_op统一处理
            n = self._match_imm_op(instr, current_reg, 'add')
            if n is not None:
                inner = self.trace_backward(i - 1, current_reg, instructions)
                return self._apply_cmp(inner.add(n), cmp_lo, cmp_hi)
            n = self._match_imm_op(instr, current_reg, 'sub')
            if n is not None:
                inner = self.trace_backward(i - 1, current_reg, instructions)
                return self._apply_cmp(inner.add(-n), cmp_lo, cmp_hi)
            n = self._match_imm_op(instr, current_reg, 'imul')
            if n is not None:
                inner = self.trace_backward(i - 1, current_reg, instructions)
                return self._apply_cmp(inner.mul(n), cmp_lo, cmp_hi)
            n = self._match_imm_op(instr, current_reg, 'shl')
            if n is not None:
                inner = self.trace_backward(i - 1, current_reg, instructions)
                return self._apply_cmp(inner.mul(1 << n), cmp_lo, cmp_hi)

            # xor reg,reg → exact(0)——双ABI通用
            m = re.match(r'xor\s+%?(\w+),\s*%?\1\b', instr)
            if m and _norm_reg(m.group(1)) == current_reg:
                return ValueRange.exact(0)

            # cmp——双ABI: _match_imm_op统一处理
            n = self._match_imm_op(instr, current_reg, 'cmp')
            if n is not None and n < 4096:
                cmp_hi = n
                continue

            # call→跨函数边界, 保守停止
            if 'call' in instr:
                return self._apply_cmp(ValueRange.unknown(), cmp_lo, cmp_hi)

        return self._apply_cmp(ValueRange.unknown(), cmp_lo, cmp_hi)

    def trace_forward_from_param(self, param_reg, instructions, start_idx=0):
        """从函数参数向前追踪——判断参数是否流向大小计算, 双ABI"""
        current_reg = param_reg.lower()
        current_range = ValueRange.unknown()
        for i in range(start_idx, min(start_idx + self._max_steps, len(instructions))):
            instr = instructions[i].strip().lower()
            if not instr or instr.startswith(';'):
                continue
            # 寄存器间mov——双ABI
            m = re.match(r'mov\s+%?(\w+),\s*%?(\w+)', instr)
            if m:
                r1, r2 = _norm_reg(m.group(1)), _norm_reg(m.group(2))
                if r2 == current_reg and r1 not in self._NON_REG and not r1[0].isdigit():
                    current_reg = r1; continue  # AT&T
                if r1 == current_reg and r2 not in self._NON_REG and not r2[0].isdigit():
                    current_reg = r2; continue  # Intel
            # add——双ABI
            n = self._match_imm_op(instr, current_reg, 'add')
            if n is not None:
                current_range = current_range.add(n); continue
            # 立即数覆盖——双ABI
            m = re.match(r'mov\s+\$?(0x[0-9a-f]+|\d+),\s*%?(\w+)', instr)
            if m and _norm_reg(m.group(2)) == current_reg:
                current_range = ValueRange.exact(self._parse_int(m.group(1))); continue
            m = re.match(r'mov\s+%?(\w+),\s*(0x[0-9a-f]+|\d+)', instr)
            if m and _norm_reg(m.group(1)) == current_reg and m.group(1) not in self._NON_REG:
                current_range = ValueRange.exact(self._parse_int(m.group(2))); continue
            if 'call' in instr and current_reg in ('rdi','rsi','rdx','edi','esi','edx'):
                break
        return current_range

    @staticmethod
    def _apply_cmp(r, lo, hi):
        """对值范围应用cmp指令推导的约束"""
        if lo is not None:
            r = ValueRange(max(r.lo, lo), r.hi)
        if hi is not None:
            r = ValueRange(r.lo, min(r.hi, hi))
        return r
