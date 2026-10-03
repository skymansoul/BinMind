# 缓冲区大小推断-基于抽象值区间的堆/栈溢出验证
# 从malloc/memcpy参数推断分配大小和拷贝长度，比较两者检测溢出
# 理论依据: 区间抽象解释思想

from __future__ import annotations

import re
import logging
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class OverflowVerdict(Enum):
    SAFE = 'safe'
    POTENTIAL_OVERFLOW = 'potential_overflow'
    CONFIRMED_OVERFLOW = 'confirmed_overflow'
    UNKNOWN = 'unknown'


@dataclass
class IntervalValue:
    """抽象值区间 [lo, hi]-表示一个值可能的最小/最大范围"""
    lo: int
    hi: int

    @staticmethod
    def exact(v: int) -> 'IntervalValue':
        return IntervalValue(v, v)

    @staticmethod
    def unknown() -> 'IntervalValue':
        return IntervalValue(0, 0xFFFFFFFF)

    @staticmethod
    def at_least(v: int) -> 'IntervalValue':
        return IntervalValue(v, 0xFFFFFFFF)

    def is_exact(self) -> bool:
        return self.lo == self.hi


@dataclass
class BufferAlloc:
    """缓冲区分配信息"""
    alloc_addr: int
    alloc_func: str              # malloc/calloc/alloca
    size: IntervalValue          # 推断的分配大小
    buf_ptr_reg: str             # 指向缓冲区的寄存器


@dataclass
class BufferOverflowVerdict:
    call_addr: int
    copy_func: str               # memcpy/strcpy/sprintf等
    alloc_size: IntervalValue
    copy_size: IntervalValue
    verdict: OverflowVerdict
    evidence: str


class BufferSizeInferer:
    """缓冲区大小推断器-追踪malloc参数和memcpy参数的值。

    追踪策略:
      对malloc(N)和memcpy(dst, src, N)中的N做反向常量传播，
      推断其区间范围。若copy_size.hi > alloc_size.lo + margin(8字节)，
      则报告潜在溢出。
    """

    # 分配函数及其大小参数位置
    _ALLOC_FUNCS = {
        'malloc': 0, 'calloc': 1,  # calloc(nmemb, size), 大小=nmemb*size(简化用size)
        'realloc': 1, 'alloca': 0,
    }
    # 拷贝函数及其大小参数位置
    _COPY_FUNCS = {
        'memcpy': 2, 'memmove': 2, 'strcpy': -1,  # -1表示隐式大小(到null)
        'strncpy': 2, 'sprintf': -1, 'snprintf': 1,
        'read': 2, 'recv': 2, 'fread': 1,
    }

    def __init__(self, safety_margin: int = 8):
        self._margin = safety_margin

    def infer_alloc_size(self,
                          instr_idx: int,
                          instructions: List[str]
                          ) -> IntervalValue:
        """推断malloc调用点的分配大小。

        对 malloc(size_expr) 中的size_expr做反向常量传播。
        """
        if instr_idx <= 0:
            return IntervalValue.unknown()

        # 查找call之前设置参数寄存器的指令
        # x64: rdi = 第一个参数 = size
        for j in range(instr_idx - 1, max(-1, instr_idx - 5), -1):
            instr = instructions[j].strip().lower() if j < len(instructions) else ''
            if not instr:
                continue

            # mov edi/rdi, imm
            m = re.match(r'mov\s+(?:e|r)di,\s*(0x[0-9a-f]+|\d+)', instr)
            if m:
                val = int(m.group(1), 16) if '0x' in m.group(1).lower() else int(m.group(1))
                return IntervalValue.exact(val)

            # mov edi, reg → 不求精确值（寄存器值需跨指令追踪）
            m = re.match(r'mov\s+edi,\s*(\w+)', instr)
            if m:
                return IntervalValue.unknown()

            # imul edi, reg, N → N倍
            m = re.match(r'imul\s+edi,\s*\w+,\s*(\d+)', instr)
            if m:
                return IntervalValue.exact(int(m.group(1)))

        return IntervalValue.unknown()

    def infer_copy_size(self,
                         instr_idx: int,
                         copy_func: str,
                         instructions: List[str]
                         ) -> IntervalValue:
        """推断memcpy等拷贝函数的拷贝长度参数。

        x64: rdx = 第三个参数 = size(memcpy/strncpy)
        x64: rsi = 第二个参数 = size(read/recv)
        """
        param_idx = self._COPY_FUNCS.get(copy_func, 2)
        if param_idx < 0:
            return IntervalValue.unknown()  # 隐式大小

        # 参数寄存器映射: rdi, rsi, rdx, rcx, r8, r9
        param_regs = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9',
                      'edi', 'esi', 'edx', 'ecx', 'r8d', 'r9d']
        target_regs = []
        if param_idx < len(param_regs):
            target_regs = [param_regs[param_idx],
                          param_regs[param_idx + 6]]  # 32-bit variant

        for j in range(instr_idx - 1, max(-1, instr_idx - 6), -1):
            instr = instructions[j].strip().lower() if j < len(instructions) else ''
            if not instr:
                continue

            for reg in target_regs:
                m = re.match(rf'mov\s+{reg},\s*(0x[0-9a-f]+|\d+)', instr)
                if m:
                    val = int(m.group(1), 16) if '0x' in m.group(1).lower() else int(m.group(1))
                    return IntervalValue.exact(val)

        return IntervalValue.unknown()

    def check_overflow(self,
                        alloc_instr_idx: int,
                        alloc_func: str,
                        copy_instr_idx: int,
                        copy_func: str,
                        instructions: List[str],
                        buf_ptr_reg: Optional[str] = None
                        ) -> BufferOverflowVerdict:
        """检查是否存在缓冲区溢出-比较分配大小和拷贝大小。"""
        alloc_size = self.infer_alloc_size(alloc_instr_idx, instructions)
        copy_size = self.infer_copy_size(copy_instr_idx, copy_func, instructions)

        if alloc_size.is_exact() and copy_size.is_exact():
            if copy_size.lo > alloc_size.lo + self._margin:
                return BufferOverflowVerdict(
                    call_addr=copy_instr_idx, copy_func=copy_func,
                    alloc_size=alloc_size, copy_size=copy_size,
                    verdict=OverflowVerdict.CONFIRMED_OVERFLOW,
                    evidence=f"alloc={alloc_size.lo}, copy={copy_size.lo}, overflow by {copy_size.lo - alloc_size.lo}")
            else:
                return BufferOverflowVerdict(
                    call_addr=copy_instr_idx, copy_func=copy_func,
                    alloc_size=alloc_size, copy_size=copy_size,
                    verdict=OverflowVerdict.SAFE,
                    evidence=f"alloc={alloc_size.lo} >= copy={copy_size.lo}")
        elif copy_size.is_exact() and alloc_size.is_exact():
            if copy_size.lo > alloc_size.lo:
                return BufferOverflowVerdict(
                    call_addr=copy_instr_idx, copy_func=copy_func,
                    alloc_size=alloc_size, copy_size=copy_size,
                    verdict=OverflowVerdict.POTENTIAL_OVERFLOW,
                    evidence=f"copy={copy_size.lo} > alloc={alloc_size.lo}, margin={self._margin}")
        elif copy_size.hi > alloc_size.lo + self._margin:
            return BufferOverflowVerdict(
                call_addr=copy_instr_idx, copy_func=copy_func,
                alloc_size=alloc_size, copy_size=copy_size,
                verdict=OverflowVerdict.POTENTIAL_OVERFLOW,
                evidence=f"copy range [{copy_size.lo},{copy_size.hi}] may exceed alloc={alloc_size.lo}")

        return BufferOverflowVerdict(
            call_addr=copy_instr_idx, copy_func=copy_func,
            alloc_size=alloc_size, copy_size=copy_size,
            verdict=OverflowVerdict.UNKNOWN,
            evidence="insufficient constant info to determine size relationship")
