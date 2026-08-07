"""跨步区间值集 — 抽象解释域, 在 objdump 反汇编上追踪寄存器的值范围.

创建: 2026-07-05
用途: 为 absint_engine 提供值集抽象, 精确建模 malloc 返回的堆指针
      和对堆指针的偏移计算.

理论依据:
  Balakrishnan & Reps "Analyzing Memory Accesses in x86 Executables"
  — strided interval [lo, hi] + stride s, s=0 为精确值, s≠0 为对齐/数组步长.
"""

from dataclasses import dataclass, field
from typing import Dict


@dataclass
class StridedValue:
    """值集: strided interval [lo, hi] stride s.
    s=0 → 精确值 lo
    is_top → 完全未知
    is_heap_ptr → 指向堆内存 (携带 alloc_addr)
    """
    lo: int = 0
    hi: int = 0
    stride: int = 0
    is_top: bool = False
    is_heap_ptr: bool = False
    alloc_addr: int = 0
    alloc_size: int = 0

    @staticmethod
    def exact(v: int) -> 'StridedValue':
        return StridedValue(lo=v, hi=v, stride=0)

    @staticmethod
    def unknown() -> 'StridedValue':
        return StridedValue(is_top=True)

    @staticmethod
    def heap_ptr(alloc_addr: int, alloc_size: int) -> 'StridedValue':
        return StridedValue(lo=alloc_addr, hi=alloc_addr, stride=16,
                           is_heap_ptr=True, alloc_addr=alloc_addr,
                           alloc_size=alloc_size)

    def is_unknown(self) -> bool:
        return self.is_top and not self.is_heap_ptr

    def is_partial(self) -> bool:
        """堆指针但偏移未知 — is_top 但 is_heap_ptr."""
        return self.is_top and self.is_heap_ptr

    def copy(self) -> 'StridedValue':
        return StridedValue(
            lo=self.lo, hi=self.hi, stride=self.stride,
            is_top=self.is_top, is_heap_ptr=self.is_heap_ptr,
            alloc_addr=self.alloc_addr, alloc_size=self.alloc_size)

    def add_imm(self, delta: int) -> 'StridedValue':
        if self.is_top:
            return self
        return StridedValue(lo=self.lo + delta, hi=self.hi + delta,
                           stride=self.stride, is_heap_ptr=self.is_heap_ptr,
                           alloc_addr=self.alloc_addr,
                           alloc_size=self.alloc_size)


@dataclass
class AbsState:
    """单条指令处的抽象状态: 寄存器 → 值集."""
    regs: Dict[str, StridedValue] = field(default_factory=dict)

    def copy(self) -> 'AbsState':
        return AbsState(regs=dict(self.regs))

    def get(self, reg: str) -> StridedValue:
        return self.regs.get(reg, StridedValue.unknown())

    def set(self, reg: str, val: StridedValue):
        if reg:
            self.regs[reg] = val

    def merge(self, other: 'AbsState') -> 'AbsState':
        """两个状态的汇合 (控制流汇合点)."""
        merged = AbsState()
        all_regs = set(self.regs.keys()) | set(other.regs.keys())
        for r in all_regs:
            a = self.get(r)
            b = other.get(r)
            if a == b:
                merged.set(r, a)
            elif a.is_heap_ptr and b.is_heap_ptr \
                    and a.alloc_addr == b.alloc_addr:
                merged.set(r, a.unknown())
                merged.regs[r].is_heap_ptr = True
                merged.regs[r].alloc_addr = a.alloc_addr
                merged.regs[r].alloc_size = a.alloc_size
            else:
                merged.set(r, StridedValue.unknown())
        return merged
