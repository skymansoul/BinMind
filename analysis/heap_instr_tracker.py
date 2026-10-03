"""
指令级堆操作追踪器 — 从x86_64反汇编中追踪寄存器值和堆操作.

职责:
  - 寄存器 → StridedInterval 映射维护
  - 立即数加载、算术运算、寄存器复制传播
  - CMP/JCC 分支约束提取
  - malloc/calloc/realloc 分配点识别
  - memcpy/memset/memmove 等内存操作检测

与 HeapOverflowDetector 的关系:
  - HeapOverflowDetector 持有本追踪器实例
  - 本追踪器提供 _resolve_si() 和分支状态查询
"""


import re
from typing import Dict, List, Optional, Tuple

from .strided_interval import (
    StridedInterval, si_singleton, si_unbounded, si_from_mul)
from .constraint_tracker import ConstraintTracker
from .heap_alloc_model import HeapAllocModel, AllocatorKind


class HeapInstrTracker:
    """指令级追踪: 寄存器值 + 分支条件 + 堆操作检测.

    处理顺序 (每条指令):
      1. 立即数加载 → 更新寄存器 SI
      2. 算术操作 → 更新寄存器 SI
      3. cmp/jcc → 更新路径约束
      4. 分配检测 → 记录 malloc 点
      5. 内存操作检测 → 产出候选对
    """

    # 分配函数签名: func_name → {param: register}
    ALLOC_SIGS: Dict[str, Dict[str, str]] = {
        "malloc":  {"size": "rdi", "ret": "rax"},
        "calloc":  {"nmemb": "rdi", "size": "rsi", "ret": "rax"},
        "realloc": {"ptr": "rdi", "size": "rsi", "ret": "rax"},
        "alloca":  {"size": "rdi", "ret": "rax"},
        "posix_memalign": {"memptr": "rdi", "alignment": "rsi",
                           "size": "rdx", "ret": "rax"},
    }

    # 内存操作函数签名
    MEMOP_SIGS: Dict[str, Dict[str, str]] = {
        "memcpy":  {"dst": "rdi", "src": "rsi", "n": "rdx"},
        "memmove": {"dst": "rdi", "src": "rsi", "n": "rdx"},
        "memset":  {"dst": "rdi", "val": "rsi", "n": "rdx"},
        "strcpy":  {"dst": "rdi", "src": "rsi"},
        "strncpy": {"dst": "rdi", "src": "rsi", "n": "rdx"},
        "sprintf": {"dst": "rdi", "fmt": "rsi"},
        "snprintf":{"dst": "rdi", "n": "rsi", "fmt": "rdx"},
        "read":    {"fd": "rdi", "buf": "rsi", "n": "rdx"},
        "fread":   {"buf": "rdi", "size": "rsi", "nmemb": "rdx"},
        "recv":    {"sock": "rdi", "buf": "rsi", "n": "rdx"},
    }

    # 32位→64位寄存器映射
    REG32_TO_64: Dict[str, str] = {
        "edi": "rdi", "esi": "rsi", "ecx": "rcx", "edx": "rdx",
        "r8d": "r8", "r9d": "r9", "eax": "rax", "ebx": "rbx",
        "ebp": "rbp", "esp": "rsp", "r10d": "r10", "r11d": "r11",
        "r12d": "r12", "r13d": "r13", "r14d": "r14", "r15d": "r15",
    }

    def __init__(self, heap_model: HeapAllocModel):
        self._heap_model = heap_model
        self._ct = ConstraintTracker()
        self._reg_si: Dict[str, StridedInterval] = {}
        # 分配记录: alloc_site → (func_name, ptr_name, size_si)
        self._allocs: Dict[int, Tuple[str, str, StridedInterval]] = {}
        # 收集到的候选对: [(alloc_site, write_site, write_func, write_size_si)]
        self._candidates: List[Tuple[int, int, str, StridedInterval]] = []

    # 公开

    @property
    def constraint_tracker(self) -> ConstraintTracker:
        return self._ct

    @property
    def allocs(self) -> Dict[int, Tuple[str, str, StridedInterval]]:
        return self._allocs

    @property
    def candidates(self) -> List[Tuple[int, int, str, StridedInterval]]:
        return self._candidates

    def clear(self):
        self._reg_si.clear()
        self._allocs.clear()
        self._candidates.clear()
        self._ct.clear()

    def resolve_si(self, reg: str) -> StridedInterval:
        """将寄存器名解析为 StridedInterval."""
        if reg in self._reg_si:
            return self._reg_si[reg]
        alias64 = self.REG32_TO_64.get(reg, "")
        if alias64 and alias64 in self._reg_si:
            return self._reg_si[alias64]
        return si_unbounded(0, 1)

    # 指令处理入口

    def process_insn(self, addr: int, il: str):
        """处理单条指令, 按优先级调度各子处理."""
        self._track_immediate(il)
        self._track_arithmetic(il)
        self._track_branch(il)
        self._track_alloc(addr, il)
        self._track_memop(addr, il)
        self._track_reg_copy(il)

    # 私有: 各类指令追踪

    def _track_immediate(self, il: str):
        m = re.match(r'mov\s+(\w+),\s*(0x[0-9a-f]+|\d+)', il)
        if not m:
            return
        reg, val = m.group(1), int(m.group(2), 0)
        si = si_singleton(val)
        self._reg_si[reg] = si
        if reg in self.REG32_TO_64:
            self._reg_si[self.REG32_TO_64[reg]] = si

    def _track_arithmetic(self, il: str):
        # add reg, imm
        m = re.match(r'add\s+(\w+),\s*(0x[0-9a-f]+|\d+)', il)
        if m:
            reg = m.group(1)
            if reg in self._reg_si:
                self._reg_si[reg] = self._reg_si[reg].add(int(m.group(2), 0))
            return
        # sub reg, imm
        m = re.match(r'sub\s+(\w+),\s*(0x[0-9a-f]+|\d+)', il)
        if m:
            reg = m.group(1)
            if reg in self._reg_si:
                self._reg_si[reg] = self._reg_si[reg].add(-int(m.group(2), 0))
            return
        # imul reg, reg, imm
        m = re.match(r'imul\s+(\w+),\s*(\w+),\s*(0x[0-9a-f]+|\d+)', il)
        if m:
            dst, src = m.group(1), m.group(2)
            if src in self._reg_si:
                self._reg_si[dst] = self._reg_si[src].mul(int(m.group(3), 0))
            return
        # shl/shr reg, imm
        m = re.match(r'sh[lr]\s+(\w+),\s*(0x[0-9a-f]+|\d+)', il)
        if m:
            reg = m.group(1)
            shift = int(m.group(2), 0)
            if reg in self._reg_si and shift <= 6:
                self._reg_si[reg] = self._reg_si[reg].mul(1 << shift)

    def _track_branch(self, il: str):
        m = re.match(r'cmp\s+(\w+),\s*(\w+)', il)
        if m:
            self._ct.feed_cmp(m.group(1), m.group(2))
            return
        m = re.match(r'test\s+(\w+),\s*(\w+)', il)
        if m and m.group(1) == m.group(2):
            self._ct.feed_cmp(m.group(1), "0")
            return
        m = re.match(r'(j[agljbegnzpsco]\w*)\s+0x[0-9a-f]+', il)
        if m:
            self._ct.feed_jcc(m.group(1), True)

    def _track_alloc(self, addr: int, il: str):
        for func, sig in self.ALLOC_SIGS.items():
            if func not in il:
                continue
            if func == "calloc":
                nmemb_si = self.resolve_si(sig["nmemb"])
                size_si = self.resolve_si(sig["size"])
                if not nmemb_si.is_unbounded() and not size_si.is_unbounded():
                    size_si = StridedInterval(
                        nmemb_si.lo * size_si.lo if nmemb_si.lo is not None and size_si.lo is not None else 0,
                        -1 if (nmemb_si.is_unbounded() or size_si.is_unbounded())
                        else nmemb_si.hi * size_si.hi,
                        max(1, nmemb_si.stride * size_si.stride))
                else:
                    size_si = si_from_mul(nmemb_si, 1)
            elif func == "posix_memalign":
                size_si = self.resolve_si(sig["size"])
            else:
                size_si = self.resolve_si(sig["size"])

            ptr_name = f"heap_ptr_{addr:x}"
            self._allocs[addr] = (func, ptr_name, size_si)
            self._reg_si["rax"] = si_singleton(addr)
            break

    def _track_memop(self, addr: int, il: str):
        for func, sig in self.MEMOP_SIGS.items():
            if func not in il:
                continue
            write_size_reg = sig.get("n", sig.get("size", ""))
            if not write_size_reg:
                continue
            write_si = self.resolve_si(write_size_reg)
            if write_si.is_bottom():
                continue
            for alloc_site in list(self._allocs.keys()):
                self._candidates.append(
                    (alloc_site, addr, func, write_si))
            break

    def _track_reg_copy(self, il: str):
        m = re.match(r'mov\s+(\w+),\s*(\w+)', il)
        if not m:
            return
        dst, src = m.group(1), m.group(2)
        if src in self._reg_si:
            self._reg_si[dst] = self._reg_si[src]
            if dst in self.REG32_TO_64:
                self._reg_si[self.REG32_TO_64[dst]] = self._reg_si[src]
        if src in self.REG32_TO_64:
            resolved = self.REG32_TO_64[src]
            if resolved in self._reg_si:
                self._reg_si[dst] = self._reg_si[resolved]
