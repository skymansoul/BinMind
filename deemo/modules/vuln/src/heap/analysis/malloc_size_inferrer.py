"""malloc 参数值流推断器 — 跨块回溯 + 对齐感知.

创建: 2026-06-01
修改: 2026-06-01 (拆分: 区间域→interval_domain, 后向追踪→backward_tracer)
用途: 追踪 malloc(size) 的 size 参数到其定义点, 使用跨步区间
      (SInterval) 推导 size 的精确范围, 然后结合分配器的对齐策略还原实际可用空间。

与 heap_bound_infer.py 的关系:
  heap_bound_infer: 做访问→分配点的边界检查 (前向)
  本模块: 做分配参数→值流来源的约束推断 (后向)
  两者互补: 前者证伪"offset >= n", 后者证实"n 的实际值是多少".
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .interval_domain import (
    SInterval, AllocatorModel, DEFAULT_ALLOCATOR)
from .backward_tracer import backward_trace


@dataclass
class MallocSite:
    """一次 malloc 调用的完整信息."""
    insn_addr: int
    func_name: str          # malloc / calloc / realloc
    size_param_reg: str     # 存放 size 参数的寄存器
    size_interval: SInterval = field(default_factory=SInterval.top)
    ptr_reg: str = ""       # 返回值寄存器 (通常 rax)
    alignment_override: int = 0   # 0=使用分配器默认对齐
    nmemb_interval: Optional[SInterval] = None  # calloc 的第一个参数
    is_array_alloc: bool = False  # calloc/realloc(array)


class MallocSizeInferrer:
    """从 malloc 调用点出发, 后向追踪 size 参数的值流.

    算法: 需求驱动的后向值流分析 (Demand-Driven Value-Flow).
    从 call malloc 的 size 参数寄存器出发, 沿 def-use 链反向搜索
    mov/lea/add/sub/imul/shl 指令, 遇到函数调用边界或最大深度时截断.

    使用方式:
      inferrer = MallocSizeInferrer()
      inferrer.set_allocator_model(AllocatorModel())
      site = inferrer.infer(instructions, malloc_call_idx, 'malloc')
      usable_lo, usable_hi = inferrer.usable_range(site)
    """

    # x86_64 calling conventions: System V (Linux) and Microsoft x64 (Windows)
    _PARAM_REGS_SYSV = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9',
                        'edi', 'esi', 'edx', 'ecx', 'r8d', 'r9d']
    _PARAM_REGS_MS = ['rcx', 'rdx', 'r8', 'r9',
                      'ecx', 'edx', 'r8d', 'r9d',
                      'rdi', 'rsi', 'edi', 'esi']  # fallback

    def __init__(self):
        self._allocator = DEFAULT_ALLOCATOR

    def set_allocator_model(self, model: AllocatorModel) -> None:
        self._allocator = model

    def infer(self, instructions: List[str],
              call_idx: int,
              func_name: str = "malloc") -> MallocSite:
        """推断一个 malloc 调用的 size 参数区间.

        自动检测调用约定: 先尝试 System V, 若 rdi 无定义则回退到 MS x64.
        """
        if call_idx < 0 or call_idx >= len(instructions):
            return MallocSite(insn_addr=call_idx, func_name=func_name)

        param_idx = self._size_param_index(func_name)

        # 尝试 System V 调用约定
        sysv_reg = (self._PARAM_REGS_SYSV[param_idx]
                    if param_idx < len(self._PARAM_REGS_SYSV) else 'rdi')
        size_si_sysv = backward_trace(instructions, call_idx, sysv_reg)

        # 尝试 Microsoft x64 调用约定
        ms_reg = (self._PARAM_REGS_MS[param_idx]
                  if param_idx < len(self._PARAM_REGS_MS) else 'rcx')
        size_si_ms = backward_trace(instructions, call_idx, ms_reg)

        # 选更精确的结果 (非 TOP 优先, 更窄区间优先)
        primary_reg, size_si = self._select_better(
            sysv_reg, size_si_sysv, ms_reg, size_si_ms)

        site = MallocSite(
            insn_addr=call_idx, func_name=func_name,
            size_param_reg=primary_reg, size_interval=size_si,
            ptr_reg='rax',
            is_array_alloc=(func_name in ('calloc', 'realloc')))

        # calloc: 追踪 nmemb 参数
        if func_name == 'calloc':
            nmemb_sysv = backward_trace(instructions, call_idx, 'rdi')
            nmemb_ms = backward_trace(instructions, call_idx, 'rcx')
            site.nmemb_interval = (
                nmemb_sysv if not nmemb_sysv.is_top else nmemb_ms)

        return site

    @staticmethod
    def _select_better(sysv_reg: str, si_sysv: SInterval,
                       ms_reg: str, si_ms: SInterval) -> Tuple[str, SInterval]:
        """选择两个调用约定的推断中更精确的那个."""
        if si_sysv.is_top and not si_ms.is_top:
            return ms_reg, si_ms
        if si_ms.is_top and not si_sysv.is_top:
            return sysv_reg, si_sysv
        if not si_sysv.is_top and not si_ms.is_top:
            range_sysv = si_sysv.hi - si_sysv.lo
            range_ms = si_ms.hi - si_ms.lo
            if range_sysv <= range_ms:
                return sysv_reg, si_sysv
            return ms_reg, si_ms
        return sysv_reg, si_sysv  # 都是 TOP: 默认 System V

    def usable_range(self, site: MallocSite) -> Tuple[int, int]:
        """返回 malloc 分配的实际可用字节范围 (lo, hi)."""
        req_lo = site.size_interval.min_possible()
        req_hi = site.size_interval.max_possible()

        if site.size_interval.is_top:
            return (0, 0xFFFFFFFF)

        if site.is_array_alloc and site.nmemb_interval is not None:
            req_lo = site.nmemb_interval.min_possible() * req_lo
            req_hi = site.nmemb_interval.max_possible() * req_hi

        usable_lo = self._allocator.usable_size(req_lo)
        usable_hi = self._allocator.usable_size(req_hi)
        return (usable_lo, min(0xFFFFFFFF, usable_hi))

    def may_overflow(self, site: MallocSite, offset: int,
                     access_size: int) -> bool:
        """检查 offset+access_size 是否可能越界."""
        usable_lo, _ = self.usable_range(site)
        return (offset + access_size) > usable_lo

    def definitely_safe(self, site: MallocSite, offset: int,
                        access_size: int) -> bool:
        """确认访问一定在边界内 (用于过滤 FP)."""
        _, usable_hi = self.usable_range(site)
        return (offset + access_size) <= usable_hi and offset >= 0

    @staticmethod
    def _size_param_index(func_name: str) -> int:
        """堆分配函数的 size 参数索引 (0-based)."""
        return {'malloc': 0, 'calloc': 1, 'realloc': 1,
                'alloca': 0, '_malloc': 0, 'kmalloc': 0}.get(func_name, 0)

    def stats(self) -> dict:
        return {'allocator_model': self._allocator.name,
                'alignment': self._allocator.alignment}
