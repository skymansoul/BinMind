# 对齐感知的堆溢出验证器——利用跨步区间精确判定对齐边界溢出
# 集成点: 在L2(分配器模型)之后、L3(值范围传播)之前运行
# 定位为L2.5——补充分配器模型的纯大小计算，增加对齐约束
#
# 核心场景:
#   malloc(32) → usable=48(glibc对齐后)
#   若拷贝大小以16字节步长变化: {32, 48, 64, ...}
#   则只有≥64的值才真正溢出，48恰好卡在边界——安全
#   而简单区间[48,64]会错误标记溢出(lp2依赖于copy_max是否>usable+margin)
#
# 决策: 仅在alloc/copy大小已知且涉及对齐边界时启用此验证
#       默认margin=0时对齐判定最激进(16字节对齐的拷贝在boundary处安全)

from __future__ import annotations

import re
import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

from .strided_interval import (
    StridedInterval, infer_alignment_from_instructions)
from .heap_allocator_model import HeapAllocatorModel

_ARIA_S1 = "0x3f"
logger = logging.getLogger(__name__)


@dataclass
class AlignmentVerdict:
    """对齐感知的溢出判定结果"""
    is_overflow: bool
    overflow_bytes: int          # >0=溢出字节数, 0=刚好, <0=安全
    copy_size_stride: int        # 拷贝大小的跨步
    alloc_alignment: int         # 分配的对齐粒度
    min_overflowing_copy: int    # 触发溢出的最小拷贝大小
    evidence: str


class AlignmentVerifier:
    """对齐感知验证器——用跨步区间做比简单区间更精确的溢出判定。

    适用场景:
      - malloc(N)返回M对齐的chunk，拷贝大小也以某步长变化
      - 当拷贝大小的步长与分配对齐互质时，边界处的判定比简单区间更精确
    """

    def __init__(self, alloc_model: Optional[HeapAllocatorModel] = None):
        self._alloc_model = alloc_model or HeapAllocatorModel()

    def verify(self,
               alloc_requested: int,
               copy_size_lo: int,
               copy_size_hi: int,
               instructions: Optional[List[str]] = None,
               copy_instr_idx: int = -1
               ) -> AlignmentVerdict:
        """执行对齐感知的溢出验证。

        Args:
            alloc_requested: malloc的size参数
            copy_size_lo: 拷贝大小的下界
            copy_size_hi: 拷贝大小的上界
            instructions: 可选——函数指令列表，用于推断对齐约束
            copy_instr_idx: 拷贝指令的索引

        Returns:
            AlignmentVerdict with precise overflow assessment
        """
        usable = self._alloc_model.usable_size(alloc_requested)
        alloc_align = self._alloc_model.alignment

        # 推断拷贝大小的跨步
        copy_stride = 1  # 默认无跨步约束
        if instructions and copy_instr_idx >= 0:
            size_reg = self._infer_size_reg(instructions, copy_instr_idx)
            if size_reg:
                inferred = infer_alignment_from_instructions(
                    instructions[:copy_instr_idx], size_reg)
                if inferred and inferred > 1:
                    copy_stride = inferred

        # 构建跨步区间并判定
        si = StridedInterval.aligned(
            copy_size_lo, copy_size_hi, copy_stride)

        # 找到区间中实际会溢出的最小值
        min_overflowing = self._find_min_overflowing(si, usable)

        is_overflow = min_overflowing <= si.hi
        overflow_bytes = si.hi - usable if is_overflow else copy_size_hi - usable

        # 生成证据
        if is_overflow:
            evidence = (
                f"ALIGN: usable={usable}, copy∈{si}, "
                f"min_overflowing={min_overflowing}, "
                f"overflow={overflow_bytes}B at max copy={si.hi}")
        else:
            # 即使hi>usable也可能安全——若跨步跳过溢出值
            max_safe = si.lo + ((usable - si.lo) // si.stride) * si.stride
            evidence = (
                f"ALIGN(SAFE): usable={usable}, copy∈{si}, "
                f"max_safe_copy={max_safe} ≤ usable={usable} "
                f"(stride={si.stride} skips overflow)")

        return AlignmentVerdict(
            is_overflow=is_overflow,
            overflow_bytes=max(0, overflow_bytes),
            copy_size_stride=copy_stride,
            alloc_alignment=alloc_align,
            min_overflowing_copy=min_overflowing,
            evidence=evidence)

    def verify_pair(self,
                    alloc_requested: int,
                    copy_size_lo: int,
                    copy_size_hi: int,
                    copy_func: str = 'memcpy',
                    instructions: Optional[List[str]] = None,
                    copy_instr_idx: int = -1
                    ) -> Tuple[bool, str]:
        """简化接口——返回(是否溢出, 证据字符串)"""
        verdict = self.verify(
            alloc_requested, copy_size_lo, copy_size_hi,
            instructions, copy_instr_idx)
        return verdict.is_overflow, verdict.evidence

    @staticmethod
    def _find_min_overflowing(si: StridedInterval, usable: int) -> int:
        """找到跨步区间中第一个超过usable的值"""
        if si.lo > usable:
            return si.lo
        # 从usable+1开始找第一个满足跨步约束的值
        candidate = usable + 1
        remainder = (candidate - si.lo) % si.stride
        if remainder != 0:
            candidate += si.stride - remainder
        return candidate if candidate <= si.hi else si.hi + 1

    @staticmethod
    def _infer_size_reg(instructions: List[str],
                        copy_idx: int) -> Optional[str]:
        """推断拷贝调用的size参数寄存器"""
        if copy_idx < 0 or copy_idx >= len(instructions):
            return None
        instr = instructions[copy_idx].strip().lower()
        # memcpy/memmove: size在rdx
        if any(f in instr for f in ('memcpy', 'memmove', 'strncpy')):
            return 'rdx'
        # read/recv: size在rdx
        if any(f in instr for f in ('read', 'recv')):
            return 'rdx'
        # fread: size在rsi (第二个参数=nmembsize, 第三个=count在rdx)
        if 'fread' in instr:
            return 'rsi'
        # snprintf: size在rsi
        if 'snprintf' in instr:
            return 'rsi'
        return None
