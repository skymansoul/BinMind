"""分配大小解析 — 从 malloc 调用点解析分配大小与分配器可用空间.

创建: 2026-06-17
设计决策:
  - 优先用 AccessExtractor 的 size_info (值流解析), 回退到常量传播
    与默认值. 分配大小不可解析时返回 None (交由引擎保守处理).
  - ptmalloc2 可用空间计算与既有 allocator_model 一致: 对齐到16B,
    最小块32B, 可用 = chunk - 16.
"""
import re
from typing import Dict, List, Optional

from .value_flow import ValueFlowTracer
from .types import ValueInfo, Provenance

MIN_CHUNK_SIZE = 32
SIZE_SZ = 8
MALLOC_ALIGNMENT = 16
MMAP_THRESHOLD = 128 * 1024
DEFAULT_ALLOC = 128


def ptmalloc2_usable(requested: int) -> int:
    """请求大小 → 分配器实际可用字节数."""
    size = max(requested, 0)
    if size >= MMAP_THRESHOLD:
        actual = (size + 2 * SIZE_SZ + 4095) & ~4095
        return actual - 2 * SIZE_SZ
    min_data = max(size, MIN_CHUNK_SIZE - 2 * SIZE_SZ)
    chunk = (min_data + 2 * SIZE_SZ + MALLOC_ALIGNMENT - 1) & \
        ~(MALLOC_ALIGNMENT - 1)
    chunk = max(MIN_CHUNK_SIZE, chunk)
    return chunk - 2 * SIZE_SZ


class AllocSizeResolver:
    """解析 malloc/calloc/realloc 调用点的分配大小."""

    def __init__(self):
        self._cache: Dict[int, Optional[int]] = {}

    def resolve(self, alloc_site: int, access_addr: int,
                mallocs: List[dict], insns: list) -> Optional[int]:
        """返回分配大小; None 表示无法解析."""
        if alloc_site in self._cache:
            return self._cache[alloc_site]

        # 1. AccessExtractor 已解析的 size_info
        for m in mallocs:
            if m.get('addr') == alloc_site:
                si = m.get('size_info')
                if si is not None and si.is_constant:
                    v = si.constant_value
                    self._cache[alloc_site] = v
                    return v
                if si is not None and si.interval_hi is not None:
                    # 上界有界 → 用上界近似(保守, 防漏报)
                    v = si.interval_hi
                    self._cache[alloc_site] = v
                    return v
                break

        # 2. 从反汇编直接解析 call 前的 size 寄存器
        v = self._resolve_from_insns(alloc_site, insns)
        if v is not None:
            self._cache[alloc_site] = v
            return v

        # 3. 不可解析 → None (保守)
        self._cache[alloc_site] = None
        return None

    @staticmethod
    def _resolve_from_insns(alloc_site: int, insns: list) -> Optional[int]:
        idx = next((i for i, insn in enumerate(insns)
                    if insn.addr == alloc_site), None)
        if idx is None:
            return None
        size_regs = ('rcx', 'rdi', 'rdx')
        tracer = ValueFlowTracer(insns)
        for reg in size_regs:
            info = tracer.trace(reg, alloc_site)
            if info.is_constant:
                return info.constant_value
            if info.interval_hi is not None and info.interval_lo is not None \
                    and info.interval_lo == info.interval_hi:
                return info.interval_lo
        return None
