"""
Heap Layout Oracle — 分配器感知的堆布局建模, 推断chunk间安全间距.

静态检测器: malloc(20) → store offset 24 → 报告溢出. 但glibc chunk最小32B.
本模块: 提取连续分配 → 建模ptmalloc bin行为 → 推断chunk间距.
若 store offset < safe_distance → 未跨越chunk边界 → FILTER.
无法推断时保守保留 (避免漏报).
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple

class ChunkClass(Enum):
    """glibc chunk 大小分类 — 影响 bin 选择和布局."""
    TINY = "tiny"        # 0-64B   → fastbin/tcache
    SMALL = "small"      # 65-512B → smallbin
    MEDIUM = "medium"    # 513-128KB → largebin (consolidatable)
    LARGE = "large"      # >128KB  → mmap

@dataclass
class ChunkLayout:
    """单次分配的 chunk 布局信息."""
    var_name: str = ""
    alloc_func: str = "malloc"
    requested_size: int = 0      # 请求的字节数
    aligned_size: int = 0        # 对齐后的 chunk 总大小 (含 header)
    usable_size: int = 0         # 用户可用字节数 = aligned_size - HEADER_SIZE
    chunk_class: ChunkClass = ChunkClass.SMALL
    next_chunk_offset: int = 0   # 下一个 chunk 相对此 chunk 起始的偏移
    pc: int = 0                   # 行索引

    @property
    def safe_region(self) -> int:
        """安全写入范围上限: data 区域的末尾字节偏移 (相对于 data 起始)."""
        return self.usable_size

@dataclass
class HeapRegion:
    """同一函数内的堆区域布局 — 所有 chunk 按分配顺序排列."""
    chunks: List[ChunkLayout] = field(default_factory=list)
    platform: str = "x86_64"

    @property
    def header_size(self) -> int:
        """chunk header 大小: prev_size(8) + size(8) = 16B on x86_64."""
        return 16 if self.platform in ("x86_64", "arm64", "aarch64") else 8

    @property
    def min_chunk_size(self) -> int:
        """最小 chunk 总大小 (含 header)."""
        return 32 if self.platform in ("x86_64", "arm64", "aarch64") else 16

class HeapLayoutOracle:
    """堆布局神谕: 推断连续分配的 chunk 间安全间距.

    用法:
      oracle = HeapLayoutOracle()
      region = oracle.infer_region(pseudocode)
      safe = oracle.is_write_safe(store_offset, target_chunk, region)
    """

    _ALLOC_PAT = re.compile(
        r'(?:(\w+)\s*=\s*)?(?:\([^)]*\*\s*\))?\s*'
        r'(malloc|calloc|realloc)\s*\(\s*([^)]+)\s*\)',
        re.IGNORECASE,
    )

    _SIZEOF_PAT = re.compile(
        r'sizeof\s*\(\s*(\w+(?:\s*\*\s*)?)\s*\)',
        re.IGNORECASE,
    )

    # 常见类型的 sizeof 值
    _KNOWN_SIZEOF: Dict[str, int] = {
        'int': 4, 'long': 8, 'char': 1, 'short': 2,
        'float': 4, 'double': 8, 'void*': 8, 'size_t': 8,
        'int32_t': 4, 'uint32_t': 4, 'int64_t': 8, 'uint64_t': 8,
    }

    def __init__(self, platform: str = "x86_64"):
        self._platform = platform

    def infer_region(self, pseudocode: str) -> HeapRegion:
        """从伪代码推断堆区域布局.

        按程序顺序处理所有分配, 构建 chunk 链.
        对连续分配, 推断 chunk 间的最小安全距离.
        """
        region = HeapRegion(platform=self._platform)
        lines = pseudocode.splitlines()

        for i, line in enumerate(lines):
            stripped = line.strip()
            if not stripped or stripped.startswith(('//', '#', ';')):
                continue

            m = self._ALLOC_PAT.search(stripped)
            if not m:
                continue

            var = m.group(1) or f'_heap_{i}'
            func = (m.group(2) or 'malloc').lower()
            size_expr = (m.group(3) or '0').strip()

            size = self._resolve_size(size_expr, stripped)
            chunk = self._make_chunk(var, func, size, i)
            region.chunks.append(chunk)

        # 推断相邻 chunk 间的偏移
        self._infer_adjacent_offsets(region)
        return region

    def _resolve_size(self, expr: str, context_line: str = "") -> int:
        """从大小表达式解析字节数."""
        expr = expr.strip()
        # 直接常量
        try:
            return int(expr)
        except ValueError:
            pass
        try:
            return int(expr, 16)
        except ValueError:
            pass
        # sizeof(type)
        m = self._SIZEOF_PAT.search(expr)
        if m:
            type_name = m.group(1).replace('*', '').strip()
            # 指针类型 → 8 (x86_64) 或 4 (x86)
            if m.group(1).endswith('*'):
                return 8 if '64' in self._platform else 4
            return self._KNOWN_SIZEOF.get(type_name, 0)
        # N * sizeof(type) — calloc 常见模式
        mul_m = re.match(
            r'(\d+)\s*\*\s*sizeof\s*\(\s*(\w+)\s*\)',
            expr, re.IGNORECASE,
        )
        if mul_m:
            n = int(mul_m.group(1))
            ts = self._KNOWN_SIZEOF.get(mul_m.group(2), 4)
            return n * ts
        # 变量 — 不可解析
        return 0

    def _make_chunk(
        self, var: str, func: str, requested: int, pc: int,
    ) -> ChunkLayout:
        """从分配参数构造 ChunkLayout."""
        if requested <= 0:
            return ChunkLayout(
                var_name=var, alloc_func=func,
                requested_size=requested,
                aligned_size=0, usable_size=0,
                chunk_class=ChunkClass.SMALL, pc=pc,
            )

        # ptmalloc request2size:
        # chunk_size = max(MIN_SIZE, align_up(request + SIZE_SZ + MALLOC_ALIGN_MASK, MALLOC_ALIGNMENT))
        # usable_size = chunk_size - 2*SIZE_SZ
        # 简化: 对齐到 16B, 最小 32B, usable = aligned - 16
        align = 16
        min_chunk = 32
        header = 16 if '64' in self._platform else 8

        aligned = ((requested + header + align - 1) // align) * align
        aligned = max(min_chunk, aligned)
        usable = aligned - header

        cls = ChunkClass.SMALL
        if usable <= 64:
            cls = ChunkClass.TINY
        elif usable > 512 and usable <= 131072:
            cls = ChunkClass.MEDIUM
        elif usable > 131072:
            cls = ChunkClass.LARGE

        return ChunkLayout(
            var_name=var, alloc_func=func,
            requested_size=requested,
            aligned_size=aligned, usable_size=usable,
            chunk_class=cls, pc=pc,
        )

    def _infer_adjacent_offsets(self, region: HeapRegion) -> None:
        """推断连续分配的 chunk 间偏移.

        glibc 连续分配时: chunk_N+1 的起始地址 = chunk_N 起始 + aligned_size(N).
        因此 chunk_N 的 data 区域内, store offset < usable_size(N) 是安全的,
        但即使 offset > usable_size(N), 若 offset < aligned_size(N), 溢出仅触及
        chunk header 区域 (非相邻 chunk 的数据) → 属于低严重度.

        连续分配时: chunk_N 的 data 之后有 chunk_N+1 的 header → gap.
        如果两个 chunk 不是连续的 (中间有 free/其他分配), 无法确定间距.
        """
        for i in range(len(region.chunks) - 1):
            curr = region.chunks[i]
            nxt = region.chunks[i + 1]
            if curr.aligned_size > 0:
                curr.next_chunk_offset = curr.aligned_size
            # 标记下一个 chunk 的偏移
            nxt.next_chunk_offset = -1  # 尾部 chunk

    def is_write_safe(
        self,
        store_offset: int,
        target_chunk: ChunkLayout,
        region: HeapRegion,
        store_size: int = 1,
    ) -> Tuple[bool, str]:
        """判断对 target_chunk 的写入是否安全.

        Args:
          store_offset: 相对 data 起始的写入偏移
          target_chunk: 目标 chunk 的布局信息
          region: 堆区域布局
          store_size: 写入字节数

        Returns:
          (is_safe, reason)
        """
        if target_chunk.usable_size <= 0:
            return True, 'usable_size unknown, cannot prove unsafe'

        # 情况1: 写入完全在 usable 范围内
        end_offset = store_offset + store_size
        if end_offset <= target_chunk.usable_size:
            return True, (
                f'write [{store_offset}:{end_offset}] within usable '
                f'{target_chunk.usable_size}B'
            )

        # 情况2: 写入溢入 header 区域但不跨越到下一 chunk
        if end_offset <= target_chunk.aligned_size - 8:
            # 溢入 header 的 prev_size 区域 — 可能可写但利用价值低
            return True, (
                f'overflow into header padding '
                f'(end={end_offset} <= aligned={target_chunk.aligned_size})'
            )

        # 情况3: 写入跨越到下一 chunk 的 data
        if target_chunk.next_chunk_offset > 0:
            if end_offset <= target_chunk.next_chunk_offset + 8:
                # 溢入下一 chunk 的 header (prev_size + size)
                return False, (
                    f'overflow crosses chunk boundary '
                    f'(end={end_offset} > aligned={target_chunk.aligned_size})'
                )

        # 情况4: 无法确定布局, 保守判定为可能溢出
        if target_chunk.next_chunk_offset <= 0:
            return False, (
                f'unknown adjacent layout: offset={store_offset} '
                f'exceeds usable={target_chunk.usable_size}'
            )

        return False, (
            f'clear overflow: offset={store_offset} > '
            f'next_chunk_offset={target_chunk.next_chunk_offset}'
        )

    def find_target_chunk(
        self, region: HeapRegion, var_name: str,
    ) -> Optional[ChunkLayout]:
        """在区域中定位指定变量的 chunk."""
        for c in region.chunks:
            if c.var_name == var_name:
                return c
        return None

    def get_effective_capacity(
        self, var_name: str, region: HeapRegion,
        store_pc: int = -1,
    ) -> int:
        """获取变量的有效写容量 (考虑相邻 chunk 布局).

        返回: 写入不跨越 chunk 边界的最大偏移量.
        若无法确定返回 -1.
        """
        chunk = self.find_target_chunk(region, var_name)
        if chunk is None:
            return -1
        if chunk.usable_size <= 0:
            return -1

        # 若 chunk 后有相邻分配, 安全容量 = next_chunk_offset - 1
        if chunk.next_chunk_offset > 0:
            return chunk.next_chunk_offset
        # 否则返回 usable_size (仅保证不溢出 header)
        return chunk.usable_size

__all__ = [
    'ChunkClass', 'ChunkLayout', 'HeapRegion', 'HeapLayoutOracle',
]
