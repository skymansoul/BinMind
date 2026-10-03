"""
glibc 分配器约束: 将 ptmalloc 语义纳入堆溢出误报过滤。
依据最小块大小 (x86_64 上 32B 含 metadata)、16B 对齐、realloc 原地缩小与 calloc 溢出返回 NULL 等行为,
对每个候选溢出判定: 实际分配大小 ≥ 写入大小 → FILTER, 实际分配大小 < 写入大小 → KEEP, 无法确定 → UNCERTAIN。
"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class AllocType(Enum):
    MALLOC = "malloc"
    CALLOC = "calloc"
    REALLOC = "realloc"


@dataclass
class AllocSize:
    """分配器的实际可用大小。"""
    requested: int        # 代码中请求的字节数
    effective: int        # glibc 实际分配的可用字节数 (含对齐+最小块约束)
    alignment: int = 16   # 平台对齐 (x86_64=16, x86=8, ARM64=16)
    min_chunk: int = 32   # 最小 chunk 可用空间 (x86_64 ptmalloc)

    @classmethod
    def from_request(cls, requested: int, platform: str = "x86_64") -> "AllocSize":
        """从请求大小计算实际可用大小。"""
        if platform == "x86_64":
            align, min_chunk = 16, 32
        elif platform == "x86":
            align, min_chunk = 8, 16
        elif platform in ("arm64", "aarch64"):
            align, min_chunk = 16, 32
        else:
            align, min_chunk = 16, 32  # 默认 x86_64

        if requested <= 0:
            return cls(requested, 0, align, min_chunk)

        # ptmalloc: 请求大小 + metadata → 向上取整到 2*sizeof(size_t)
        # 可用空间 ≈ aligned_size - 2*sizeof(size_t) (chunk header)
        aligned = ((requested + align - 1) // align) * align
        effective = max(min_chunk, aligned)
        return cls(requested, effective, align, min_chunk)

    def can_contain(self, write_size: int) -> bool:
        """实际可用空间能否容纳 write_size 字节的写入。"""
        return self.effective >= write_size


@dataclass
class ReallocCheck:
    original_size: Optional[int]  # 原始块的大小 (已知情况)
    new_size: int                  # realloc 请求的新大小
    is_shrink: bool                # 新大小 ≤ 原大小 → 原地操作

    @classmethod
    def analyze(cls, new_size: int, original_size: Optional[int] = None) -> "ReallocCheck":
        if new_size == 0:
            return cls(original_size, 0, False)  # free 语义
        if original_size is not None and new_size <= original_size:
            return cls(original_size, new_size, True)
        return cls(original_size, new_size, False)

    @property
    def actual_alloc_size(self) -> int:
        """realloc 实际需要分配的字节数。"""
        if self.new_size == 0:
            return 0
        if self.is_shrink:
            return self.original_size or self.new_size
        return self.new_size


class AllocatorConstraintChecker:
    """分配器约束检查器。

    对每个堆操作候选应用 glibc 语义判断是否为真溢出; 无法确定时返回 UNCERTAIN (宁可保留, 不误过滤)。
    """

    def __init__(self, platform: str = "x86_64"):
        self._platform = platform

    def check_overflow(
        self, alloc_size: int, write_size: int, alloc_type: str = "malloc",
    ) -> str:
        """检查 (分配大小, 写入大小) 是否构成真正的溢出。返回 "KEEP" (真阳性)、"FILTER" (误报)、"UNCERTAIN"。"""
        if alloc_size <= 0 or write_size <= 0:
            return "UNCERTAIN"

        actual = AllocSize.from_request(alloc_size, self._platform)

        if alloc_type == "calloc":
            # calloc 已做零初始化, 但大小语义同 malloc
            pass
        elif alloc_type == "realloc":
            # realloc: 新大小 ≤ 旧大小 → 原地缩小, 不分配新块
            if write_size <= alloc_size:
                return "FILTER"

        if actual.can_contain(write_size):
            return "FILTER"
        if actual.effective < write_size:
            return "KEEP"
        return "UNCERTAIN"

    def check_upper_bound(
        self, upper_bound: int, write_size: int, alloc_type: str = "malloc",
    ) -> str:
        """使用 value-flow 追踪到的上界做更精确的判断。若约束确保分配大小 ≥ 写入大小, 则安全。"""
        if upper_bound <= 0:
            return "UNCERTAIN"
        actual = AllocSize.from_request(upper_bound, self._platform)
        if actual.can_contain(write_size):
            return "FILTER"
        return "KEEP"


__all__ = ['AllocSize', 'ReallocCheck', 'AllocatorConstraintChecker']
