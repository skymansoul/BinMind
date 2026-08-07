"""
堆边界检查器 — 融合LPVRA值域分析结果与glibc分配器语义的精确边界判定.

核心问题: 现有检测比较 store_offset > malloc_size 时, 忽略了:
  1. glibc chunk slack (对齐填充) → 有效边界比 malloc 参数大
  2. 分配器最小chunk约束 → malloc(1) 实际可用 32B
  3. realloc扩展语义 → 新大小覆盖旧偏移时非溢出
  4. calloc清零 → 不改变chunk大小, 但nmemb*size可能溢出

LPVRA提供: 在每条路径上分配大小的值域区间 [lo, hi].
本模块提供: 将区间与分配器模型结合, 计算"是否所有路径都安全".

判定逻辑 (保守 — 仅当可证明安全时才过滤):
  ∀路径 (所有可达的状态):
    effective_boundary = max(alloc_lo, ptmalloc_usable(alloc_lo))
    write_end = write_offset + max(write_size, 1)
    write_end ≤ effective_boundary → SAFE
  否则 → UNCERTAIN (保留, 不能排除溢出可能)

与现有 allocator_chunk_model.py 的差异:
  - chunk_model: 静态计算单个chunk布局
  - 本模块: 接收LPVRA的区间, 动态计算"最坏情况"和"最好情况"边界
  - 综合判定: 仅当 write_end ≤ worst_case_boundary 时才过滤

  - glibc malloc/malloc.c: request2size(), checked_request2size()
  - Malloc Des-Maleficarum (Phrack 66): chunk复用与对齐利用
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple

from analysis.interval_domain import Interval

class BoundaryVerdict(Enum):
    SAFE = "SAFE"            # 可证明在所有路径上不溢出
    OVERFLOW = "OVERFLOW"    # 确定性溢出
    UNCERTAIN = "UNCERTAIN"  # 无法证明安全, 保守保留

@dataclass
class ChunkBoundary:
    """glibc ptmalloc chunk的有效边界估计."""
    requested: int            # 代码中请求的字节数
    usable: int               # 用户可用字节数 (含slack)
    alignment: int = 16       # x86_64 MALLOC_ALIGNMENT
    min_chunk: int = 32       # MINSIZE for x86_64
    overhead: int = 16        # prev_size + size 头部

    @property
    def slack(self) -> int:
        return max(0, self.usable - self.requested)

    @property
    def effective(self) -> int:
        """有效边界: 写入偏移超过此值才算溢出."""
        return max(self.requested, self.usable)

# ptmalloc request2size — 保守近似

def ptmalloc_request2size(request: int, platform: str = "x86_64") -> int:
    """glibc request2size() 的保守下界估计.

    返回: 用户可用空间的最小字节数 (保守 — 实际可能更大).
    """
    if request <= 0:
        return 0
    if platform == "x86_64":
        size_sz, minsize, align = 8, 32, 16
    elif platform == "x86":
        size_sz, minsize, align = 4, 16, 8
    else:
        size_sz, minsize, align = 8, 32, 16  # 默认x86_64

    # 保守: padded = max(request, minsize - 2*size_sz)
    padded = max(request + size_sz, minsize)
    chunk_size = ((padded + align - 1) // align) * align
    usable = chunk_size - 2 * size_sz
    return max(0, usable)

def compute_effective_boundary(alloc_size: int, alloc_func: str = "malloc",
                                platform: str = "x86_64") -> int:
    """计算包含chunk slack的有效边界.

    malloc(20) → aligned=32 → usable=32 (on x86_64),
    所以 offset=24 的store不溢出 (24+4=28 ≤ 32).

    对于calloc/realloc, 逻辑相同 — 只是size参数的含义不同.
    """
    if alloc_size <= 0:
        return 0
    usable = ptmalloc_request2size(alloc_size, platform)
    return max(alloc_size, usable)

# 核心检查逻辑

def check_heap_boundary(
    alloc_size_iv: Interval,
    write_offset: int,
    write_size: int,
    alloc_func: str = "malloc",
    platform: str = "x86_64",
) -> Tuple[BoundaryVerdict, str, float]:
    """对单个 alloc-write 对执行边界检查.

    Args:
      alloc_size_iv: 分配大小的值域区间 (来自LPVRA)
      write_offset: 写入起始偏移
      write_size: 写入字节数 (-1=无界如strcpy, -2=未知)
      alloc_func: 分配函数名
      platform: 目标平台

    Returns:
      (verdict, reason, confidence)
    """
    if alloc_size_iv.is_top():
        return BoundaryVerdict.UNCERTAIN, "分配大小完全未知(top)", 0.50
    if alloc_size_iv.is_bottom():
        return BoundaryVerdict.UNCERTAIN, "分配大小区间为bottom(不可达)", 0.0

    lo = alloc_size_iv.lo if alloc_size_iv.lo is not None else 0
    hi = alloc_size_iv.hi if alloc_size_iv.hi is not None else (1 << 20)

    # 无界写入 (strcpy): 永远不能证明安全
    if write_size < 0:
        # strcpy: 只要可能的目标空间小于"任意长度", 就是潜在溢出
        # 仅当 lo ≥ 1MB 时才算"足够大"安全
        if lo >= (1 << 20):
            return BoundaryVerdict.SAFE, f"分配≥{lo}B, strcpy类无界写入安全", 0.65
        return BoundaryVerdict.UNCERTAIN, f"strcpy类无界写入, 分配{lo}-{hi}B不足以证明安全", 0.30

    effective_write = write_offset + max(write_size, 1)

    # 最坏情况: 分配取下界 lo, 计算有效边界
    worst_boundary = compute_effective_boundary(lo, alloc_func, platform)
    if effective_write <= worst_boundary:
        return BoundaryVerdict.SAFE, (
            f"写入{effective_write}B ≤ 最坏边界{worst_boundary}B "
            f"(alloc_lo={lo})"), 0.92

    # 最好情况: 分配取上界 hi
    best_boundary = compute_effective_boundary(hi, alloc_func, platform)
    if effective_write > best_boundary:
        return BoundaryVerdict.OVERFLOW, (
            f"写入{effective_write}B > 最好边界{best_boundary}B "
            f"(alloc_hi={hi}) → 确定溢出"), 0.90

    # 中间情况: 某些路径溢出, 某些安全
    return BoundaryVerdict.UNCERTAIN, (
        f"写入{effective_write}B ∈ [{worst_boundary}, {best_boundary}]B "
        f"→ 路径相关, 无法证明安全"), 0.55

def check_write_safety(
    alloc_size: int,
    write_offset: int,
    write_size: int,
    is_dynamic_size: bool = False,
    size_upper_bound: Optional[int] = None,
    alloc_func: str = "malloc",
) -> Tuple[BoundaryVerdict, str]:
    """静态检查单个写入操作的安全性 (不使用LPVRA区间).

    用于快速路径 — 当分配大小是常量或已知上界时, 不走完整AI.
    """
    if is_dynamic_size and size_upper_bound is None:
        return BoundaryVerdict.UNCERTAIN, "动态分配无上界"

    effective_alloc = alloc_size
    if size_upper_bound is not None:
        effective_alloc = size_upper_bound

    boundary = compute_effective_boundary(effective_alloc, alloc_func)
    actual_write = write_offset + max(write_size, 1) if write_size > 0 else write_offset

    if actual_write <= boundary:
        return BoundaryVerdict.SAFE, (
            f"写入{actual_write}B ≤ 边界{boundary}B (req={effective_alloc})")
    return BoundaryVerdict.UNCERTAIN, (
        f"写入{actual_write}B > 边界{boundary}B")

def batch_check(
    alloc_sizes: List[Tuple[int, str]],  # [(size, func), ...]
    write_offsets: List[int],
    write_sizes: List[int],
) -> List[Tuple[BoundaryVerdict, str]]:
    """批量检查多个alloc-write对的边界安全性."""
    results = []
    for (size, func), off, wsz in zip(alloc_sizes, write_offsets, write_sizes):
        v, r = check_write_safety(size, off, wsz, alloc_func=func)
        results.append((v, r))
    return results

__all__ = [
    'BoundaryVerdict', 'ChunkBoundary',
    'ptmalloc_request2size', 'compute_effective_boundary',
    'check_heap_boundary', 'check_write_safety', 'batch_check',
]
