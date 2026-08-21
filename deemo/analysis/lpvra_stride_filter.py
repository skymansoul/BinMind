"""
LPVRA 步长区间精化过滤器 — 将 StridedInterval 域集成到LPVRA管线.

问题: 现有 Interval 域无法表达 malloc(n * sizeof(T)) 的分配模式.
  sizeof(T)=4 时, 分配大小 ∈ {0, 4, 8, 12, ...}
  但 Interval[0, 4096] 包含所有中间值 — 导致写入安全性检查过度保守.

方法: 对每个 alloc-write 对, 用 StridedInterval 精化区间:
  1. 从malloc表达式推断步长: malloc(n * 8) → stride=8
  2. 从循环守卫推断n的范围: for(i=0;i<10;i++) → n∈[0,10) → alloc_size∈8[0,72]
  3. 步长感知的安全检查: write_total ≤ min(alloc with matching stride alignment)

与 lpvra_affine 互补:
  - 仿射域: 证明两个变量间的关系 (write ≤ alloc)
  - 步长域: 精化单个变量的值集合 (排除不可能的值)
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Set, Tuple

from analysis.interval_domain import Interval
from analysis.strided_interval import StridedInterval

class StrideRefiner:
    """步长精化器 — 从C源码推断分配大小的步长约束.

    识别模式:
      malloc(n * sizeof(T)): 步长=sizeof(T)
      calloc(n, sizeof(T)): 步长=sizeof(T)
      malloc(k * n + c): 步长=k (仿射模式)
    """

    _SIZEOF_MAP = {
        'int': 4, 'long': 8, 'long long': 8, 'short': 2, 'char': 1,
        'float': 4, 'double': 8, 'void*': 8, 'char*': 8, 'int*': 4,
        'size_t': 8, 'ssize_t': 8, 'uint32_t': 4, 'uint64_t': 8,
        'uint8_t': 1, 'uint16_t': 2, 'int32_t': 4, 'int64_t': 8,
    }
    # malloc(n * const)
    _MUL_ALLOC_RE = re.compile(
        r'(?:malloc|calloc|realloc)\s*\(\s*(\w+)\s*\*\s*(\d+)\s*\)')
    # malloc(sizeof(type) * n)
    _SIZEOF_MUL_RE = re.compile(
        r'(?:malloc|calloc|realloc)\s*\(\s*sizeof\s*\(\s*([\w\s*]+)\s*\)\s*\*\s*(\w+)')
    # calloc(n, sizeof(type))
    _CALLOC_SIZEOF_RE = re.compile(
        r'calloc\s*\(\s*(\w+)\s*,\s*sizeof\s*\(\s*([\w\s*]+)\s*\)\s*\)')

    def infer_stride(self, source: str, var: str) -> Optional[int]:
        """推断变量var的步长.

        返回 stride值 (≥2), 或 None (无法推断).
        """
        for line in source.splitlines():
            s = line.strip()
            if var not in s:
                continue
            # 模式1: malloc(n * const)
            m = self._MUL_ALLOC_RE.search(s)
            if m and self._contains_var(m.group(1), var):
                const = int(m.group(2))
                if const >= 2:
                    return const
            # 模式2: malloc(sizeof(T) * n)
            m = self._SIZEOF_MUL_RE.search(s)
            if m and self._contains_var(m.group(2), var):
                type_name = m.group(1).strip()
                elem_size = self._SIZEOF_MAP.get(type_name, 0)
                if elem_size >= 2:
                    return elem_size
            # 模式3: calloc(n, sizeof(T))
            m = self._CALLOC_SIZEOF_RE.search(s)
            if m and self._contains_var(m.group(1), var):
                type_name = m.group(2).strip()
                elem_size = self._SIZEOF_MAP.get(type_name, 0)
                if elem_size >= 2:
                    return elem_size
        return None

    @staticmethod
    def _contains_var(expr: str, var: str) -> bool:
        """检查表达式是否引用了变量var."""
        return bool(re.search(r'\b' + re.escape(var) + r'\b', expr))

    def refine_interval(self, iv: Interval, stride: int) -> StridedInterval:
        """将Interval精化为StridedInterval.

        Interval.top() (lo=None,hi=None) → StridedInterval unbounded (hi=-1).
        """
        if iv.is_top():
            return StridedInterval(lo=0, hi=-1, stride=stride)
        if iv.is_bottom():
            return StridedInterval(lo=1, hi=0, stride=stride)  # bottom
        lo = iv.lo if iv.lo is not None else 0
        hi = iv.hi if iv.hi is not None else -1  # -1 = unbounded
        return StridedInterval(lo=lo, hi=hi, stride=stride)

class StrideAwareChecker:
    """步长感知的安全检查器 — 对alloc-write对做精化判定.

    核心: 考虑分配大小的步长约束后, 写入安全检查更精确.
    例如: alloc ∈ 8[64, 256] (只有{64,72,80,...,256}),
    write=70 → 若简单区间[64,256]判定不确定 (write可能<也可能>),
    但步长区间8[64,256]中所有值≥72 → 70 < 72 → 必然溢出.
    反之: write=62, alloc最小64 → 安全.
    """

    def check(self, alloc_iv: Interval, write_total: int,
              stride: int, chunk_slack: int = 16) -> Optional[bool]:
        """步长感知安全检查。

        alloc_iv 为 LPVRA 分配大小区间, write_total 为写入总字节数,
        stride=1 表示无步长约束。返回 True=可证安全, False=可证溢出,
        None=不确定。
        """
        if alloc_iv.is_top() or alloc_iv.is_bottom():
            return None
        lo = alloc_iv.lo if alloc_iv.lo is not None else 0
        hi = alloc_iv.hi if alloc_iv.hi is not None else (1 << 30)

        # 无步长约束: 用标准区间逻辑
        if stride <= 1:
            return self._interval_check(lo, hi, write_total, chunk_slack)

        # 步长感知: 计算实际可达的最小分配大小
        # s[lo, hi] 中最小的 ≥ lo 的值 = lo 向上取整到最近的步长倍数
        aligned_lo = ((lo + stride - 1) // stride) * stride
        effective_lo = aligned_lo + chunk_slack

        if write_total <= effective_lo:
            return True  # 最坏情况分配仍足够 → 安全

        # 计算最大的可达分配大小（在界内）
        aligned_hi = (hi // stride) * stride
        effective_hi = aligned_hi + chunk_slack
        if write_total > effective_hi:
            return False  # 最好情况分配仍不够 → 溢出

        return None  # 不确定

    @staticmethod
    def _interval_check(lo: int, hi: int, write_total: int,
                        slack: int) -> Optional[bool]:
        """标准区间安全检查 (无步长)."""
        if write_total <= lo + slack:
            return True
        if write_total > hi + slack:
            return False
        return None

def enhance_heap_verdict_with_stride(
    alloc_var: str, alloc_iv: Interval,
    write_total: int, source: str,
) -> Optional[bool]:
    """便捷函数: 对alloc-write对做步长增强检查.

    返回 True=安全(应过滤), False=溢出, None=不确定.
    """
    refiner = StrideRefiner()
    stride = refiner.infer_stride(source, alloc_var) or 1
    checker = StrideAwareChecker()
    return checker.check(alloc_iv, write_total, stride)

__all__ = ['StrideRefiner', 'StrideAwareChecker',
           'enhance_heap_verdict_with_stride']
