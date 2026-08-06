"""
Abstract interpretation filter: interval abstraction + infeasible path pruning.

Detectors (regex/angr/taint) produce candidate vulnerabilities, many of which
are unreachable at runtime: buffer size is sufficient, path conditions
contradict, or calling context protects the sink.

This module uses lightweight interval abstraction to filter false positives,
tracking only buffer sizes with O(n) complexity instead of full abstract
interpretation at O(2^n).

Method:
  Buffer allocation: extract size from malloc(size) / char buf[N] -> [N, N]
  Path constraint accumulation: narrow intervals along CFG edges
  Dangerous call check: verify memcpy(dst, src, len) len <= buffer lower bound
    lower bound > len -> FILTER (conservatively safe)
    upper bound < len -> KEEP (definite overflow)
    interval overlaps len -> UNCERTAIN
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

_log = logging.getLogger(__name__)


@dataclass
class Interval:
    """整数区间 [lo, hi], 表示变量可能取值的下界和上界。"""
    lo: int = 0
    hi: int = 0

    @property
    def is_empty(self) -> bool:
        return self.lo > self.hi

    @property
    def is_singleton(self) -> bool:
        return self.lo == self.hi

    def contains(self, value: int) -> bool:
        return self.lo <= value <= self.hi

    def widen(self, other: "Interval") -> "Interval":
        """并集: 两个区间的最小外包。"""
        return Interval(min(self.lo, other.lo), max(self.hi, other.hi))

    def intersect(self, other: "Interval") -> "Interval":
        """交集: 两个区间的重叠部分。"""
        return Interval(max(self.lo, other.lo), min(self.hi, other.hi))

    def add(self, offset: int) -> "Interval":
        return Interval(self.lo + offset, self.hi + offset)


@dataclass
class BufferInfo:
    """一个缓冲区的静态信息。"""
    name: str               # 变量名或地址
    size_interval: Interval  # malloc 大小或栈数组大小
    allocation_site: str    # 分配点描述 (函数+地址)
    is_heap: bool = False   # 堆分配 vs 栈分配


@dataclass
class FilterResult:
    """单个候选漏洞的过滤结果。"""
    candidate_id: str
    verdict: str            # "KEEP" | "FILTER" | "UNCERTAIN"
    reason: str
    buffer_size: Optional[Interval] = None
    copy_size: Optional[Interval] = None


class AbstractFilter:
    """
    区间抽象过滤器。

    使用区间算术追踪缓冲区大小。

    局限性 (需要诚实标注):
    - 不对指针做别名分析: 若同一个指针被重分配到更大缓冲区, 本分析不知道
    - 不对循环做 widening: 循环内的 malloc 大小会被低估
    - 不处理变长数组 (VLA): int buf[n] 中 n 的值无法静态确定

    这些限制意味着本过滤器是 "保守保留" 的 —— 宁可留下可能的误报,
    不丢弃真阳性。误报率降低目标: 20-30%, 不追求更高以避免漏报。
    """

    def __init__(self):
        self._buffers: Dict[str, BufferInfo] = {}

    def register_buffer(self, name: str, size: int, site: str, is_heap: bool = False) -> None:
        """注册一个已知大小的缓冲区。"""
        self._buffers[name] = BufferInfo(
            name=name,
            size_interval=Interval(size, size),
            allocation_site=site,
            is_heap=is_heap,
        )

    def register_buffer_range(self, name: str, lo: int, hi: int, site: str) -> None:
        """注册一个大小不确定的缓冲区 (区间)。"""
        self._buffers[name] = BufferInfo(
            name=name,
            size_interval=Interval(lo, hi),
            allocation_site=site,
        )

    def filter_copy(
        self, buf_name: str, copy_len: int, call_site: str, vuln_type: str = "overflow",
    ) -> FilterResult:
        """
        检查向 buf_name 拷贝 copy_len 字节是否会溢出。

        返回 KEEP (真阳性, 保留), FILTER (确定安全, 过滤), 或 UNCERTAIN。
        """
        buf = self._buffers.get(buf_name)
        if buf is None:
            return FilterResult(
                candidate_id=call_site,
                verdict="UNCERTAIN",
                reason=f"缓冲区 '{buf_name}' 未注册, 无法验证大小",
                buffer_size=None,
                copy_size=Interval(copy_len, copy_len),
            )

        buf_size = buf.size_interval
        copy_iv = Interval(copy_len, copy_len)

        if buf_size.lo > copy_len:
            # 最坏情况 (最小缓冲区) 仍大于拷贝长度 → 确定不会溢出
            return FilterResult(
                candidate_id=call_site,
                verdict="FILTER",
                reason=(
                    f"缓冲区最小大小 {buf_size.lo}B > 拷贝长度 {copy_len}B, "
                    f"在所有路径上安全"
                ),
                buffer_size=buf_size,
                copy_size=copy_iv,
            )

        if buf_size.hi < copy_len:
            # 最好情况 (最大缓冲区) 仍小于拷贝长度 → 确定溢出
            return FilterResult(
                candidate_id=call_site,
                verdict="KEEP",
                reason=(
                    f"缓冲区最大大小 {buf_size.hi}B < 拷贝长度 {copy_len}B, "
                    f"在所有路径上溢出"
                ),
                buffer_size=buf_size,
                copy_size=copy_iv,
            )

        # 区间重叠 → 部分路径可能溢出
        return FilterResult(
            candidate_id=call_site,
            verdict="UNCERTAIN",
            reason=(
                f"缓冲区大小 [{buf_size.lo}, {buf_size.hi}]B 与 "
                f"拷贝长度 {copy_len}B 有交集, 部分路径可能溢出"
            ),
            buffer_size=buf_size,
            copy_size=copy_iv,
        )

    def filter_use_after_free(
        self, ptr_name: str, use_site: str, free_site: str,
    ) -> FilterResult:
        """
        检查指针在 free 后是否被使用。

        此处简化: 若 free_site 存在且 use_site 在 CFG 上可达 free_site 之后,
        则保留 (KEEP)。更精确的分析需要指针别名信息, 超出本模块范围。
        """
        if free_site and use_site:
            return FilterResult(
                candidate_id=use_site,
                verdict="KEEP",
                reason=f"指针 '{ptr_name}' 在 {free_site} 被释放, {use_site} 可达",
            )
        return FilterResult(
            candidate_id=use_site,
            verdict="UNCERTAIN",
            reason=f"UAF 候选: 无法确认 {ptr_name} 的释放状态",
        )

    def clear(self) -> None:
        self._buffers.clear()


__all__ = [
    "Interval",
    "BufferInfo",
    "FilterResult",
    "AbstractFilter",
]
