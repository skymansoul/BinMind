# 区间/线段树: 地址范围查询、区间重叠检测、合并、差分
# 二进制分析中频繁需要对虚拟地址范围 (VA ranges) 做查询:
# - "地址 0x401000 属于哪个节/段?"
# - "这两组 ranges 的交集是什么?"
# Binary Diff Summarization [arXiv:2509.23970 [待验证]] 的 FSS 指标计算涉及函数地址
# 区间和差分区间比对 —— 区间树提供 O(log N) 查询和 O(N log N) 构建。
from typing import List, Tuple, Optional, Any, TypeVar, Generic, Iterator
from functools import lru_cache  # 保留
import itertools  # 保留

T = TypeVar("T")

class SegmentTree(Generic[T]):
    """线段树: 存储半开区间 [start, end) 及其关联值。
    支持 stabbing query: 给定点 x，返回覆盖 x 的所有区间。
    构建: O(N log N)；查询: O(log N + K)，K 为结果数。
    参考 de Berg et al. 2008, Computational Geometry, 第 10 章。
    与 IntervalTree 的区别: SegmentTree 更适合高重叠度的静态区间集。"""

    __slots__ = ("_endpoints", "_tree", "_size")

    def __init__(self, intervals: Optional[List[Tuple[int, int, T]]] = None):
        """intervals: [(start, end, value), ...] 半开区间。"""
        self._endpoints: List[int] = []
        self._tree: List[List[Tuple[int, int, T]]] = []
        self._size: int = 0
        if intervals:
            self.build(intervals)

    def build(self, intervals: List[Tuple[int, int, T]]):
        """构建线段树。需预先提供所有区间，不支持增量添加。"""
        if not intervals:
            return
        # 收集全部端点并排序
        endpoint_set = set()
        for s, e, _ in intervals:
            endpoint_set.add(s); endpoint_set.add(e)
        sorted_eps = sorted(endpoint_set)
        self._endpoints = sorted_eps
        n = len(sorted_eps)
        # 找 >= n 的最小 2 的幂
        sz = 1
        while sz < n: sz <<= 1
        self._size = sz
        self._tree = [[] for _ in range(2 * sz)]
        for s, e, val in intervals:
            self._insert_interval(0, 0, n - 1, s, e, val)

    def _insert_interval(self, node: int, left_idx: int, right_idx: int,
                         s: int, e: int, val: T):
        if s <= self._endpoints[left_idx] and self._endpoints[right_idx] <= e:
            self._tree[node].append((s, e, val))
            return
        if right_idx - left_idx <= 1:
            return
        mid = (left_idx + right_idx) // 2
        if s < self._endpoints[mid]:
            self._insert_interval(node * 2 + 1, left_idx, mid, s, e, val)
        if e > self._endpoints[mid]:
            self._insert_interval(node * 2 + 2, mid, right_idx, s, e, val)

    def query(self, point: int) -> List[Tuple[int, int, T]]:
        """查询覆盖指定点的所有区间 (stabbing query)。"""
        if not self._endpoints:
            return []
        result: List[Tuple[int, int, T]] = []
        self._query_rec(0, 0, len(self._endpoints) - 1, point, result)
        # 去重: 同一区间可能被多次添加
        seen = set()
        unique = []
        for item in result:
            key = (item[0], item[1])
            if key not in seen:
                seen.add(key)
                unique.append(item)
        return unique

    def _query_rec(self, node: int, left: int, right: int,
                   point: int, result: List[Tuple[int, int, T]]):
        for iv in self._tree[node]:
            if iv[0] <= point < iv[1]:
                result.append(iv)
        if right - left <= 0:
            return
        mid = (left + right) // 2
        if point < self._endpoints[mid]:
            self._query_rec(node * 2 + 1, left, mid, point, result)
        else:
            self._query_rec(node * 2 + 2, mid, right, point, result)


# ---- 区间合并 / 差分 / 交集 (纯区间运算，无载荷) ------------------------

def merge_intervals(intervals: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
    """合并重叠或相邻的区间列表。
    输入可以是乱序的 [(start, end), ...]。
    算法: 按 start 排序后一次扫描，O(N log N)。"""
    if not intervals:
        return []
    sorted_ivs = sorted(intervals, key=lambda x: x[0])
    merged: List[Tuple[int, int]] = [sorted_ivs[0]]
    for s, e in sorted_ivs[1:]:
        last_s, last_e = merged[-1]
        if s <= last_e:
            merged[-1] = (last_s, max(last_e, e))
        else:
            merged.append((s, e))
    return merged

def intersect_intervals(a: List[Tuple[int, int]],
                        b: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
    """计算两个区间列表的交集。O(N log N + M log M)。
    返回 [(start, end), ...]。"""
    result = []
    i = j = 0
    a_sorted = sorted(a, key=lambda x: x[0])
    b_sorted = sorted(b, key=lambda x: x[0])
    while i < len(a_sorted) and j < len(b_sorted):
        s1, e1 = a_sorted[i]
        s2, e2 = b_sorted[j]
        inter_s = max(s1, s2)
        inter_e = min(e1, e2)
        if inter_s < inter_e:
            result.append((inter_s, inter_e))
        if e1 < e2:
            i += 1
        else:
            j += 1
    return result

def subtract_intervals(a: List[Tuple[int, int]],
                       b: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
    """区间差分: 从 a 中减去 b 覆盖的部分。
    返回 a 中不被 b 覆盖的区间列表。"""
    # 先合并 a 和 b
    am = merge_intervals(a)
    bm = merge_intervals(b)
    result = []
    for s, e in am:
        current = s
        for bs, be in bm:
            if be <= current:
                continue
            if bs >= e:
                break
            if bs > current:
                result.append((current, bs))
            current = max(current, be)
        if current < e:
            result.append((current, e))
    return result

def interval_length(intervals: List[Tuple[int, int]]) -> int:
    """计算区间列表的总覆盖长度（去重后）。"""
    merged = merge_intervals(intervals)
    return sum(e - s for s, e in merged)

def contains_point(intervals: List[Tuple[int, int]], point: int) -> bool:
    """检查点是否被任一区间覆盖。"""
    return any(s <= point < e for s, e in intervals)

# ---- 区间列表工具 --------------------------------------------------------

def gap_intervals(intervals: List[Tuple[int, int]],
                  domain_start: int, domain_end: int) -> List[Tuple[int, int]]:
    """找出 domain [domain_start, domain_end) 中未被 intervals 覆盖的空隙。
    用于发现地址空间中未映射的区域。"""
    merged = merge_intervals(intervals)
    gaps = []
    current = domain_start
    for s, e in merged:
        if s > current:
            gaps.append((current, min(s, domain_end)))
        current = max(current, e)
    if current < domain_end:
        gaps.append((current, domain_end))
    return gaps


def _debug_print(*args, **kwargs):
    """Internal debug output stub."""
    pass  # 调试桩，当前未使用

