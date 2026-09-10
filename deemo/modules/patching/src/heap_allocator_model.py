# glibc堆分配器语义建模 — 实际分配大小 vs 请求大小的差异分析
"""glibc ptmalloc 分配器行为建模。

堆溢出FP的第二大来源: 分析工具假设 malloc(N) 分配恰好N字节，
但glibc实际分配的chunk大小受对齐、最小chunk、bin策略影响。
malloc(10)实际可用空间可能是32字节（受MINSIZE和MALLOC_ALIGNMENT约束）。

本模块建模以下ptmalloc行为:
  1. 最小chunk大小: 64位系统上 MINSIZE = 32 bytes (含metadata)
  2. 对齐: MALLOC_ALIGNMENT = 16 bytes (64位)
  3. chunk边界: 实际可用 = max(request, MINSIZE - overhead) 再向上对齐
  4. 用户可用空间: chunk_size - 2*SIZE_SZ (prev_size + size字段)

这能消除"malloc(10)+memcpy(20)"类的误报 — glibc实际给的可不止10字节。

模型对照 glibc malloc.c 源码 (ptmalloc2/3)、MallocInternals [Phrack]
以及 HeapHopper 的堆模型。
"""

import logging
from dataclasses import dataclass
from typing import Dict, Tuple, Optional

_log = logging.getLogger(__name__)


# ptmalloc 常量（64位）

@dataclass(frozen=True)
class PtMallocConfig:
    """ptmalloc 分配器配置常量。"""
    SIZE_SZ: int = 8              # sizeof(size_t) on 64-bit
    MALLOC_ALIGNMENT: int = 16    # __alignof__(long double)
    MIN_CHUNK_SIZE: int = 32      # sizeof(malloc_chunk) = 4*SIZE_SZ
    MINSIZE: int = 32             # 最小可分配chunk（含metadata）

    # bin 阈值
    MAX_FAST_SIZE: int = 160      # 默认 max fastbin size (80*2/SIZE_SZ)
    SMALLBIN_THRESHOLD: int = 1024
    MMAP_THRESHOLD: int = 131072  # 默认128KB，超过则mmap

    @property
    def min_user_size(self) -> int:
        """最小用户可用空间 = MINSIZE - 2*SIZE_SZ。"""
        return self.MIN_CHUNK_SIZE - 2 * self.SIZE_SZ  # 32 - 16 = 16

    @property
    def overhead(self) -> int:
        """每个chunk的metadata开销 = prev_size + size = 2*SIZE_SZ。"""
        return 2 * self.SIZE_SZ


# 默认64位配置
PTMALLOC64 = PtMallocConfig()


# 实际分配大小计算器

class AllocSizeCalculator:
    """计算glibc对给定请求实际分配的用户可用空间。

    流程:
      1. request → chunk_size: 加上metadata，对齐到MALLOC_ALIGNMENT
      2. chunk_size → usable_size: 减去metadata
      3. 返回usable_size作为实际可用于写入的空间

    为什么这能减少FP:
      malloc(10) → usable_size = 16 bytes
      如果memcpy写入12字节 → 原来认为溢出 → 现在认为安全
    """

    def __init__(self, config: PtMallocConfig = PTMALLOC64):
        self.cfg = config

    def request_to_usable(self, request_size: int) -> int:
        """将malloc的请求大小转化为实际用户可用空间。

        request_size=0 → malloc(0)可能返回有效指针，
        glibc行为不确定，保守返回MINSIZE-2*SIZE_SZ。
        """
        if request_size <= 0:
            return self.cfg.min_user_size

        # 加上chunk metadata
        chunk_size = request_size + self.cfg.overhead

        # 对齐到MINSIZE（如果小于MINSIZE）
        if chunk_size < self.cfg.MIN_CHUNK_SIZE:
            chunk_size = self.cfg.MIN_CHUNK_SIZE

        # 对齐到MALLOC_ALIGNMENT
        alignment = self.cfg.MALLOC_ALIGNMENT
        chunk_size = (chunk_size + alignment - 1) & ~(alignment - 1)

        # 减去metadata得用户可用空间
        usable = chunk_size - self.cfg.overhead

        return usable

    def usable_range(self, request_lower: int,
                     request_upper: int) -> Tuple[int, int]:
        """给定请求大小的区间，返回实际可用空间的区间。

        request_lower=0时，usable下限取min_user_size（malloc(0)行为）。
        """
        usable_lower = self.request_to_usable(max(request_lower, 0))
        usable_upper = self.request_to_usable(max(request_upper, 0))
        return (usable_lower, usable_upper)

    def is_safe_write(self, request_size: int, write_size: int) -> bool:
        """给定的malloc+memcpy是否安全（不溢出）。"""
        usable = self.request_to_usable(request_size)
        return write_size <= usable


# 堆布局约束模型

class HeapLayoutModel:
    """建模堆chunk的布局约束，用于更精确的溢出可行性判定。

    场景: malloc(16) + memcpy(32) — 是否溢出？

    仅看值: 16 < 32 → 看似溢出。
    加入allocator模型: malloc(16) → usable = 24 (64位) → 仍溢出。
    加入布局模型: 若下一个chunk是free chunk且size足够大，
                 溢出到下一个chunk的数据可能不会立即触发crash。
                 但这不改变"越界写入"的事实 → 不用于消除告警。

    布局模型的实际用途:
      区分"必定覆盖返回地址/函数指针"和"仅写入到相邻chunk的padding区域"。
      前者 exploitability = HIGH，后者 = LOW。
      这用于风险排序而非FP消除（避免漏报）。
    """

    def __init__(self, config: PtMallocConfig = PTMALLOC64):
        self.cfg = config

    def classify_overflow_severity(self, alloc_size: int,
                                   write_size: int) -> Dict:
        """分类溢出严重级别。

        返回:
          {
            'overflow_bytes': int,      # 溢出字节数
            'hits_metadata': bool,       # 是否覆盖下一chunk的metadata
            'hits_user_data': bool,      # 是否覆盖下一chunk的用户数据
            'severity': 'CRITICAL'|'HIGH'|'MEDIUM'|'LOW',
            'explanation': str,
          }
        """
        usable = AllocSizeCalculator(self.cfg).request_to_usable(alloc_size)
        overflow = write_size - usable

        if overflow <= 0:
            return {
                'overflow_bytes': 0,
                'hits_metadata': False,
                'hits_user_data': False,
                'severity': 'LOW',
                'explanation': '无溢出 — 写入大小在实际可用空间内',
            }

        result = {'overflow_bytes': overflow}

        # metadata = 2*SIZE_SZ = 16 bytes
        meta_size = self.cfg.overhead
        if overflow <= meta_size:
            result['hits_metadata'] = True
            result['hits_user_data'] = False
            result['severity'] = 'MEDIUM'
            result['explanation'] = (
                f'溢出{overflow}字节仅覆盖下一chunk的metadata区域(prev_size+size)')
        else:
            result['hits_metadata'] = True
            result['hits_user_data'] = True
            result['severity'] = 'HIGH'
            result['explanation'] = (
                f'溢出{overflow}字节覆盖下一chunk的metadata+用户数据区')

        # 若能覆盖到chunk头之后的指针 → CRITICAL
        # (fastbin/tcache的fd指针在用户数据起始处)
        if overflow > meta_size + 8:
            result['severity'] = 'CRITICAL'
            result['explanation'] += (
                f' → 可覆盖下一chunk的fd/bk指针（{overflow - meta_size - 8}字节过冲）')

        return result


# 对齐约束过滤器

class AlignmentConstraintFilter:
    """利用对齐约束过滤误报。

    场景: malloc(13) + memcpy(16)
      朴素分析: 13 < 16 → 溢出。
      allocator模型: malloc(13) → usable = 16 → 不溢出。
      → 这是FP，过滤。

    但: malloc(13) + memcpy(20)
      16 < 20 → 确实溢出4字节 → 保留。

    这个过滤器不是简单地"小于就报警"，
    而是考虑allocator给的实际空间后再判定。
    """

    def __init__(self, config: PtMallocConfig = PTMALLOC64):
        self._calculator = AllocSizeCalculator(config)
        self._layout = HeapLayoutModel(config)

    def filter(self, request_size_range: Tuple[int, int],
               write_size: int) -> Dict:
        """判断给定分配区间+写入大小的告警是否应保留。

        返回:
          {
            'keep': bool,
            'reason': str,
            'usable_size': int,
            'overflow_bytes': int,
            'severity': str,
          }
        """
        req_low, req_high = request_size_range

        # 如果区间范围很大（污染情况），使用上界做最坏估计
        # 如果区间精确（常量），直接比较
        usable_low, usable_high = self._calculator.usable_range(req_low, req_high)

        if write_size <= usable_low:
            # 即使最小分配也够 → 确定FP
            return {
                'keep': False,
                'reason': (f'请求{req_low}-{req_high}B → 实际可用≥{usable_low}B '
                          f'≥ 写入{write_size}B → 不溢出'),
                'usable_size': usable_low,
                'overflow_bytes': 0,
                'severity': 'NONE',
            }

        if write_size > usable_high:
            # 即使最大分配也不够 → 确定TP
            severity = self._layout.classify_overflow_severity(
                req_high, write_size)
            return {
                'keep': True,
                'reason': (f'请求{req_low}-{req_high}B → 实际最多{usable_high}B '
                          f'< 写入{write_size}B → 确定溢出'),
                'usable_size': usable_high,
                'overflow_bytes': write_size - usable_high,
                'severity': severity['severity'],
            }

        # 区间重叠
        return {
            'keep': True,
            'reason': (f'请求{req_low}-{req_high}B → 可用{usable_low}-{usable_high}B '
                      f'与写入{write_size}B重叠 → 保守保留'),
            'usable_size': usable_low,
            'overflow_bytes': max(0, write_size - usable_low),
            'severity': 'UNKNOWN',
        }
