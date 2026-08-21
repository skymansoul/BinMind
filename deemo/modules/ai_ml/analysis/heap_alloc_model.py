# 堆分配器语义模型: 精确建模glibc ptmalloc2的chunk布局和大小计算
# 这是降低堆溢出误报的核心基础设施之一
#
# 理论背景:
#   glibc malloc (ptmalloc2) 的内部chunk布局:
#     [prev_size(8B)] [size(8B)] [user data...]
#     - 最小chunk: 0x20 (32B on x86_64) = 16B metadata + 16B min data
# malloc(N) 实际分配的可用空间:
#         usable = max(MINSIZE, round_up(N + SIZE_SZ, MALLOC_ALIGNMENT)) - 2*SIZE_SZ
#      其中 SIZE_SZ=8(x86_64), MALLOC_ALIGNMENT=16(x86_64)
# 关键: malloc(48) = 实际可用56字节, 不是48
#
#   calloc特殊处理: 内部调用malloc(nmemb*size), 可能溢出
#   realloc: 可能扩展原位或分配新块
#
# 根据 glibc 2.31+ 源码 (malloc/malloc.c) 和
#   "Malloc Internals" (https://sourceware.org/glibc/wiki/MallocInternals)
#   验证上述常量

from __future__ import annotations

import re
import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class AllocFamily(Enum):
    MALLOC = 'malloc'
    CALLOC = 'calloc'
    REALLOC = 'realloc'
    ALLOCA = 'alloca'   # 栈分配
    MMAP = 'mmap'
    UNKNOWN = 'unknown'


@dataclass
class ChunkLayout:
    """glibc chunk的精确内存布局"""
    prev_size: int = 8       # 前一个chunk的大小字段(复用时为用户数据)
    size_field: int = 8      # 当前chunk的大小字段(含flag位)
    min_chunk: int = 32      # 最小chunk总大小(MIN_CHUNK_SIZE on x86_64)
    alignment: int = 16      # MALLOC_ALIGNMENT
    # ptmalloc2 计算可用大小的公式:
    # usable = max(MINSIZE, (req + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK)
    # 其中 SIZE_SZ=8(x86_64), MALLOC_ALIGN_MASK=15

    def usable_size(self, requested: int) -> int:
        """给定malloc(N)的N, 返回实际可用字节数"""
        if requested <= 0:
            return 0
        # glibc实际公式: usable = ((req + 8 + 15) & ~15) - 8
        rounded = (requested + self.size_field + self.alignment - 1) & ~(self.alignment - 1)
        usable = max(self.min_chunk - 2 * self.size_field, rounded - 2 * self.size_field)
        return usable

    def actual_chunk_size(self, requested: int) -> int:
        """给定malloc(N)的N, 返回实际分配的chunk总大小(含metadata)"""
        if requested <= 0:
            return 0
        size = (requested + self.size_field + self.alignment - 1) & ~(self.alignment - 1)
        return max(self.min_chunk, size)

    def overflow_threshold(self, requested: int) -> int:
        """返回触发堆溢出的最小拷贝字节数"""
        return self.usable_size(requested) + 1


@dataclass
class AllocSiteInfo:
    """堆分配点的完整信息"""
    instr_idx: int
    alloc_func: str
    alloc_family: AllocFamily
    requested_size: int            # 参数值(精确或最小)
    usable_size: int               # 实际可用字节
    chunk_size: int                # 完整chunk大小
    is_size_exact: bool            # 参数值是否确定
    has_overflow_check_nearby: bool = False  # 附近是否有大小检查
    evidence: List[str] = field(default_factory=list)


class HeapAllocModel:
    """堆分配器语义模型。

    核心职责: 给定malloc(N)中的N, 计算实际可用空间。
    这一步对降低误报至关重要, 很多"溢出"实际上在
    合法分配空间内，因为glibc分配的chunk比请求大。

    支持的平台:
      x86_64: SIZE_SZ=8, MALLOC_ALIGNMENT=16
      x86:    SIZE_SZ=4, MALLOC_ALIGNMENT=8
      ARM64:  SIZE_SZ=8, MALLOC_ALIGNMENT=16
    """

    def __init__(self, arch: str = 'x86_64'):
        if arch == 'x86':
            self._layout = ChunkLayout(
                prev_size=4, size_field=4, min_chunk=16, alignment=8)
        elif arch == 'arm64':
            self._layout = ChunkLayout(
                prev_size=8, size_field=8, min_chunk=32, alignment=16)
        else:  # x86_64 default
            self._layout = ChunkLayout(
                prev_size=8, size_field=8, min_chunk=32, alignment=16)

        self._alloc_pattern = re.compile(
            r'\b(malloc|calloc|realloc|alloca|mmap)\b', re.I)

    def analyze_alloc_site(self,
                            instr_idx: int,
                            instructions: List[str],
                            requested_size: Optional[int] = None,
                            has_size_check: bool = False
                            ) -> AllocSiteInfo:
        """分析单个分配点的chunk信息。"""
        instr = instructions[instr_idx].strip().lower() if instr_idx < len(instructions) else ''
        alloc_func = 'malloc'
        alloc_family = AllocFamily.UNKNOWN

        for f in ('malloc', 'calloc', 'realloc', 'alloca', 'mmap'):
            if f in instr:
                alloc_func = f
                alloc_family = AllocFamily(f)
                break

        # 若未传入大小，尝试本地推断
        if requested_size is None:
            requested_size = self._local_size_infer(instr_idx, instructions)

        usable = self._layout.usable_size(requested_size)
        chunk = self._layout.actual_chunk_size(requested_size)
        is_exact = requested_size > 0

        evidence = []
        if is_exact:
            evidence.append(
                f"{alloc_func}({requested_size}): usable={usable}, "
                f"chunk={chunk}, wasted={chunk - requested_size - 16}")
        else:
            evidence.append(f"{alloc_func}(?): unable to infer size locally")

        # calloc: nmemb * size, 两参数相乘
        if alloc_family == AllocFamily.CALLOC and is_exact:
            evidence.append("calloc: size may be product of nmemb*size")

        return AllocSiteInfo(
            instr_idx=instr_idx,
            alloc_func=alloc_func,
            alloc_family=alloc_family,
            requested_size=requested_size,
            usable_size=usable,
            chunk_size=chunk,
            is_size_exact=is_exact,
            has_overflow_check_nearby=has_size_check,
            evidence=evidence)

    def compute_overflow_margin(self,
                                 alloc_info: AllocSiteInfo,
                                 copy_size: int
                                 ) -> Tuple[bool, int, str]:
        """判断copy_size是否真的溢出。"""
        usable = alloc_info.usable_size

        if not alloc_info.is_size_exact:
            return (False, 0,
                    "alloc size unknown → cannot confirm overflow")

        if copy_size <= 0:
            return (False, 0, "copy size unknown/zero")

        margin = copy_size - usable
        if margin <= 0:
            return (False, margin,
                    f"copy({copy_size}) ≤ usable({usable}): margin={margin}")

        # 检查是否在chunk header边界内(consider metadata reuse)
        if copy_size <= alloc_info.chunk_size - 8:
            return (False, margin,
                    f"copy({copy_size}) ≤ chunk_size({alloc_info.chunk_size})-8 "
                    f"(prev_size复用): 技术上合法但可疑")

        return (True, margin,
                f"OVERFLOW: copy({copy_size}) > usable({usable}), margin={margin}")

    def _local_size_infer(self, instr_idx: int,
                           instructions: List[str]) -> int:
        """在call指令前5条指令内快速推断常量大小参数"""
        for j in range(instr_idx - 1, max(-1, instr_idx - 6), -1):
            if j < 0:
                continue
            instr = instructions[j].strip().lower() if j < len(instructions) else ''
            # AT&T: mov $imm, %edi/%rdi
            m = re.match(r'mov\s+\$?(0x[0-9a-f]+|\d+),\s*%(?:e|r)di', instr, re.I)
            if m:
                return int(m.group(1), 16) if '0x' in m.group(1).lower() else int(m.group(1))
            # AT&T imul $imm, %reg, %edi
            m = re.match(r'imul\s+\$?(0x[0-9a-f]+|\d+),\s*%\w+,\s*%(?:e|r)di', instr, re.I)
            if m:
                return int(m.group(1), 16) if '0x' in m.group(1).lower() else int(m.group(1))
        return 0

    def batch_analyze(self,
                       alloc_sites: List[Tuple[int, Optional[int]]],
                       instructions: List[str]
                       ) -> List[AllocSiteInfo]:
        """批量分析多个分配点"""
        return [self.analyze_alloc_site(idx, instructions, size)
                for idx, size in alloc_sites]
