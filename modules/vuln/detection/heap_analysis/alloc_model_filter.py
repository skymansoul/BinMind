# coding: utf-8
#
"""
分配器感知FP消除 — 基于多分配器内部模型的false positive削减。

现有fp_filter_v2.py的缺陷:
  1. 硬编码ptmalloc2常量(MIN_CHUNK=32, ALIGN=16, HEADER=16)
  2. 不支持MinGW/MSVC分配器(对齐=8/16差异)
  3. 不考虑jemalloc/tcmalloc的size class表
  4. 无实际可用大小(usable_size)的精确计算

本模块的改进:
  A. 多分配器模型: ptmalloc2, jemalloc, tcmalloc, MinGW, MSVC
  B. 每个模型提供usable_size(requested) → 实际可用字节
  C. size class表: jemalloc/tcmalloc的精确size class
  D. padding zone计算: [requested, usable) 区间内写入不越界
  E. 自动检测分配器类型(从二进制中的符号/链接库推断)

  ptmalloc2 — glibc默认分配器
  jemalloc(Facebook) — size class分离
  tcmalloc(Google) — thread cache + central heap
  Inferbo — 区间域+分配器推理
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from enum import Enum

class AllocatorType(Enum):
    """支持的分配器类型"""
    PTMALLOC2 = "ptmalloc2"
    JEMALLOC = "jemalloc"
    TCALLOC = "tcmalloc"
    MINGW = "mingw"
    MSVC = "msvc"
    UNKNOWN = "unknown"

@dataclass
class AllocModelResult:
    """分配器模型判定结果"""
    alloc_type: AllocatorType = AllocatorType.UNKNOWN
    requested_size: int = 0
    usable_size: int = 0
    padding_start: int = 0
    padding_end: int = 0
    write_offset: int = 0
    write_size: int = 0
    write_end: int = 0
    is_safe: bool = False
    reasoning: str = ""

def detect_allocator(binary_symbols: List[str]) -> AllocatorType:
    """从符号/段信息检测分配器类型"""
    sym_str = ' '.join(binary_symbols).lower()
    if 'jemalloc' in sym_str or 'je_malloc' in sym_str:
        return AllocatorType.JEMALLOC
    if 'tcmalloc' in sym_str or 'tc_malloc' in sym_str:
        return AllocatorType.TCALLOC
    if 'mingw' in sym_str or '__mingw' in sym_str:
        return AllocatorType.MINGW
    if 'msvcr' in sym_str or '_msize' in sym_str:
        return AllocatorType.MSVC
    if 'ptmalloc' in sym_str or 'glibc' in sym_str:
        return AllocatorType.PTMALLOC2
    return AllocatorType.UNKNOWN

# ptmalloc2 模型

_PTMALLOC_MIN_CHUNK = 32
_PTMALLOC_ALIGNMENT = 16
_PTMALLOC_HEADER = 16  # prev_size(8) + size(8)

def ptmalloc_usable_size(requested: int) -> int:
    """ptmalloc2: usable = round_up(req+16, 16) - 16"""
    if requested <= 0:
        return 0
    raw = requested + _PTMALLOC_HEADER
    aligned = ((raw + _PTMALLOC_ALIGNMENT - 1)
               // _PTMALLOC_ALIGNMENT) * _PTMALLOC_ALIGNMENT
    # 最小chunk 32字节 → usable至少 32-16=16
    usable = max(aligned - _PTMALLOC_HEADER,
                 _PTMALLOC_MIN_CHUNK - _PTMALLOC_HEADER)
    return usable

# MinGW 模型

_MINGW_ALIGNMENT = 16
_MINGW_HEADER = 8  # MinGW(RTL) overhead较小

def mingw_usable_size(requested: int) -> int:
    """MinGW: usable = round_up(req+8, 16) - 8"""
    if requested <= 0:
        return 0
    raw = requested + _MINGW_HEADER
    aligned = ((raw + _MINGW_ALIGNMENT - 1)
               // _MINGW_ALIGNMENT) * _MINGW_ALIGNMENT
    return aligned - _MINGW_HEADER

# MSVC CRT 模型

_MSVC_ALIGNMENT = 16
_MSVC_HEADER = 8  # MSVC debug模式额外32字节, release仅8

def msvc_usable_size(requested: int) -> int:
    """MSVC CRT: round_up(req+8, 16) - 8"""
    if requested <= 0:
        return 0
    raw = requested + _MSVC_HEADER
    aligned = ((raw + _MSVC_ALIGNMENT - 1)
               // _MSVC_ALIGNMENT) * _MSVC_ALIGNMENT
    return aligned - _MSVC_HEADER

# jemalloc 模型

# jemalloc small size classes (x86-64)
_JEMALLOC_SIZE_CLASSES = [
    8, 16, 32, 48, 64, 80, 96, 112, 128, 160, 192, 224, 256,
    320, 384, 448, 512, 640, 768, 896, 1024, 1280, 1536, 1792,
    2048, 2560, 3072, 3584, 4096, 5120, 6144, 7168, 8192,
]

def jemalloc_usable_size(requested: int) -> int:
    """jemalloc: 最近size class"""
    if requested <= 0:
        return 0
    for sz in _JEMALLOC_SIZE_CLASSES:
        if sz >= requested:
            return sz
    # large: round up to page
    page = 4096
    return ((requested + page - 1) // page) * page

# tcmalloc 模型

_TCMALLOC_SIZE_CLASSES = [
    8, 16, 32, 48, 64, 80, 96, 112, 128, 144, 160, 176, 192,
    208, 224, 240, 256, 288, 320, 352, 384, 416, 448, 480, 512,
]

def tcmalloc_usable_size(requested: int) -> int:
    """tcmalloc: 最近size class"""
    if requested <= 0:
        return 0
    for sz in _TCMALLOC_SIZE_CLASSES:
        if sz >= requested:
            return sz
    page = 4096
    return ((requested + page - 1) // page) * page

_USABLE_FUNCS = {
    AllocatorType.PTMALLOC2: ptmalloc_usable_size,
    AllocatorType.JEMALLOC: jemalloc_usable_size,
    AllocatorType.TCALLOC: tcmalloc_usable_size,
    AllocatorType.MINGW: mingw_usable_size,
    AllocatorType.MSVC: msvc_usable_size,
    AllocatorType.UNKNOWN: ptmalloc_usable_size,  # 默认ptmalloc2
}

class AllocModelFilter:
    """分配器感知FP消除

    对符号约束传播的uncertain候选:
    若write落在padding zone内 → 证明安全 → 滤除FP
    """

    def __init__(self, alloc_type: AllocatorType = AllocatorType.UNKNOWN):
        self.alloc_type = alloc_type
        self._usable_fn = _USABLE_FUNCS.get(
            alloc_type, ptmalloc_usable_size)

    def evaluate(self, requested_size: int, write_offset: int,
                 write_size: int) -> AllocModelResult:
        """评估单条写入是否在分配器padding zone内

        参数: requested_size malloc请求的size, write_offset
        写入偏移(相对于buffer起始), write_size 写入字节数
        (0=单元素写入); 返回 AllocModelResult。
        """
        result = AllocModelResult()
        result.alloc_type = self.alloc_type
        result.requested_size = requested_size
        result.write_offset = write_offset
        result.write_size = write_size

        if requested_size <= 0:
            result.reasoning = "requested_size unknown — conservative"
            result.is_safe = False
            return result

        usable = self._usable_fn(requested_size)
        result.usable_size = usable
        result.padding_start = requested_size
        result.padding_end = usable

        # 单元素写入: write_size=0时用access_size=1推断
        effective_write = write_size if write_size > 0 else 1
        write_end = write_offset + effective_write
        result.write_end = write_end

        if write_end <= requested_size:
            result.is_safe = True
            result.reasoning = (
                f"write_end={write_end} ≤ requested={requested_size} "
                f"— provably safe")
        elif write_end <= usable:
            result.is_safe = True
            result.reasoning = (
                f"write_end={write_end} ≤ usable={usable} "
                f"(padding [{requested_size},{usable})) — safe")
        else:
            result.is_safe = False
            if write_end > usable:
                result.reasoning = (
                    f"write_end={write_end} > usable={usable} "
                    f"— confirmed overflow")
            else:
                result.reasoning = "insufficient info"

        return result

    def batch_evaluate(
            self, findings: List[dict]) -> List[AllocModelResult]:
        """批量评估

        findings: [{requested_size, write_offset, write_size}, ...]
        """
        results = []
        for f in findings:
            r = self.evaluate(
                f.get('requested_size', 0),
                f.get('write_offset', 0),
                f.get('write_size', 0))
            results.append(r)
        return results

def evaluate_alloc_safety(
        requested_size: int, write_offset: int, write_size: int,
        alloc_type: AllocatorType = AllocatorType.UNKNOWN) -> AllocModelResult:
    """便捷函数: 评估单条写入的分配器安全性"""
    amf = AllocModelFilter(alloc_type)
    return amf.evaluate(requested_size, write_offset, write_size)

__all__ = [
    "AllocatorType", "AllocModelResult", "AllocModelFilter",
    "detect_allocator",
    "ptmalloc_usable_size", "mingw_usable_size", "msvc_usable_size",
    "jemalloc_usable_size", "tcmalloc_usable_size",
    "evaluate_alloc_safety",
]
