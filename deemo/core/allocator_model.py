"""
分配器感知约束模型 -- glibc ptmalloc2 chunk size对齐与最小尺寸约束。

设计理由:
  堆溢出检测中的一类误报源于忽略分配器的内部对齐。
  例如 malloc(13) 实际分配的chunk可用空间是 24 字节(ptmalloc2在x86_64
  上最小chunk 32B, 减去 8B metadata = 24B可用)。若写入大小是 18B,
  纯比较 18>13 会误报, 但 18<24 实际上不会溢出。
  引入分配器模型可将此类误报过滤。

支持:
  - glibc ptmalloc2 (Linux默认): chunk_size = max(32, align_up(req+8, 16))
    可用空间 = chunk_size - 8 (metadata overhead)
  - jemalloc (FreeBSD/Firefox): 按size class分桶, 近似
  - tcmalloc (gperftools): 按size class分桶, 近似

局限: 不处理自定义分配器(如内核的kmalloc/slab)。检测到非标准分配器时
      保守处理——使用原始requested size做比较, 宁可误报不漏报。

参考:
  - glibc malloc.c (source): chunk_size = (request + 8 + 0xF) & ~0xF, min 0x20
  - jemalloc size_classes.sh: 预定义的size class查找表
"""

from __future__ import annotations

from enum import Enum
from typing import Dict, Optional, Tuple


class AllocatorType(Enum):
    GLIBC_PTMALLOC2 = 'glibc-ptmalloc2'
    JEMALLOC = 'jemalloc'
    TCMALLOC = 'tcmalloc'
    UNKNOWN = 'unknown'


# jemalloc size classes (x86_64, 4KB pages) —— 近似值, 取自jemalloc 5.3
_JEMALLOC_SIZE_CLASSES = [
    8, 16, 32, 48, 64, 80, 96, 112, 128, 160, 192, 224, 256,
    320, 384, 448, 512, 640, 768, 896, 1024, 1280, 1536, 1792,
    2048, 2560, 3072, 3584, 4096, 5120, 6144, 7168, 8192,
    10240, 12288, 14336, 16384,
]

# tcmalloc size classes (x86_64) —— 近似值
_TCMALLOC_SIZE_CLASSES = [
    8, 16, 32, 48, 64, 80, 96, 112, 128, 144, 160, 176, 192,
    208, 224, 240, 256, 288, 320, 352, 384, 416, 448, 480, 512,
    576, 640, 704, 768, 832, 896, 960, 1024,
]


def detect_allocator(binary_path: str) -> AllocatorType:
    """检测二进制使用的内存分配器类型。"""
    try:
        import subprocess
        proc = subprocess.run(
            ['nm', '-D', binary_path], capture_output=True, text=True, timeout=15,
        )
        symbols = proc.stdout
        if 'malloc@@GLIBC' in symbols or '__libc_malloc' in symbols:
            return AllocatorType.GLIBC_PTMALLOC2
        if 'je_malloc' in symbols or 'jemalloc' in symbols.lower():
            return AllocatorType.JEMALLOC
        if 'tc_malloc' in symbols:
            return AllocatorType.TCMALLOC
    except Exception:
        pass
    return AllocatorType.UNKNOWN


def effective_chunk_size(requested_bytes: int,
                         allocator: AllocatorType = AllocatorType.GLIBC_PTMALLOC2,
                         arch_bits: int = 64) -> int:
    """给定malloc请求大小, 返回实际可用chunk大小(扣除metadata后)。

    glibc ptmalloc2 (x86_64):
      chunk_size = max(0x20, (request + 8 + 0xF) & ~0xF)
      usable = chunk_size - 8 (prev_size + size字段)
      最小可用: 0x20 - 8 = 24 字节

    Returns: 实际可安全写入的字节数
    """
    if allocator == AllocatorType.GLIBC_PTMALLOC2:
        if arch_bits == 64:
            min_chunk = 0x20  # 32B
            overhead = 8      # prev_size(8) field, size field embedded in prev chunk
        else:
            min_chunk = 0x10  # 16B (i386)
            overhead = 4
        chunk_size = max(min_chunk, (requested_bytes + overhead + 0xF) & ~0xF)
        return max(0, chunk_size - overhead)

    elif allocator == AllocatorType.JEMALLOC:
        for sc in _JEMALLOC_SIZE_CLASSES:
            if sc >= requested_bytes:
                return sc
        return requested_bytes  # fallthrough: 大对象直接mmap

    elif allocator == AllocatorType.TCMALLOC:
        for sc in _TCMALLOC_SIZE_CLASSES:
            if sc >= requested_bytes:
                return sc
        return requested_bytes

    else:  # UNKNOWN
        return requested_bytes  # 保守: 使用原始请求大小


def is_write_safe(requested_bytes: int, write_bytes: int,
                  allocator: AllocatorType = AllocatorType.GLIBC_PTMALLOC2,
                  arch_bits: int = 64) -> Tuple[bool, str]:
    """判断写入大小是否在分配器实际提供的可用空间内。

    Returns:
      (is_safe, reason)
      is_safe=True → 写入不溢出, 此为误报
      is_safe=False → 确实溢出, 保留告警
    """
    effective = effective_chunk_size(requested_bytes, allocator, arch_bits)

    if write_bytes <= effective:
        return True, (
            f'write({write_bytes}B) <= effective_chunk({effective}B) '
            f'[requested={requested_bytes}B, {allocator.value}]'
        )
    else:
        return False, (
            f'write({write_bytes}B) > effective_chunk({effective}B) '
            f'[requested={requested_bytes}B, overflow={write_bytes - effective}B]'
        )


def apply_allocator_filter(
    findings: list,
    binary_path: str = "",
    arch_bits: int = 64,
) -> Tuple[list, Dict[str, int]]:
    """对堆溢出告警应用分配器感知过滤。

    每条finding需含: allocation_size, write_size (均为int或可转换)
    若 write_size <= effective_chunk_size(allocation_size) → 过滤

    Returns:
      (filtered_findings, stats)
    """
    allocator = detect_allocator(binary_path) if binary_path else AllocatorType.GLIBC_PTMALLOC2
    stats = {'total': len(findings), 'filtered': 0, 'retained': 0, 'skipped': 0}

    for f in findings:
        alloc_sz = f.get('allocation_size', f.get('estimated_size', -1))
        write_sz = f.get('write_size', f.get('overflow_bytes', -1))
        if alloc_sz <= 0 or write_sz <= 0:
            stats['skipped'] += 1
            continue

        safe, reason = is_write_safe(alloc_sz, write_sz, allocator, arch_bits)
        f['allocator_check'] = {'safe': safe, 'reason': reason, 'allocator': allocator.value}

        if safe:
            f['confidence'] = round(f.get('confidence', 0.5) * 0.30, 3)
            f['filter_reason'] = f'allocator-safe: {reason}'
            stats['filtered'] += 1
        else:
            stats['retained'] += 1

    return findings, stats
