# analysis/heap_layout_model — glibc/ptmalloc2 堆分配器行为建模
# 将分配器的内部约束 (对齐、最小chunk、元数据开销) 纳入静态分析,
# 以精确判定"分配 N 字节时实际可用空间至少/至多是 M 字节"。
#
# 核心问题:
#   malloc(N) 不意味着恰好分配 N 字节。glibc 会:
#   1. 对齐到 MALLOC_ALIGNMENT (x86_64: 16, i386: 8)
#   2. 保证最小 chunk 大小 (MINSIZE = 32 on x86_64)
#   3. chunk header 占用 16 字节 (prev_size + size)
#   4. 可能从更大的 free chunk 中切分, 导致实际可用空间 > N
#
# 这意味着: 静态分析判定 "memcpy(buf, src, N+4) 溢出" 时,
# 若 N=28, malloc(28) 实际返回 32-16=16 字节可用空间?
# 不对: malloc(28) → chunk_size = align_up(28+8, 16) = 48,
# 用户可用 = 48 - 16 = 32 字节。所以 memcpy(buf, src, 29) 不会溢出。
# 若忽略此对齐, 会产生大量误报。
#

from __future__ import annotations
from typing import Dict, List, Tuple, Optional
import sys

class AllocatorModel:
    """抽象分配器模型: 给定请求大小, 返回有效用户可用空间的范围。

    不同平台的参数不同:
    - x86_64 (glibc): align=16, min_chunk=32, header=16
    - i386 (glibc):   align=8,  min_chunk=16, header=8
    - ARM32 (glibc):  align=8,  min_chunk=16, header=8
    - Win32 (HeapAlloc): align=8, min_chunk=24 (approximate)

    header 占用: prev_size(word) + size(word) on 32-bit, 2*word each on 64-bit
    """

    def __init__(self, word_size: int = 8, alignment: int = 16,
                 min_chunk_size: int = 32):
        self.word_size = word_size
        self.alignment = alignment
        self.min_chunk_size = min_chunk_size
        # 用户最小可用空间
        self.min_user_size = min_chunk_size - 2 * word_size

    @classmethod
    def x86_64(cls) -> "AllocatorModel":
        return cls(word_size=8, alignment=16, min_chunk_size=32)

    @classmethod
    def i386(cls) -> "AllocatorModel":
        return cls(word_size=4, alignment=8, min_chunk_size=16)

    @classmethod
    def auto(cls, checksec: Dict = None) -> "AllocatorModel":
        """根据 checksec 信息自动选择分配器模型。"""
        arch = (checksec or {}).get("arch", "x86_64")
        if arch in ("i386", "x86", "arm32", "arm"):
            return cls.i386()
        return cls.x86_64()

    def requested_to_chunk_size(self, request: int) -> int:
        """用户请求 → chunk 整体大小 (含 header)。"""
        # 公式: chunk_size = max(MINSIZE, (request + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK)
        mask = self.alignment - 1
        min_req = request + self.word_size  # + SIZE_SZ
        padded = (min_req + mask) & ~mask
        return max(self.min_chunk_size, padded)

    def usable_size_min(self, request: int) -> int:
        """用户请求 N 字节时, 最小的可用用户空间。"""
        chunk = self.requested_to_chunk_size(request)
        return max(self.min_user_size, chunk - 2 * self.word_size)

    def usable_size_max(self, request: int) -> int:
        """用户请求 N 字节时, 最大的可用用户空间。
        因为 chunk 可能从更大的 free chunk 切分, 只保证最小值。
        上限 = 下一个 bin 大小阈值 - 1。保守返回 + alignment。"""
        return self.usable_size_min(request) + self.alignment

    def check_overflow_under_alignment(self, alloc_request: int,
                                        write_size: int) -> Tuple[bool, float, str]:
        """精确检查: 给定分配请求值和写入量, 考虑分配器对齐后是否溢出。

        返回: (is_overflow, confidence, reason)
        """
        usable_min = self.usable_size_min(alloc_request)

        if write_size <= usable_min:
            return (False, 0.03,
                    f"写入{write_size}B ≤ 对齐后可用空间{usable_min}B"
                    f"(请求{alloc_request}B)→安全")

        # 写入量超过最小可用空间 → 检查是否在最大可用空间内
        usable_max = self.usable_size_max(alloc_request)
        if write_size <= usable_max:
            return (False, 0.12,
                    f"写入{write_size}B ≤ 最大可用{usable_max}B"
                    f"(请求{alloc_request}B, 对齐余量)→可能安全")

        # 明确溢出
        overflow_bytes = write_size - usable_min
        return (True, 0.88 - min(overflow_bytes / 1024.0, 0.30),
                f"写入{write_size}B > 对齐后最小可用{usable_min}B"
                f"(溢出{overflow_bytes}B)→高置信溢出")

    def compute_safe_write_limit(self, alloc_request: int) -> int:
        """给定分配请求, 返回保证安全的写入上限 (字节数)。"""
        return self.usable_size_min(alloc_request)

# 全局单例, 按平台缓存
_MODEL_CACHE: Dict[str, AllocatorModel] = {}

def get_allocator_model(arch: str = "x86_64") -> AllocatorModel:
    if arch not in _MODEL_CACHE:
        if arch in ("i386", "x86", "arm32", "arm"):
            _MODEL_CACHE[arch] = AllocatorModel.i386()
        else:
            _MODEL_CACHE[arch] = AllocatorModel.x86_64()
    return _MODEL_CACHE[arch]

def model_multi_alloc(alloc_sites: Dict[str, int],
                      write_sites: Dict[str, int]) -> List[Dict]:
    """批量建模: 对多个分配-写入对同时评估。

    alloc_sites: {buffer_name: alloc_request_size}
    write_sites: {buffer_name: write_size}
    返回每个配对的风险评估。
    """
    model = AllocatorModel.x86_64()
    results = []
    for buf, alloc_req in alloc_sites.items():
        write_sz = write_sites.get(buf)
        if write_sz is None:
            continue
        overflow, conf, reason = model.check_overflow_under_alignment(
            alloc_req, write_sz)
        results.append({
            "buffer": buf,
            "alloc_request": alloc_req,
            "write_size": write_sz,
            "usable_min": model.usable_size_min(alloc_req),
            "usable_max": model.usable_size_max(alloc_req),
            "overflow": overflow,
            "confidence": round(conf, 2),
            "reason": reason,
        })
    return results
