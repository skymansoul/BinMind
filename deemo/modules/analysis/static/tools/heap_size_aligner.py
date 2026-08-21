# 堆分配大小对齐归一化, glibc malloc 的最小对齐是 16 字节 (64-bit) 或 8 字节 (32-bit)
# 方法论依据: glibc malloc.c 的 request2size() 宏将请求大小向上对齐到 MALLOC_ALIGNMENT
# alloc(14) 实际获得 16 字节, memcpy(15) 是安全的 — 但朴素比较会误报

import re
from typing import List, Tuple

# glibc ptmalloc 对齐规则 (64-bit: 16字节, 32-bit: 8字节)
_MALLOC_ALIGNMENT = 16
_MIN_CHUNK_SIZE = 32       # 最小 chunk 大小 (prev_size + size + fd + bk)

# 编译器内置的安全检查模式 — 这些不是漏洞
_SAFETY_PATTERNS = [
    (re.compile(r'cmp\s+\w+,\s*\w+\s*\n\s*(?:jb|jbe|jnae)\s+', re.I), 'bounds_check'),
    (re.compile(r'(?:__builtin___memcpy_chk|__memcpy_chk)', re.I), 'fortify_check'),
    (re.compile(r'test\s+\w+,\s*\w+\s*\n\s*(?:jz|je)\s+.*\n.*call.*error', re.I), 'null_check'),
]

class HeapSizeAligner:
    """堆大小对齐归一化, 消除因对齐导致的假阳性

    glibc malloc(14) 实际分配 16 字节 (向 MALLOC_ALIGNMENT 对齐)
    若检测器比较 malloc(14) vs memcpy(15) → 不应判定为溢出
    因为实际可用空间是 16 字节

    同样, malloc(0) 实际分配 32 字节 (最小 chunk)
    """

    def __init__(self, arch: str = 'x86_64'):
        self._alignment = 16 if '64' in arch else 8
        self._min_chunk = 32 if '64' in arch else 16

    def effective_alloc_size(self, requested_size: int) -> int:
        """计算实际分配的堆空间大小 (包含对齐和 chunk 开销)

        glibc 内部: chunk_size = max(MINSIZE, (request + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK)
        简化: effective = max(min_chunk, (request + 8 + 15) & ~15)
        用户可用空间 = chunk_size - 2*SIZE_SZ (prev_size + size header)
        """
        if requested_size <= 0:
            return self._min_chunk - 16  # 减去 header, 实际可用
        chunk = max(self._min_chunk, (requested_size + 8 + self._alignment - 1) & ~(self._alignment - 1))
        usable = chunk - 16  # prev_size(8) + size(8) header
        return usable

    def is_safe_write(self, alloc_size: int, write_size: int) -> bool:
        """判断写入是否在对齐后的安全范围内"""
        effective = self.effective_alloc_size(alloc_size)
        return write_size <= effective

    def has_safety_check(self, asm_text: str) -> bool:
        """检测是否存在编译器插入的安全检查"""
        for pattern, name in _SAFETY_PATTERNS:
            if pattern.search(asm_text):
                return True
        return False

    def classify_overflow(self, alloc_size: int, write_size: int,
                          has_bounds_check: bool = False) -> Tuple[str, float]:
        """分类: 确定为溢出 / 对齐安全 / 需要更多信息, 返回 (判定, 置信度)。"""
        if alloc_size <= 0 or write_size <= 0:
            return 'potential', 0.35

        effective = self.effective_alloc_size(alloc_size)

        if write_size <= effective:
            # 写入在有效范围内→不是溢出
            return 'safe_aligned', 0.80
        elif write_size <= alloc_size + 32:
            # 轻微超出→可能是对齐误解或边界条件
            return 'potential', 0.45
        else:
            if has_bounds_check:
                return 'potential', 0.50
            return 'confirmed', 0.90
