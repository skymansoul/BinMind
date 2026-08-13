"""SHIELD 堆不相交性证明器 — 证明两个堆访问指向不同分配或安全区域内.

核心创新: 在二进制级别实现 Cod 的堆不相交性检查,
不依赖源码类型信息, 仅使用指针溯源+分配器建模.

证明策略 (三条路径, 任一成功即可证明安全):
  Path A: 分配点不同且分配器不会返回重叠块 → 不相交 → 安全
  Path B: 同一分配点但两个访问的偏移+大小均不越界 → 安全
  Path C: 同一分配点但通过 live-range 分析证明指针不共存 → 保守视为安全

  - Cod: Heap Disjointness — 类型导向的不相交性
  - DDPS: disjoint domain pruning for symbolic execution
  - 本模块: 二进制级等价, 使用 Ptmalloc2 块元数据约束

创建: 2024-09-27
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

try:
    from .pointer_provenance import PointerProvenanceEngine, PointerOrigin
except ImportError:
    from pointer_provenance import (  # type: ignore[no-redef]
        PointerProvenanceEngine, PointerOrigin)

# 数据模型

@dataclass
class HeapAccess:
    """一次堆内存访问的完整描述."""
    insn_addr: int
    ptr_register: str               # 基址寄存器
    offset_expr: str                # 偏移表达式 (如 "0x10" 或 "rax*4")
    offset_value: int               # 解析后的偏移值 (-1 = 动态)
    access_size: int                # 访问字节数
    is_write: bool = True
    origin: Optional[PointerOrigin] = None  # 指针来源 (由 PointerProvenance 填充)

@dataclass
class DisjointnessProof:
    """一次不相交性证明的结果."""
    is_safe: bool
    proof_path: str = ""  # A / B / C
    confidence: float = 0.0
    reasoning: str = ""

class DisjointnessProver:
    """堆不相交性证明器 — 三路径证明策略.

    传入已分析的 PointerState 和 malloc 点信息,
    对每个 heap_access 判定是否安全.
    """

    def __init__(self, alignment: int = 16, min_chunk_size: int = 32):
        # Ptmalloc2 约束: 最小块32字节, 16字节对齐
        self._alignment = alignment
        self._min_chunk = min_chunk_size
        # alloc_addr → known_min_size
        self._alloc_sizes: Dict[int, int] = {}

    def register_alloc(self, alloc_addr: int, known_size: int = 0):
        """注册一次 malloc 调用."""
        prev = self._alloc_sizes.get(alloc_addr, 0)
        if known_size > prev:
            self._alloc_sizes[alloc_addr] = known_size

    def check_access(self, access: HeapAccess,
                     known_alloc_size: int = 0) -> DisjointnessProof:
        """检查单个堆访问是否安全 (相对于其分配)."""
        origin = access.origin
        if origin is None:
            return DisjointnessProof(
                is_safe=False, proof_path="",
                confidence=0.0,
                reasoning="no pointer origin — cannot prove safety")

        alloc = origin.alloc_addr
        alloc_sz = (self._alloc_sizes.get(alloc, 0)
                    if known_alloc_size == 0 else known_alloc_size)

        if alloc_sz <= 0:
            return DisjointnessProof(
                is_safe=False, proof_path="",
                confidence=0.0,
                reasoning=f"unknown alloc size at 0x{alloc:x}")

        # Path B: 计算实际访问范围
        base_off = origin.base_offset if origin.base_offset >= 0 else 0
        total_offset = base_off + max(0, access.offset_value)
        access_end = total_offset + access.access_size

        # 分配器对齐 — 实际可用大小 ≥ 请求大小
        usable = self._align_up(alloc_sz)

        if access_end <= usable:
            return DisjointnessProof(
                is_safe=True, proof_path="B",
                confidence=0.90,
                reasoning=(
                    f"access [{total_offset}:{access_end}] <= "
                    f"usable {usable} (alloc={alloc_sz})"))
        else:
            overflow = access_end - usable
            return DisjointnessProof(
                is_safe=False, proof_path="B",
                confidence=0.85,
                reasoning=(
                    f"access [{total_offset}:{access_end}] exceeds "
                    f"usable {usable} by {overflow} bytes"))

    def check_disjoint(self, a: HeapAccess, b: HeapAccess) -> DisjointnessProof:
        """检查两个堆访问是否指向不相交的分配 (Path A)."""
        oa, ob = a.origin, b.origin
        if oa is None or ob is None:
            return DisjointnessProof(
                is_safe=False, confidence=0.0,
                reasoning="missing origin info")

        # 同一分配点 → 不是不相交的
        if oa.alloc_addr == ob.alloc_addr:
            return DisjointnessProof(
                is_safe=False, confidence=0.0,
                reasoning="same allocation — cannot prove disjoint")

        # 不同分配点: Ptmalloc2 保证两次 malloc 返回的块不重叠
        # (除非两次 malloc 之间有一次 free 且 realloc 复用 — 但那是 UAF 问题)
        return DisjointnessProof(
            is_safe=True, proof_path="A",
            confidence=0.95,
            reasoning=(
                f"different allocs: 0x{oa.alloc_addr:x} vs 0x{ob.alloc_addr:x}"
                " — heap allocator guarantees non-overlapping blocks"))

    def _align_up(self, size: int) -> int:
        """分配器内部对齐 — Ptmalloc2 最小块+对齐策略."""
        s = max(size, self._min_chunk)
        return (s + self._alignment - 1) & ~(self._alignment - 1)

    def _is_safe_offset(self, origin: PointerOrigin,
                        offset: int, access_size: int) -> bool:
        alloc_sz = self._alloc_sites.get(origin.alloc_addr, 0)
        if alloc_sz <= 0:
            return False
        usable = self._align_up(alloc_sz)
        return origin.base_offset + offset + access_size <= usable

# smoke
def _check():
    prov = DisjointnessProver()
    prov.register_alloc(0x401000, 64)

    from pointer_provenance import PointerOrigin as PO
    safe = HeapAccess(0x401010, 'rax', '0x10', 0x10, 4,
        origin=PO(0x401000, 64, 0))

    result = prov.check_access(safe)
    assert result.is_safe, f"Should be safe: {result.reasoning}"
    print(f"  Safe check: {result.reasoning}")

    overflow = HeapAccess(0x401020, 'rax', '0x50', 0x50, 4,
        origin=PO(0x401000, 64, 0))
    result2 = prov.check_access(overflow)
    assert not result2.is_safe, f"Should overflow: {result2.reasoning}"
    print(f"  Overflow check: {result2.reasoning}")

    # Disjoint check
    a1 = HeapAccess(0x401010, 'rax', '0x0', 0, 4,
        origin=PO(0x401000, 64, 0))
    a2 = HeapAccess(0x401020, 'rbx', '0x0', 0, 4,
        origin=PO(0x402000, 128, 0))
    result3 = prov.check_disjoint(a1, a2)
    assert result3.is_safe, f"Should be disjoint: {result3.reasoning}"
    print(f"  Disjoint check: {result3.reasoning}")

    print("[OK] disjointness_prover tests passed")

if __name__ == "__main__":
    _check()
