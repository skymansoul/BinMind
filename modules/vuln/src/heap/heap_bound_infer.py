"""堆边界推断器 — 区间抽象域 + malloc/free 边界追踪.

创建: 2025-03-03 15:22
用途: 对 malloc(n) 的返回值建立区间抽象域, 追踪 *(ptr+offset) 的 offset 与 n 的关系,
      检测 offset >= n 的越界访问。

设计决策:
  - 为什么用区间抽象域而非完整的多面体域: 多面体域 O(n³) 对二进制级分析不可行。
    区间域 O(n) 且对堆溢出检测足够——大多数溢出是简单的 offset>size 问题。
  - 与 Cod 的区别: Cod 做 heap disjointness 需要源码级指针分析,
    本模块做单二进制轻量版——不需要精确的别名信息, 对无法确定指针目标的场景保守放弃。
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class IntervalDomain:
    """区间抽象域: [lo, hi]."""
    lo: int = 0
    hi: int = 0

    def contains(self, val: int) -> bool:
        return self.lo <= val <= self.hi

    def union(self, other: 'IntervalDomain') -> 'IntervalDomain':
        return IntervalDomain(min(self.lo, other.lo), max(self.hi, other.hi))

    def add_constant(self, c: int) -> 'IntervalDomain':
        return IntervalDomain(self.lo + c, self.hi + c)

    def width(self) -> int:
        return self.hi - self.lo + 1


@dataclass
class HeapAccess:
    """一次堆内存访问."""
    insn_addr: int = 0
    base_ptr: str = ''
    offset_expr: str = ''
    access_size: int = 0
    function_name: str = ''
    is_write: bool = False


class HeapBoundInferrer:
    """堆边界推断器 — 静态分析 malloc 返回值的合法范围.

    对每个 malloc(n) 调用点:
      - base_ptr → IntervalDomain(0, n-1)
      - 追踪 base_ptr + constant 的传播
      - 对 *(base_ptr + offset) 检查 offset in [0, n-1]

    使用方式:
      inferrer = HeapBoundInferrer()
      inferrer.register_malloc(0x401000, 'rax', 256)
      inferrer.register_access(HeapAccess(0x401020, 'rax', '0x100', 4, 'vuln_fn'))
      violations = inferrer.check_all()
    """

    def __init__(self):
        self._allocations: Dict[int, Tuple[str, int]] = {}
        self._bounds: Dict[str, IntervalDomain] = {}
        self._accesses: List[HeapAccess] = []
        self._violations: List[Tuple[HeapAccess, int, str]] = []

    def register_malloc(self, insn_addr: int, ptr_name: str,
                        alloc_size: int) -> None:
        """注册 malloc(n) 调用."""
        if alloc_size <= 0:
            return
        self._allocations[insn_addr] = (ptr_name, alloc_size)
        self._bounds[ptr_name] = IntervalDomain(0, alloc_size - 1)

    def register_access(self, access: HeapAccess) -> None:
        """注册堆访问并即时检查越界."""
        self._accesses.append(access)
        bound = self._bounds.get(access.base_ptr)
        if bound is None:
            return
        offset = self._parse_offset(access.offset_expr)
        if offset is None:
            return
        start = offset
        end = offset + access.access_size - 1
        if not bound.contains(start) or not bound.contains(end):
            self._violations.append(
                (access, offset,
                 f'heap overflow: *({access.base_ptr}+{offset}) '
                 f'exceeds [{bound.lo}, {bound.hi}] '
                 f'in {access.function_name}'))

    def check_all(self) -> List[Tuple[HeapAccess, int, str]]:
        """返回所有检测到的越界访问."""
        return list(self._violations)

    @staticmethod
    def _parse_offset(expr: str) -> Optional[int]:
        """解析偏移表达式为整数."""
        expr = expr.strip()
        try:
            return int(expr, 0)
        except ValueError:
            pass
        if '+' in expr:
            parts = expr.split('+')
            try:
                return sum(int(p.strip(), 0) for p in parts
                          if p.strip().startswith(('0x', '0')) or p.strip().isdigit())
            except ValueError:
                pass
        return 0

    def stats(self) -> dict:
        return {
            'n_allocations': len(self._allocations),
            'n_accesses': len(self._accesses),
            'n_violations': len(self._violations),
            'rate': len(self._violations) / max(1, len(self._accesses)),
        }

    def clear(self) -> None:
        self._allocations.clear()
        self._bounds.clear()
        self._accesses.clear()
        self._violations.clear()
