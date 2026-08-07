"""
堆抽象域 —— 用区间抽象表示堆分配对象的状态空间。

DDAI-ASR 系统的第一层: 每个堆分配被抽象为一个三元组
  (base_ptr, offset_range, capacity)
其中 offset_range 是 Interval([low, high]), 表示对该块的所有
写入偏移的范围。capacity 是分配器实际提供的可用字节数。

若 ∀写入: offset_range.high < capacity → 安全 (FILTER)
若 ∃写入: offset_range.high ≥ capacity → 保留 (KEEP)

与现有IntervalAbstractor的差异:
  - 后者只追踪单个变量的[min,max], 无堆对象上下文
  - 本模块追踪(pointer → 分配大小 → 写入偏移)的完整关联链
  - 引入 MustAlias / MayAlias 区分, 避免保守合并导致的精度损失

  - Mine "Weakly Relational Numerical Abstract Domains"
  - Cheng et al. "Precise Sparse Abstract Execution via
    Cross-Domain Interaction" —— 地址×区间双向细化的思路
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple

class AliasClass(Enum):
    """别名类别 —— 决定合并精度。"""
    MUST = "must"    # 确定指向同一对象 (如直接的指针赋值)
    MAY = "may"      # 可能指向同一对象 (如通过条件分支)

@dataclass
class Interval:
    """整数区间 [low, high]; None 表示无界。"""
    low: Optional[int] = None
    high: Optional[int] = None

    @classmethod
    def constant(cls, v: int) -> "Interval":
        return cls(v, v)

    @classmethod
    def unbounded(cls) -> "Interval":
        return cls(None, None)

    @classmethod
    def upto(cls, hi: int) -> "Interval":
        return cls(None, hi)

    @property
    def is_finite(self) -> bool:
        return self.low is not None and self.high is not None

    def join(self, other: "Interval") -> "Interval":
        """最小上界 (∪) —— 用于控制流合并。"""
        lo = (min(self.low, other.low)
              if self.low is not None and other.low is not None
              else (self.low if other.low is None else other.low))
        hi = (max(self.high, other.high)
              if self.high is not None and other.high is not None
              else None)
        return Interval(lo, hi)

    def widen(self, other: "Interval") -> "Interval":
        """Widening ▽ —— 确保迭代收敛。若上界增长则跳到+∞。"""
        lo = self.low if self.low is not None and other.low is not None and self.low <= other.low else None
        hi = (None
              if self.high is not None and other.high is not None and other.high > self.high
              else self.high)
        return Interval(lo, hi)

    def meet(self, other: "Interval") -> "Interval":
        """最大下界 (∩) —— 约束求精。"""
        lo = (max(self.low, other.low)
              if self.low is not None and other.low is not None
              else (self.low or other.low))
        hi = (min(self.high, other.high)
              if self.high is not None and other.high is not None
              else (self.high or other.high))
        if lo is not None and hi is not None and lo > hi:
            return Interval(None, None)  # 空区间
        return Interval(lo, hi)

    def add_offset(self, offset_iv: "Interval") -> "Interval":
        lo = (self.low + offset_iv.low
              if self.low is not None and offset_iv.low is not None else None)
        hi = (self.high + offset_iv.high
              if self.high is not None and offset_iv.high is not None else None)
        return Interval(lo, hi)

    def __repr__(self) -> str:
        lo = str(self.low) if self.low is not None else "-∞"
        hi = str(self.high) if self.high is not None else "+∞"
        return f"[{lo}, {hi}]"

@dataclass
class HeapObject:
    """堆分配对象的抽象表示。"""
    ptr_var: str                # 指针变量名 (如 "buf")
    alloc_func: str             # malloc / calloc / realloc
    requested_size: int         # 代码中请求的字节数 (常量) 或 0 (变量)
    effective_size: int         # 分配器实际可用大小 (含对齐 + min_chunk)
    size_var: str = ""          # 若为变量大小, 记录变量名
    offset_range: Interval = field(default_factory=Interval.unbounded)
    is_freed: bool = False
    freed_at_line: int = -1

    @property
    def can_overflow(self) -> bool:
        """是否存在可能的溢出: offset_range.high >= effective_size。"""
        if self.offset_range.high is None:
            return True
        return self.offset_range.high >= self.effective_size

    @property
    def definitely_safe(self) -> bool:
        """确定安全: offset_range.high < effective_size。"""
        if self.offset_range.high is None:
            return False
        return self.offset_range.high < self.effective_size

class HeapAbstractDomain:
    """
    堆抽象域 —— 维护 (ptr_var → HeapObject) 的映射。

    对每条语句转移抽象状态:
      malloc:   创建新 HeapObject, offset_range = [0, 0]
      free:     标记 HeapObject.is_freed = True
      memcpy:   更新目标 HeapObject 的 offset_range
      store:    计算偏移范围并更新
      branch:   用条件约束求精 offset_range
    """

    def __init__(self, arch_bits: int = 64):
        self._objects: Dict[str, HeapObject] = {}
        self._arch_bits = arch_bits

    def clone(self) -> "HeapAbstractDomain":
        """深拷贝 —— 用于分支状态分叉。"""
        nd = HeapAbstractDomain(self._arch_bits)
        nd._objects = {
            k: HeapObject(
                ptr_var=v.ptr_var, alloc_func=v.alloc_func,
                requested_size=v.requested_size, effective_size=v.effective_size,
                size_var=v.size_var,
                offset_range=Interval(v.offset_range.low, v.offset_range.high),
                is_freed=v.is_freed, freed_at_line=v.freed_at_line,
            )
            for k, v in self._objects.items()
        }
        return nd

    def join(self, other: "HeapAbstractDomain") -> "HeapAbstractDomain":
        """合并两个分支状态 (φ-node)。"""
        nd = HeapAbstractDomain(self._arch_bits)
        all_keys = set(self._objects.keys()) | set(other._objects.keys())
        for k in all_keys:
            a = self._objects.get(k)
            b = other._objects.get(k)
            if a is None:
                nd._objects[k] = b.clone() if b else a  # type: ignore
            elif b is None:
                nd._objects[k] = a
            else:
                nd._objects[k] = HeapObject(
                    ptr_var=k, alloc_func=a.alloc_func,
                    requested_size=max(a.requested_size, b.requested_size),
                    effective_size=max(a.effective_size, b.effective_size),
                    size_var=a.size_var or b.size_var,
                    offset_range=a.offset_range.join(b.offset_range),
                    is_freed=a.is_freed or b.is_freed,
                    freed_at_line=max(a.freed_at_line, b.freed_at_line),
                )
        return nd

    # 转移函数 ──────────────────────────────────────────

    def alloc(self, ptr: str, func: str, size: int, effective: int,
              size_var: str = "") -> None:
        """处理 malloc/calloc 调用。"""
        self._objects[ptr] = HeapObject(
            ptr_var=ptr, alloc_func=func,
            requested_size=size, effective_size=effective,
            size_var=size_var, offset_range=Interval(0, 0),
        )

    def free(self, ptr: str, line_no: int = -1) -> None:
        """处理 free 调用 —— 标记已释放。"""
        if ptr in self._objects:
            self._objects[ptr].is_freed = True
            self._objects[ptr].freed_at_line = line_no

    def mem_write(self, ptr: str, offset: Interval, write_size: int) -> None:
        """处理 memcpy/strcpy/store —— 更新偏移范围。"""
        obj = self._resolve(ptr)
        if obj is None:
            return
        new_range = offset.add_offset(Interval.constant(write_size))
        obj.offset_range = obj.offset_range.join(new_range)

    def store_index(self, ptr: str, index_var: str, index_range: Interval) -> None:
        """处理 ptr[idx] = val —— 用 index 的区间更新偏移。"""
        obj = self._resolve(ptr)
        if obj is None:
            return
        obj.offset_range = obj.offset_range.join(index_range)

    def constrain_offset(self, ptr: str, max_offset: int) -> None:
        """用条件约束求精偏移 —— 如 if(idx < N) 则 idx ∈ [0, N-1]。"""
        obj = self._resolve(ptr)
        if obj is None:
            return
        obj.offset_range = obj.offset_range.meet(Interval(0, max_offset))

    # 查询 ──────────────────────────────────────────────

    def get_object(self, ptr: str) -> Optional[HeapObject]:
        return self._objects.get(ptr)

    def get_all_objects(self) -> Dict[str, HeapObject]:
        return dict(self._objects)

    def get_overflow_candidates(self) -> List[HeapObject]:
        """返回可能溢出的堆对象列表。"""
        return [o for o in self._objects.values()
                if o.can_overflow and not o.is_freed]

    def get_uaf_candidates(self) -> List[HeapObject]:
        """返回可能的 UAF 对象。"""
        return [o for o in self._objects.values()
                if o.is_freed and o.offset_range.high is not None
                and o.offset_range.high > 0]

    # 内部 ──────────────────────────────────────────────

    def _resolve(self, ptr: str) -> Optional[HeapObject]:
        """解析指针 —— 直接匹配或通过别名追踪。"""
        if ptr in self._objects:
            return self._objects[ptr]
        # 去除解引用运算符
        clean = ptr.lstrip("*& ")
        if clean in self._objects:
            return self._objects[clean]
        return None

def compute_effective_size(requested: int, platform: str = "x86_64",
                          allocator: str = "glibc") -> int:
    """从请求大小计算分配器实际可用字节数。

    glibc ptmalloc2 (x86_64):
      chunk_size = max(0x20, (req + 8 + 0xF) & ~0xF)
      usable = chunk_size - 8
    """
    if allocator == "jemalloc":
        classes = [8, 16, 32, 48, 64, 80, 96, 112, 128, 160, 192, 224, 256,
                   320, 384, 448, 512, 640, 768, 896, 1024, 1280, 1536, 1792,
                   2048, 2560, 3072, 3584, 4096, 5120, 6144, 7168, 8192,
                   10240, 12288, 14336, 16384]
        for sc in classes:
            if sc >= requested:
                return sc
        return requested
    if allocator == "tcmalloc":
        classes = [8, 16, 32, 48, 64, 80, 96, 112, 128, 144, 160, 176, 192,
                   208, 224, 240, 256, 288, 320, 352, 384, 416, 448, 480, 512,
                   576, 640, 704, 768, 832, 896, 960, 1024]
        for sc in classes:
            if sc >= requested:
                return sc
        return requested

    # glibc ptmalloc2
    if platform in ("x86_64", "arm64", "aarch64"):
        min_chunk, overhead = 0x20, 8
    else:
        min_chunk, overhead = 0x10, 4
    chunk_size = max(min_chunk, (requested + overhead + 0xF) & ~0xF)
    return max(0, chunk_size - overhead)

__all__ = [
    'AliasClass', 'Interval', 'HeapObject', 'HeapAbstractDomain',
    'compute_effective_size',
]
