# coding: utf-8
"""
堆分配器轻量抽象解释 — 用抽象域模拟堆操作, 检测不变式违反.

HeapMD 用双轨运行时架构做异常检测, 但需要执行二进制.
本模块在静态分析阶段构建抽象堆模型: 将 malloc/free 序列解释为对
抽象域的操作, 在不执行代码的前提下检测 double-free/invalid-free/UAF.

抽象域组成:
  size_class — 大小类分区 (每个大小类维护 alloc/free 计数和自由槽)
  pointer_set — 活跃指针的抽象集合 (每个指针关联其 size_class)
  invariant — 不变式集合:
    - 同一指针不能被 free 两次 (double-free)
    - free 的对象不能再次被使用 (UAF, 需调用方提供 use 事件)
    - alloc 和 free 的大小类必须匹配 (size mismatch)

与 heap_analyzer.py 的关系: 本模块替代现有的字符串精确匹配风水检测,
提供形式化的堆状态机, 对 API 名称变化和事件序列扰动不敏感.
"""

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class AbstractChunk:
    """堆块的抽象表示 — 不跟踪具体地址, 只跟踪大小类和分配计数."""
    size_class: int       # 归一化大小类 (如 32, 64, 128...)
    alloc_count: int = 0  # 当前活跃分配数
    free_count: int = 0   # 累计释放数
    max_concurrent: int = 0  # 峰值并发分配数

    @property
    def active(self) -> int:
        return self.alloc_count - self.free_count


@dataclass
class Violation:
    """抽象域中的不变式违反记录."""
    violation_type: str   # 'double_free' | 'invalid_free' | 'size_mismatch' | 'potential_uaf'
    detail: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.8


class AbstractHeapModel:
    """堆的轻量静态抽象模型.

    用法:
      model = AbstractHeapModel()
      model.on_alloc(ptr_id='p1', size=128)
      model.on_free(ptr_id='p1')
      model.on_free(ptr_id='p1')  # → double-free violation
      violations = model.flush_violations()
    """

    # 大小类映射: 将任意 size 归一到最近的 slab 大小
    _SIZE_CLASSES = [16, 32, 48, 64, 96, 128, 192, 256, 384, 512,
                     768, 1024, 1536, 2048, 3072, 4096, 8192]

    def __init__(self):
        self._chunks: Dict[int, AbstractChunk] = {}      # size_class → chunk
        self._ptr_map: Dict[str, int] = {}               # ptr_id → size_class
        self._freed_ptrs: Set[str] = set()               # 已释放但可能被重用的指针
        self._violations: List[Violation] = []
        self._event_count = 0

# 公开 API
    def on_alloc(self, ptr_id: str, size: int,
                 call_addr: int = 0, **meta) -> Optional[Violation]:
        """注册一次分配操作."""
        self._event_count += 1
        sc = self._to_size_class(size)
        if sc not in self._chunks:
            self._chunks[sc] = AbstractChunk(size_class=sc)

        chunk = self._chunks[sc]
        chunk.alloc_count += 1
        chunk.max_concurrent = max(chunk.max_concurrent, chunk.active)

        # 检测: 同一 ptr_id 被重复 alloc 而未 free (potential leak)
        if ptr_id in self._ptr_map and ptr_id not in self._freed_ptrs:
            # 未释放就重新分配 → 前一个对象泄漏
            pass  # 在静态分析中不强制报错 (可能是复用变量)

        self._ptr_map[ptr_id] = sc
        self._freed_ptrs.discard(ptr_id)
        return None

    def on_free(self, ptr_id: str, call_addr: int = 0,
                freed_size: int = 0, **meta) -> Optional[Violation]:
        """注册一次释放操作, 检测 double-free."""
        self._event_count += 1
        sc = self._ptr_map.get(ptr_id)

        # 检测 1: double-free — 指针已在 freed 集合中
        if ptr_id in self._freed_ptrs:
            v = Violation('double_free',
                f'指针 {ptr_id} 被重复释放 (首次释放后未重新分配)',
                {'ptr_id': ptr_id, 'call_addr': call_addr}, confidence=0.95)
            self._violations.append(v)
            return v

        # 检测 2: invalid free — 释放了从未分配的指针
        if sc is None:
            v = Violation('invalid_free',
                f'释放了未跟踪的指针 {ptr_id} (可能来自其他分配器或栈对象)',
                {'ptr_id': ptr_id, 'call_addr': call_addr}, confidence=0.7)
            self._violations.append(v)
            return v

        # 检测 3: size mismatch — 释放大小与分配时不匹配
        if freed_size > 0:
            expected_sc = self._to_size_class(freed_size)
            if expected_sc != sc:
                v = Violation('size_mismatch',
                    f'释放大小 (class={expected_sc}) 与分配时 (class={sc}) 不一致',
                    {'ptr_id': ptr_id, 'alloc_class': sc, 'free_class': expected_sc},
                    confidence=0.6)
                self._violations.append(v)

        chunk = self._chunks.get(sc)
        if chunk:
            chunk.free_count += 1

        self._freed_ptrs.add(ptr_id)
        return None

    def on_use(self, ptr_id: str, use_addr: int = 0, **meta) -> Optional[Violation]:
        """注册一次指针解引用, 检测 UAF (use-after-free)."""
        if ptr_id in self._freed_ptrs:
            v = Violation('potential_uaf',
                f'指针 {ptr_id} 在释放后仍被使用 (UAF)',
                {'ptr_id': ptr_id, 'use_addr': use_addr}, confidence=0.85)
            self._violations.append(v)
            return v
        return None

    def check_dangling(self) -> List[Violation]:
        """返回当前所有悬垂指针 (已释放但未重新分配)."""
        result = []
        for ptr_id in self._freed_ptrs:
            sc = self._ptr_map.get(ptr_id, 0)
            # 仅当同一大小类的分配计数不足以覆盖释放时, 标记为悬垂
            chunk = self._chunks.get(sc)
            if chunk and chunk.active > 0:
                continue  # 有其他分配在使用此大小类 → 可能被重用
            result.append(Violation('potential_uaf',
                f'悬垂指针 {ptr_id} 指向已释放的大小类 {sc}, 且该大小类无活跃分配',
                {'ptr_id': ptr_id, 'size_class': sc}, confidence=0.5))
        return result

# 查询
    def size_class_stats(self) -> Dict[int, Dict[str, int]]:
        return {
            sc: {'active': c.active, 'total_alloc': c.alloc_count,
                 'total_free': c.free_count, 'peak': c.max_concurrent}
            for sc, c in self._chunks.items()
        }

    def flush_violations(self) -> List[Violation]:
        v = list(self._violations)
        self._violations.clear()
        return v

    def probable_allocator(self) -> str:
        """根据大小类分布推断可能的分配器类型."""
        sizes = sorted(self._chunks.keys())
        if not sizes:
            return 'unknown'
        # slab 特征: 大小类严格按 2^n 分布, 最大值 < 4096
        is_slab = all(
            sizes[i] * 2 >= sizes[i+1] for i in range(len(sizes)-1)
        ) and max(sizes) <= 8192
        if is_slab and len(sizes) >= 4:
            return 'kernel_slab' if 8 in sizes else 'glibc_ptmalloc'
        # 大块为主 → arena/buddy
        if any(s >= 0x10000 for s in sizes):
            return 'arena_based'
        return 'generic'

    @classmethod
    def _to_size_class(cls, size: int) -> int:
        for sc in cls._SIZE_CLASSES:
            if size <= sc:
                return sc
        # 超过最大类: 向上取整到 4096 倍数
        return ((size + 4095) // 4096) * 4096
