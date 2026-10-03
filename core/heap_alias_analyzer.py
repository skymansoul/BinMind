"""
堆别名分析 — 面向堆域的轻量级 Andersen 包含式指针分析。
追踪指针赋值与算术, 计算各指针变量的指向集, 将 memcpy 目标与分配基址关联,
从而判定写入范围是否超出分配。域不敏感/流不敏感/函数内, 栈与全局指针视为 ⊤。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

# 指向集数据结构 ────────────────────────────────────────

@dataclass
class HeapObject:
    """抽象堆对象 —— 在单个分配点创建。"""
    obj_id: int
    alloc_site_line: int
    alloc_func: str        # malloc / calloc / realloc
    base_name: str         # 接收指针的变量名

@dataclass
class PointsToSet:
    """指针变量的指向集: 基对象 + 整数偏移区间。"""
    base: str              # 基变量名 ('' 表示 ⊤)
    offset_min: int        # 相对基址的偏移下界
    offset_max: int        # 相对基址的偏移上界

    @staticmethod
    def unknown() -> "PointsToSet":
        return PointsToSet(base='', offset_min=0, offset_max=2**63 - 1)

    @staticmethod
    def exact(base: str, offset: int = 0) -> "PointsToSet":
        return PointsToSet(base=base, offset_min=offset, offset_max=offset)

    @property
    def is_unknown(self) -> bool:
        return self.base == ''

    def offset_by(self, delta: int) -> "PointsToSet":
        if self.is_unknown:
            return self
        return PointsToSet(
            base=self.base,
            offset_min=self.offset_min + delta,
            offset_max=self.offset_max + delta)

    def may_same_base(self, other: "PointsToSet") -> bool:
        return (not self.is_unknown and not other.is_unknown
                and self.base == other.base)

    def effective_write_range(self, write_size: int) -> Tuple[int, int]:
        """返回经该指针写入的字节区间 [start, end)。"""
        if self.is_unknown:
            return (0, 2**63 - 1)
        return (self.offset_min, self.offset_max + write_size)

    def __repr__(self) -> str:
        if self.is_unknown:
            return "⊤"
        off = (f"+{self.offset_min}" if self.offset_min == self.offset_max
               else f"+[{self.offset_min},{self.offset_max}]")
        return f"{self.base}{off}"

# 模式匹配宏 ──────────────────────────────────────────

# var = malloc(N) → 堆对象
_PTR_ALLOC_RE = re.compile(
    r'(\w[\w.]*)\s*=\s*(?:\(\s*\w+\s*\*?\s*\)\s*)?'
    r'(malloc|calloc|realloc)\s*\(')

# var = base + offset → 指针算术
_PTR_ADD_RE = re.compile(r'(\w[\w.]*)\s*=\s*(\w[\w.]*)\s*\+\s*(\d+)')

# var = &base[offset] → 数组元素地址
_PTR_IDX_RE = re.compile(r'(\w[\w.]*)\s*=\s*&(\w[\w.]*)\[(\d+)\]')

# var = base → 简单指针复制
_PTR_COPY_RE = re.compile(r'(\w[\w.]*)\s*=\s*(\w[\w.]*)\s*$')

# 指针写入: *var = val / var[idx] = val
_PTR_STORE_RE = re.compile(
    r'(?:memcpy|strcpy|strncpy|__memcpy_chk)\s*\(\s*(\w[\w.]*)\s*,'
    r'|(\w[\w.]*)\[(\d+)\]\s*=')

@dataclass
class AliasResult:
    """单个指针变量的别名分析结果。"""
    var_name: str
    points_to: PointsToSet
    definition_line: int
    is_heap_derived: bool   # ultimately derived from malloc/calloc/realloc

class HeapAliasAnalyzer:
    """轻量级函数内堆指针别名分析。"""

    def __init__(self):
        self._heap_objects: Dict[str, HeapObject] = {}
        self._points_to: Dict[str, PointsToSet] = {}
        self._obj_counter: int = 0

    def analyze(self, ir_lines: List[str]) -> Dict[str, PointsToSet]:
        """单趟分析: 提取堆对象并追踪指针流向, 返回全部已追踪指针的 {变量→指向集}。"""
        self._heap_objects = {}
        self._points_to = {}
        self._obj_counter = 0

        for i, line in enumerate(ir_lines):
            stripped = line.strip()

            # 分配: ptr = malloc(N)
            m = _PTR_ALLOC_RE.search(stripped)
            if m:
                ptr_var = m.group(1)
                alloc_func = m.group(2)
                self._obj_counter += 1
                obj = HeapObject(
                    obj_id=self._obj_counter,
                    alloc_site_line=i,
                    alloc_func=alloc_func,
                    base_name=ptr_var,
                )
                self._heap_objects[ptr_var] = obj
                self._points_to[ptr_var] = PointsToSet.exact(ptr_var, 0)
                continue

            # 指针算术: dst = base + offset
            m = _PTR_ADD_RE.search(stripped)
            if m:
                dst = m.group(1)
                base = m.group(2)
                delta = int(m.group(3))
                if base in self._points_to:
                    pt = self._points_to[base]
                    self._points_to[dst] = pt.offset_by(delta)
                continue

            # 数组索引: dst = &base[idx]
            m = _PTR_IDX_RE.search(stripped)
            if m:
                dst = m.group(1)
                base = m.group(2)
                idx = int(m.group(3))
                if base in self._points_to:
                    pt = self._points_to[base]
                    # 保守处理: idx 是本行内的常量偏移
                    self._points_to[dst] = pt.offset_by(idx)
                continue

            # 指针复制: dst = base
            m = _PTR_COPY_RE.match(stripped)
            if m:
                dst = m.group(1)
                base = m.group(2)
                if base in self._points_to and base != dst:
                    self._points_to[dst] = self._points_to[base]
                continue

        return self._points_to

    def resolve(self, var_name: str) -> PointsToSet:
        """将变量解析为指向集。"""
        return self._points_to.get(var_name, PointsToSet.unknown())

    def get_aliases(self, var_name: str) -> List[str]:
        """查找与 var_name 可能互为别名的全部变量。"""
        target = self.resolve(var_name)
        if target.is_unknown:
            return []

        aliases = []
        for v, pt in self._points_to.items():
            if v != var_name and pt.base == target.base:
                aliases.append(v)
        return aliases

    def compute_write_range(
        self, var_name: str, write_size: int,
    ) -> Tuple[int, int]:
        """计算经 var_name 写入的字节区间 [start, end)。"""
        pt = self.resolve(var_name)
        return pt.effective_write_range(write_size)

    def stats(self) -> Dict:
        return {
            'heap_objects': len(self._heap_objects),
            'tracked_pointers': len(self._points_to),
            'obj_counter': self._obj_counter,
        }

def analyze_heap_aliases(
    ir_lines: List[str],
) -> Tuple[Dict[str, PointsToSet], Dict[int, HeapObject]]:
    """便捷接口: 对IR行执行完整别名分析, 返回 (指向集映射, 按行号堆对象)。"""
    analyzer = HeapAliasAnalyzer()
    pt_map = analyzer.analyze(ir_lines)
    obj_map = {obj.alloc_site_line: obj
               for obj in analyzer._heap_objects.values()}
    return pt_map, obj_map

__all__ = ['HeapObject', 'PointsToSet', 'AliasResult',
           'HeapAliasAnalyzer', 'analyze_heap_aliases']
