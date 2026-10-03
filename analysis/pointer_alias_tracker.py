"""
轻量级指针别名追踪 —— 在 decompiled IR 上检测多个变量指向同一堆块。

堆溢出误报的另一大来源: 同一个堆块通过不同指针访问, 现有检测器将每个指针
独立分析, 对每个指针-偏移组合发出独立的溢出警告。

例如:
  buf = malloc(64);
  p = buf + 32;
  p[40] = 0;  // 现有检测: 偏移 40 > 64 → 溢出?
  // 实际: p[40] ≡ buf[72], 确实溢出 —— 但现有漏掉了 p = buf+32 的语义

本模块做两件事:
  1. 别名检测: 追踪指针算术 (ptr ± offset), 建立基址-派生关系
  2. 合并告警: 将指向同一基址的多个告警合并, 以基址 + 派生偏移为准

实现方法:
  · 正则匹配指针算术模式: p = buf + N;  p = buf - N;  p++ (循环内)
  · 维护 {派生指针 → (基址指针, 累积偏移)} 的映射
  · 在 store 检测时解析: 若 store 的基址变量是派生指针, 用基址+总偏移替换
  · 不做完整 points-to 分析 (stripped binary 上变量名不可靠, 完整分析精度低),
    仅追踪形如 p = buf ± N 的显式指针偏移派生 — 堆溢出的最常见模式
"""

import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

@dataclass
class PointerAlias:
    """指针别名记录。"""
    derived: str         # 派生指针变量名
    base: str            # 基址 (malloc 的返回值变量)
    offset: int          # 累积偏移 (正=正向, 负=反向)
    base_is_heap: bool   # 基址是否是堆分配的产物

@dataclass
class ResolvedStore:
    """解析后的 store: 将派生指针的偏移映射回基址。"""
    base_var: str         # 最终基址 (malloc 的返回值)
    total_offset: int     # 基址 + 总偏移
    store_size: int       # 写入大小
    original_line: str    # 原始 IR 行
    derived_var: str = ""  # 如果有派生, 记录派生变量

class PointerAliasTracker:
    """指针别名追踪器。

    使用: 在提取所有 store 后, 调用 resolve_stores 将派生指针的 store
    统一映射回基址+总偏移, 然后交给堆溢出检测器做统一的边界检查。
    """

    def __init__(self):
        self._aliases: Dict[str, PointerAlias] = {}
        self._heap_bases: Set[str] = set()

    def register_heap_base(self, var: str) -> None:
        """注册一个堆分配的基址变量。"""
        if var:
            self._heap_bases.add(var)

    def trace_aliases(self, ir_lines: List[str]) -> Dict[str, PointerAlias]:
        """从 IR 行中追踪所有指针别名关系。

        识别模式:
          · p = base + N       (加法偏移)
          · p = &base[N]        (数组下标)
          · p = base            (简单赋值, 别名)
          · p++ in loop         (循环递增, 记录但不精确追踪)
        """
        self._aliases.clear()

        # 模式 1: p = base + N 或 p = base - N
        add_pattern = re.compile(
            r'(\w+)\s*=\s*(\w+)\s*\+\s*(\d+)',
        )
        sub_pattern = re.compile(
            r'(\w+)\s*=\s*(\w+)\s*-\s*(\d+)',
        )
        # 模式 2: p = &base[N]
        addr_pattern = re.compile(
            r'(\w+)\s*=\s*&(\w+)\[(\d+)\]',
        )
        # 模式 3: p = base (别名)
        assign_pattern = re.compile(
            r'(\w+)\s*=\s*(\w+)\s*[;]?$',
        )

        for line in ir_lines:
            stripped = line.strip()

            m = add_pattern.search(stripped)
            if m:
                derived, base, off = m.group(1), m.group(2), int(m.group(3))
                if base in self._heap_bases or base in self._aliases:
                    self._aliases[derived] = self._resolve_chain(
                        base, derived, off)

            m = sub_pattern.search(stripped)
            if m:
                derived, base, off = m.group(1), m.group(2), -int(m.group(3))
                if base in self._heap_bases or base in self._aliases:
                    self._aliases[derived] = self._resolve_chain(
                        base, derived, off)

            m = addr_pattern.search(stripped)
            if m:
                derived, base, off = m.group(1), m.group(2), int(m.group(3))
                if base in self._heap_bases or base in self._aliases:
                    self._aliases[derived] = self._resolve_chain(
                        base, derived, off)

            m = assign_pattern.search(stripped)
            if m:
                derived, base = m.group(1), m.group(2)
                if (base in self._heap_bases or base in self._aliases) and \
                   derived != base:
                    self._aliases[derived] = self._resolve_chain(
                        base, derived, 0)

        return dict(self._aliases)

    def _resolve_chain(self, base: str, derived: str,
                       offset: int) -> PointerAlias:
        """解析别名链: 若 base 本身是派生指针, 递归到最终的堆基址。"""
        if base in self._aliases:
            prev = self._aliases[base]
            return PointerAlias(
                derived=derived, base=prev.base,
                offset=prev.offset + offset,
                base_is_heap=prev.base_is_heap,
            )
        return PointerAlias(
            derived=derived, base=base,
            offset=offset,
            base_is_heap=base in self._heap_bases,
        )

    def resolve_store(self, store_var: str, store_offset: int) -> ResolvedStore:
        """将 store 指令的基址变量解析为最终的 (基址, 总偏移)。

        若 store_var 是派生指针, 返回 (heap_base, alias_offset + store_offset)。
        否则原样返回。
        """
        if store_var in self._aliases:
            alias = self._aliases[store_var]
            return ResolvedStore(
                base_var=alias.base,
                total_offset=alias.offset + store_offset,
                store_size=-1,
                original_line="",
                derived_var=store_var,
            )
        return ResolvedStore(
            base_var=store_var,
            total_offset=store_offset,
            store_size=-1,
            original_line="",
        )

    def resolve_stores(
        self, stores: List[dict],
    ) -> List[ResolvedStore]:
        """批量解析 store 列表。"""
        resolved = []
        for s in stores:
            rs = self.resolve_store(
                s.get("base_var", ""),
                s.get("offset", 0),
            )
            rs.store_size = s.get("store_size", -1)
            rs.original_line = s.get("original_line", "")
            resolved.append(rs)
        return resolved

    def get_aliases_for_base(self, base_var: str) -> List[PointerAlias]:
        """获取某个基址的所有派生别名。"""
        return [a for a in self._aliases.values() if a.base == base_var]

    def dump(self) -> str:
        """调试: 输出当前别名映射。"""
        lines = [f"{k} → {v.base} + {v.offset} (heap={v.base_is_heap})"
                 for k, v in self._aliases.items()]
        return "\n".join(lines)

def track_pointer_aliases(
    ir_lines: List[str], heap_bases: Set[str],
) -> Dict[str, PointerAlias]:
    """便捷函数: 追踪指针别名。"""
    tracker = PointerAliasTracker()
    for b in heap_bases:
        tracker.register_heap_base(b)
    return tracker.trace_aliases(ir_lines)

__all__ = ['PointerAlias', 'ResolvedStore', 'PointerAliasTracker',
           'track_pointer_aliases']
