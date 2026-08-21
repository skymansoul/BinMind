"""
指针身份追踪 — 从 malloc 返回值到 memcpy/memset 目标的别名链解析.
核心问题: 现有检测将所有 malloc 和 memcpy 两两配对, 若 write 目标不是 alloc 缓冲区则误报.
方法: 追踪指针赋值链 (q=p; r=q->field), 在 memcpy 点解析目标指针的根.

与现有模块关系:
  - path_sensitive_vrf: 依赖本模块过滤 write 目标不匹配的 alloc-write 对
  - affine_relation_tracker: 本模块提供精确的目标指针, 补充仿射关系的变量绑定
参考: ISSTA 2024 "Heap Disjointness" — 堆对象身份识别的思想, 适配到反编译伪代码层面.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


# 指针表达式解析
#   支持: p, p->field, *p, p[idx], &(p->field)
_RE_SIMPLE_PTR = re.compile(r'^([a-zA-Z_]\w*)$')
_RE_ARROW_FIELD = re.compile(r'^([a-zA-Z_]\w*)\s*->\s*(\w+)$')
_RE_DEREF = re.compile(r'^\*\s*([a-zA-Z_]\w*)$')
_RE_ARRAY_IDX = re.compile(r'^([a-zA-Z_]\w*)\s*\[\s*[^\]]+\s*\]$')

# malloc/calloc/realloc 赋值模式: var = func(size)
_RE_MALLOC_ASSIGN = re.compile(
    r'(\w[\w]*)\s*=\s*\(\s*\w+\s*\*?\s*\)\s*(malloc|calloc|realloc)\s*\(')
# 无条件 malloc (无赋值目标): 用于声明中的内联分配
_RE_MALLOC_INLINE = re.compile(
    r'(?:^|;)\s*\w+\s*\*?\s*(\w+)\s*=\s*(?:\(\s*\w+\s*\*?\s*\)\s*)?(?:malloc|calloc|realloc)\s*\(')

# memcpy/memset/memmove/strcpy/sprintf 写入目标提取
_RE_WRITE_TARGET = re.compile(
    r'(memcpy|memmove|memset|strcpy|strncpy|sprintf|snprintf|read|fread|recv)\s*\(\s*([^,]+)')

# 指针赋值: q = p; q = p + offset; q = &p->field
_RE_PTR_ASSIGN = re.compile(r'(\w[\w]*)\s*=\s*([^;]+?)\s*;')

# 函数调用中的指针传递
_RE_FUNC_CALL_ARG = re.compile(r'(\w+)\s*\(\s*([^)]+)\s*\)')


@dataclass
class PtrAllocSite:
    """堆分配点记录."""
    ptr_name: str           # 接收 malloc 返回值的变量名
    alloc_func: str         # malloc/calloc/realloc
    size_expr: str          # 大小表达式文本
    line_no: int            # 行号
    context_vars: Set[str] = field(default_factory=set)  # 同行其他变量


@dataclass
class PtrWriteSite:
    """堆写入点记录."""
    target_expr: str        # 写入目标表达式 (如 p, p->data, p+offset)
    write_func: str         # memcpy/memset/strcpy 等
    size_expr: str          # 写入大小表达式
    line_no: int
    resolved_root: str = ""  # 解析后的根指针


class PtrIdentityTracker:
    """指针身份追踪器 — 解析 malloc→memcpy 的指针流向.

    关键操作:
      - track_alloc(): 记录 malloc 返回的指针名
      - track_assign(): 追踪指针赋值链 (q=p, r=q->next)
      - resolve_target(): 将 memcpy 目标解析到最根的指针变量
      - match_alloc_write(): 判定 write 目标和 alloc 目标是否同一对象
    """

    def __init__(self):
        self._aliases: Dict[str, str] = {}        # var → canonical name
        self._rev_aliases: Dict[str, Set[str]] = defaultdict(set)  # canonical → aliases
        self._alloc_sites: List[PtrAllocSite] = []
        self._struct_members: Dict[str, Set[str]] = defaultdict(set)  # ptr → {field names}

    def clear(self):
        self._aliases.clear()
        self._rev_aliases.clear()
        self._alloc_sites.clear()
        self._struct_members.clear()

    # 扫描阶段

    def scan_line(self, line: str, line_no: int):
        """扫描一行伪代码, 提取指针身份信息."""
        stripped = line.strip()

        # malloc 赋值
        m = _RE_MALLOC_ASSIGN.search(stripped)
        if m:
            ptr, func = m.group(1), m.group(2)
            # 提取 size
            paren_start = m.end()
            if paren_start < len(stripped) and stripped[paren_start - 1] == '(':
                size_text = _extract_paren_content(stripped, paren_start - 1)
            else:
                size_text = "?"
            self.track_alloc(ptr, func, size_text, line_no)
            return

        # 指针赋值: q = p 或 q = p->field 或 q = &p->field
        pm = _RE_PTR_ASSIGN.search(stripped)
        if pm and not stripped.startswith('if') and not stripped.startswith('for'):
            lhs = pm.group(1)
            rhs = pm.group(2).strip().rstrip(';').strip()
            self.track_assign(lhs, rhs, line_no)

    def track_alloc(self, ptr: str, func: str, size_expr: str, line_no: int):
        """记录堆分配点."""
        if ptr in self._aliases:
            # 已存在的指针被重新分配 — 清除旧别名
            old_root = self._find_root(ptr)
            if old_root in self._rev_aliases:
                self._rev_aliases[old_root].discard(ptr)
        self._aliases[ptr] = ptr  # 新分配, ptr 自己是根
        self._rev_aliases[ptr].add(ptr)
        self._alloc_sites.append(PtrAllocSite(
            ptr_name=ptr, alloc_func=func.lower(),
            size_expr=size_expr, line_no=line_no))

    def track_assign(self, lhs: str, rhs: str, line_no: int = 0):
        """追踪指针赋值, 建立别名关系.

        处理模式:
          - q = p          → q 是 p 的别名
          - q = p->field   → q 指向 p 的子对象 (仍属于 p 的缓冲区)
          - q = &p->field  → 同上, 取地址
          - q = p + n      → q 是 p 内部偏移 (仍属 p 的缓冲区)
          - q = *p         → q 不建立别名 (值拷贝)
        """
        # 提取 rhs 中最可能的根变量
        root = _extract_root_var(rhs)
        if root is None:
            return
        if root == lhs:
            return
        # 避免覆盖 malloc 的直接赋值
        if lhs in self._alloc_sites_refs():
            return

        # 检测 rhs 是否是 field access
        arrow_m = re.search(r'(\w+)\s*->\s*(\w+)', rhs)
        if arrow_m:
            base_ptr, field = arrow_m.group(1), arrow_m.group(2)
            base_root = self._find_root(base_ptr)
            self._struct_members[base_root].add(field)
            # q = p->field: q 仍指向 p 的缓冲区内部
            self._aliases[lhs] = base_root
            self._rev_aliases[base_root].add(lhs)
            return

        # q = p + offset (或 q = &p[idx])
        plus_m = re.search(r'(\w+)\s*\+', rhs)
        amp_m = re.search(r'&\s*(\w+)\s*\[', rhs)
        if plus_m or amp_m:
            base = plus_m.group(1) if plus_m else amp_m.group(1)
            base_root = self._find_root(base)
            self._aliases[lhs] = base_root
            self._rev_aliases[base_root].add(lhs)
            return

        # 简单赋值 q = p
        if _RE_SIMPLE_PTR.match(rhs):
            rhs_root = self._find_root(rhs)
            self._aliases[lhs] = rhs_root
            self._rev_aliases[rhs_root].add(lhs)

    # 查询阶段

    def _find_root(self, ptr: str) -> str:
        """沿别名链找到根指针 (Union-Find)."""
        seen = {ptr}
        cur = ptr
        while cur in self._aliases and self._aliases[cur] != cur:
            nxt = self._aliases[cur]
            if nxt in seen:
                break
            seen.add(nxt)
            cur = nxt
        # 路径压缩
        if cur != ptr:
            self._aliases[ptr] = cur
        return cur

    def _alloc_sites_refs(self) -> Set[str]:
        return {s.ptr_name for s in self._alloc_sites}

    def resolve_target(self, target_expr: str) -> Optional[str]:
        """将写入目标表达式解析为根指针名.

        例: q->buf → q 的根; *p → p 的根; arr[i] → arr 的根.
        返回 None 表示无法识别 (可能是栈变量或字面量).
        """
        target = target_expr.strip().lstrip('&').strip()
        # p->field
        arrow_m = re.search(r'^(\w+)\s*->', target)
        if arrow_m:
            return self._find_root(arrow_m.group(1))
# p
        deref_m = re.search(r'^\*\s*(\w+)', target)
        if deref_m:
            return self._find_root(deref_m.group(1))
        # p[expr]
        arr_m = re.search(r'^(\w+)\s*\[', target)
        if arr_m:
            return self._find_root(arr_m.group(1))
        # 简单变量
        simple_m = _RE_SIMPLE_PTR.match(target)
        if simple_m:
            return self._find_root(simple_m.group(1))
        # p + offset
        plus_m = re.search(r'^(\w+)\s*\+', target)
        if plus_m:
            return self._find_root(plus_m.group(1))
        return None

    def match_alloc_write(self, target_root: str) -> Optional[PtrAllocSite]:
        """检查写入目标根指针是否对应已知堆分配。

        命中返回 PtrAllocSite; None 表示目标是栈/全局/未知,
        不应触发堆溢出告警。
        """
        if not target_root:
            return None
        for site in self._alloc_sites:
            site_root = self._find_root(site.ptr_name)
            if site_root == target_root:
                return site
            # 检查反向别名
            if target_root in self._rev_aliases.get(site_root, set()):
                return site
        return None

    def is_heap_buffer(self, ptr_name: str) -> bool:
        """判定 ptr_name 是否为堆分配缓冲区 (vs 栈/全局)."""
        root = self._find_root(ptr_name)
        return root in self._alloc_sites_refs()

    def get_stats(self) -> Dict:
        return {
            'alloc_sites': len(self._alloc_sites),
            'alias_count': len(self._aliases),
            'tracked_ptrs': len(self._rev_aliases),
        }


# 辅助函数

def _extract_paren_content(text: str, open_pos: int) -> str:
    """提取括号内容."""
    d, i = 1, open_pos + 1
    while i < len(text) and d > 0:
        if text[i] == '(':
            d += 1
        elif text[i] == ')':
            d -= 1
        i += 1
    return text[open_pos + 1:i - 1] if d == 0 else text[open_pos + 1:]


def _extract_root_var(expr: str) -> Optional[str]:
    """从表达式中提取根变量名."""
    expr = expr.strip()
    sm = _RE_SIMPLE_PTR.match(expr)
    if sm: return sm.group(1)
    for pat in (r'(\w+)\s*->', r'&\s*(\w+)\s*->', r'^\*\s*(\w+)',
                r'^(\w+)\s*\+', r'^(\w+)\s*\[', r'\(\s*\w+\s*\*?\s*\)\s*(\w+)'):
        m = __import__('re').search(pat, expr)
        if m: return m.group(1)
    return None


__all__ = ['PtrIdentityTracker', 'PtrAllocSite', 'PtrWriteSite',
           '_extract_root_var']
