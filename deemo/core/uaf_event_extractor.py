"""
UAF事件提取器 — 从伪代码IR提取指针生命周期事件 (ALLOC/FREE/USE/ALIAS)。
事件提取独立于TARPS评估管道, 仅依赖 PtrEvent dataclass 和正则模式。
设计要点: 数组索引指针支持, 跨函数call跟踪, 数组基名USE传播, 别名闭包。
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Set, Tuple

# data types ────────────────────────────────────────────────────────

@dataclass
class PtrEvent:
    """指针生命周期事件"""
    line_idx: int
    ptr_name: str
    event_type: str  # 'ALLOC' | 'USE' | 'FREE' | 'NULLIFY' | 'REASSIGN'
    detail: str = ""

# IR pattern regexes ────────────────────────────────────────────────
# 支持数组索引指针: nodes[i], nodes[1] 等

_PTR_RE = r'(\w[\w.]*(?:\[[^\]]*\])?)'

_MALLOC_RE = re.compile(
    _PTR_RE + r'\s*=\s*(?:\([^)]*\))?\s*(?:malloc|calloc|realloc)\s*\(')
_FREE_RE = re.compile(r'free\s*\(\s*' + _PTR_RE + r'\s*\)')
_NULL_RE = re.compile(r'(\w[\w.]*)\s*=\s*(?:NULL|0|nullptr)\s*;?')
_ALIAS_ASSIGN_RE = re.compile(_PTR_RE + r'\s*=\s*' + _PTR_RE + r'\s*;?')
_CALL_ARG_RE = re.compile(r'call\s+(\w[\w.]*)\s*\(([^)]*)\)')

_C_KEYWORDS = {'if', 'for', 'while', 'do', 'else', 'return', 'goto',
               'break', 'continue', 'case', 'default', 'switch', 'sizeof',
               'typedef', 'struct', 'enum', 'union', 'void'}

# alias propagation helpers ──────────────────────────────────────────

def _resolve_alias_chain(alias_map: Dict[str, str], ptr: str) -> str:
    """解析别名链: r→q→p → 返回p (原始指针)。"""
    visited = {ptr}
    current = ptr
    while current in alias_map:
        nxt = alias_map[current]
        if nxt in visited:
            break
        visited.add(nxt)
        current = nxt
    return current

def _collect_transitive_aliases(
    alias_map: Dict[str, str], root: str,
) -> List[str]:
    """收集root的所有传递别名。"""
    result = []
    for alias, target in alias_map.items():
        resolved = _resolve_alias_chain(alias_map, alias)
        if resolved == root:
            result.append(alias)
    return result

def _propagate_free_to_aliases(
    alias_map: Dict[str, str], ptr: str, line_idx: int,
    stripped: str, events: List[PtrEvent],
) -> None:
    """传递闭包: free(ptr) → 所有别名也获得FREE事件。"""
    for alias in _collect_transitive_aliases(alias_map, ptr):
        events.append(PtrEvent(
            line_idx, alias, 'FREE',
            f'alias of {ptr}: {stripped[:60]}'))

def _propagate_nullify_to_aliases(
    alias_map: Dict[str, str], ptr: str, line_idx: int,
    stripped: str, events: List[PtrEvent],
) -> None:
    """传递闭包: ptr=NULL → 直接别名获得NULLIFY事件。"""
    for alias, target in alias_map.items():
        if target == ptr:
            events.append(PtrEvent(
                line_idx, alias, 'NULLIFY',
                f'alias of {ptr}: {stripped[:60]}'))

# event extraction ──────────────────────────────────────────────────

def extract_uaf_events(ir_lines: List[str]) -> Tuple[List[PtrEvent], Dict[str, str]]:
    """从伪代码IR提取指针生命周期事件 + 别名映射。

    返回 (events, alias_map)。
    alias_map: lhs → rhs, 表示 lhs 是 rhs 的别名。
    """
    events: List[PtrEvent] = []
    alias_map: Dict[str, str] = {}

    for i, line in enumerate(ir_lines):
        stripped = line.strip()

        # malloc/calloc/realloc: 分配事件
        mm = _MALLOC_RE.search(stripped)
        if mm:
            ptr = mm.group(1)
            if ptr and re.match(r'^[a-zA-Z_]\w*$', ptr):
                events.append(PtrEvent(i, ptr, 'ALLOC', stripped[:80]))
                alias_map.pop(ptr, None)
                continue

        # free: 释放事件
        fm = _FREE_RE.search(stripped)
        if fm:
            ptr = fm.group(1)
            events.append(PtrEvent(i, ptr, 'FREE', stripped[:80]))
            _propagate_free_to_aliases(alias_map, ptr, i, stripped, events)
            continue

        # NULL赋值: NULL置零 (Stage A)
        nm = _NULL_RE.search(stripped)
        if nm:
            ptr = nm.group(1)
            if ptr not in _C_KEYWORDS:
                events.append(PtrEvent(i, ptr, 'NULLIFY', stripped[:60]))
            continue

        # 别名赋值: q = p (Stage C)
        am = _ALIAS_ASSIGN_RE.match(stripped)
        if am:
            lhs, rhs = am.group(1), am.group(2)
            if lhs in _C_KEYWORDS or rhs in _C_KEYWORDS:
                continue
            if re.match(r'^[a-zA-Z_]\w*$', lhs) and re.match(r'^[a-zA-Z_]\w*$', rhs):
                alias_map[lhs] = rhs
                events.append(PtrEvent(i, lhs, 'ALIAS', rhs))
                continue

        # 指针解引用: USE事件
        known_ptrs = _collect_known_ptrs(events)
        is_use = bool(re.search(r'->', stripped)) or \
                 bool(re.search(r'(?<!\w)\*(?!\*)', stripped))

        if is_use:
            for ptr in sorted(known_ptrs):
                if re.search(rf'\b{re.escape(ptr)}\b', stripped):
                    events.append(PtrEvent(i, ptr, 'USE', stripped[:80]))
                    continue
                bm = re.match(r'^(\w+)\[', ptr)
                if bm and re.search(rf'\b{re.escape(bm.group(1))}\[', stripped):
                    events.append(PtrEvent(i, ptr, 'USE',
                                  f'array base: {stripped[:60]}'))

        # 函数调用参数
        if not is_use:
            for ptr in sorted(known_ptrs):
                if not re.search(rf'\b{re.escape(ptr)}\b', stripped):
                    bm = re.match(r'^(\w+)\[', ptr)
                    if not (bm and re.search(
                            rf'\b{re.escape(bm.group(1))}\[', stripped)):
                        continue
                if 'free(' in stripped:
                    continue
                if re.match(rf'\s*{re.escape(ptr)}\s*=', stripped):
                    continue
                events.append(PtrEvent(i, ptr, 'USE',
                              f'func arg: {stripped[:60]}'))

        # call func(ptr) 行: 用户函数参数也是USE (跨函数UAF)
        cm = _CALL_ARG_RE.search(stripped)
        if cm:
            args = cm.group(2)
            for ptr in sorted(known_ptrs):
                if re.search(rf'\b{re.escape(ptr)}\b', args):
                    events.append(PtrEvent(i, ptr, 'USE',
                                  f'call arg: {stripped[:60]}'))
                bm = re.match(r'^(\w+)\[', ptr)
                if bm and re.search(rf'\b{re.escape(bm.group(1))}\[', args):
                    events.append(PtrEvent(i, ptr, 'USE',
                                  f'call arr: {stripped[:60]}'))

    # 数组基名USE传播: nodes USE → nodes[1] USE
    extra_uses: List[PtrEvent] = []
    for ev in events:
        bm = re.match(r'^(\w+)\[', ev.ptr_name)
        if not bm:
            continue
        base = bm.group(1)
        for uev in events:
            if uev.event_type == 'USE' and uev.ptr_name == base \
               and uev.line_idx > ev.line_idx:
                extra_uses.append(PtrEvent(
                    uev.line_idx, ev.ptr_name, 'USE',
                    f'base-prop from {base}: {uev.detail[:40]}'))
    events.extend(extra_uses)

    return events, alias_map

def _collect_known_ptrs(events: List[PtrEvent]) -> Set[str]:
    """收集已出现过的指针名 — 包含ALLOC/ALIAS/FREE, 以及数组基名。

    数组基名: nodes[1] → 同时添加 nodes, 使 nodes[i] 也可匹配。
    FREE事件: 跨函数参数 (无ALLOC) 也可被USE检测到。
    """
    ptrs: Set[str] = set()
    for ev in events:
        if ev.event_type in ('ALLOC', 'ALIAS', 'FREE'):
            ptrs.add(ev.ptr_name)
            bm = re.match(r'^(\w+)\[', ev.ptr_name)
            if bm:
                ptrs.add(bm.group(1))
    return ptrs

__all__ = ['extract_uaf_events', '_collect_known_ptrs']
