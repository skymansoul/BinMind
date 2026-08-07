"""
HOIG Builder — 从伪代码构建 Heap Object Identity Graph.
malloc→ObjectID, 赋值→IdentityEdge, free→FREED, NULL→NULLIFIED.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Set, Tuple

from .uaf_hoig_types import (
    ObjState, ObjectID, ObjStateAtPoint,
    IdentityEdge, FuncObjSummary, UafHoigVerdict,
)
from .uaf_hoig_use_checker import check_use


# 匹配模式
_RE_MALLOC = re.compile(
    r'(\w[\w]*)\s*=\s*(?:\([^)]*\)\s*)?'
    r'(malloc|calloc|realloc|kmalloc|kzalloc|vmalloc|kcalloc|strdup|new\s+\w+)'
    r'\s*\(([^)]*)\)'
)
_RE_FREE = re.compile(r'(?:free|kfree|delete)\s*\(\s*([\w][\w\->\.]*)\s*\)')
_RE_NULLIFY = re.compile(r'(\w[\w]*)\s*=\s*(?:NULL|nullptr|0)\s*;?')
_RE_ASSIGN = re.compile(
    r'(\w[\w]*)\s*=\s*(\w[\w]*(?:\s*->\s*\w+)?)\s*;?'
)
_RE_FIELD_ASSIGN = re.compile(
    r'(\w[\w]*)\s*->\s*(\w[\w]*)\s*=\s*(\w[\w]*(?:\s*->\s*\w+)?)\s*;?'
)
_RE_RETURN = re.compile(r'return\s+(\w[\w]*)\s*;?')
_RE_FUNC_CALL = re.compile(
    r'(\w[\w]*)\s*=\s*(\w+)\s*\(([^)]*)\)\s*;?'
)
_RE_CALL_ARG = re.compile(r'(\w[\w]*)\s*=\s*(\w+)\s*\(([^)]*)\)\s*;?')


class HoigBuilder:
    """从函数伪代码构建 HOIG."""

    def __init__(self):
        self._next_ctx = 1
        self.allocations: Dict[str, ObjectID] = {}  # var → ObjectID
        self.edges: List[IdentityEdge] = []
        self.state_snapshots: List[ObjStateAtPoint] = []
        self.free_events: List[Tuple[str, int]] = []  # (var, line)
        self.nullify_events: List[Tuple[str, int]] = []
        self.realloc_map: Dict[str, str] = {}  # old_ptr → new_ptr
        self.ptr_to_obj: Dict[str, ObjectID] = {}  # current ptr → obj mapping
        self.obj_to_ptrs: Dict[ObjectID, Set[str]] = {}  # obj → {ptr_names}
        self.invalidated_ptrs: Dict[str, int] = {}  # ptr_name → line (freed or realloc'd)
        self.freed_obj_ids: Dict[ObjectID, int] = {}  # obj_id → free_line
        self.func_site: str = ""  # 当前函数名

    def build(self, pseudocode: str, func_name: str = "",
              call_args: Optional[Dict[str, ObjectID]] = None
              ) -> Tuple[List[ObjStateAtPoint], Dict[str, ObjectID], List[UafHoigVerdict]]:
        """构建 HOIG 并发现 UAF. 返回 (state_snapshots, final_ptr_to_obj, uaf_verdicts)."""
        self.func_site = func_name
        if call_args:
            for arg_name, obj_id in call_args.items():
                self.ptr_to_obj[arg_name] = obj_id
                self.obj_to_ptrs.setdefault(obj_id, set()).add(arg_name)

        lines = pseudocode.split('\n')
        states: List[ObjStateAtPoint] = []
        verdicts: List[UafHoigVerdict] = []

        for lineno, raw_line in enumerate(lines, 1):
            line = raw_line.strip()
            if not line or line.startswith('//') or line.startswith('#'):
                continue

            self._process_malloc(line, lineno)
            self._process_free(line, lineno)
            self._process_nullify(line, lineno)
            self._process_assign(line, lineno)
            self._process_field_assign(line, lineno)
            self._process_realloc(line, lineno)

            verdicts_from_use = check_use(
                line, lineno, self.invalidated_ptrs, self.ptr_to_obj,
                self.freed_obj_ids, self.free_events, self.nullify_events,
                self.edges)
            verdicts.extend(verdicts_from_use)

            # 每行结束时记录当前状态
            for obj_id, ptrs in self.obj_to_ptrs.items():
                state = ObjState.LIVE
                for ptr in ptrs:
                    if ptr in [fv[0] for fv in self.free_events]:
                        state = state.join(ObjState.FREED)
                    if ptr in [nv[0] for nv in self.nullify_events]:
                        state = state.join(ObjState.NULLIFIED)
                snap = ObjStateAtPoint(
                    obj_id=obj_id, line_no=lineno,
                    state=state,
                    ptr_names=set(ptrs),
                )
                if state == ObjState.FREED:
                    for fv, fl in self.free_events:
                        if fv in ptrs:
                            snap.free_line = fl
                states.append(snap)

        return states, dict(self.ptr_to_obj), verdicts

    def _alloc_obj_id(self, line: int) -> ObjectID:
        oid = ObjectID(line, self.func_site, self._next_ctx)
        self._next_ctx += 1
        return oid

    def _process_malloc(self, line: str, lineno: int):
        m = _RE_MALLOC.search(line)
        if not m:
            return
        lhs = m.group(1)
        func = m.group(2)
        oid = self._alloc_obj_id(lineno)

        if func == 'realloc':
            # realloc: 需要找到旧指针的ObjectID并延续
            args = m.group(3).split(',')
            old_ptr = args[0].strip() if args else ''
            if old_ptr and old_ptr in self.ptr_to_obj:
                # realloc 保持旧对象的身份
                old_oid = self.ptr_to_obj[old_ptr]
                self.realloc_map[old_ptr] = lhs
                self.ptr_to_obj[lhs] = old_oid
                self.obj_to_ptrs.setdefault(old_oid, set()).add(lhs)
                self.edges.append(IdentityEdge(
                    src_var=old_ptr, dst_var=lhs, obj_id=old_oid,
                    line_no=lineno, edge_type='realloc',
                ))
                return

        # 新分配
        self.allocations[lhs] = oid
        self.ptr_to_obj[lhs] = oid
        self.obj_to_ptrs.setdefault(oid, set()).add(lhs)

    def _process_free(self, line: str, lineno: int):
        m = _RE_FREE.search(line)
        if not m:
            return
        ptr = m.group(1)
        self.free_events.append((ptr, lineno))
        self.invalidated_ptrs[ptr] = lineno
        # 直接指针: 通过 ObjectID 追踪别名失效
        if ptr in self.ptr_to_obj:
            oid = self.ptr_to_obj[ptr]
            self.freed_obj_ids[oid] = lineno
            for alias_ptr in self.obj_to_ptrs.get(oid, set()):
                if alias_ptr != ptr:
                    self.invalidated_ptrs.setdefault(alias_ptr, lineno)
        # 结构体字段: free(e->data) → 通过 IdentityEdge 追踪字段对应的 ObjectID
        elif '->' in ptr or '.' in ptr:
            for edge in self.edges:
                if edge.dst_var == ptr and edge.edge_type == 'field_assign':
                    self.freed_obj_ids[edge.obj_id] = lineno
                    for alias_ptr in self.obj_to_ptrs.get(edge.obj_id, set()):
                        self.invalidated_ptrs.setdefault(alias_ptr, lineno)

    def _process_nullify(self, line: str, lineno: int):
        m = _RE_NULLIFY.search(line)
        if not m:
            return
        ptr = m.group(1)
        self.nullify_events.append((ptr, lineno))

    def _process_assign(self, line: str, lineno: int):
        """处理简单赋值: p = q."""
        m = _RE_ASSIGN.search(line)
        if not m:
            return
        lhs, rhs = m.group(1), m.group(2)
        # 跳过 malloc 匹配 (已在 _process_malloc 中处理)
        if any(kw in line for kw in ['malloc', 'calloc', 'free', 'NULL']):
            return
        if rhs in self.ptr_to_obj and '->' not in rhs:
            oid = self.ptr_to_obj[rhs]
            self.ptr_to_obj[lhs] = oid
            self.obj_to_ptrs.setdefault(oid, set()).add(lhs)
            self.edges.append(IdentityEdge(
                src_var=rhs, dst_var=lhs, obj_id=oid,
                line_no=lineno, edge_type='direct_assign',
            ))

    def _process_field_assign(self, line: str, lineno: int):
        """处理结构体字段赋值: obj->field = value."""
        m = _RE_FIELD_ASSIGN.search(line)
        if not m:
            return
        obj, field, rhs = m.group(1), m.group(2), m.group(3)
        if rhs in self.ptr_to_obj:
            # obj->field 获得 rhs 的对象身份
            # 记录为别名边, 但不更新 ptr_to_obj (字段访问不同于直接指针赋值)
            oid = self.ptr_to_obj[rhs]
            self.edges.append(IdentityEdge(
                src_var=rhs, dst_var=f'{obj}->{field}', obj_id=oid,
                line_no=lineno, edge_type='field_assign',
            ))

    def _process_realloc(self, line: str, lineno: int):
        """处理 realloc: p = realloc(q, size)."""
        m = _RE_MALLOC.search(line)
        if not m:
            return
        if m.group(2) != 'realloc':
            return
        lhs = m.group(1)
        args = m.group(3).split(',')
        old_ptr = args[0].strip() if args else ''
        if old_ptr in self.ptr_to_obj:
            old_oid = self.ptr_to_obj[old_ptr]
            self.realloc_map[old_ptr] = lhs
            # 新指针继承旧对象的ObjectID
            self.ptr_to_obj[lhs] = old_oid
            self.obj_to_ptrs.setdefault(old_oid, set()).add(lhs)
            # 旧指针失效 (realloc 隐式 free)
            self.invalidated_ptrs[old_ptr] = lineno

    def get_summary(self) -> FuncObjSummary:
        """生成函数对象摘要 (用于跨过程分析)."""
        killed = []
        for ptr, line in self.free_events:
            if ptr in self.ptr_to_obj:
                killed.append((self.ptr_to_obj[ptr], line))
            elif '->' in ptr or '.' in ptr:
                for edge in self.edges:
                    if edge.dst_var == ptr and edge.edge_type == 'field_assign':
                        killed.append((edge.obj_id, line))
                        break
        return FuncObjSummary(
            func_name=self.func_site,
            allocated=list(self.allocations.values()),
            killed=killed, escaped=dict(self.ptr_to_obj))


__all__ = ['HoigBuilder']
