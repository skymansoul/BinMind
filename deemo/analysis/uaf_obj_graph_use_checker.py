"""
UAF 对象身份图 use-after-free 检测器 — 指针使用点分析.

通过 ObjectID 追踪别名链上的已释放对象.
"""

from __future__ import annotations

import re
from typing import Dict, List, Set

from .uaf_obj_graph_types import ObjectID, UafHoigVerdict

_SKIP_FUNCS = {
    'malloc', 'calloc', 'realloc', 'kmalloc',
    'kzalloc', 'vmalloc', 'kcalloc', 'strdup',
    'free', 'kfree', 'delete',
}


def check_use(
    line: str, lineno: int,
    invalidated_ptrs: Dict[str, int],
    ptr_to_obj: Dict[str, ObjectID],
    freed_obj_ids: Dict[ObjectID, int],
    free_events: List,
    nullify_events: List,
    edges: List,
) -> List[UafHoigVerdict]:
    """检查指针使用是否触发 UAF.

    跳过 free/kfree/delete 行. 检测解引用和函数调用参数中的已失效指针.
    通过 ObjectID 追踪别名链上的释放事件.
    """
    if re.search(r'\b(?:free|kfree|delete)\s*\(', line):
        return []

    deref = re.findall(r'\*(\w[\w]*)|(\w[\w]*)\s*->|(\w[\w]*)\s*\[', line)
    used_vars: Set[str] = set()
    for d in deref:
        used_vars.update(v for v in d if v)

    # 函数调用参数中的已失效指针
    for m in re.finditer(r'(\w+)\s*\(([^)]*)\)', line):
        fname = m.group(1).lower()
        if fname in _SKIP_FUNCS:
            continue
        for arg in m.group(2).split(','):
            arg = arg.strip()
            if re.match(r'^[a-z_]\w*$', arg):
                if arg in invalidated_ptrs or arg in ptr_to_obj:
                    used_vars.add(arg)

    verdicts: List[UafHoigVerdict] = []

    for var in used_vars:
        # 直接失效检查
        if var in invalidated_ptrs:
            inval_line = invalidated_ptrs[var]
            reassigned = any(
                edge.dst_var == var and edge.line_no > inval_line
                for edge in edges
            )
            nullified = var in {nv[0] for nv in nullify_events}

            if not reassigned and not nullified:
                oid = ptr_to_obj.get(var)
                free_line = freed_obj_ids.get(oid, inval_line) if oid else inval_line
                verdicts.append(UafHoigVerdict(
                    verdict='CONFIRMED', confidence=0.90,
                    obj_id=oid, free_line=free_line,
                    use_line=lineno, use_var=var, free_var=var,
                    reason=f'{var} invalidated at line {inval_line}, '
                           f'used at line {lineno}',
                    is_cross_func=False,
                ))
            continue

        # ObjectID 别名追踪
        if var in ptr_to_obj:
            oid = ptr_to_obj[var]
            if oid in freed_obj_ids:
                free_line = freed_obj_ids[oid]
                nullified = var in {nv[0] for nv in nullify_events}
                reassigned = any(
                    (edge.dst_var == var and
                     edge.edge_type == 'realloc' and
                     edge.line_no > free_line)
                    for edge in edges
                )
                if not reassigned and not nullified:
                    free_var = next(
                        (fv for fv, fl in free_events
                         if fl == free_line), var)
                    verdicts.append(UafHoigVerdict(
                        verdict='CONFIRMED', confidence=0.85,
                        obj_id=oid, free_line=free_line,
                        use_line=lineno, use_var=var, free_var=free_var,
                        reason=f'ObjectID {oid} freed at line {free_line} '
                               f'via alias, {var} used at line {lineno}',
                        is_cross_func=False,
                    ))

    return verdicts


__all__ = ['check_use']
