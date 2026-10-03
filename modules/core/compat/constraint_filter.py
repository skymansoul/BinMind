# coding: utf-8
"""
约束过滤器 — 对堆溢出候选批量执行约束求解, 过滤可证明不可行的候选.

"""

from typing import Any, Dict, List, Tuple

from modules.core.compat.constraint_solver import (
    Constraint, ConstraintOp, ConstraintSystem,
    build_heap_overflow_constraints, prove_overflow_infeasible,
)


def batch_constraint_filter(
    candidates: List[Dict],
    allocator_type: str = 'glibc_ptmalloc',
    arch: str = 'x86_64',
) -> Tuple[List[Dict], Dict[str, Any]]:
    """对候选集批量执行约束求解过滤.

    每个候选的 alloc_size 和 write_size 被编码为约束系统,
    若约束系统判定溢出条件不可满足, 则该候选被过滤.
    """
    from modules.core.compat.alloc_constraints import get_constraints

    ac = get_constraints(allocator_type, arch)
    retained = []
    filtered = 0
    details = []

    for c in candidates:
        alloc_sz = c.get('alloc_size', c.get('size', 0))
        write_sz = c.get('write_size', c.get('overflow_bytes', 0))

        if alloc_sz <= 0 or write_sz <= 0:
            retained.append(c)
            continue

        feasible, reason = prove_overflow_infeasible(
            alloc_sz, write_sz,
            alloc_lo=alloc_sz, alloc_hi=alloc_sz + ac.usable_size(alloc_sz) - alloc_sz,
            write_lo=write_sz, write_hi=write_sz + 64,
        )

        if feasible:
            filtered += 1
            details.append({'filtered': c.get('overflow_site', ''), 'reason': reason})
        else:
            retained.append(c)

    stats = {
        'total': len(candidates), 'retained': len(retained),
        'filtered': filtered,
        'reduction_rate': f'{filtered/max(1,len(candidates)):.1%}',
        'details': details[:10],
    }
    return retained, stats
