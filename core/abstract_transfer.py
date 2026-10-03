"""
抽象解释转移函数 — 单语句的语义效果建模。

包含 malloc/calloc/realloc、free、memcpy/memset、数组下标写入、
变量赋值、if条件约束的转移函数。
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from core.abstract_state import AbstractState
from core.heap_abstract_domain import Interval, compute_effective_size
from core.path_constraints import ConstraintOp, LinearConstraint


def transfer_line(
    line: str, state: AbstractState,
    all_lines: List[str], line_idx: int,
    engine: Any,  # AbstractEngine, 避免循环导入
) -> Optional[AbstractState]:
    """应用单条语句的转移函数。"""
    stripped = line.strip()
    if not stripped or stripped.startswith('//') or stripped.startswith('#'):
        return state

    # malloc / calloc / realloc
    alloc_m = re.search(
        r'(\w[\w\d_]*)\s*=\s*(?:\([^)]*\*?\s*\))?\s*(malloc|calloc|realloc)\s*\(\s*([^)]+)\s*\)',
        stripped,
    )
    if alloc_m:
        return _transfer_alloc(alloc_m, state, all_lines, line_idx, engine)

    # free
    free_m = re.search(r'(?:free|kfree)\s*\(\s*(\w[\w\d_]*)\s*\)', stripped)
    if free_m:
        ptr = free_m.group(1)
        state.heap.free(ptr, line_idx)
        return state

    # memcpy / strcpy / memset 等写入
    write_m = re.search(
        r'(memcpy|memmove|memset|strcpy|strncpy|sprintf|snprintf|read|fread|recv)\s*\(([^)]+)\)',
        stripped,
    )
    if write_m:
        return _transfer_write(write_m, state, stripped, line_idx, engine)

    # 数组下标写入: ptr[idx] = val
    idx_m = re.search(r'(\w+)\s*\[\s*(\w+)\s*\]\s*=', stripped)
    if idx_m:
        ptr, idx_var = idx_m.group(1), idx_m.group(2)
        idx_iv = state.intervals.get(idx_var, Interval(0, None))
        state.heap.store_index(ptr, idx_var, idx_iv)
        return state

    # 赋值: var = const / expr
    assign_m = re.search(r'(\w[\w\d_]*)\s*=\s*(-?\d+)\s*;?$', stripped)
    if assign_m:
        var, val = assign_m.group(1), int(assign_m.group(2))
        state.intervals[var] = Interval.constant(val)
        return state

    # if 条件约束 → 对当前状态求精 (true分支)
    if_m = re.search(
        r'if\s*\(\s*(\w+)\s*(>=?|<=?|==|!=)\s*(-?\d+)\s*\)',
        stripped,
    )
    if if_m:
        var, op_str, val_str = if_m.group(1), if_m.group(2), if_m.group(3)
        return _apply_condition(var, op_str, int(val_str), state, True)

    return state


def _transfer_alloc(
    m: re.Match, state: AbstractState,
    all_lines: List[str], line_idx: int,
    engine: Any,
) -> AbstractState:
    ptr = m.group(1)
    func = m.group(2)
    size_expr = m.group(3).strip().split(',')[0].strip() if func == 'calloc' else m.group(3).strip()
    req_size = engine._eval_size(size_expr, state, all_lines, line_idx)
    effective = compute_effective_size(req_size, "x86_64")
    state.heap.alloc(ptr, func, req_size, effective, size_expr)
    return state


def _transfer_write(
    m: re.Match, state: AbstractState,
    line: str, line_idx: int,
    engine: Any,
) -> AbstractState:
    func = m.group(1)
    args_str = m.group(2)
    args = engine._split_args(args_str)
    if not args:
        return state

    dst = args[0].strip()
    base = dst.split('[')[0].strip() if '[' in dst else dst

    write_size = engine._estimate_write_size(func, args, state)
    if write_size is None:
        return state

    offset_iv = Interval(0, 0)
    if '[' in dst:
        idx_match = re.search(r'\[(\w+)\]', dst)
        if idx_match:
            idx_var = idx_match.group(1)
            offset_iv = state.intervals.get(idx_var, Interval(0, None))

    state.heap.mem_write(base, offset_iv, write_size)
    return state


def _apply_condition(
    var: str, op_str: str, val: int,
    state: AbstractState, is_true_branch: bool,
) -> AbstractState:
    """应用条件约束 (if 分支)。"""
    op_map = {
        '<': ConstraintOp.LT, '<=': ConstraintOp.LE,
        '>': ConstraintOp.GT, '>=': ConstraintOp.GE,
        '==': ConstraintOp.EQ, '!=': ConstraintOp.NE,
    }
    op = op_map.get(op_str)
    if op is None:
        return state

    # 对于 false 分支, 取反
    if not is_true_branch:
        neg_map = {
            ConstraintOp.LT: ConstraintOp.GE, ConstraintOp.LE: ConstraintOp.GT,
            ConstraintOp.GT: ConstraintOp.LE, ConstraintOp.GE: ConstraintOp.LT,
            ConstraintOp.EQ: ConstraintOp.NE, ConstraintOp.NE: ConstraintOp.EQ,
        }
        op = neg_map[op]

    c = LinearConstraint(var=var, op=op, bound=val)
    current = state.intervals.get(var, Interval(None, None))
    clo, chi = c.to_interval()
    refined_lo = max(current.low, clo) if current.low is not None and clo is not None else (current.low or clo)
    refined_hi = min(current.high, chi) if current.high is not None and chi is not None else (current.high or chi)

    if refined_lo is not None and refined_hi is not None and refined_lo > refined_hi:
        state.reachable = False
    else:
        state.intervals[var] = Interval(refined_lo, refined_hi)
    return state
