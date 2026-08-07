"""
约束收集器 — 从IR/伪代码中提取四类堆溢出约束并构建ConstraintSystem.

四类约束来源:
  1. 分配大小约束: malloc(N)的N来自常量/类型上界/守卫约束
  2. 拷贝大小约束: memcpy的第三参数来自常量/变量/循环计数
  3. 写入偏移约束: store指令的offset来自常量/索引变量/循环变量
  4. 循环上界约束: for(i=0;i<N;i++)的N和步长

每个候选(alloc, write)对构建一个ConstraintSystem, 供求解器判定.

拷贝/偏移约束的子收集函数已拆至 cj_constraint_collector_collectors.py
"""

from __future__ import annotations
import re

from core.cj_constraint_types import (
    ConstraintType, LinearConstraint, ConstraintSystem,
)
from core.cj_constraint_tracer import (
    trace_constant_assignment,
    trace_type_bound,
    trace_guard_upper_bound,
)
from core.heap_overflow_detector import HeapAllocSite, HeapStore, HeapOverflowCandidate
from core.cj_constraint_collector_collectors import (
    _collect_lib_copy_constraints,
    _collect_array_index_constraints,
    _collect_ptr_deref_constraints,
    _collect_sprintf_constraints,
    _collect_offset_constraints,
)


def collect_constraints(
    candidate: HeapOverflowCandidate,
    ir_lines: list[str],
    decompiled_text: str = "",
) -> ConstraintSystem:
    """为单个候选构建约束系统.

    从IR行和伪代码中提取分配大小、拷贝大小、写入偏移、循环上界四类约束,
    统一为LinearConstraint格式.
    """
    alloc = candidate.alloc_site
    store = candidate.overflow_store
    sys = ConstraintSystem()

    _collect_alloc_constraints(alloc, ir_lines, sys)
    _collect_copy_constraints(store, ir_lines, sys)
    _collect_offset_constraints(store, ir_lines, sys)
    _collect_loop_constraints(alloc, store, ir_lines, sys)

    if decompiled_text:
        _collect_guard_constraints(
            decompiled_text, alloc, store, sys)

        # SFOD: 结构体字段偏移域桥接
        try:
            from core.cj_struct_field import inject_sfod_constraints
            inject_sfod_constraints(sys, decompiled_text, alloc, store)
        except Exception:
            pass

    return sys


def _collect_alloc_constraints(
    alloc: HeapAllocSite,
    ir_lines: list[str],
    sys: ConstraintSystem,
) -> None:
    """提取分配大小约束.

    已知常量分配大小直接记录在sys.alloc_size中, 不作为线性约束.
    仅动态大小的守卫/上界约束进入约束列表.
    """
    sys.alloc_var = alloc.size_expr if alloc.size_is_dynamic else ""
    sys.alloc_size = alloc.size_arg

    if not alloc.size_is_dynamic and alloc.size_arg > 0:
        return

    size_var = alloc.size_expr
    if not size_var:
        return

    line = ir_lines[alloc.pc] if alloc.pc < len(ir_lines) else ""
    m = re.search(r'(?:malloc|calloc|realloc)\s*\(\s*(\w+)\s*[),]', line)
    if m:
        size_var = m.group(1)

    sys.alloc_var = size_var

    trace_constant_assignment(ir_lines, size_var, alloc.pc, sys,
                              ConstraintType.ALLOC_SIZE, "alloc")
    trace_type_bound(ir_lines, size_var, alloc.pc, sys,
                     ConstraintType.TYPE_BOUND)
    trace_guard_upper_bound(ir_lines, size_var, alloc.pc, sys,
                            ConstraintType.GUARD_CONDITION, "alloc")


def _collect_copy_constraints(
    store: HeapStore,
    ir_lines: list[str],
    sys: ConstraintSystem,
) -> None:
    """提取拷贝大小约束 — 支持库函数写入和源码级写入模式."""
    sys.mnemonic = store.mnemonic

    if store.mnemonic in (
            'strcpy', 'strcat', 'memcpy', 'strncpy',
            'memset', 'strncat', 'memmove', 'copy'):
        _collect_lib_copy_constraints(store, ir_lines, sys)
        return

    if store.mnemonic == 'array_index':
        _collect_array_index_constraints(store, ir_lines, sys)
        return

    if store.mnemonic == 'ptr_deref':
        _collect_ptr_deref_constraints(store, ir_lines, sys)
        return

    if store.mnemonic in ('sprintf', 'snprintf'):
        _collect_sprintf_constraints(store, ir_lines, sys)
        return

    sys.store_size = store.store_size if store.store_size > 0 else 4


def _collect_loop_constraints(
    alloc: HeapAllocSite,
    store: HeapStore,
    ir_lines: list[str],
    sys: ConstraintSystem,
) -> None:
    """提取循环上界约束."""
    window = ir_lines[alloc.pc:min(len(ir_lines), store.pc + 1)]
    window_text = "\n".join(window)

    for_pat = re.search(
        r'for\s*\([^;]*;\s*(\w+)\s*(<|<=)\s*(\w+|\d+)[^;]*;',
        window_text)
    if for_pat:
        loop_var = for_pat.group(1)
        bound_expr = for_pat.group(3)
        try:
            bound = int(bound_expr, 0)
            sys.loop_var = loop_var
            sys.loop_bound = bound
            sys.add(LinearConstraint(
                coefficients={loop_var: 1.0},
                constant=float(-(bound - 1)) if for_pat.group(2) == '<'
                else float(-bound),
                operator="<=",
                source=ConstraintType.LOOP_BOUND,
                confidence=0.9,
                description=f"loop: {loop_var} {for_pat.group(2)} {bound}",
            ))
        except ValueError:
            if bound_expr == sys.alloc_var and sys.alloc_size > 0:
                sys.loop_var = loop_var
                sys.loop_bound = sys.alloc_size
                sys.add(LinearConstraint(
                    coefficients={loop_var: 1.0},
                    constant=float(-sys.alloc_size),
                    operator="<=",
                    source=ConstraintType.LOOP_BOUND,
                    confidence=0.85,
                    description=f"loop: {loop_var} < {bound_expr} = alloc_size",
                ))
            else:
                sys.loop_var = loop_var
                trace_constant_assignment(
                    ir_lines, bound_expr, alloc.pc, sys,
                    ConstraintType.LOOP_BOUND, "loop_bound")
                sys.add(LinearConstraint(
                    coefficients={loop_var: 1.0, bound_expr: -1.0},
                    constant=0.0 if for_pat.group(2) == '<=' else 1.0,
                    operator="<=",
                    source=ConstraintType.LOOP_BOUND,
                    confidence=0.85,
                    description=f"loop: {loop_var} {for_pat.group(2)} {bound_expr}",
                ))
                for c in sys.constraints:
                    if (c.source == ConstraintType.LOOP_BOUND
                            and c.operator == '=='
                            and bound_expr in c.coefficients
                            and c.coefficients.get(bound_expr, 0) == 1.0):
                        val = -c.constant
                        if val > 0 and val < 100000:
                            sys.loop_bound = int(val)
                            break

    cmp_pat = re.search(
        r'cmp\s+\w+,\s*(0x[0-9a-fA-F]+|\d+)',
        window_text, re.IGNORECASE)
    if cmp_pat and not sys.loop_var:
        try:
            bound = int(cmp_pat.group(1), 0)
            if 0 < bound < 100000:
                sys.loop_bound = bound
        except ValueError:
            pass


def _collect_guard_constraints(
    decompiled_text: str,
    alloc: HeapAllocSite,
    store: HeapStore,
    sys: ConstraintSystem,
) -> None:
    """从伪代码中提取守卫条件约束."""
    try:
        from analysis.guard_condition_inferrer import GuardConditionInferrer
        inferrer = GuardConditionInferrer()
        guards = inferrer.extract_guards(decompiled_text)
        for gs in guards:
            if gs.line > store.pc:
                continue
            bounds = gs.get_bounds()
            for var, (lo, hi) in bounds.items():
                if var in sys.var_names or var == sys.offset_var:
                    if hi is not None and hi < 2**62:
                        sys.add(LinearConstraint(
                            coefficients={var: 1.0},
                            constant=float(-hi),
                            operator="<=",
                            source=ConstraintType.GUARD_CONDITION,
                            confidence=0.85,
                            description=f"guard: {var} <= {hi}",
                        ))
                    if lo is not None and lo > -(2**62):
                        sys.add(LinearConstraint(
                            coefficients={var: 1.0},
                            constant=float(-(lo - 1)),
                            operator=">=",
                            source=ConstraintType.GUARD_CONDITION,
                            confidence=0.85,
                            description=f"guard: {var} >= {lo}",
                        ))
    except ImportError:
        pass


__all__ = ['collect_constraints']
