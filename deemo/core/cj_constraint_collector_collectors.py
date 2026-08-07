"""
约束收集器子模块 — 拷贝大小约束与偏移约束提取.

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
from core.heap_overflow_detector import HeapStore


def _collect_lib_copy_constraints(
    store: HeapStore,
    ir_lines: list[str],
    sys: ConstraintSystem,
) -> None:
    """提取库函数拷贝大小约束(原有逻辑)."""
    if store.mnemonic in ('strcpy', 'strcat'):
        sys.copy_var = ""
        sys.copy_size = -1
        return

    if store.store_size > 0:
        sys.copy_size = store.store_size
        return

    if store.mnemonic in ('memcpy', 'strncpy', 'memset', 'strncat'):
        line = ir_lines[store.pc] if store.pc < len(ir_lines) else ""
        m = re.search(
            r'(?:memcpy|memmove|memset|strncpy|strncat)\s*\('
            r'[^,]+,\s*[^,]+,\s*(\w+)\s*\)',
            line)
        if m:
            copy_var = m.group(1)
            try:
                int(copy_var, 0)
                return
            except ValueError:
                sys.copy_var = copy_var
                trace_constant_assignment(
                    ir_lines, copy_var, store.pc, sys,
                    ConstraintType.COPY_SIZE, "copy")
                trace_type_bound(
                    ir_lines, copy_var, store.pc, sys,
                    ConstraintType.TYPE_BOUND)
                trace_guard_upper_bound(
                    ir_lines, copy_var, store.pc, sys,
                    ConstraintType.GUARD_CONDITION, "copy")


def _collect_array_index_constraints(
    store: HeapStore,
    ir_lines: list[str],
    sys: ConstraintSystem,
) -> None:
    """提取数组索引写入约束: buf[idx] = val.

    关键约束: 写入大小=1字节/元素大小, 偏移=idx*stride.
    循环内写入时, 写入范围=loop_bound*stride.
    """
    line = ir_lines[store.pc] if store.pc < len(ir_lines) else ""

    m = re.search(r'(\w+)\s*\[\s*(\w+)(?:\s*\+\s*(\d+))?\s*\]', line)
    if m:
        idx_var = m.group(2)
        stride = 1
        if 'int' in line[:line.find('[')] if '[' in line else False:
            stride = 4

        sys.store_size = stride
        sys.offset_var = idx_var
        try:
            int(idx_var, 0)
        except ValueError:
            trace_type_bound(
                ir_lines, idx_var, store.pc, sys,
                ConstraintType.TYPE_BOUND)
            trace_guard_upper_bound(
                ir_lines, idx_var, store.pc, sys,
                ConstraintType.GUARD_CONDITION, "offset")

    # 循环内多次写入: copy_size = loop_bound * stride
    sys.copy_size = -1


def _collect_ptr_deref_constraints(
    store: HeapStore,
    ir_lines: list[str],
    sys: ConstraintSystem,
) -> None:
    """提取指针解引用写入约束: *(ptr+off) = val.

    store.offset已在候选提取阶段解析.
    动态偏移时追踪偏移变量的边界约束.
    """
    sys.store_size = store.store_size if store.store_size > 0 else 1

    if store.offset_is_dynamic:
        line = ir_lines[store.pc] if store.pc < len(ir_lines) else ""
        m = re.search(r'\*\s*\(\s*\w+\s*\+\s*(\w+)\s*\)', line)
        if m:
            off_var = m.group(1)
            sys.offset_var = off_var
            try:
                int(off_var, 0)
            except ValueError:
                trace_type_bound(
                    ir_lines, off_var, store.pc, sys,
                    ConstraintType.TYPE_BOUND)
                trace_guard_upper_bound(
                    ir_lines, off_var, store.pc, sys,
                    ConstraintType.GUARD_CONDITION, "offset")
    else:
        sys.offset_val = store.offset

    sys.copy_size = -1


def _collect_sprintf_constraints(
    store: HeapStore,
    ir_lines: list[str],
    sys: ConstraintSystem,
) -> None:
    """提取sprintf/snprintf写入约束.

    sprintf: 写入大小=格式化后的字符串长度(运行时确定) → copy_size=-1.
    snprintf: 写入大小上限=第二参数 → copy_size=snprintf_bufsz.
    """
    if store.mnemonic == 'snprintf' and store.store_size > 0:
        sys.copy_size = store.store_size
        return

    sys.copy_var = ""
    sys.copy_size = -1


def _collect_offset_constraints(
    store: HeapStore,
    ir_lines: list[str],
    sys: ConstraintSystem,
) -> None:
    """提取写入偏移约束 — 支持库函数和源码级写入模式."""
    if store.mnemonic == 'array_index':
        if store.offset_is_dynamic:
            line = ir_lines[store.pc] if store.pc < len(ir_lines) else ""
            m = re.search(r'(\w+)\s*\[\s*(\w+)', line)
            if m:
                idx_var = m.group(2)
                sys.offset_var = idx_var
                trace_type_bound(
                    ir_lines, idx_var, store.pc, sys,
                    ConstraintType.TYPE_BOUND)
                trace_guard_upper_bound(
                    ir_lines, idx_var, store.pc, sys,
                    ConstraintType.GUARD_CONDITION, "offset")
        return

    if store.mnemonic == 'ptr_deref':
        if not store.offset_is_dynamic and store.offset >= 0:
            sys.offset_val = store.offset
        return

    if store.mnemonic in ('sprintf', 'snprintf'):
        sys.offset_val = 0
        return

    if not store.offset_is_dynamic and store.offset >= 0:
        sys.offset_val = store.offset
        return

    line = ir_lines[store.pc] if store.pc < len(ir_lines) else ""
    m = re.search(r'\[(\w+)\s*\+\s*(\w+)\]', line)
    if not m:
        m = re.search(r'\[(\w+)\s*\*\s*(\d+)\s*\+\s*(\w+)\]', line)
        if m:
            idx_var = m.group(1)
            off_var = m.group(3)
            sys.offset_var = idx_var
            if off_var and off_var != '0':
                try:
                    base_off = int(off_var, 0)
                    sys.offset_val = base_off
                except ValueError:
                    pass
            return

    if m:
        idx_var = m.group(2)
        try:
            int(idx_var, 0)
            return
        except ValueError:
            sys.offset_var = idx_var
            trace_type_bound(
                ir_lines, idx_var, store.pc, sys,
                ConstraintType.TYPE_BOUND)
            trace_guard_upper_bound(
                ir_lines, idx_var, store.pc, sys,
                ConstraintType.GUARD_CONDITION, "offset")
