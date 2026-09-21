"""
constraint_safety_prover 辅助函数 — 写入边界与可用大小的计算逻辑.

主流程精简, 将几何计算下沉到本模块.
"""

from typing import Optional

from core.constraint_constraint_types import (
    ConstraintType, ConstraintSystem,
)


def evaluate_constant_write_end(sys: ConstraintSystem) -> Optional[float]:
    """当write_end表达式为纯常量时, 计算其数值."""
    is_copy_op = sys.mnemonic in (
        'strcpy', 'strcat', 'memcpy', 'strncpy',
        'memset', 'strncat', 'memmove', 'copy')

    if is_copy_op:
        if sys.copy_size == -1:
            return None
        base_offset = sys.offset_val if sys.offset_val > 0 else 0
        if sys.copy_size > 0:
            return float(sys.copy_size + base_offset)
        return None

    store_sz = sys.store_size if sys.store_size > 0 else 4
    if sys.offset_val > 0 and not sys.offset_var:
        return float(sys.offset_val + store_sz)
    if sys.loop_bound > 0:
        return float(sys.loop_bound * store_sz)
    return None


def compute_usable_size(
    sys: ConstraintSystem,
    platform: str,
) -> int:
    """计算分配器实际可用大小(含对齐)."""
    from analysis.allocator_chunk_model import compute_effective_boundary

    base_size = sys.alloc_size
    if base_size <= 0 and sys.alloc_var:
        for c in sys.constraints:
            if (c.source == ConstraintType.ALLOC_SIZE
                    and c.is_constant_only()
                    and c.constant > 0):
                base_size = int(c.constant)
                break
            if (c.source == ConstraintType.GUARD_CONDITION
                    and sys.alloc_var in c.coefficients):
                bound = int(-c.constant / c.coefficients[sys.alloc_var])
                if bound > 0 and (base_size == 0 or bound < base_size):
                    base_size = bound

    if base_size <= 0:
        return 0

    return compute_effective_boundary(base_size, "malloc")


def compute_write_end(
    sys: ConstraintSystem,
) -> tuple[Optional[dict[str, float]], str]:
    """计算写入结束位置的表达式.

    对copy操作(memcpy/strcpy等): write_end = copy_size + offset
    对store操作(store/mov): write_end = offset + store_size
    对循环写入: write_end = loop_bound * elem_size

    返回 (coefficients_dict, description) 或 (None, "").
    coefficients_dict为空字典表示纯常量表达式.
    """
    is_copy_op = sys.mnemonic in (
        'strcpy', 'strcat', 'memcpy', 'strncpy',
        'memset', 'strncat', 'memmove', 'copy')

    if is_copy_op:
        if sys.copy_size == -1:
            return None, "unbounded copy (strcpy/strcat)"

        base_offset = sys.offset_val if sys.offset_val > 0 else 0

        if sys.copy_size > 0:
            end = sys.copy_size + base_offset
            return ({}, f"copy_size({sys.copy_size})+off({base_offset})={end}")

        if sys.copy_var:
            return (
                {sys.copy_var: 1.0},
                f"copy_size({sys.copy_var})+off({base_offset})",
            )
        return None, ""

    store_sz = sys.store_size if sys.store_size > 0 else 4

    if sys.offset_val > 0 and not sys.offset_var:
        end = sys.offset_val + store_sz
        return ({}, f"offset({sys.offset_val})+store({store_sz})={end}")

    # 循环写入: loop_bound已知时write_end为纯常量, 无需loop_var
    if sys.loop_bound > 0:
        max_offset = (sys.loop_bound - 1) * store_sz
        write_end = max_offset + store_sz
        return (
            {},
            f"loop_bound({sys.loop_bound})*{store_sz}={write_end}",
        )

    # 无显式loop_bound但有loop_var和约束时, 推断write_end上界
    if sys.loop_var and not sys.offset_var:
        # 从约束中提取loop_var的上界
        for c in sys.constraints:
            if sys.loop_var in c.coefficients:
                coef = c.coefficients[sys.loop_var]
                if coef > 0 and c.operator == '<=':
                    bound = (-c.constant) / coef
                    if bound > 0:
                        write_end = int(bound) * store_sz
                        return (
                            {},
                            f"loop_var({sys.loop_var}<={int(bound)})*{store_sz}={write_end}",
                        )

    if sys.offset_var:
        return (
            {sys.offset_var: 1.0},
            f"offset({sys.offset_var})+store({store_sz})",
        )

    return None, ""


__all__ = [
    'evaluate_constant_write_end',
    'compute_usable_size',
    'compute_write_end',
]
