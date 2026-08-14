"""路径敏感CFG数据类型 — BasicBlock/CFGPath定义及guard约束提取。
供CFG构建器引用, 分离数据类型定义与CFG构建逻辑, 降低单文件行数。"""

import re
from dataclasses import dataclass, field
from typing import List, Optional

from core.cj_constraint_types import (
    ConstraintType, LinearConstraint,
)


@dataclass
class BasicBlock:
    """基本块: 一段顺序执行的语句, 以分支/循环/函数边界结束。"""
    start_line: int
    end_line: int
    stmts: List[str] = field(default_factory=list)
    branch_cond: str = ""
    branch_taken_line: int = 0
    branch_not_taken_line: int = 0
    is_loop_header: bool = False
    is_loop_body: bool = False
    loop_bound_var: str = ""
    loop_bound_val: int = -1


@dataclass
class CFGPath:
    """一条从alloc到write的CFG路径。"""
    blocks: List[BasicBlock] = field(default_factory=list)
    guard_constraints: List[LinearConstraint] = field(default_factory=list)
    is_feasible: bool = True
    description: str = ""


def extract_guard_from_cond(
    cond: str, taken: bool,
) -> Optional[LinearConstraint]:
    """从分支条件提取guard约束。

    taken=True: 分支被取时, cond为真;
    taken=False: 分支未被取时, cond为假 (取反)。
    """
    if not cond:
        return None
    m = re.match(
        r'(\w+)\s*(>|<|>=|<=|==|!=)\s*(\d+|0x[0-9a-fA-F]+)', cond.strip())
    if not m:
        return None
    var = m.group(1)
    op = m.group(2)
    try:
        val = int(m.group(3), 0)
    except ValueError:
        return None

    if not taken:
        op = _negate_op(op)

    if op == '>':
        return LinearConstraint(
            coefficients={var: 1.0}, constant=float(-(val + 1)),
            operator=">=", source=ConstraintType.GUARD_CONDITION,
            confidence=0.90,
            description=f"path guard: {var} > {val}")
    if op == '>=':
        return LinearConstraint(
            coefficients={var: 1.0}, constant=float(-val),
            operator=">=", source=ConstraintType.GUARD_CONDITION,
            confidence=0.90,
            description=f"path guard: {var} >= {val}")
    if op == '<':
        return LinearConstraint(
            coefficients={var: 1.0}, constant=float(-(val - 1)),
            operator="<=", source=ConstraintType.GUARD_CONDITION,
            confidence=0.90,
            description=f"path guard: {var} < {val}")
    if op == '<=':
        return LinearConstraint(
            coefficients={var: 1.0}, constant=float(-val),
            operator="<=", source=ConstraintType.GUARD_CONDITION,
            confidence=0.90,
            description=f"path guard: {var} <= {val}")
    if op == '==':
        return LinearConstraint(
            coefficients={var: 1.0}, constant=float(-val),
            operator="==", source=ConstraintType.GUARD_CONDITION,
            confidence=0.90,
            description=f"path guard: {var} == {val}")
    return None


def _negate_op(op: str) -> str:
    """逻辑取反操作符。"""
    return {'>': '<=', '>=': '<', '<': '>=', '<=': '>',
            '==': '!=', '!=': '=='}[op]


__all__ = [
    'BasicBlock', 'CFGPath', 'extract_guard_from_cond',
]
