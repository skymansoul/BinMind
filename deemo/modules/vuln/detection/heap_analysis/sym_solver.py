# coding: utf-8
"""符号尺寸约束传播约束求解器 — write_size vs alloc_size+offset 的约束关系判定.

- 常量比较判定
- 符号关系推导(同变量系数差)
- 路径约束安全的证明
- jcc方向推断
- 分配标签查找
"""
from typing import Dict, List, Optional

from modules.vuln.detection.heap_analysis.sym_types import (
    SymExpr, SymAllocRecord, SymWriteRecord, ConstraintRecord,
)
from modules.vuln.detection.heap_analysis.sym_parser import (
    parse_insn, extract_imm, normalize_reg,
)


def solve_write(
    write: SymWriteRecord,
    constraints: List[ConstraintRecord],
) -> str:
    """求解 write_size vs alloc_size + offset 的约束关系

    返回 "safe" / "overflow" / "uncertain"。
    """
    if write.linked_alloc is None:
        return "uncertain"

    alloc_expr = write.linked_alloc.size_expr
    write_expr = write.size_expr
    offset_expr = write.offset_expr

    env: Dict[str, int] = {}
    alloc_val = alloc_expr.eval(env)
    write_val = write_expr.eval(env)
    offset_val = offset_expr.eval(env) or 0

    # 双方已知常量 → 直接比较
    if alloc_val is not None and write_val is not None:
        bound = alloc_val - offset_val
        if write_val <= bound:
            return "safe"
        if write_val > alloc_val:
            return "overflow"
        return "safe" if write_val <= bound else "overflow"

    # 同变量系数差推导
    if (alloc_expr.var and write_expr.var
            and alloc_expr.var == write_expr.var):
        diff = write_expr.const - alloc_expr.const - offset_val
        if diff > 0:
            return "overflow"
        if diff <= 0:
            return "safe"

    # 同变量同系数 — 常量差判定
    if (alloc_expr.var and write_expr.var
            and alloc_expr.var == write_expr.var
            and alloc_expr.coeff == write_expr.coeff):
        diff = write_expr.const - alloc_expr.const - offset_val
        return "overflow" if diff > 0 else "safe"

    if check_constraint_safe(write_expr, alloc_expr, offset_val, constraints):
        return "safe"

    return "uncertain"


def check_constraint_safe(
    write_expr: SymExpr, alloc_expr: SymExpr,
    offset: int, constraints: List[ConstraintRecord],
) -> bool:
    """检查路径约束是否能证明 write <= alloc - offset"""
    if not write_expr.var or not alloc_expr.var:
        return False
    if write_expr.var != alloc_expr.var:
        return False
    for c in constraints:
        if c.var == write_expr.var:
            if c.op in ('le', 'lt') and c.value <= alloc_expr.const:
                return True
    return False


def find_jcc_op(insns: List[str], cmp_idx: int) -> Optional[str]:
    """cmp后查找条件跳转方向"""
    for j in range(cmp_idx + 1, min(cmp_idx + 5, len(insns))):
        mnem, _ = parse_insn(insns[j])
        op_map = {
            'jle': 'le', 'jbe': 'le', 'jge': 'ge', 'jae': 'ge',
            'jl': 'lt', 'jb': 'lt', 'jg': 'gt', 'ja': 'gt',
            'je': 'eq', 'jne': 'ne'}
        if mnem in op_map:
            return op_map[mnem]
    return None


def find_alloc_by_label(
    label: str,
    allocs: Dict[str, SymAllocRecord],
) -> Optional[SymAllocRecord]:
    """通过指针标签查找分配记录"""
    if not label or label == "unknown":
        return None
    if label in allocs:
        return allocs[label]
    base = label.split('+')[0].split('-')[0].strip()
    return allocs.get(base)


def extract_offset(reg: str, regs: Dict[str, SymExpr]) -> SymExpr:
    """从寄存器值提取已知偏移表达式"""
    expr = regs.get(reg)
    if expr and not expr.is_const:
        return SymExpr(is_const=True, const=expr.const)
    return SymExpr(is_const=True, const=0)


def clobber(
    regs: Dict[str, SymExpr],
    ptr_labels: Dict[str, str],
) -> None:
    """call后清除caller-saved寄存器(保留rax返回值)"""
    caller_saved = {'rcx', 'rdx', 'r8', 'r9', 'r10', 'r11'}
    for r in caller_saved:
        regs.pop(r, None)
        ptr_labels.pop(r, None)


__all__ = [
    'solve_write', 'check_constraint_safe', 'find_jcc_op',
    'find_alloc_by_label', 'extract_offset', 'clobber',
]
