"""
FM 边界推理增强: 从 Fourier-Motzkin 消元残差约束中推导变量边界: 消元后残差如 `2*var <= 100` 可直接推出 var <= 50, 但原流程只检查纯常量矛盾而返回 INCONCLUSIVE。
本模块追加一步: 从残差约束提取单变量不等式 `c*var + k <= 0` 推出 var <= -k/c, 计算每个变量的 [lo, hi] 区间, 区间能确定 write_end <= alloc_usable 则 SAFE, 能确定 write_end > alloc_usable 则 OVERFLOW。
不替代 SMT 求解器, 仅处理单变量线性边界推导, 理论依据为区间算术传播规则。
"""


from typing import Optional, Dict, Tuple
from dataclasses import dataclass

from core.cj_constraint_types import (
    ConstraintType, LinearConstraint, ConstraintSystem, SolverVerdict,
)
from core.cj_fourier_motzkin import fourier_motzkin_eliminate


@dataclass
class VarBound:
    """变量的区间边界."""
    lo: float = float('-inf')
    hi: float = float('inf')
    source: str = ""

    def intersect(self, other: 'VarBound') -> 'VarBound':
        return VarBound(
            lo=max(self.lo, other.lo),
            hi=min(self.hi, other.hi),
            source=f"{self.source}∩{other.source}",
        )


def derive_bounds(
    constraints: list[LinearConstraint],
) -> Dict[str, VarBound]:
    """从约束列表推导每个变量的区间边界.

    对每条单变量约束 c*var + k OP 0:
      c > 0, OP '<=' 即 var <= -k/c (hi bound)
      c < 0, OP '<=' 即 var >= -k/c (lo bound)
      c > 0, OP '>=' 即 var >= -k/c (lo bound)
      c < 0, OP '>=' 即 var <= -k/c (hi bound)
      OP '==' 即 var = -k/c (both bounds)

    多变量约束不在本步处理 (需要FM消元先消去其他变量).
    """
    bounds: Dict[str, VarBound] = {}

    for c in constraints:
        if len(c.coefficients) != 1:
            continue

        var = list(c.coefficients.keys())[0]
        coef = c.coefficients[var]
        k = c.constant
        op = c.operator

        bound_val = -k / coef if abs(coef) > 1e-12 else float('inf')
        b = bounds.get(var, VarBound())

        if coef > 0:
            if op in ('<=', '<'):
                b.hi = min(b.hi, bound_val)
            elif op in ('>=', '>'):
                b.lo = max(b.lo, bound_val)
            elif op == '==':
                b.lo = max(b.lo, bound_val)
                b.hi = min(b.hi, bound_val)
        else:
            if op in ('<=', '<'):
                b.lo = max(b.lo, bound_val)
            elif op in ('>=', '>'):
                b.hi = min(b.hi, bound_val)
            elif op == '==':
                b.lo = max(b.lo, bound_val)
                b.hi = min(b.hi, bound_val)

        b.source = c.description
        bounds[var] = b

    return bounds


def eval_write_end_with_bounds(
    write_end_expr: dict[str, float],
    bounds: Dict[str, VarBound],
    alloc_usable: int,
    const_offset: float = 0.0,
) -> Optional[SolverVerdict]:
    """用变量边界评估write_end表达式, 判定安全/溢出.

    write_end_expr = sum(coef_i * var_i) + const_offset
    安全判定需要write_end_hi: 对coef>0取var.hi, 对coef<0取var.lo
    溢出判定需要write_end_lo: 对coef>0取var.lo, 对coef<0取var.hi

    write_end_hi <= alloc_usable 判 PROVEN_SAFE
    write_end_lo > alloc_usable 判 PROVEN_OVERFLOW
    否则返回 None
    """
    if not write_end_expr:
        return None

    NEG_INF = float('-inf')
    POS_INF = float('inf')

    hi_acc = const_offset
    hi_ok = True
    for var, coef in write_end_expr.items():
        if coef == 0:
            continue
        b = bounds.get(var)
        if b is None:
            hi_ok = False
            break
        if coef > 0:
            if b.hi == POS_INF:
                hi_ok = False
                break
            hi_acc += coef * b.hi
        else:
            if b.lo == NEG_INF:
                hi_ok = False
                break
            hi_acc += coef * b.lo

    if hi_ok and hi_acc <= alloc_usable + 1e-9:
        return SolverVerdict.PROVEN_SAFE

    lo_acc = const_offset
    lo_ok = True
    for var, coef in write_end_expr.items():
        if coef == 0:
            continue
        b = bounds.get(var)
        if b is None:
            lo_ok = False
            break
        if coef > 0:
            if b.lo == NEG_INF:
                lo_ok = False
                break
            lo_acc += coef * b.lo
        else:
            if b.hi == POS_INF:
                lo_ok = False
                break
            lo_acc += coef * b.hi

    if lo_ok and lo_acc > alloc_usable + 1e-9:
        return SolverVerdict.PROVEN_OVERFLOW

    return None


def fm_bound_refine(
    sys: ConstraintSystem,
    write_end_expr: dict[str, float],
    alloc_usable: int,
) -> Optional[Tuple[SolverVerdict, str]]:
    """FM消元 + 边界推导的联合判定.

    流程:
      1. 对非write_end变量做FM消元
      2. 从残差约束提取单变量边界
      3. 用边界评估write_end

    返回 (verdict, reason) 或 None.
    """
    if not write_end_expr or alloc_usable <= 0:
        return None

    const_offset = _compute_const_offset(sys)

    all_constraints = list(sys.constraints)

    target_vars = set(write_end_expr.keys())
    non_target = [v for v in sys.var_names if v not in target_vars]

    if non_target:
        all_constraints = fourier_motzkin_eliminate(
            all_constraints, non_target)

    remaining_target = [v for v in target_vars if v in
                        {k for c in all_constraints for k in c.coefficients}]

    if len(remaining_target) > 1:
        elim = list(remaining_target[1:])
        all_constraints = fourier_motzkin_eliminate(
            all_constraints, elim)

    bounds = derive_bounds(all_constraints)

    verdict = eval_write_end_with_bounds(
        write_end_expr, bounds, alloc_usable, const_offset)

    bounds_str = ", ".join(
        f"{k}=[{v.lo:.0f},{v.hi:.0f}]" for k, v in bounds.items())

    if verdict == SolverVerdict.PROVEN_SAFE:
        return verdict, (
            f"FM boundary derivation: write_end max <= {alloc_usable} "
            f"(bounds: {bounds_str})")
    if verdict == SolverVerdict.PROVEN_OVERFLOW:
        return verdict, (
            f"FM boundary derivation: write_end min > {alloc_usable} "
            f"(bounds: {bounds_str})")

    return None


def _compute_const_offset(sys: ConstraintSystem) -> float:
    """从约束系统提取write_end表达式的常量偏移.

    _compute_write_end返回的系数dict只含变量, 常量偏移在描述字符串中.
      copy操作: write_end = copy_var + offset_val, const = offset_val
      store操作: write_end = offset_var + store_size, const = store_size
    """
    is_copy_op = sys.mnemonic in (
        'strcpy', 'strcat', 'memcpy', 'strncpy',
        'memset', 'strncat', 'memmove', 'copy')

    if is_copy_op:
        return float(sys.offset_val) if sys.offset_val > 0 else 0.0

    return float(sys.store_size if sys.store_size > 0 else 4)


__all__ = [
    'VarBound', 'derive_bounds',
    'eval_write_end_with_bounds', 'fm_bound_refine',
]
