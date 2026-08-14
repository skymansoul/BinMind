"""
路径敏感区间域抽象解释器 — CJ 前置精度增强层: 在 CJ 求解前沿 alloc→write 路径逐行传播变量区间 (语法解析在 cj_interval_parser), 多变量联合约束 (2*x+y<=N) 用区间算术分解传播, 迭代到不动点后输出额外 LinearConstraint 注入约束系统。
与 fm_boundary 的区别: fm_boundary 从残差约束反推边界, 本模块从控制流正向传播边界, 信息来源互补。
"""


from dataclasses import dataclass

from core.cj_constraint_types import (
    ConstraintType, LinearConstraint, ConstraintSystem,
)

NEG_INF = float('-inf')
POS_INF = float('inf')
_MAX_ITER = 5


@dataclass
class Interval:
    """闭区间 [lo, hi]."""
    lo: float = NEG_INF
    hi: float = POS_INF

    def is_bottom(self) -> bool:
        return self.lo > self.hi

    def is_const(self) -> bool:
        return self.lo == self.hi and self.lo != NEG_INF

    def join(self, other: 'Interval') -> 'Interval':
        return Interval(min(self.lo, other.lo), max(self.hi, other.hi))

    def meet(self, other: 'Interval') -> 'Interval':
        return Interval(max(self.lo, other.lo), min(self.hi, other.hi))

    def __repr__(self) -> str:
        if self.is_bottom():
            return "_"
        return f"[{self.lo}, {self.hi}]"


class IntervalDomain:
    """变量到区间的映射, 支持路径敏感传播."""

    def __init__(self):
        self._vars: dict[str, Interval] = {}

    def get(self, var: str) -> Interval:
        return self._vars.get(var, Interval())

    def set(self, var: str, val: Interval) -> None:
        if not val.is_bottom():
            self._vars[var] = val

    def copy(self) -> 'IntervalDomain':
        dom = IntervalDomain()
        dom._vars = dict(self._vars)
        return dom

    def meet_var(self, var: str, other: Interval) -> None:
        self.set(var, self.get(var).meet(other))

    def items(self):
        return self._vars.items()


def analyze_path_interval(
    ir_lines: list[str],
    alloc_pc: int,
    write_pc: int,
    decompiled_text: str = "",
) -> IntervalDomain:
    """从alloc_pc到write_pc做路径敏感区间传播."""
    from core.cj_interval_parser import (
        apply_constant_assignments, apply_binary_assignments,
        apply_guard_conditions, apply_guard_conditions_text,
        apply_loop_bounds,
    )

    dom = IntervalDomain()
    if alloc_pc < 0 or write_pc < 0:
        return dom

    end = min(len(ir_lines), write_pc + 1)
    start = max(0, alloc_pc)
    lines = ir_lines[start:end]
    context_text = "\n".join(lines) if lines else decompiled_text

    apply_constant_assignments(dom, lines)
    apply_binary_assignments(dom, lines)
    apply_guard_conditions(dom, lines, context_text)
    apply_loop_bounds(dom, context_text)

    if decompiled_text:
        apply_guard_conditions_text(dom, decompiled_text)

    return dom


def interval_refine(
    sys: ConstraintSystem,
    ir_lines: list[str],
    decompiled_text: str = "",
    alloc_pc: int = -1,
    write_pc: int = -1,
) -> ConstraintSystem:
    """区间域增强入口: 迭代到不动点, 注入额外约束."""
    refined = _shallow_copy_sys(sys)
    dom = analyze_path_interval(
        ir_lines, alloc_pc, write_pc, decompiled_text)

    for _ in range(_MAX_ITER):
        before = len(refined.constraints)

        for c in _domain_to_constraints(dom, sys):
            if not _is_redundant(c, refined.constraints):
                refined.add(c)

        _refine_with_multivar(dom, refined)

        for c in _domain_to_constraints(dom, refined):
            if not _is_redundant(c, refined.constraints):
                refined.add(c)

        if len(refined.constraints) == before:
            break

    return refined


def _domain_to_constraints(
    dom: IntervalDomain, sys: ConstraintSystem,
) -> list[LinearConstraint]:
    """将区间域中的变量边界转为线性约束."""
    result = []
    sys_vars = sys.var_names

    for var, iv in dom.items():
        if var not in sys_vars:
            continue
        if iv.is_const():
            result.append(LinearConstraint(
                coefficients={var: 1.0}, constant=float(-iv.lo),
                operator="==", source=ConstraintType.GUARD_CONDITION,
                confidence=0.95,
                description=f"interval: {var} = {iv.lo:.0f} (path-sensitive)",
            ))
            continue

        if iv.hi != POS_INF and iv.hi < 2**62:
            result.append(LinearConstraint(
                coefficients={var: 1.0}, constant=float(-iv.hi),
                operator="<=", source=ConstraintType.GUARD_CONDITION,
                confidence=0.90,
                description=f"interval: {var} <= {iv.hi:.0f} (path-sensitive)",
            ))
        if iv.lo != NEG_INF and iv.lo > -(2**62):
            result.append(LinearConstraint(
                coefficients={var: 1.0}, constant=float(-(iv.lo - 1)),
                operator=">=", source=ConstraintType.GUARD_CONDITION,
                confidence=0.90,
                description=f"interval: {var} >= {iv.lo:.0f} (path-sensitive)",
            ))

    return result


def _refine_with_multivar(
    dom: IntervalDomain, sys: ConstraintSystem,
) -> None:
    """多变量联合约束的区间分解传播.

    对 a*x + b*y + k OP 0, 若y已知则推导x的边界.
    先从约束系统的单变量约束同步域, 再迭代传播.
    """
    _sync_domain_from_constraints(dom, sys)

    for c in sys.constraints:
        if len(c.coefficients) < 2:
            continue

        unknown = [
            v for v in c.coefficients
            if dom.get(v).lo == NEG_INF and dom.get(v).hi == POS_INF
        ]
        if len(unknown) != 1:
            continue

        target = unknown[0]
        tc = c.coefficients[target]
        k_lo = k_hi = 0.0

        for v, coef in c.coefficients.items():
            if v == target:
                continue
            iv = dom.get(v)
            if coef > 0:
                k_lo += coef * iv.lo
                k_hi += coef * iv.hi
            else:
                k_lo += coef * iv.hi
                k_hi += coef * iv.lo

        k = c.constant
        if c.operator in ('<=', '<') and tc > 0:
            dom.meet_var(target, Interval(NEG_INF, -(k_lo + k) / tc))
        elif c.operator in ('<=', '<') and tc < 0:
            dom.meet_var(target, Interval(-(k_hi + k) / tc, POS_INF))
        elif c.operator in ('>=', '>') and tc > 0:
            dom.meet_var(target, Interval(-(k_hi + k) / tc, POS_INF))
        elif c.operator in ('>=', '>') and tc < 0:
            dom.meet_var(target, Interval(NEG_INF, -(k_lo + k) / tc))
        elif c.operator == '==' and tc > 0:
            dom.meet_var(target, Interval(
                -(k_hi + k) / tc, -(k_lo + k) / tc))


def _sync_domain_from_constraints(
    dom: IntervalDomain, sys: ConstraintSystem,
) -> None:
    """从约束系统的单变量约束同步域区间."""
    for c in sys.constraints:
        if len(c.coefficients) != 1:
            continue
        var = list(c.coefficients.keys())[0]
        coef = c.coefficients[var]
        if abs(coef) < 1e-12:
            continue
        val = -c.constant / coef
        cur = dom.get(var)

        if c.operator == '==':
            dom.set(var, cur.meet(Interval(val, val)))
        elif c.operator in ('<=', '<'):
            bound = Interval(NEG_INF, val) if coef > 0 else Interval(val, POS_INF)
            dom.set(var, cur.meet(bound))
        elif c.operator in ('>=', '>'):
            bound = Interval(val, POS_INF) if coef > 0 else Interval(NEG_INF, val)
            dom.set(var, cur.meet(bound))


def _is_redundant(
    new_c: LinearConstraint, existing: list[LinearConstraint],
) -> bool:
    """检查约束是否与已有约束重复."""
    for c in existing:
        if (c.operator == new_c.operator and
                c.constant == new_c.constant and
                c.coefficients == new_c.coefficients):
            return True
    return False


def _shallow_copy_sys(sys: ConstraintSystem) -> ConstraintSystem:
    """深拷贝约束系统."""
    return ConstraintSystem(
        constraints=list(sys.constraints),
        alloc_var=sys.alloc_var, alloc_size=sys.alloc_size,
        copy_var=sys.copy_var, copy_size=sys.copy_size,
        offset_var=sys.offset_var, offset_val=sys.offset_val,
        loop_var=sys.loop_var, loop_bound=sys.loop_bound,
        mnemonic=sys.mnemonic, store_size=sys.store_size,
    )


__all__ = [
    'Interval', 'IntervalDomain',
    'analyze_path_interval', 'interval_refine',
]
