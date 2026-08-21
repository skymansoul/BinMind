"""
Fourier-Motzkin 消元: 线性不等式系统的变量消去与可行性判定: 将约束按 x_j 系数正/负/零分组, 组合正负系数约束消去 x_j, 系数为零的约束保留。
消元后出现矛盾 (如 1 <= 0) 则系统不可行, 无剩余约束则可行; 复杂度最坏 O(n^2)/变量, 堆溢出约束系统通常 <20 条, 实际运行 <1ms。
不替代 SMT 求解器, 仅处理线性不等式, 不处理位运算/非线性关系; 这是 GAPSBV-CJ 的核心简化。
"""

from typing import Optional

from core.cj_constraint_types import LinearConstraint


INF = float('inf')


def substitute_constant(
    constraint: LinearConstraint,
    bound_map: dict[str, float],
) -> Optional[LinearConstraint]:
    """将已知常量值代入约束, 返回简化后的约束.

    若约束中所有变量都已知, 返回纯常量约束.
    若约束中仍有未知变量, 代入已知值, 保留未知变量.
    """
    new_coeffs = {}
    new_const = constraint.constant

    for var, coef in constraint.coefficients.items():
        if var in bound_map:
            new_const += coef * bound_map[var]
        else:
            new_coeffs[var] = coef

    if not new_coeffs:
        if _evaluate(constraint.operator, new_const):
            return None
        return LinearConstraint(
            coefficients={},
            constant=new_const,
            operator=constraint.operator,
            source=constraint.source,
            confidence=constraint.confidence,
            description=constraint.description + " [contradiction]",
        )

    return LinearConstraint(
        coefficients=new_coeffs,
        constant=new_const,
        operator=constraint.operator,
        source=constraint.source,
        confidence=constraint.confidence,
        description=constraint.description,
    )


def fourier_motzkin_eliminate(
    constraints: list[LinearConstraint],
    target_vars: list[str],
) -> list[LinearConstraint]:
    """对约束系统消去target_vars中的变量, 返回剩余约束.

    按target_vars顺序逐一消去. 每次消去后约束数可能增长,
    但对于堆溢出场景(变量数<10, 约束数<20)可控.
    """
    result = list(constraints)

    for var in target_vars:
        positive = []
        negative = []
        neutral = []

        for c in result:
            coef = c.coefficients.get(var, 0.0)
            if coef > 1e-12:
                positive.append(c)
            elif coef < -1e-12:
                negative.append(c)
            else:
                neutral.append(c)

        combined = list(neutral)

        for cp in positive:
            for cn in negative:
                new_c = _combine(cp, cn, var)
                if new_c is not None:
                    combined.append(new_c)

        result = combined

    return result


def check_feasibility(
    constraints: list[LinearConstraint],
) -> tuple[bool, str]:
    """检查约束系统是否可行(无矛盾).

    返回 (feasible, reason).
    feasible=True: 系统可能可行(未发现矛盾)
    feasible=False: 系统确定不可行(存在矛盾约束)

    矛盾检测: 纯常量约束 1 <= 0 判不可行.
    """
    for c in constraints:
        if c.is_constant_only():
            if not _evaluate(c.operator, c.constant):
                return False, f"contradiction: {c.description}"

    return True, "no contradiction found"


def _combine(
    c_pos: LinearConstraint,
    c_neg: LinearConstraint,
    var: str,
) -> Optional[LinearConstraint]:
    """组合正系数约束和负系数约束消去变量var.

    c_pos: a*x_j + rest_pos <= 0  (a > 0)
    c_neg: b*x_j + rest_neg <= 0  (b < 0)

    消去x_j: |b|*c_pos + a*c_neg 即 (|b|*rest_pos + a*rest_neg) <= 0
    x_j被消去.
    """
    a = c_pos.coefficients[var]
    b = c_neg.coefficients[var]

    scale_pos = abs(b)
    scale_neg = abs(a)

    new_coeffs: dict[str, float] = {}
    new_const = c_pos.constant * scale_pos + c_neg.constant * scale_neg

    all_vars = set(c_pos.coefficients.keys()) | set(c_neg.coefficients.keys())
    for v in all_vars:
        if v == var:
            continue
        vp = c_pos.coefficients.get(v, 0.0) * scale_pos
        vn = c_neg.coefficients.get(v, 0.0) * scale_neg
        total = vp + vn
        if abs(total) > 1e-12:
            new_coeffs[v] = total

    new_conf = min(c_pos.confidence, c_neg.confidence) * 0.95

    if not new_coeffs:
        val = new_const
        if val < -1e-9:
            return LinearConstraint(
                coefficients={},
                constant=new_const,
                operator="<=",
                source=c_pos.source,
                confidence=new_conf,
                description=f"[FM contradiction] {c_pos.description} + {c_neg.description}",
            )
        return None

    op = _merge_operator(c_pos.operator, c_neg.operator)
    if op is None:
        op = "<="

    return LinearConstraint(
        coefficients=new_coeffs,
        constant=new_const,
        operator=op,
        source=c_pos.source,
        confidence=new_conf,
        description=f"[FM] eliminate {var}",
    )


def _merge_operator(op1: str, op2: str) -> Optional[str]:
    """合并两个不等式的操作符."""
    if op1 == op2:
        return op1
    if '<' in op1 and '<' in op2:
        return '<='
    if '>' in op1 and '>' in op2:
        return '>='
    if op1 == '==' or op2 == '==':
        return '<='
    return '<='


def _evaluate(operator: str, value: float) -> bool:
    """求值纯常量约束."""
    if operator == "<=":
        return value <= 1e-9
    elif operator == "<":
        return value < -1e-9
    elif operator == ">=":
        return value >= -1e-9
    elif operator == ">":
        return value > 1e-9
    elif operator == "==":
        return abs(value) < 1e-9
    return True


__all__ = [
    'substitute_constant',
    'fourier_motzkin_eliminate',
    'check_feasibility',
]
