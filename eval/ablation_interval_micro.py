"""

针对性场景验证区间域在约束收集器无法覆盖时的增量价值.
"""
from __future__ import annotations
from typing import Any, Dict, List


def _micro_row(
    name: str,
    sys_cj: Any,
    sys_iv: Any,
    r_cj: Any,
    r_iv: Any,
    expected: Any,
    desc: str,
) -> Dict:
    """构建微基准测试结果行."""
    cj_constraints = len(sys_cj.constraints)
    iv_constraints = len(sys_iv.constraints)
    new_constraints = iv_constraints - cj_constraints
    cj_verdict = r_cj.verdict.value
    iv_verdict = r_iv.verdict.value
    improved = (r_cj.verdict != r_iv.verdict and
                (expected is None or r_iv.verdict == expected))
    return {
        "test": name,
        "description": desc,
        "cj_constraints": cj_constraints,
        "iv_constraints": iv_constraints,
        "new_constraints": new_constraints,
        "cj_verdict": cj_verdict,
        "iv_verdict": iv_verdict,
        "expected": expected.value if expected else "N/A",
        "improved": improved,
        "cj_reason": r_cj.reason[:80] if r_cj.reason else "",
        "iv_reason": r_iv.reason[:80] if r_iv.reason else "",
    }


def run_micro_benchmarks() -> List[Dict]:
    """微基准测试: 直接对比约束求解 vs 约束求解+Interval在约束精度上的差异.

    M1: 路径条件传播, M2: 多变量联合约束, M3: 赋值传播,
    M4: CMP/JCC条件, M5: 循环边界传播.
    """
    from core.constraint_constraint_types import (
        ConstraintType, LinearConstraint, ConstraintSystem, SolverVerdict,
    )
    from core.constraint_solver import ConstraintJoinSolver
    from core.constraint_interval_domain import interval_refine

    micro = []

    # M1: 路径条件传播 — if(x<50) bound x via interval domain
    ir_m1 = [
        "call malloc(56)",
        "mov rax, buf",
        "cmp x, 50",
        "jl done",
        "done:",
        "mov [buf+x], rdi  ; store 4 bytes",
    ]
    sys_m1 = ConstraintSystem(
        alloc_size=56, store_size=4, offset_var='x', mnemonic='store',
        constraints=[],
    )
    sys_m1_refined = interval_refine(sys_m1, ir_m1, "\n".join(ir_m1), 0, 5)
    solver = ConstraintJoinSolver("x86_64")
    r_m1_cj = solver.solve(sys_m1)
    r_m1_iv = solver.solve(sys_m1_refined)
    micro.append(_micro_row(
        "M1-path-condition", sys_m1, sys_m1_refined,
        r_m1_cj, r_m1_iv, SolverVerdict.PROVEN_SAFE,
        "if(x<50) should bound x via interval domain"))

    # M2: 多变量联合约束
    sys_m2 = ConstraintSystem(
        alloc_size=64, store_size=4, offset_var='x', mnemonic='store',
    )
    sys_m2.add(LinearConstraint(
        coefficients={'x': 2.0, 'y': 1.0}, constant=-100,
        operator="<=", source=ConstraintType.GUARD_CONDITION,
        confidence=0.9, description="2*x+y<=100",
    ))
    sys_m2.add(LinearConstraint(
        coefficients={'y': 1.0}, constant=-30,
        operator="==", source=ConstraintType.AFFINE_RELATION,
        confidence=0.95, description="y=30",
    ))
    sys_m2_refined = interval_refine(sys_m2, [], "", 0, 0)
    r_m2_cj = solver.solve(sys_m2)
    r_m2_iv = solver.solve(sys_m2_refined)
    micro.append(_micro_row(
        "M2-multivar-constraint", sys_m2, sys_m2_refined,
        r_m2_cj, r_m2_iv, SolverVerdict.PROVEN_SAFE,
        "2*x+y<=100, y=30 → x<=35 via multivar propagation"))

    # M3: 赋值传播
    ir_m3 = [
        "call malloc(64)",
        "mov x, 40",
        "mov y, x",
        "add y, 5",
        "mov [buf+y], rdi  ; store 4 bytes",
    ]
    sys_m3 = ConstraintSystem(
        alloc_size=64, store_size=4, offset_var='y', mnemonic='store',
    )
    sys_m3.add(LinearConstraint(
        coefficients={'x': 1.0}, constant=-40,
        operator="<=", source=ConstraintType.GUARD_CONDITION,
        confidence=0.9, description="x<=40",
    ))
    sys_m3_refined = interval_refine(sys_m3, ir_m3, "\n".join(ir_m3), 0, 4)
    r_m3_cj = solver.solve(sys_m3)
    r_m3_iv = solver.solve(sys_m3_refined)
    micro.append(_micro_row(
        "M3-assignment-propagation", sys_m3, sys_m3_refined,
        r_m3_cj, r_m3_iv, SolverVerdict.PROVEN_SAFE,
        "y=x+5, x<=40 → y<=45 via assignment propagation"))

    # M4: CMP/JCC条件提取
    ir_m4 = [
        "call malloc(32)",
        "cmp offset, 28",
        "jle safe_label",
        "safe_label:",
        "mov [buf+offset], rax  ; store 4 bytes",
    ]
    sys_m4 = ConstraintSystem(
        alloc_size=32, store_size=4, offset_var='offset', mnemonic='store',
    )
    sys_m4_refined = interval_refine(sys_m4, ir_m4, "\n".join(ir_m4), 0, 4)
    r_m4_cj = solver.solve(sys_m4)
    r_m4_iv = solver.solve(sys_m4_refined)
    micro.append(_micro_row(
        "M4-cmp-jcc-condition", sys_m4, sys_m4_refined,
        r_m4_cj, r_m4_iv, SolverVerdict.PROVEN_SAFE,
        "cmp offset,28; jle → offset<=28 via JCC extraction"))

    # M5: 循环边界 + 路径条件联合传播
    ir_m5 = [
        "mov n, 20",
        "call malloc(n)",
        "for(i=0; i<n; i++) {",
        "  mov [buf+i], 0  ; store 1 byte",
        "}",
    ]
    sys_m5 = ConstraintSystem(
        alloc_size=20, store_size=1, loop_var='i', loop_bound=20,
        mnemonic='store',
    )
    sys_m5_refined = interval_refine(sys_m5, ir_m5, "\n".join(ir_m5), 0, 4)
    r_m5_cj = solver.solve(sys_m5)
    r_m5_iv = solver.solve(sys_m5_refined)
    micro.append(_micro_row(
        "M5-loop-bound-propagation", sys_m5, sys_m5_refined,
        r_m5_cj, r_m5_iv, None,
        "loop bound propagation reinforces existing constraint"))

    return micro


def print_micro_results(micro: List[Dict]):
    print(f"\n{'=' * 80}")
    print(f" Micro-benchmarks: Interval Domain Precision Enhancement")
    print(f"{'=' * 80}")
    print(f"\n{'Test':<32} {'CJ Constr':>10} {'IV Constr':>10} {'Δ':>4} "
          f"{'CJ Verdict':>16} {'IV Verdict':>16} {'Improved':>8}")
    print("-" * 80)
    for m in micro:
        print(f"{m['test']:<32} {m['cj_constraints']:>10} "
              f"{m['iv_constraints']:>10} {m['new_constraints']:>+4} "
              f"{m['cj_verdict']:>16} {m['iv_verdict']:>16} "
              f"{'YES' if m['improved'] else '—':>8}")
    print(f"\n Details:")
    for m in micro:
        print(f"  {m['test']}: {m['description']}")
        print(f"    CJ: {m['cj_verdict']} — {m['cj_reason']}")
        print(f"    IV: {m['iv_verdict']} — {m['iv_reason']}")
        if m['new_constraints'] > 0:
            print(f"    Interval domain added {m['new_constraints']} constraint(s)")
    improved_count = sum(1 for m in micro if m['improved'])
    total_new = sum(m['new_constraints'] for m in micro)
    print(f"\n Summary: {improved_count}/{len(micro)} tests improved, "
          f"{total_new} total new constraints injected")
    print(f"{'=' * 80}")


__all__ = ['run_micro_benchmarks', 'print_micro_results']
