#!/usr/bin/env python3
"""
CJ FM边界推理 + 跨函数约束传播 回归测试.
"""
import sys
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind")
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind\deemo")

from core.cj_constraint_types import (
    ConstraintType, LinearConstraint, ConstraintSystem, SolverVerdict,
)
from core.cj_solver import ConstraintJoinSolver
from tests.test_cj_enhanced_cases import (
    build_fm_boundary_cases, build_interproc_cases, build_interval_domain_cases,
)

passed = 0
failed = 0


def _check_case(name, sys_obj, expected_verdict):
    global passed, failed
    solver = ConstraintJoinSolver("x86_64")
    result = solver.solve(sys_obj)
    ok = result.verdict == expected_verdict
    if ok:
        passed += 1
        print(f"  [PASS] {name}: {result.verdict.value} — {result.reason}")
    else:
        failed += 1
        print(f"  [FAIL] {name}: got {result.verdict.value}, expected {expected_verdict.value}")
        print(f"         reason: {result.reason}")


def fm_boundary_tests():
    """FM边界推理测试用例."""
    print("\n--- FM边界推理测试 ---")
    for name, sys_obj, expected in build_fm_boundary_cases():
        _check_case(name, sys_obj, expected)


def interproc_tests():
    """跨函数约束传播测试用例."""
    global passed, failed
    print("\n--- 跨函数约束传播测试 ---")
    from core.cj_interproc_constraints import InterProcCJCollector

    for name, sys_obj, code, alloc_func, write_func, expected in build_interproc_cases():
        collector = InterProcCJCollector()
        collector.build_summaries(code)
        added = collector.enrich_constraint_system(sys_obj, alloc_func=alloc_func, write_func=write_func)
        print(f"  [INFO] {name}: interproc injected {added} constraints")
        _check_case(name, sys_obj, expected)


def interval_domain_tests():
    """区间域抽象解释测试用例."""
    global passed, failed
    print("\n--- 区间域抽象解释测试 ---")
    from core.cj_interval_domain import IntervalDomain, Interval, interval_refine
    from core.cj_interval_parser import apply_constant_assignments, apply_binary_assignments

    for item in build_interval_domain_cases():
        name, sys_obj, ir_lines, code, expected = item

        if name == "17.路径条件传播":
            refined = interval_refine(sys_obj, [], code, alloc_pc=0, write_pc=0)
            count = len(refined.constraints)
            print(f"  [INFO] Case 17: interval_refine injected {count} constraints")
            _check_case("17.路径条件传播 n<=100+off=n", refined, expected)

        elif name == "20.不动点收敛":
            refined = interval_refine(sys_obj, ir_lines, "", alloc_pc=0, write_pc=2)
            count = len(refined.constraints)
            print(f"  [INFO] Case 20: fixed-point produced {count} constraints")
            _check_case("20.不动点收敛 m<=50+off=m+4,alloc64", refined, expected)

    # Case 18: 区间域copy独立性
    dom18 = IntervalDomain()
    dom18.set('m', Interval(20, 20))
    dom18.set('n', Interval(30, 30))
    dom18_copy = dom18.copy()
    dom18_copy.set('m', Interval(99, 99))
    assert dom18.get('m').lo == 20, "copy should be independent"
    passed += 1
    print(f"  [PASS] 18a.区间域copy独立性: m={dom18.get('m')} (copy modified)")

    # Case 19: 汇编语法赋值 — mov eax, 64; add eax, 8
    dom19 = IntervalDomain()
    ir19_asm = ["mov eax, 64", "add eax, 8"]
    apply_constant_assignments(dom19, ir19_asm)
    apply_binary_assignments(dom19, ir19_asm)
    eax_val = dom19.get('eax')
    print(f"  [INFO] Case 19: eax={eax_val} after mov+add")
    ok19 = eax_val.lo == 72 and eax_val.hi == 72
    if ok19:
        passed += 1
        print("  [PASS] 19.汇编语法 mov eax,64+add eax,8 → eax=72")
    else:
        failed += 1
        print(f"  [FAIL] 19.汇编语法: got eax={eax_val}, expected [72,72]")


def run_all():
    global passed, failed
    passed = 0
    failed = 0

    fm_boundary_tests()
    interproc_tests()
    interval_domain_tests()

    print(f"\n{'='*60}")
    print(f"CJ增强回归测试: {passed} passed, {failed} failed, {passed+failed} total")
    print(f"{'='*60}")
    return failed == 0


if __name__ == '__main__':
    ok = run_all()
    sys.exit(0 if ok else 1)
