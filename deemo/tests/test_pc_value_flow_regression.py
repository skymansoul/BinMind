#!/usr/bin/env python3
"""
路径条件后向值流路径约束感知回归测试.

测试路径条件后向值流在后向值流-INCONCLUSIVE场景下利用路径约束判定的能力:
  1. 固定alloc+路径约束限write→SAFE: 后向值流 INCONCLUSIVE, 路径条件后向值流 SAFE
  2. 固定alloc+路径约束放宽write→OVERFLOW: 后向值流 INCONCLUSIVE, 路径条件后向值流 OVERFLOW
  3. 多约束组—n>=0&&n<=128)→SAFE
  4. 共享变量+路径约束配合
  5. tainted变量被路径约束限—
预期: 路径条件后向值流应在后向值流无法判定的样本上正确判定SAFE/OVERFLOW.
"""
import sys, os, json
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind")
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind\deemo")

from pathlib import Path
from core.constraint_solver import solve_candidate
from core.constraint_constraint_types import SolverVerdict
from core.constraint_pc_value_flow_constraints import extract_path_constraints
from core.constraint_pc_value_flow_correlator import correlate_with_constraints
from core.constraint_value_flow_tracer import BackwardValueFlow, SymbolicExpr
from tests.value_flow_candidate_extractor import extract_candidates_from_code

PC_VALUE_FLOW_SAMPLES_DIR = Path(__file__).parent / 'pc_value_flow_samples'

PC_VALUE_FLOW_EXPECTED = {
    'pc_value_flow_01': False,
    'pc_value_flow_02': True,
    'pc_value_flow_03': False,
    'pc_value_flow_04': True,
    'pc_value_flow_05': False,
    'pc_value_flow_06': False,
    'pc_value_flow_07': True,
    'pc_value_flow_08': False,
    'pc_value_flow_09': False,
    'pc_value_flow_10': True,
    'pc_value_flow_11': False,
    'pc_value_flow_12': False,
}


passed = 0
failed = 0


def _check_case(name, condition, detail=""):
    global passed, failed
    if condition:
        passed += 1
        print(f"  [PASS] {name}")
    else:
        failed += 1
        print(f"  [FAIL] {name}: {detail}")


def run_pipeline_test():
    """通过solve_candidate管线测试路径条件后向值流集成."""
    global passed, failed
    print("\n=== PC-BVF Pipeline Test ===\n")

    for sample_dir in sorted(PC_VALUE_FLOW_SAMPLES_DIR.iterdir()):
        if not sample_dir.is_dir():
            continue
        vuln_c = sample_dir / 'vuln.c'
        if not vuln_c.exists():
            continue

        name = sample_dir.name
        expected = PC_VALUE_FLOW_EXPECTED.get(name)
        if expected is None:
            continue

        code = vuln_c.read_text(encoding='utf-8', errors='replace')
        candidates, ir_lines = extract_candidates_from_code(code)
        if not candidates:
            _check_case(name, not expected,
                      "no candidates extracted")
            continue

        detected = False
        verdict_str = "inconclusive"
        for c in candidates:
            result, _ = solve_candidate(c, ir_lines, code)
            if result.verdict == SolverVerdict.PROVEN_OVERFLOW:
                detected = True
                verdict_str = result.reason[:80]
                break
            if result.verdict == SolverVerdict.PROVEN_SAFE:
                verdict_str = result.reason[:80]

        if expected:
            _check_case(f"{name} (expect VULN)", detected,
                      f"verdict={verdict_str}")
        else:
            _check_case(f"{name} (expect SAFE)", not detected,
                      f"verdict={verdict_str}")


def run_unit_test():
    """直接测试路径条件后向值流约束提取和相关性判—"""
    global passed, failed
    print("\n=== PC-BVF Unit Test ===\n")

    ir = [
        "len = atoi(argv[1])",
        "buf = malloc(64)",
        "if (len <= 64) {",
        "memcpy(buf, src, len)",
        "}",
    ]

    bounds = extract_path_constraints(ir, 3)
    _check_case("constraint extraction: len<=64",
              'len' in bounds and bounds['len'].hi == 64.0,
              f"bounds={ {k: str(v) for k, v in bounds.items()} }")

    bvf = BackwardValueFlow()
    alloc_expr = SymbolicExpr(const=64.0, origin="const:64")
    write_expr = SymbolicExpr(coefs={'len': 1.0}, tainted=True,
                              origin="atoi(argv)")
    offset_expr = SymbolicExpr(const=0.0)

    result = correlate_with_constraints(
        alloc_expr, write_expr, offset_expr, bounds)
    _check_case("taint constrained safe: len<=64, alloc=64",
              result.proven_safe,
              f"reason={result.reason}")

    bounds2 = {'len': VarBound(lo=65, source="len>=65")}
    result2 = correlate_with_constraints(
        alloc_expr, write_expr, offset_expr, bounds2)
    _check_case("taint constrained overflow: len>=65, alloc=64",
              result2.proven_overflow,
              f"reason={result2.reason}")

    ir2 = [
        "n = get_size()",
        "buf = malloc(n)",
        "if (n <= 256) {",
        "memcpy(buf, src, n)",
        "}",
    ]
    bounds3 = extract_path_constraints(ir2, 3)
    alloc3 = SymbolicExpr(coefs={'n': 1.0}, origin="n")
    write3 = SymbolicExpr(coefs={'n': 1.0}, origin="n")
    result3 = correlate_with_constraints(
        alloc3, write3, SymbolicExpr(const=0.0), bounds3)
    _check_case("shared var + constraint: n<=256, alloc=n, write=n",
              result3.proven_safe,
              f"reason={result3.reason}, bounds={ {k: str(v) for k, v in bounds3.items()} }")


from core.constraint_pc_value_flow_constraints import VarBound

def run_all():
    global passed, failed
    passed = 0
    failed = 0

    run_unit_test()
    run_pipeline_test()

    print(f"\n{'='*60}")
    print(f"PC-BVF回归测试: {passed} passed, {failed} failed, "
          f"{passed+failed} total")
    print(f"{'='*60}")
    return failed == 0


if __name__ == '__main__':
    ok = run_all()
    sys.exit(0 if ok else 1)
