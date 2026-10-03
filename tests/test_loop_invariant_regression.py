#!/usr/bin/env python3
"""
循环不变式分层证明分层安全证明器回归测—

测试场景:
  1. 后向值流-SAFE的后向值流回归不受循环不变式分层证明影响 (无退—
  2. 后向值流-INCONCLUSIVE场景被循环不变式分层证明正确过滤/确认
  3. 循环不变式分层证明三层各自覆盖目标场景

测试结构:
  Phase 1: 单独测试循环不变式分层证明模块 (Layer 2/3)
  Phase 2: 端到端solve_candidate集成测试
  Phase 3: 后向值流回归确认无退—(8个子测试)
"""
import re
import sys

sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind")
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind\deemo")

from core.constraint_value_flow_tracer import BackwardValueFlow, SymbolicExpr
from core.constraint_value_flow_correlator import correlate
from core.constraint_solver import solve_candidate
from core.constraint_value_flow_solver_bridge import try_bvf_proof
from core.constraint_constraint_types import SolverVerdict
from core.loop_invariant_orchestrator import try_lsp_proof, reset_lsp_stats, get_lsp_stats
from core.loop_invariant_invariant_prover import prove_with_invariants
from core.loop_invariant_allocator_prover import prove_with_allocator_alignment
from core.heap_overflow_detector import (
    HeapAllocSite, HeapStore, HeapOverflowCandidate,
)

from tests.loop_invariant_ground_truth import LSP_EXPECTED
from tests.value_flow_candidate_extractor import extract_candidates_from_code

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


def make_ir(code_lines):
    return [line.strip() for line in code_lines]


def make_candidate(alloc_pc, alloc_size, is_dyn, size_expr,
                   write_pc, mnemonic, store_size=0,
                   offset=0, offset_dyn=False):
    alloc = HeapAllocSite(
        pc=alloc_pc, alloc_func='malloc',
        size_arg=alloc_size if not is_dyn else 0,
        size_is_dynamic=is_dyn,
        size_expr=size_expr if is_dyn else '',
    )
    store = HeapStore(
        pc=write_pc, base_var='buf', offset=offset,
        offset_is_dynamic=offset_dyn,
        store_size=store_size, mnemonic=mnemonic,
    )
    return HeapOverflowCandidate(
        alloc_site=alloc, overflow_store=store,
        confidence=0.50, description='lsp_test')


def run_phase1():
    """Phase 1: 单独测试循环不变式分层证明模块."""
    print("\n--- Phase 1: 循环不变式分层证明 Module Tests ---")

    bvf = BackwardValueFlow()

    # Test 1: Layer 2 路径条件安全
    ir1 = make_ir([
        "if (n <= 256) {",
        "  buf = malloc(256);",
        "  memcpy(buf, src, n);",
        "}",
    ])
    ae1 = SymbolicExpr(const=256.0, origin="const:256")
    we1 = SymbolicExpr(coefs={"n": 1.0}, origin="n(var)")
    off1 = SymbolicExpr(const=0.0)
    r1 = prove_with_invariants(ae1, we1, off1, ir1, 1, 2, 256)
    _check_case("1.L2路径安全 if(n<=256)+malloc(256)+memcpy(n)",
              r1 is not None and r1.verdict.value == "lsp_safe",
              f"result={r1}")

    # Test 2: Layer 2 路径条件溢出
    ir2 = make_ir([
        "if (n >= 512) {",
        "  buf = malloc(256);",
        "  memcpy(buf, src, n);",
        "}",
    ])
    r2 = prove_with_invariants(ae1, we1, off1, ir2, 1, 2, 256)
    _check_case("2.L2路径溢出 if(n>=512)+malloc(256)+memcpy(n)",
              r2 is not None and r2.verdict.value == "lsp_overflow",
              f"result={r2}")

    # Test 3: Layer 3 分配器padding安全
    # malloc(17) —glibc usable=24 (slack=7), memcpy(20) <= 24 —SAFE
    ae3 = SymbolicExpr(const=17.0, origin="const:17")
    we3 = SymbolicExpr(const=20.0, origin="const:20")
    off3 = SymbolicExpr(const=0.0)
    r3 = prove_with_allocator_alignment(ae3, we3, off3, 17)
    _check_case("3.L3 padding安全 malloc(17)+memcpy(20)",
              r3 is not None and r3.verdict.value == "lsp_safe",
              f"result={r3}")

    # Test 4: Layer 3 分配器padding溢出
    # malloc(17) —usable=24, memcpy(40) > 24 —OVERFLOW
    we4 = SymbolicExpr(const=40.0, origin="const:40")
    r4 = prove_with_allocator_alignment(ae3, we4, off3, 17)
    _check_case("4.L3 padding溢出 malloc(17)+memcpy(40)",
              r4 is not None and r4.verdict.value == "lsp_overflow",
              f"result={r4}")

    # Test 5: Layer 2 无谓——None
    ir5 = make_ir([
        "buf = malloc(128);",
        "memcpy(buf, src, n);",
    ])
    ae5 = SymbolicExpr(const=128.0)
    we5 = SymbolicExpr(coefs={"n": 1.0})
    r5 = prove_with_invariants(ae5, we5, off1, ir5, 0, 1, 128)
    _check_case("5.L2无谓词→None malloc(128)+memcpy(无约束n)",
              r5 is None, f"result={r5}")

    # Test 6: Layer 2 assert约束
    ir6 = make_ir([
        "assert(len <= 64);",
        "buf = malloc(64);",
        "memcpy(buf, src, len);",
    ])
    ae6 = SymbolicExpr(const=64.0)
    we6 = SymbolicExpr(coefs={"len": 1.0})
    r6 = prove_with_invariants(ae6, we6, off1, ir6, 1, 2, 64)
    _check_case("6.L2 assert约束 assert(len<=64)+malloc(64)+memcpy(len)",
              r6 is not None and r6.verdict.value == "lsp_safe",
              f"result={r6}")


def run_phase2():
    """Phase 2: 端到端集成测——从循环不变式分层证明样本运行solve_candidate."""
    print("\n--- Phase 2: End-to-End Integration ---")
    import os
    from pathlib import Path

    lsp_dir = Path(r"C:\Users\Administrator\Desktop\BinMind\deemo\tests\lsp_samples")
    reset_lsp_stats()

    correct = 0
    total = 0
    inconclusive_ok = 0

    for sample_dir in sorted(lsp_dir.iterdir()):
        if not sample_dir.is_dir():
            continue
        vuln_c = sample_dir / 'vuln.c'
        if not vuln_c.exists():
            continue

        name = sample_dir.name
        expected = LSP_EXPECTED.get(name)
        if expected is None:
            continue

        code = vuln_c.read_text(encoding='utf-8', errors='replace')
        candidates, ir_lines = extract_candidates_from_code(code)
        if not candidates:
            _check_case(f"E2E.{name}", False, "no candidates")
            continue

        total += 1
        result, _ = solve_candidate(candidates[0], ir_lines, code)
        verdict = result.verdict

        if expected:
            detected = verdict == SolverVerdict.PROVEN_OVERFLOW
            _check_case(f"E2E.{name} (expect=VULN)",
                      detected,
                      f"verdict={verdict.value}, reason={result.reason[:80]}")
            if detected:
                correct += 1
        else:
            safe = verdict == SolverVerdict.PROVEN_SAFE
            _check_case(f"E2E.{name} (expect=SAFE)",
                      safe,
                      f"verdict={verdict.value}, reason={result.reason[:80]}")
            if safe:
                correct += 1

    stats = get_lsp_stats()
    print(f"\n  循环不变式分层证明 stats: triggered={stats.total_triggered}, "
          f"safe={stats.proven_safe}, overflow={stats.proven_overflow}, "
          f"inconclusive={stats.inconclusive}")
    print(f"  E2E: {correct}/{total} correct")


def run_phase3():
    """Phase 3: 后向值流回归确认无退—"""
    print("\n--- Phase 3: 后向值流 Regression (no degradation) ---")
    from core.constraint_value_flow_tracer import BackwardValueFlow, SymbolicExpr

    bvf = BackwardValueFlow()

    # Case 1: 共享变量安全
    ir1 = make_ir(["n = 256", "buf = malloc(n)", "memcpy(buf, src, n)"])
    ae1 = bvf.trace_alloc_size(ir1, "malloc", "n", 1)
    we1 = bvf.trace_write_size(ir1, 2, "memcpy", 0)
    r1 = bvf.correlate(ae1, we1)
    _check_case("3.1 BVF共享变量安全", r1.proven_safe,
              f"alloc={ae1}, write={we1}")

    # Case 2: 共享变量溢出
    ir2 = make_ir(["n = 128", "buf = malloc(n)", "memcpy(buf, src, n * 2)"])
    m2 = re.search(r'memcpy\s*\([^,]+,\s*[^,]+,\s*([^)]+)\)', ir2[2])
    we2 = bvf.trace_var(ir2, m2.group(1).strip(), 2) if m2 else SymbolicExpr()
    ae2 = bvf.trace_alloc_size(ir2, "malloc", "n", 1)
    r2 = bvf.correlate(ae2, we2)
    _check_case("3.2 BVF共享变量溢出", r2.proven_overflow,
              f"alloc={ae2}, write={we2}")

    # Case 3: 常量安全
    ir3 = make_ir(["buf = malloc(64)", "memcpy(buf, src, 32)"])
    ae3 = bvf.trace_alloc_size(ir3, "malloc", "64", 0)
    we3 = bvf.trace_write_size(ir3, 1, "memcpy", 0)
    r3 = bvf.correlate(ae3, we3, SymbolicExpr(const=0.0))
    _check_case("3.3 BVF常量安全", r3.proven_safe,
              f"alloc={ae3}, write={we3}")

    # Case 4: 共享变量+常数溢出
    ir4 = make_ir(["n = 64", "buf = malloc(n)", "memcpy(buf, src, n + 128)"])
    m4 = re.search(r'memcpy\s*\([^,]+,\s*[^,]+,\s*([^)]+)\)', ir4[2])
    we4 = bvf.trace_var(ir4, m4.group(1).strip(), 2) if m4 else SymbolicExpr()
    ae4 = bvf.trace_alloc_size(ir4, "malloc", "n", 1)
    r4 = bvf.correlate(ae4, we4)
    _check_case("3.4 BVF共享变量+常数溢出", r4.proven_overflow,
              f"alloc={ae4}, write={we4}")


def run_all():
    global passed, failed
    passed = 0
    failed = 0

    run_phase1()
    run_phase2()
    run_phase3()

    print(f"\n{'='*60}")
    print(f"循环不变式分层证明回归测试: {passed} passed, {failed} failed, {passed+failed} total")
    print(f"{'='*60}")
    return failed == 0


if __name__ == '__main__':
    ok = run_all()
    sys.exit(0 if ok else 1)
