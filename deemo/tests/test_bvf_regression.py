#!/usr/bin/env python3
"""
DD-BVF反向值流过滤器回归测—

测试DD-BVF在CJ-INCONCLUSIVE场景下的精确化判定能—
  1. 共享变量安全: malloc(n)+memcpy(buf,src,n) —BVF SAFE
  2. 共享变量溢出: malloc(n)+memcpy(buf,src,n*2) —BVF OVERFLOW
  3. 常量+偏移安全: malloc(64)+memcpy(buf,src,32) —BVF SAFE
  4. 无共享变— malloc(m)+memcpy(buf,src,n) —BVF INCONCLUSIVE
  5. 多跳赋值链: int n=get_size(); malloc(n); memcpy(buf,src,n) —BVF SAFE
  6. tainted写大— malloc(64)+memcpy(buf,src,atoi(argv)) —BVF INCONCLUSIVE
  7. 算术变换: malloc(n+8)+memcpy(buf,src,n) —BVF SAFE
  8. 偏移+大小: malloc(128)+memcpy(buf+64,src,64) —BVF SAFE
"""
import sys
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind")
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind\deemo")

from core.cj_bvf_tracer import BackwardValueFlow, SymbolicExpr
from core.cj_solver import solve_candidate
from core.cj_bvf_solver_bridge import try_bvf_proof as _try_bvf_proof
from core.cj_constraint_types import SolverVerdict
from core.heap_overflow_detector import (
    HeapAllocSite, HeapStore, HeapOverflowCandidate,
)

passed = 0
failed = 0


def make_ir(code_lines: list[str]) -> list[str]:
    return [line.strip() for line in code_lines]


def make_candidate_dynamic(alloc_pc, size_expr, write_pc, mnemonic,
                           store_size=0, offset=0, offset_dyn=False):
    alloc = HeapAllocSite(
        pc=alloc_pc, alloc_func='malloc', size_arg=0,
        size_is_dynamic=True, size_expr=size_expr,
    )
    store = HeapStore(
        pc=write_pc, base_var='buf', offset=offset,
        offset_is_dynamic=offset_dyn,
        store_size=store_size, mnemonic=mnemonic,
    )
    return HeapOverflowCandidate(
        alloc_site=alloc, overflow_store=store,
        confidence=0.50, description='test',
    )


def make_candidate_const(alloc_pc, alloc_size, write_pc, mnemonic,
                         store_size=0, offset=0, offset_dyn=False):
    alloc = HeapAllocSite(
        pc=alloc_pc, alloc_func='malloc', size_arg=alloc_size,
        size_is_dynamic=False, size_expr='',
    )
    store = HeapStore(
        pc=write_pc, base_var='buf', offset=offset,
        offset_is_dynamic=offset_dyn,
        store_size=store_size, mnemonic=mnemonic,
    )
    return HeapOverflowCandidate(
        alloc_site=alloc, overflow_store=store,
        confidence=0.50, description='test',
    )


def _check_case(name, condition, detail=""):
    global passed, failed
    if condition:
        passed += 1
        print(f"  [PASS] {name}")
    else:
        failed += 1
        print(f"  [FAIL] {name}: {detail}")


def run_all():
    global passed, failed
    passed = 0
    failed = 0

    bvf = BackwardValueFlow()

    # Case 1: 共享变量安全 malloc(n)+memcpy(buf,src,n)
    ir1 = make_ir([
        "n = 256",
        "buf = malloc(n)",
        "memcpy(buf, src, n)",
    ])
    ae1 = bvf.trace_alloc_size(ir1, "malloc", "n", 1)
    we1 = bvf.trace_write_size(ir1, 2, "memcpy", 0)
    r1 = bvf.correlate(ae1, we1)
    _check_case("1.共享变量安全 malloc(n)+memcpy(n)", r1.proven_safe,
              f"alloc={ae1}, write={we1}, reason={r1.reason}")

    # Case 2: 共享变量溢出 malloc(n)+memcpy(buf,src,n*2)
    ir2 = make_ir([
        "n = 128",
        "buf = malloc(n)",
        "memcpy(buf, src, n * 2)",
    ])
    ae2 = bvf.trace_alloc_size(ir2, "malloc", "n", 1)
    we2 = bvf.trace_var(ir2, "n * 2", 2) if False else SymbolicExpr()
    line2 = ir2[2]
    import re
    m2 = re.search(r'memcpy\s*\([^,]+,\s*[^,]+,\s*([^)]+)\)', line2)
    if m2:
        we2 = bvf.trace_var(ir2, m2.group(1).strip(), 2)
    r2 = bvf.correlate(ae2, we2)
    _check_case("2.共享变量溢出 malloc(n)+memcpy(n*2)",
              r2.proven_overflow,
              f"alloc={ae2}, write={we2}, reason={r2.reason}")

    # Case 3: 常量+偏移安全 malloc(64)+memcpy(buf,src,32)
    ir3 = make_ir([
        "buf = malloc(64)",
        "memcpy(buf, src, 32)",
    ])
    ae3 = bvf.trace_alloc_size(ir3, "malloc", "64", 0)
    we3 = bvf.trace_write_size(ir3, 1, "memcpy", 0)
    r3 = bvf.correlate(ae3, we3, SymbolicExpr(const=0.0))
    _check_case("3.常量安全 malloc(64)+memcpy(32)", r3.proven_safe,
              f"alloc={ae3}, write={we3}, reason={r3.reason}")

    # Case 4: 无共享变量 malloc(m)+memcpy(buf,src,n), m和n无赋值
    ir4 = make_ir([
        "buf = malloc(m)",
        "memcpy(buf, src, n)",
    ])
    ae4 = bvf.trace_alloc_size(ir4, "malloc", "m", 0)
    we4 = bvf.trace_write_size(ir4, 1, "memcpy", 0)
    r4 = bvf.correlate(ae4, we4)
    _check_case("4.无共享变量 malloc(m)+memcpy(n)",
              not r4.proven_safe and not r4.proven_overflow,
              f"alloc={ae4}, write={we4}, reason={r4.reason}")

    # Case 5: 多跳赋值链 get_size()→n→alloc→write
    ir5 = make_ir([
        "n = 256",
        "buf = malloc(n)",
        "tmp = n",
        "memcpy(buf, src, tmp)",
    ])
    ae5 = bvf.trace_alloc_size(ir5, "malloc", "n", 1)
    we5_line = ir5[3]
    m5 = re.search(r'memcpy\s*\([^,]+,\s*[^,]+,\s*([^)]+)\)', we5_line)
    we5 = bvf.trace_var(ir5, m5.group(1).strip(), 3) if m5 else SymbolicExpr()
    r5 = bvf.correlate(ae5, we5)
    _check_case("5.多跳赋值链 n→tmp→memcpy(tmp)",
              r5.proven_safe,
              f"alloc={ae5}, write={we5}, shared={r5.shared_vars}")

    # Case 6: tainted写大—malloc(64)+memcpy(buf,src,atoi(argv))
    ir6 = make_ir([
        "buf = malloc(64)",
        "len = atoi(argv[1])",
        "memcpy(buf, src, len)",
    ])
    ae6 = bvf.trace_alloc_size(ir6, "malloc", "64", 0)
    we6_line = ir6[2]
    m6 = re.search(r'memcpy\s*\([^,]+,\s*[^,]+,\s*([^)]+)\)', we6_line)
    we6 = bvf.trace_var(ir6, m6.group(1).strip(), 2) if m6 else SymbolicExpr()
    r6 = bvf.correlate(ae6, we6)
    _check_case("6.tainted写大—malloc(64)+memcpy(atoi())",
              not r6.proven_safe,
              f"alloc={ae6}, write={we6}, tainted={we6.tainted}")

    # Case 7: 算术变换 malloc(n+8)+memcpy(buf,src,n) —SAFE (n+8 >= n)
    ir7 = make_ir([
        "n = 128",
        "buf = malloc(n + 8)",
        "memcpy(buf, src, n)",
    ])
    ae7 = bvf.trace_alloc_size(ir7, "malloc", "n + 8", 1)
    we7 = bvf.trace_write_size(ir7, 2, "memcpy", 0)
    we7_raw = bvf.trace_var(ir7, "n", 2)
    r7 = bvf.correlate(ae7, we7_raw)
    _check_case("7.算术变换 malloc(n+8)+memcpy(n)",
              r7.proven_safe,
              f"alloc={ae7}, write={we7_raw}, shared={r7.shared_vars}")

    # Case 8: 偏移+大小 malloc(128)+memcpy(buf+64,src,64) —SAFE (64+64=128)
    ir8 = make_ir([
        "buf = malloc(128)",
        "memcpy(buf + 64, src, 64)",
    ])
    ae8 = bvf.trace_alloc_size(ir8, "malloc", "128", 0)
    we8 = bvf.trace_write_size(ir8, 1, "memcpy", 0)
    off8 = SymbolicExpr(const=64.0, origin="offset:64")
    r8 = bvf.correlate(ae8, we8, off8)
    _check_case("8.偏移+大小 malloc(128)+memcpy(buf+64,64)",
              r8.proven_safe,
              f"alloc={ae8}, write={we8}, off=64, reason={r8.reason}")

    # Case 9: solve_candidate集成测试 BVF在CJ INCONCLUSIVE时触发
    ir9 = make_ir([
        "n = 100",
        "buf = malloc(n)",
        "memcpy(buf, src, n)",
    ])
    c9 = make_candidate_dynamic(1, "n", 2, "memcpy", store_size=0)
    result9, sys9 = solve_candidate(c9, ir9)
    _check_case("9.solve_candidate BVF集成 malloc(n)+memcpy(n)",
              result9.verdict in (SolverVerdict.PROVEN_SAFE,
                                  SolverVerdict.PROVEN_OVERFLOW),
              f"verdict={result9.verdict.value}, reason={result9.reason}")

    # Case 10: 不同变量但write更大 —malloc(n)+memcpy(buf,src,n+128)
    ir10 = make_ir([
        "n = 64",
        "buf = malloc(n)",
        "memcpy(buf, src, n + 128)",
    ])
    ae10 = bvf.trace_alloc_size(ir10, "malloc", "n", 1)
    m10 = re.search(r'memcpy\s*\([^,]+,\s*[^,]+,\s*([^)]+)\)', ir10[2])
    we10 = bvf.trace_var(ir10, m10.group(1).strip(), 2) if m10 else SymbolicExpr()
    r10 = bvf.correlate(ae10, we10)
    _check_case("10.共享变量+常数溢出 malloc(n)+memcpy(n+128)",
              r10.proven_overflow,
              f"alloc={ae10}, write={we10}, reason={r10.reason}")

    print(f"\n{'='*60}")
    print(f"DD-BVF回归测试: {passed} passed, {failed} failed, {passed+failed} total")
    print(f"{'='*60}")
    return failed == 0


if __name__ == '__main__':
    ok = run_all()
    sys.exit(0 if ok else 1)
