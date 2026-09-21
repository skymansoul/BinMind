#!/usr/bin/env python3
"""
约束求解约束联结求解器回归测试 — 覆盖全部关键场景.

用例设计:
  1. 简单常量溢出 (malloc(64) + offset 72)        → PROVEN_OVERFLOW
  2. 安全写入 (malloc(64) + offset 32)             → PROVEN_SAFE
  3. 循环溢出 (malloc(32) + for i<64 buf[i]=x)     → PROVEN_OVERFLOW
  4. strcpy无界溢出 (malloc(32) + strcpy)           → INCONCLUSIVE (保守保留)
  5. memcpy常量溢出 (malloc(32)+memcpy 64B)        → PROVEN_OVERFLOW
  6. memcpy安全 (malloc(64)+memcpy 32B)            → PROVEN_SAFE
  7. 分配器边界安全 (malloc(20)+offset 24)         → PROVEN_SAFE (usable=24)
  8. 守卫约束安全 (malloc(n) n<=100 + off=n)       → PROVEN_SAFE (FM边界推理)
  9. 对齐边界安全 (malloc(63)+offset 62+8B)        → PROVEN_SAFE (usable=72)
  --- FM边界推理增强 ---
  10. 无约束变量 (malloc(64)+off=m, m无约束)         → INCONCLUSIVE
  11. 变量边界溢出 (malloc(32)+off=m, m>=40)         → PROVEN_OVERFLOW (FM边界)
  --- 跨函数约束传播 ---
  12. 跨函数guard注入 (alloc_func有guard约束)        → 约束数量增加
"""
import sys
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind")
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind\deemo")

from core.constraint_constraint_types import (
    ConstraintType, LinearConstraint, ConstraintSystem, SolverVerdict,
)
from core.constraint_solver import ConstraintJoinSolver
from core.constraint_fm_boundary import derive_bounds, eval_write_end_with_bounds, VarBound
from core.constraint_interproc_constraints import InterProcCJCollector
from core.heap_overflow_detector import HeapAllocSite, HeapStore, HeapOverflowCandidate

passed = 0
failed = 0


def make_candidate(alloc_size, offset, store_size, mnemonic='store',
                   offset_is_dynamic=False, dynamic=False, desc=''):
    alloc = HeapAllocSite(
        pc=0, alloc_func='malloc', size_arg=alloc_size,
        size_is_dynamic=dynamic, size_expr='' if not dynamic else 'n',
    )
    store = HeapStore(
        pc=1, base_var='buf', offset=offset,
        offset_is_dynamic=offset_is_dynamic,
        store_size=store_size, mnemonic=mnemonic,
    )
    return HeapOverflowCandidate(
        alloc_site=alloc, overflow_store=store,
        confidence=0.50, description=desc,
    )


def _check_case(name, sys_obj, expected_verdict, expected_delta_sign=0):
    global passed, failed
    solver = ConstraintJoinSolver("x86_64")
    result = solver.solve(sys_obj)
    ok = result.verdict == expected_verdict
    if ok:
        passed += 1
        print(f"  [PASS] {name}: {result.verdict.value} -- {result.reason}")
    else:
        failed += 1
        print(f"  [FAIL] {name}: got {result.verdict.value}, expected {expected_verdict.value}")
        print(f"         reason: {result.reason}")


def run_all():
    global passed, failed
    passed = 0
    failed = 0

# Case 1: 简单常量溢出
    sys1 = ConstraintSystem(
        alloc_size=64, store_size=8, offset_val=72, mnemonic='store',
    )
    _check_case("1.常量溢出 malloc(64)+off72", sys1, SolverVerdict.PROVEN_OVERFLOW)

# Case 2: 安全写入
    sys2 = ConstraintSystem(
        alloc_size=64, store_size=8, offset_val=32, mnemonic='store',
    )
    _check_case("2.安全写入 malloc(64)+off32", sys2, SolverVerdict.PROVEN_SAFE)

# Case 3: 循环溢出
    sys3 = ConstraintSystem(
        alloc_size=32, store_size=1, loop_bound=64,
        loop_var='i', mnemonic='store',
    )
    _check_case("3.循环溢出 malloc(32)+for(i<64)", sys3, SolverVerdict.PROVEN_OVERFLOW)

# Case 4: strcpy无界 -- INCONCLUSIVE
    sys4 = ConstraintSystem(
        alloc_size=32, mnemonic='strcpy', copy_size=-1,
    )
    _check_case("4.strcpy无界 malloc(32)+strcpy", sys4, SolverVerdict.INCONCLUSIVE)

# Case 5: memcpy常量溢出
    sys5 = ConstraintSystem(
        alloc_size=32, mnemonic='memcpy', copy_size=64,
    )
    _check_case("5.memcpy溢出 malloc(32)+memcpy64", sys5, SolverVerdict.PROVEN_OVERFLOW)

# Case 6: memcpy安全
    sys6 = ConstraintSystem(
        alloc_size=64, mnemonic='memcpy', copy_size=32,
    )
    _check_case("6.memcpy安全 malloc(64)+memcpy32", sys6, SolverVerdict.PROVEN_SAFE)

    # === Case 7: 分配器边界安全 (malloc(20) usable=24 on x86_64) ===
    from analysis.allocator_chunk_model import compute_effective_boundary
    usable_20 = compute_effective_boundary(20, "malloc")
    safe_offset = usable_20 - 4
    sys7 = ConstraintSystem(
        alloc_size=20, store_size=4, offset_val=safe_offset, mnemonic='store',
    )
    _check_case(f"7.分配器安全 malloc(20)+off{safe_offset}", sys7, SolverVerdict.PROVEN_SAFE)

# Case 8: 守卫约束 -- FM边界推理证明安全
    # malloc(n) n<=100, usable(100)=104, write_end=n+4<=104 -> PROVEN_SAFE
    sys8 = ConstraintSystem(
        alloc_size=0, alloc_var='n', store_size=4,
        offset_var='n', mnemonic='store',
    )
    sys8.add(LinearConstraint(
        coefficients={'n': 1.0}, constant=-100,
        operator="<=", source=ConstraintType.GUARD_CONDITION,
        confidence=0.9, description="if(n>100) exit()",
    ))
    _check_case("8.FM边界安全 malloc(n)+n<=100+off=n", sys8, SolverVerdict.PROVEN_SAFE)

# Case 9: 对齐边界安全
    # malloc(63) usable=72 (prev_size reuse), offset 62+8=70 <= 72 -> safe
    sys9 = ConstraintSystem(
        alloc_size=63, store_size=8, offset_val=62, mnemonic='store',
    )
    _check_case("9.对齐安全 malloc(63)+off62+8B", sys9, SolverVerdict.PROVEN_SAFE)

# FM边界推理增强测试

# Case 10: 无约束变量 -- INCONCLUSIVE
    # malloc(64), offset=m, m没有任何约束 -> 无法判定
    sys10 = ConstraintSystem(
        alloc_size=64, store_size=4, offset_var='m', mnemonic='store',
    )
    _check_case("10.无约束变量 malloc(64)+off=m", sys10, SolverVerdict.INCONCLUSIVE)

# Case 11: 变量边界溢出 -- FM边界推理证明溢出
    # malloc(32) usable=40, offset=m, m>=40 (guard), write_end=m+4>=44>40 -> PROVEN_OVERFLOW
    sys11 = ConstraintSystem(
        alloc_size=32, store_size=4, offset_var='m', mnemonic='store',
    )
    sys11.add(LinearConstraint(
        coefficients={'m': 1.0}, constant=-40,
        operator=">=", source=ConstraintType.GUARD_CONDITION,
        confidence=0.9, description="m >= 40",
    ))
    _check_case("11.FM边界溢出 malloc(32)+m>=40", sys11, SolverVerdict.PROVEN_OVERFLOW)

# 跨函数约束传播测试

# Case 12: 跨函数guard注入
    # 验证InterProcCJCollector能从多函数伪代码中提取guard并注入约束系统
    test_interproc()

    print(f"\n{'='*60}")
    print(f"CJ回归测试: {passed} passed, {failed} failed, {passed+failed} total")
    print(f"{'='*60}")
    return failed == 0


def test_interproc():
    """测试跨函数约束传播."""
    global passed, failed

    decompiled = """
void alloc_and_write(int n) {
    char *buf = malloc(n);
    if (n > 256) return;
    memcpy(buf, src, n);
}

void caller() {
    int size = get_size();
    if (size > 128) return;
    alloc_and_write(size);
}
"""

    collector = InterProcCJCollector()
    summaries = collector.build_summaries(decompiled)

    # 验证函数摘要被正确构建
    ok = 'alloc_and_write' in summaries and 'caller' in summaries
    if ok:
        aw = summaries['alloc_and_write']
        ok = len(aw.alloc_sites) > 0 and len(aw.guard_constraints) > 0

    if ok:
        passed += 1
        print(f"  [PASS] 12a.跨函数摘要构建: "
              f"alloc_and_write({len(summaries['alloc_and_write'].alloc_sites)} allocs, "
              f"{len(summaries['alloc_and_write'].guard_constraints)} guards)")
    else:
        failed += 1
        print(f"  [FAIL] 12a.跨函数摘要构建失败")
        return

    # 验证guard约束注入
    sys12 = ConstraintSystem(
        alloc_size=0, alloc_var='n', store_size=4,
        offset_var='n', mnemonic='store',
    )
    before = len(sys12.constraints)
    added = collector.enrich_constraint_system(
        sys12, alloc_func='alloc_and_write', write_func='alloc_and_write',
        summaries=summaries,
    )
    after = len(sys12.constraints)

    if added > 0 and after > before:
        passed += 1
        print(f"  [PASS] 12b.跨函数guard注入: +{added} constraints "
              f"({before} -> {after})")
    else:
        failed += 1
        print(f"  [FAIL] 12b.跨函数guard注入: added={added}, "
              f"{before} -> {after}")


if __name__ == '__main__':
    ok = run_all()
    sys.exit(0 if ok else 1)
