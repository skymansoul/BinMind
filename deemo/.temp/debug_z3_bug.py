#!/usr/bin/env python3
"""直接测试Z3对CVE_10/CVE_11场景的求解"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

from modules.analysis.static.sym_size_correlator import SymExpr
from modules.analysis.static.value_range import ValueRange

from z3 import BitVec, BitVecVal, Solver, sat, unsat, UGT, UGE, ULE, And

# CVE_10: alloc=12(const), write=param_1(var)
# param_1 > 12 should be SAT
print("=== CVE_10 test ===")
solver = Solver()
solver.set("timeout", 2000)
bv_width = 64
param_bv = BitVec("param_1", bv_width)
alloc_z3 = BitVecVal(12, bv_width)
write_z3 = param_bv  # coeff=1, const=0
overflow = UGT(write_z3, alloc_z3)
# 路径约束: param_1 > 0 (from jle fallthrough)
# but path constraint is on [rbp+0x18] which is skipped
# alloc_vr and write_vr: need to check what values are passed
# write_vr might be [0, 2147483647]
# If alloc_vr is [12, 12] and we use param_bv for both, that constrains param_bv to [12,12]!
# That's the bug! We apply alloc_vr and write_vr to the SAME param_bv!
# alloc_vr=[12,12] means param_bv in [12,12], so param_bv=12, then 12>12 is UNSAT
solver.add(overflow)
# Without range constraints
result = solver.check()
print(f"  Without range: {result}")
if result == sat:
    m = solver.model()
    print(f"    param_1={m[param_bv]}")

# With alloc_vr applied to param_bv
solver2 = Solver()
solver2.set("timeout", 2000)
alloc_vr = ValueRange(12, 12)
range_conds = [
    UGE(param_bv, BitVecVal(alloc_vr.lo, bv_width)),
    ULE(param_bv, BitVecVal(alloc_vr.hi, bv_width)),
]
solver2.add(And(*(range_conds + [overflow])))
result2 = solver2.check()
print(f"  With alloc_vr [12,12] on param_bv: {result2}")

# With write_vr applied to param_bv
solver3 = Solver()
solver3.set("timeout", 2000)
write_vr = ValueRange(0, 2147483647)
range_conds3 = [
    UGE(param_bv, BitVecVal(write_vr.lo, bv_width)),
    ULE(param_bv, BitVecVal(write_vr.hi, bv_width)),
]
solver3.add(And(*(range_conds3 + [overflow])))
result3 = solver3.check()
print(f"  With write_vr [0,MAX] on param_bv: {result3}")
if result3 == sat:
    m = solver3.model()
    print(f"    param_1={m[param_bv]}")

# With BOTH alloc_vr and write_vr on same param_bv
solver4 = Solver()
solver4.set("timeout", 2000)
range_conds4 = [
    UGE(param_bv, BitVecVal(alloc_vr.lo, bv_width)),
    ULE(param_bv, BitVecVal(alloc_vr.hi, bv_width)),
    UGE(param_bv, BitVecVal(write_vr.lo, bv_width)),
    ULE(param_bv, BitVecVal(write_vr.hi, bv_width)),
]
solver4.add(And(*(range_conds4 + [overflow])))
result4 = solver4.check()
print(f"  With BOTH alloc_vr[12,12] AND write_vr[0,MAX] on param_bv: {result4}")

print()
print("BUG: alloc_vr=[12,12] is for alloc_size, not param_bv!")
print("     write_vr=[0,MAX] is for write_size, not param_bv!")
print("     But alloc_size=const 12 has no relation to param_bv!")
print("     We should NOT apply alloc_vr to param_bv when alloc is const!")
