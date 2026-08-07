#!/usr/bin/env python3
"""直接调试CVE_05的Z3求解"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

from modules.analysis.static.disasm_util import disassemble_binary
from modules.analysis.static.heap_overflow_detect import HeapOverflowDetector
from modules.analysis.static.heap_alloc_model import AllocatorFamily
from modules.analysis.static.import_resolver import resolve_call_targets
from modules.analysis.static.demand_smt_solver import PathConstraintCollector
from modules.analysis.static.sym_size_correlator import SymExpr
from modules.analysis.static.value_range import ValueRange
from modules.analysis.static.path_condition import CondOp

from z3 import BitVec, BitVecVal, Solver, sat, unsat, UGT, UGE, ULE, And

binary = os.path.join('modules', 'vuln', 'sample_bins', 'heap_overflow_cve',
                      'CVE_05', 'vuln_CVE_05.exe')
instructions, file_format, main_addr, user_ranges = disassemble_binary(binary)
instructions = resolve_call_targets(binary, instructions, file_format)

target_addr = 5368715183
collector = PathConstraintCollector()
pcs = collector.collect(instructions, target_addr, {})
print(f"Constraints: {len(pcs)}")
for pc in pcs:
    print(f"  {pc}")

# Z3 solve
alloc_expr = SymExpr(None, 0, 256)  # const 256
write_expr = SymExpr(var="param_1", coeff=1, const=0)  # param_1

bv_width = 64
solver = Solver()
solver.set("timeout", 2000)

param_bv = BitVec("param_1", bv_width)
alloc_z3 = BitVecVal(256, bv_width)
write_z3 = param_bv

overflow = UGT(write_z3, alloc_z3)

path_conds = []
for pc in pcs:
    if "[" in pc.reg or "qword" in pc.reg or "dword" in pc.reg:
        print(f"  Skipping memory op: {pc}")
        continue
    reg_bv = BitVec(pc.reg, bv_width)
    val_bv = BitVecVal(pc.value, bv_width)
    cond_map = {
        CondOp.EQ: lambda a, b: a == b,
        CondOp.NE: lambda a, b: a != b,
        CondOp.LT: lambda a, b: a < b,
        CondOp.LE: lambda a, b: a <= b,
        CondOp.GT: lambda a, b: a > b,
        CondOp.GE: lambda a, b: a >= b,
        CondOp.BELOW: lambda a, b: a < b,
        CondOp.BELOW_EQ: lambda a, b: a <= b,
        CondOp.ABOVE: lambda a, b: a > b,
        CondOp.ABOVE_EQ: lambda a, b: a >= b,
    }
    fn = cond_map.get(pc.op)
    if fn:
        cond = fn(reg_bv, val_bv)
        path_conds.append(cond)
        print(f"  Added: {pc.reg} {pc.op} {pc.value}")

all_conds = path_conds + [overflow]
solver.add(And(*all_conds))
result = solver.check()
print(f"\nZ3 result: {result}")
if result == sat:
    m = solver.model()
    print(f"  param_1={m[param_bv]}")
else:
    print(f"  UNSAT - overflow impossible under path constraints")
