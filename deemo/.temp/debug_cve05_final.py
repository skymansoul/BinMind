#!/usr/bin/env python3
"""直接用detector运行的Z3结果调试CVE_05"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

from modules.analysis.static.disasm_util import disassemble_binary
from modules.analysis.static.heap_overflow_detect import HeapOverflowDetector
from modules.analysis.static.heap_alloc_model import AllocatorFamily
from modules.analysis.static.import_resolver import resolve_call_targets
from modules.analysis.static.demand_smt_solver import PathConstraintCollector, DemandDrivenSMTSolver
from modules.analysis.static.sym_size_correlator import SymExpr
from modules.analysis.static.value_range import ValueRange
from modules.analysis.static.path_condition import CondOp

binary = os.path.join('modules', 'vuln', 'sample_bins', 'heap_overflow_cve',
                      'CVE_05', 'vuln_CVE_05.exe')
instructions, file_format, main_addr, user_ranges = disassemble_binary(binary)
instructions = resolve_call_targets(binary, instructions, file_format)
detector = HeapOverflowDetector(
    allocator=AllocatorFamily.GLIBC,
    use_win64_abi='pei' in file_format.lower())
detector.set_user_func_ranges(user_ranges)
detector.pre_analyze(instructions)
for ins in instructions:
    detector.analyze_instruction(ins)

deduped = detector._dedup_by_alloc(detector._raw_findings)
stage4 = [f for f in deduped if detector._stage4_path_sensitive_check(f)]
stage5 = [f for f in stage4 if detector._stage5_struct_field_check(f)]
stage123 = detector._fp_filter.filter(stage5, instructions, detector._alloc_tracker)

for f in stage123:
    alloc_addr = f.get("_snapshot_alloc_addr", f.get("alloc_addr", 0))
    write_addr = f.get("write_addr", 0)
    write_expr = f.get("_write_sym_expr")
    sym_snap = detector._sym_snapshots.get(alloc_addr, {})
    alloc_expr = sym_snap.get("alloc_expr")
    print(f"alloc_expr={alloc_expr}, write_expr={write_expr}")
    print(f"alloc_addr={alloc_addr}, write_addr={write_addr}")

    # Collect path constraints
    collector = PathConstraintCollector()
    pcs = collector.collect(instructions, write_addr, detector._known_constants)
    print(f"path_constraints: {len(pcs)}")
    for pc in pcs:
        print(f"  {pc}")

    # Run actual Z3 solver
    solver = DemandDrivenSMTSolver()
    print(f"z3_available: {solver.z3_available}")
    
    alloc_vr = ValueRange(256, 256)
    write_vr = ValueRange(0, 2147483647)
    
    result = solver.verify_overflow(
        instructions, write_addr,
        alloc_expr, write_expr,
        alloc_vr, write_vr, detector._known_constants)
    print(f"Z3 result: {result}")
    print(f"stats: {solver.stats}")
    
    # Manual Z3 test
    from z3 import BitVec, BitVecVal, Solver, sat, unsat, UGT, UGE, ULE, And
    bv_width = 64
    s = Solver()
    s.set("timeout", 2000)
    param_bv = BitVec("param_1", bv_width)
    alloc_z3 = BitVecVal(256, bv_width)
    write_z3 = param_bv
    overflow = UGT(write_z3, alloc_z3)
    # rdx <= 256 → param_1 <= 256
    rdx_bv = BitVec("param_1", bv_width)
    path_cond = ULE(rdx_bv, BitVecVal(256, bv_width))
    s.add(And(path_cond, overflow))
    r = s.check()
    print(f"Manual Z3 (param_1 <= 256 AND param_1 > 256): {r}")
