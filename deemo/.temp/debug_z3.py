#!/usr/bin/env python3
"""调试Z3求解器的约束构建和求解结果"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

from modules.analysis.static.disasm_util import disassemble_binary
from modules.analysis.static.heap_overflow_detect import HeapOverflowDetector
from modules.analysis.static.heap_alloc_model import AllocatorFamily
from modules.analysis.static.import_resolver import resolve_call_targets
from modules.analysis.static.ddssc_coordinator import DDSSCCoordinator
from modules.analysis.static.ddssc_fp_filter import DDSSCFPFilter
from modules.analysis.static.sym_size_correlator import SymExpr
from modules.analysis.static.heap_constraint import Interval
from modules.analysis.static.value_range import ValueRange

# 测试Z3直接求解
try:
    from z3 import BitVec, BitVecVal, Solver, sat, unsat, UGT, UGE, ULE, And
    print("Z3 available")
    
    solver = Solver()
    solver.set("timeout", 2000)
    bv_width = 64
    size_var = BitVec("size", bv_width)
    write_var = BitVec("size_write", bv_width)
    
    # 模拟CVE_02的范围: alloc=[0, MAX], write=[0, MAX]
    range_conds = [
        UGE(size_var, BitVecVal(0, bv_width)),
        ULE(size_var, BitVecVal),
        UGE(write_var, BitVecVal(0, bv_width)),
        ULE(write_var, BitVecVal),
    ]
    overflow_cond = UGT(write_var, size_var)
    solver.add(And(*(range_conds + [overflow_cond])))
    
    result = solver.check()
    print(f"Z3 result: {result}")
    if result == sat:
        m = solver.model()
        print(f"  size={m[size_var]}, write={m[write_var]}")
    
except ImportError as e:
    print(f"Z3 not available: {e}")

print()

# 测试每个CVE的filter阶段数据
for cve in ['CVE_02', 'CVE_05', 'CVE_07', 'CVE_08', 'CVE_10', 'CVE_11', 'CVE_14']:
    binary = os.path.join('modules', 'vuln', 'sample_bins', 'heap_overflow_cve',
                          cve, 'vuln_' + cve + '.exe')
    if not os.path.isfile(binary):
        continue
    instructions, file_format, main_addr, user_ranges = disassemble_binary(binary)
    instructions = resolve_call_targets(binary, instructions, file_format)
    detector = HeapOverflowDetector(
        allocator=AllocatorFamily.GLIBC,
        use_win64_abi='pei' in file_format.lower())
    detector.set_user_func_ranges(user_ranges)
    detector.pre_analyze(instructions)
    for ins in instructions:
        detector.analyze_instruction(ins)
    
    # 拿到finalize前的findings
    findings = detector.finalize(instructions)
    
    # 查看内部数据
    coord = detector._ddssc_coord
    fp_filter = detector._ddssc_filter
    
    # 获取raw findings (Stage1-5后)
    # 需要检查finalize前的数据
    print(f"=== {cve} ===")
    print(f"  stats: {detector.stats.get('raw_findings', '?')} raw, "
          f"{detector.stats.get('filtered_findings', '?')} filtered")
    
    # 检查sym_exprs
    sym_exprs = getattr(detector, '_sym_exprs', {})
    print(f"  sym_exprs keys: {list(sym_exprs.keys())[:5]}")
    for k, v in list(sym_exprs.items())[:3]:
        print(f"    {k}: {v}")
    
    print()
