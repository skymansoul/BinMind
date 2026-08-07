#!/usr/bin/env python3
"""深入调试Z3求解过程, 打印路径约束和约束公式"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

from modules.analysis.static.disasm_util import disassemble_binary
from modules.analysis.static.heap_overflow_detect import HeapOverflowDetector
from modules.analysis.static.heap_alloc_model import AllocatorFamily
from modules.analysis.static.import_resolver import resolve_call_targets
from modules.analysis.static.demand_smt_solver import (
    PathConstraintCollector, DemandDrivenSMTSolver, _HAS_Z3)
from modules.analysis.static.sym_size_correlator import SymExpr
from modules.analysis.static.value_range import ValueRange
from modules.analysis.static.heap_constraint import Interval

if _HAS_Z3:
    from z3 import (BitVec, BitVecVal, Solver, sat, unsat, UGT,
                     UGE, ULE, And, simplify)

for cve in ['CVE_02', 'CVE_07', 'CVE_05']:
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

    # 获取stage123 survivors
    deduped = detector._dedup_by_alloc(detector._raw_findings)
    stage4 = [f for f in deduped if detector._stage4_path_sensitive_check(f)]
    stage5 = [f for f in stage4 if detector._stage5_struct_field_check(f)]
    stage123 = detector._fp_filter.filter(stage5, instructions, detector._alloc_tracker)

    print(f"=== {cve}: {len(stage123)} stage123 survivors ===")
    for f in stage123:
        alloc_addr = f.get("_snapshot_alloc_addr", f.get("alloc_addr", 0))
        write_addr = f.get("write_addr", 0)
        alloc_sz = f.get("alloc_size", 0)
        write_sz = f.get("write_size", 0)
        alloc_range = f.get("alloc_size_range", "?")
        write_range = f.get("write_size_range", "?")
        write_expr = f.get("_write_sym_expr")
        print(f"  alloc_addr={alloc_addr}, write_addr={write_addr}")
        print(f"  alloc_size={alloc_sz}, write_size={write_sz}")
        print(f"  alloc_range={alloc_range}, write_range={write_range}")
        print(f"  write_sym_expr={write_expr}")

        # 获取符号快照
        sym_snap = detector._sym_snapshots.get(alloc_addr, {})
        alloc_expr = sym_snap.get("alloc_expr")
        print(f"  alloc_sym_expr={alloc_expr}")
        print(f"  sym_snapshot keys: {list(sym_snap.keys())}")

        # 获取alloc constraint
        alloc_con = detector._alloc_tracker._allocations.get(alloc_addr)
        if alloc_con:
            raw_size = getattr(alloc_con, "raw_alloc_size", alloc_con.alloc_size)
            print(f"  alloc_constraint raw_size={raw_size}")

        # 收集路径约束
        collector = PathConstraintCollector()
        pcs = collector.collect(instructions, write_addr, detector._known_constants)
        print(f"  path_constraints: {len(pcs)}")
        for pc in pcs:
            print(f"    {pc}")

        # 手动运行Z3
        if _HAS_Z3 and alloc_expr and write_expr:
            solver = Solver()
            solver.set("timeout", 2000)
            bv_width = 64

            # 正确编码: alloc_expr和write_expr共享param变量
            # alloc_expr = coeff_a * var + const_a
            # write_expr = coeff_w * var + const_w
            var_name = alloc_expr.var or write_expr.var
            if var_name:
                param_var = BitVec(var_name, bv_width)
                alloc_z3 = alloc_expr.coeff * param_var + BitVecVal(alloc_expr.const, bv_width)
                write_z3 = write_expr.coeff * param_var + BitVecVal(write_expr.const, bv_width)

                # 路径约束
                path_conds = []
                for pc in pcs:
                    reg_bv = BitVec(pc.reg, bv_width)
                    val_bv = BitVecVal(pc.value, bv_width)
                    from modules.analysis.static.path_condition import CondOp
                    cond_map = {
                        CondOp.EQ: lambda a, b: a == b,
                        CondOp.NE: lambda a, b: a != b,
                        CondOp.LT: lambda a, b: a < b,
                        CondOp.LE: lambda a, b: a <= b,
                        CondOp.GT: lambda a, b: a > b,
                        CondOp.GE: lambda a, b: a >= b,
                    }
                    fn = cond_map.get(pc.op)
                    if fn:
                        path_conds.append(fn(reg_bv, val_bv))

                overflow_cond = UGT(write_z3, alloc_z3)
                all_conds = path_conds + [overflow_cond]
                if all_conds:
                    solver.add(And(*all_conds))

                result = solver.check()
                print(f"  Z3 (shared var): {result}")
                if result == sat:
                    m = solver.model()
                    if param_var in m:
                        print(f"    param={m[param_var]}")
            else:
                # 不共享变量 - 测试独立变量的情况
                size_var = BitVec("size", bv_width)
                write_var = BitVec("size_write", bv_width)
                overflow_cond = UGT(write_var, size_var)
                
                alloc_vr = ValueRange(0, alloc_sz) if alloc_sz > 0 else None
                write_vr = ValueRange(0, write_sz) if write_sz > 0 else None
                range_conds = []
                if alloc_vr and not alloc_vr.is_bottom:
                    range_conds.append(UGE(size_var, BitVecVal(alloc_vr.lo, bv_width)))
                    range_conds.append(ULE(size_var, BitVecVal(alloc_vr.hi, bv_width)))
                if write_vr and not write_vr.is_bottom:
                    range_conds.append(UGE(write_var, BitVecVal(write_vr.lo, bv_width)))
                    range_conds.append(ULE(write_var, BitVecVal(write_vr.hi, bv_width)))

                # 路径约束
                path_conds = []
                for pc in pcs:
                    reg_bv = BitVec(pc.reg, bv_width)
                    val_bv = BitVecVal(pc.value, bv_width)
                    from modules.analysis.static.path_condition import CondOp
                    cond_map = {
                        CondOp.EQ: lambda a, b: a == b,
                        CondOp.NE: lambda a, b: a != b,
                        CondOp.LT: lambda a, b: a < b,
                        CondOp.LE: lambda a, b: a <= b,
                        CondOp.GT: lambda a, b: a > b,
                        CondOp.GE: lambda a, b: a >= b,
                    }
                    fn = cond_map.get(pc.op)
                    if fn:
                        path_conds.append(fn(reg_bv, val_bv))

                all_conds = path_conds + range_conds + [overflow_cond]
                if all_conds:
                    solver.add(And(*all_conds))
                result = solver.check()
                print(f"  Z3 (independent vars): {result}")
                if result == unsat:
                    print(f"    UNSAT! path_conds={len(path_conds)}, range_conds={len(range_conds)}")
                    # 打印约束
                    for pc in pcs:
                        print(f"      pc: {pc}")

        print()
