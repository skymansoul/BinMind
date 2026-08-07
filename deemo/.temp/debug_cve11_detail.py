#!/usr/bin/env python3
"""调试CVE_11: Stage8 SMT误杀, 检查write_expr和Z3约束"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

from modules.analysis.static.disasm_util import disassemble_binary
from modules.analysis.static.heap_overflow_detect import HeapOverflowDetector
from modules.analysis.static.heap_alloc_model import AllocatorFamily
from modules.analysis.static.import_resolver import resolve_call_targets
from modules.analysis.static.demand_smt_solver import PathConstraintCollector, DemandDrivenSMTSolver
from modules.analysis.static.value_range import ValueRange

binary = os.path.join('modules', 'vuln', 'sample_bins', 'heap_overflow_cve',
                      'CVE_11', 'vuln_CVE_11.exe')
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

print(f"raw_findings: {len(detector._raw_findings)}")
print(f"deduped: {len(deduped)}")
print(f"stage4: {len(stage4)}")
print(f"stage5: {len(stage5)}")
print(f"stage123: {len(stage123)}")

for f in stage123:
    alloc_addr = f.get("_snapshot_alloc_addr", f.get("alloc_addr", 0))
    write_addr = f.get("write_addr", 0)
    write_expr = f.get("_write_sym_expr")
    sym_snap = detector._sym_snapshots.get(alloc_addr, {})
    alloc_expr = sym_snap.get("alloc_expr")
    alloc_vr = sym_snap.get("alloc_vr")
    write_vr = sym_snap.get("write_vr")
    print(f"\nalloc_expr={alloc_expr}, write_expr={write_expr}")
    print(f"alloc_addr={alloc_addr}, write_addr={hex(write_addr)}")
    print(f"alloc_vr={alloc_vr}, write_vr={write_vr}")
    print(f"finding keys: {list(f.keys())}")

    # Path constraints
    collector = PathConstraintCollector()
    pcs = collector.collect(instructions, write_addr, detector._known_constants)
    print(f"path_constraints: {len(pcs)}")
    for pc in pcs:
        print(f"  {pc}")

    # Z3 solver
    solver = DemandDrivenSMTSolver()
    result = solver.verify_overflow(
        instructions, write_addr,
        alloc_expr, write_expr,
        alloc_vr, write_vr, detector._known_constants)
    print(f"Z3 result: {result}")

# Dump disassembly around the write area
print("\n=== Disassembly around memcpy call ===")
for i, ins in enumerate(instructions):
    addr = ins.get("address", 0)
    mnem = ins.get("mnemonic", "")
    ops = ins.get("operands", [])
    ops_str = ", ".join(ops) if ops else ""
    if mnem in ("call", "cmp", "jbe", "ja", "jg", "jle", "jmp", "mov", "ret") or "memcpy" in ops_str or "read" in ops_str:
        print(f"  {hex(addr)}: {mnem} {ops_str}")
