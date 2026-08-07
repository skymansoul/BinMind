#!/usr/bin/env python3
"""调试CVE_10和CVE_11的Z3求解"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

from modules.analysis.static.disasm_util import disassemble_binary
from modules.analysis.static.heap_overflow_detect import HeapOverflowDetector
from modules.analysis.static.heap_alloc_model import AllocatorFamily
from modules.analysis.static.import_resolver import resolve_call_targets
from modules.analysis.static.demand_smt_solver import PathConstraintCollector

for cve in ['CVE_10', 'CVE_11']:
    binary = os.path.join('modules', 'vuln', 'sample_bins', 'heap_overflow_cve',
                          cve, 'vuln_' + cve + '.exe')
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

    print(f"=== {cve}: {len(stage123)} stage123 survivors ===")
    for f in stage123:
        alloc_addr = f.get("_snapshot_alloc_addr", f.get("alloc_addr", 0))
        write_addr = f.get("write_addr", 0)
        alloc_sz = f.get("alloc_size", 0)
        write_sz = f.get("write_size", 0)
        write_expr = f.get("_write_sym_expr")
        print(f"  alloc_addr={alloc_addr}, write_addr={write_addr}")
        print(f"  alloc_size={alloc_sz}, write_size={write_sz}")
        print(f"  write_sym_expr={write_expr}")

        sym_snap = detector._sym_snapshots.get(alloc_addr, {})
        alloc_expr = sym_snap.get("alloc_expr")
        print(f"  alloc_sym_expr={alloc_expr}")

        alloc_con = detector._alloc_tracker._allocations.get(alloc_addr)
        if alloc_con:
            raw_size = getattr(alloc_con, "raw_alloc_size", alloc_con.alloc_size)
            print(f"  alloc raw_size={raw_size}")

        collector = PathConstraintCollector()
        pcs = collector.collect(instructions, write_addr, detector._known_constants)
        print(f"  path_constraints: {len(pcs)}")
        for pc in pcs:
            print(f"    {pc}")

        # 打印write_addr附近的指令
        print(f"  instructions near write_addr {write_addr}:")
        for i, ins in enumerate(instructions):
            if abs(ins.get("address", 0) - write_addr) < 80:
                print(f"    {ins.get('address',0)}: {ins.get('mnemonic','')} {ins.get('operands',[])}")
    print()
