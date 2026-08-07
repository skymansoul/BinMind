#!/usr/bin/env python3
"""调试CVE_12和CVE_15的Stage7问题"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

from modules.analysis.static.disasm_util import disassemble_binary
from modules.analysis.static.heap_overflow_detect import HeapOverflowDetector
from modules.analysis.static.heap_alloc_model import AllocatorFamily
from modules.analysis.static.import_resolver import resolve_call_targets
from modules.analysis.static.sym_size_correlator import correlate_sizes, SymExpr

for cve in ['CVE_12', 'CVE_15']:
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

    print(f"=== {cve}: {len(stage123)} stage123, raw={len(detector._raw_findings)} ===")
    for f in stage123:
        alloc_addr = f.get("_snapshot_alloc_addr", f.get("alloc_addr", 0))
        write_expr = f.get("_write_sym_expr")
        sym_snap = detector._sym_snapshots.get(alloc_addr, {})
        alloc_expr = sym_snap.get("alloc_expr")
        print(f"  alloc_expr={alloc_expr}, write_expr={write_expr}")
        cat, oflow = correlate_sizes(alloc_expr, write_expr)
        print(f"  correlate_sizes: category={cat}, overflow={oflow}")
        print(f"  alloc_size={f.get('alloc_size')}, write_size={f.get('write_size')}")
        print(f"  finding type={f.get('type')}")
    print()
