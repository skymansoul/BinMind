#!/usr/bin/env python3
"""调试被Stage8过滤的真阳样本"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

from modules.analysis.static.disasm_util import disassemble_binary
from modules.analysis.static.heap_overflow_detect import HeapOverflowDetector
from modules.analysis.static.heap_alloc_model import AllocatorFamily
from modules.analysis.static.import_resolver import resolve_call_targets

cves = ['CVE_01', 'CVE_02', 'CVE_03', 'CVE_04', 'CVE_05', 'CVE_07',
        'CVE_08', 'CVE_10', 'CVE_11', 'CVE_14']

for cve in cves:
    binary = os.path.join('modules', 'vuln', 'sample_bins', 'heap_overflow_cve',
                          cve, 'vuln_' + cve + '.exe')
    if not os.path.isfile(binary):
        print(f'{cve}: binary not found')
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
    findings = detector.finalize(instructions)
    raw = detector.stats.get('raw_findings', 0)
    filt = detector.stats.get('filtered_findings', 0)
    ddssc = detector.stats.get('ddssc_filter', {})
    coord = detector.stats.get('ddssc_coordinator', {})
    smt = coord.get('smt_solver', {})

    print(f'=== {cve}: {len(findings)} survivors (raw={raw}, filtered={filt}) ===')
    print(f'  DDSSC: s6={ddssc.get("stage6_interval_filtered",0)}, '
          f's7={ddssc.get("stage7_symbolic_filtered",0)}, '
          f's8={ddssc.get("stage8_smt_filtered",0)}, '
          f'passed={ddssc.get("passed",0)}')
    print(f'  Coord: L1_safe={coord.get("layer1_safe",0)}, '
          f'L1_oflow={coord.get("layer1_overflow",0)}, '
          f'L2_safe={coord.get("layer2_safe",0)}, '
          f'L2_oflow={coord.get("layer2_overflow",0)}, '
          f'L3_fp={coord.get("layer3_fp_filtered",0)}, '
          f'L3_conf={coord.get("layer3_confirmed",0)}, '
          f'unknown={coord.get("unknown",0)}')
    print(f'  SMT: z3={smt.get("z3_available",False)}, '
          f'solves={smt.get("total_solves",0)}, '
          f'sat={smt.get("sat",0)}, unsat={smt.get("unsat",0)}')

    for f in findings:
        verdict = f.get('ddssc_verdict', '?')
        layer = f.get('ddssc_layer', '?')
        detail = f.get('ddssc_detail', '?')[:100]
        alloc_sz = f.get('alloc_size_range', '?')
        write_sz = f.get('write_size_range', '?')
        print(f'  finding: verdict={verdict}, layer={layer}')
        print(f'    alloc_range={alloc_sz}, write_range={write_sz}')
        print(f'    detail={detail}')
    print()
