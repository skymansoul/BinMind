import sys
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind")
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind\deemo")

from modules.analysis.static.disasm_util import disassemble_binary
from modules.analysis.static.heap_overflow_detect import HeapOverflowDetector
from modules.analysis.static.heap_alloc_model import AllocatorFamily

binary = r"C:\Users\Administrator\Desktop\BinMind\deemo\modules\analysis\benchmark\samples\cve_2015_0235_ghost\cve_2015_0235_ghost_heap_O0.exe"
ins, fmt, main_addr, ranges = disassemble_binary(binary)

det = HeapOverflowDetector(AllocatorFamily.GLIBC, use_win64_abi="pei" in fmt.lower())
det.set_min_user_addr(main_addr)
det.set_user_func_ranges(ranges)
det.pre_analyze(ins)
for i in ins:
    det.analyze_instruction(i)

print(f"Raw findings: {len(det.raw_findings)}")
for f in det.raw_findings:
    print(f"  type={f.get('type')} alloc={f.get('alloc_size')} write={f.get('write_size')} overflow={f.get('overflow_bytes')}")

# 手动执行finalize各阶段
from typing import List
deduped = det._dedup_by_alloc(det._raw_findings)
print(f"\nAfter dedup: {len(deduped)}")

stage4 = []
for f in deduped:
    if det._stage4_path_sensitive_check(f):
        stage4.append(f)
    else:
        print(f"  Stage4 filtered: fp_stage={f.get('fp_stage','?')}")
print(f"After stage4: {len(stage4)}")

stage5 = []
for f in stage4:
    if det._stage5_struct_field_check(f):
        stage5.append(f)
    else:
        print(f"  Stage5 filtered: fp_stage={f.get('fp_stage','?')}")
print(f"After stage5: {len(stage5)}")

stage123 = det._fp_filter.filter(stage5, ins, det._alloc_tracker)
print(f"After fp_filter: {len(stage123)}")
for f in stage123:
    print(f"  type={f.get('type')} alloc={f.get('alloc_size')} write={f.get('write_size')}")

if stage123:
    sym_expr_map = det._build_sym_expr_map(stage123)
    stage678 = det._ddssc_filter.filter(stage123, ins, det._alloc_tracker, det._known_constants, sym_expr_map)
    print(f"After DDSSC: {len(stage678)}")
    for f in stage678:
        print(f"  type={f.get('type')} alloc={f.get('alloc_size')} write={f.get('write_size')} fp_stage={f.get('fp_stage','')}")

    det._struct_size_tracker.set_instructions(ins)
    det._struct_size_tracker.reset()
    for ins_item in ins:
        det._struct_size_tracker.process(ins_item)
    corr_results = det._symbolic_correlator.correlate(det._struct_size_tracker, det._alloc_tracker)
    stage9 = []
    for f in stage678:
        filter_reason = det._symbolic_correlator.filter_finding(f, corr_results)
        if filter_reason:
            print(f"  Stage9 SAWCE filtered: {filter_reason}")
            f["fp_stage"] = "stage9_sawce_correlation"
            f["fp_reason"] = filter_reason
        else:
            stage9.append(f)
    print(f"After SAWCE: {len(stage9)}")
