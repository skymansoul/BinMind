# 快速测试 loop_accumulate 和 derived_boundary 修复
import sys
sys.path.insert(0, r'C:\Users\Administrator\Desktop\BinMind\deemo')
from modules.analysis.static.disasm_util import disassemble_binary
from modules.analysis.static.heap_overflow_detect import HeapOverflowDetector
from modules.analysis.static.heap_alloc_model import AllocatorFamily

def test_binary(path, label):
    print(f"\n{'='*60}")
    print(f"TEST: {label}")
    instrs, fmt, main_addr, user_ranges = disassemble_binary(path)
    detector = HeapOverflowDetector(
        allocator=AllocatorFamily.GLIBC, use_win64_abi=True)
    detector.set_user_func_ranges(user_ranges)
    detector.pre_analyze(instrs)
    for ins in instrs:
        detector.analyze_instruction(ins)
    findings = detector.finalize(instrs)
    stats = detector.stats
    print(f"  Raw findings: {stats['raw_findings']}")
    print(f"  Filtered findings: {stats['filtered_findings']}")
    print(f"  FP reduction: {stats['fp_reduction_pct']}%")
    print(f"  Loop accumulator: {stats['loop_accumulator']}")
    for f in findings:
        print(f"  -> finding: type={f.get('type')} method={f.get('detection_method','')} "
              f"alloc={f.get('alloc_size',0)} write={f.get('write_size',0)} "
              f"overflow={f.get('overflow_bytes',0)} fp_stage={f.get('fp_stage','none')}")
    return findings

# Test derived_boundary O0
f1 = test_binary(
    r'C:\Users\Administrator\Desktop\BinMind\deemo\modules\analysis\benchmark\samples_sawce\sawce_derived_boundary\sawce_derived_boundary_O0.exe',
    'derived_boundary O0 (expect: 0 findings)')

# Test loop_accumulate O0
f2 = test_binary(
    r'C:\Users\Administrator\Desktop\BinMind\deemo\modules\analysis\benchmark\samples_sawce\sawce_loop_accumulate\sawce_loop_accumulate_O0.exe',
    'loop_accumulate O0 (expect: 1 finding, loop_accumulation)')

# Test same_source O0
f3 = test_binary(
    r'C:\Users\Administrator\Desktop\BinMind\deemo\modules\analysis\benchmark\samples_sawce\sawce_same_source\sawce_same_source_O0.exe',
    'same_source O0 (expect: 1 finding, _diff overflow)')

# Test arithmetic O0
f4 = test_binary(
    r'C:\Users\Administrator\Desktop\BinMind\deemo\modules\analysis\benchmark\samples_sawce\sawce_arithmetic\sawce_arithmetic_O0.exe',
    'arithmetic O0 (expect: 0 findings)')

# Test nested_call O0
f5 = test_binary(
    r'C:\Users\Administrator\Desktop\BinMind\deemo\modules\analysis\benchmark\samples_sawce\sawce_nested_call\sawce_nested_call_O0.exe',
    'nested_call O0 (expect: 0 findings)')

print("\n" + "="*60)
print("SUMMARY:")
print(f"  derived_boundary: {len(f1)} findings (expect 0) {'PASS' if len(f1)==0 else 'FAIL'}")
print(f"  loop_accumulate:  {len(f2)} findings (expect 1) {'PASS' if len(f2)==1 else 'FAIL'}")
print(f"  same_source:      {len(f3)} findings (expect 1) {'PASS' if len(f3)==1 else 'FAIL'}")
print(f"  arithmetic:       {len(f4)} findings (expect 0) {'PASS' if len(f4)==0 else 'FAIL'}")
print(f"  nested_call:      {len(f5)} findings (expect 0) {'PASS' if len(f5)==0 else 'FAIL'}")
