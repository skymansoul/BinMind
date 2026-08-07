# 测试 loop_accumulate 全部3个优化级别
import sys
sys.path.insert(0, r'C:\Users\Administrator\Desktop\BinMind\deemo')
from modules.analysis.static.disasm_util import disassemble_binary
from modules.analysis.static.heap_overflow_detect import HeapOverflowDetector
from modules.analysis.static.heap_alloc_model import AllocatorFamily

def test_binary(path, label, expect_count):
    print(f"\n{'='*60}")
    print(f"TEST: {label}")
    try:
        instrs, fmt, main_addr, user_ranges = disassemble_binary(path)
    except Exception as e:
        print(f"  ERROR: {e}")
        return None
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
    print(f"  Loop accumulator: {stats['loop_accumulator']}")
    for f in findings:
        dm = f.get('detection_method', '')
        tc = f.get('loop_trip_count', '')
        sw = f.get('single_write_size', '')
        print(f"  -> method={dm} alloc={f.get('alloc_size',0)} "
              f"write={f.get('write_size',0)} overflow={f.get('overflow_bytes',0)}"
              f" trip={tc} single={sw}")
    ok = len(findings) == expect_count
    print(f"  RESULT: {len(findings)} findings (expect {expect_count}) "
          f"{'PASS' if ok else 'FAIL'}")
    return findings

base = r'C:\Users\Administrator\Desktop\BinMind\deemo\modules\analysis\benchmark\samples_sawce\sawce_loop_accumulate'

results = {}
for opt in ['O0', 'O2', 'Os']:
    path = f'{base}\\sawce_loop_accumulate_{opt}.exe'
    r = test_binary(path, f'loop_accumulate {opt} (expect: 1 finding)', 1)
    results[opt] = r

print("\n" + "="*60)
print("LOOP ACCUMULATE SUMMARY:")
allok = True
for opt in ['O0', 'O2', 'Os']:
    r = results[opt]
    n = len(r) if r is not None else -1
    ok = n == 1
    if not ok:
        allok = False
    print(f"  {opt}: {n} findings (expect 1) {'PASS' if ok else 'FAIL'}")
print(f"\nOVERALL: {'ALL PASS' if allok else 'SOME FAIL'}")
