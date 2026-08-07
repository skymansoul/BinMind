import sys, json
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind")
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind\deemo")

from modules.analysis.static.disasm_util import disassemble_binary
from modules.analysis.static.heap_overflow_detect import HeapOverflowDetector
from modules.analysis.static.heap_alloc_model import AllocatorFamily

binary = r"C:\Users\Administrator\Desktop\BinMind\deemo\modules\analysis\benchmark\samples\cve_2015_0235_ghost\cve_2015_0235_ghost_heap_O0.exe"
ins, fmt, main_addr, ranges = disassemble_binary(binary)
print(f"Format: {fmt}, Main: {hex(main_addr) if main_addr else 'None'}, Ranges: {len(ranges)}")
print(f"Instructions: {len(ins)}")

det = HeapOverflowDetector(AllocatorFamily.GLIBC, use_win64_abi="pei" in fmt.lower())
if main_addr:
    det.set_min_user_addr(main_addr)
if ranges:
    det.set_user_func_ranges(ranges)
det.pre_analyze(ins)
for i in ins:
    det.analyze_instruction(i)
findings = det.finalize(ins)
print(f"Raw findings: {len(det.raw_findings)}")
print(f"Filtered findings: {len(findings)}")
for f in findings:
    print(f"  {f.get('type', '?')} alloc={f.get('alloc_addr', 0):x} write={f.get('write_addr', 0):x}")

# 检查 alloc_tracker 状态
print(f"\nAlloc tracker stats: {det._alloc_tracker.stats()}")
print(f"Known constants: {len(det._known_constants)}")
print(f"Ptr map: {det._alloc_tracker._ptr_to_alloc}")
