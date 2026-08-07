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
    import json
    print(json.dumps(f, indent=2, default=str))

findings = det.finalize(ins)
print(f"\nFiltered findings: {len(findings)}")
for f in findings:
    import json
    print(json.dumps(f, indent=2, default=str))
