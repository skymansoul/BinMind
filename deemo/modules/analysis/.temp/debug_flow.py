import sys
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind")
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind\deemo")

from modules.analysis.static.disasm_util import disassemble_binary
from modules.analysis.static.heap_overflow_detect import HeapOverflowDetector
from modules.analysis.static.heap_alloc_model import AllocatorFamily

binary = r"C:\Users\Administrator\Desktop\BinMind\deemo\modules\analysis\benchmark\samples\cve_2015_0235_ghost\cve_2015_0235_ghost_heap_O0.exe"
ins, fmt, main_addr, ranges = disassemble_binary(binary)
print(f"Format: {fmt}, Main: {hex(main_addr)}, Ranges: {len(ranges)}, Ins: {len(ins)}")

det = HeapOverflowDetector(AllocatorFamily.GLIBC, use_win64_abi="pei" in fmt.lower())
det.set_min_user_addr(main_addr)
det.set_user_func_ranges(ranges)
det.pre_analyze(ins)

# 手动分析指令，在关键点检查状态
for i, inst in enumerate(ins):
    addr = inst.get("address", 0)
    mnem = inst.get("mnemonic", "").lower()
    ops = inst.get("operands", [])

    # 检查 call 指令前后的状态
    if mnem == "call" and ops:
        target = ops[0].lower()
        if "malloc" in target or "memcpy" in target:
            rax_map = det._alloc_tracker._ptr_to_alloc.get("rax")
            rcx_map = det._alloc_tracker._ptr_to_alloc.get("rcx")
            print(f"\n[{hex(addr)}] {mnem} {target}")
            print(f"  Before: rax->alloc={hex(rax_map) if rax_map else None}, rcx->alloc={hex(rcx_map) if rcx_map else None}")
            print(f"  _is_user_code({hex(addr)})={det._is_user_code(addr)}")

    det.analyze_instruction(inst)

    if mnem == "call" and ops:
        target = ops[0].lower()
        if "malloc" in target or "memcpy" in target:
            rax_map = det._alloc_tracker._ptr_to_alloc.get("rax")
            rcx_map = det._alloc_tracker._ptr_to_alloc.get("rcx")
            print(f"  After: rax->alloc={hex(rax_map) if rax_map else None}, rcx->alloc={hex(rcx_map) if rcx_map else None}")
            raw = len(det._raw_findings)
            if raw > 0:
                print(f"  *** RAW FINDINGS: {raw}")

print(f"\nTotal raw findings: {len(det.raw_findings)}")
findings = det.finalize(ins)
print(f"Filtered findings: {len(findings)}")
for f in findings:
    print(f"  {f.get('type','?')} alloc={hex(f.get('alloc_addr',0))} write={hex(f.get('write_addr',0))} overflow={f.get('overflow_bytes',0)}")
