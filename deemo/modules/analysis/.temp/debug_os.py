import sys
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind")
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind\deemo")

from modules.analysis.static.disasm_util import disassemble_binary
from modules.analysis.static.heap_overflow_detect import HeapOverflowDetector
from modules.analysis.static.heap_alloc_model import AllocatorFamily

binary = r"C:\Users\Administrator\Desktop\BinMind\deemo\modules\analysis\benchmark\samples\cve_2015_0235_ghost\cve_2015_0235_ghost_heap_overflow_Os.exe"
ins, fmt, main_addr, ranges = disassemble_binary(binary)
print(f"Format: {fmt}, Main: {hex(main_addr) if main_addr else 'None'}, Ins: {len(ins)}, Ranges: {len(ranges)}")

det = HeapOverflowDetector(AllocatorFamily.GLIBC, use_win64_abi="pei" in fmt.lower())
det.set_min_user_addr(main_addr)
det.set_user_func_ranges(ranges)
det.pre_analyze(ins)
for i in ins:
    det.analyze_instruction(i)

print(f"Raw findings: {len(det.raw_findings)}")
for f in det.raw_findings:
    print(f"  type={f.get('type')} alloc={f.get('alloc_size')} write={f.get('write_size')} overflow={f.get('overflow_bytes')} alloc_addr={hex(f.get('_snapshot_alloc_addr',0))}")

# 检查malloc/memcpy调用
malloc_addrs = []
memcpy_addrs = []
for inst in ins:
    mnem = inst.get("mnemonic", "").lower()
    ops = inst.get("operands", [])
    addr = inst.get("address", 0)
    if mnem == "call" and ops:
        target = ops[0].lower()
        if "malloc" in target:
            in_range = any(lo <= addr < hi for lo, hi in ranges)
            malloc_addrs.append((addr, target, in_range))
        if "memcpy" in target:
            in_range = any(lo <= addr < hi for lo, hi in ranges)
            memcpy_addrs.append((addr, target, in_range))

print(f"\nMalloc calls: {len(malloc_addrs)}")
for addr, target, in_range in malloc_addrs:
    print(f"  {hex(addr)}: {target} (user={in_range})")
print(f"Memcpy calls: {len(memcpy_addrs)}")
for addr, target, in_range in memcpy_addrs:
    print(f"  {hex(addr)}: {target} (user={in_range})")

findings = det.finalize(ins)
print(f"\nFiltered findings: {len(findings)}")
