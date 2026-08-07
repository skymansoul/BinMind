import sys
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind")
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind\deemo")

from modules.analysis.static.disasm_util import disassemble_binary

binary = r"C:\Users\Administrator\Desktop\BinMind\deemo\modules\analysis\benchmark\samples\cve_2015_0235_ghost\cve_2015_0235_ghost_heap_O0.exe"
ins, fmt, main_addr, ranges = disassemble_binary(binary)
print(f"Format: {fmt}")
print(f"Main: {hex(main_addr) if main_addr else 'None'}")
print(f"Ranges ({len(ranges)}):")
for lo, hi in ranges[:20]:
    print(f"  {hex(lo)}-{hex(hi)}")

# 查找所有call malloc指令
malloc_calls = []
memcpy_calls = []
for i in ins:
    mnem = i.get("mnemonic", "").lower()
    ops = i.get("operands", [])
    addr = i.get("address", 0)
    if mnem == "call" and ops:
        target = ops[0].lower()
        if "malloc" in target:
            in_range = any(lo <= addr < hi for lo, hi in ranges)
            malloc_calls.append((addr, target, in_range))
        if "memcpy" in target:
            in_range = any(lo <= addr < hi for lo, hi in ranges)
            memcpy_calls.append((addr, target, in_range))

print(f"\nMalloc calls: {len(malloc_calls)}")
for addr, target, in_range in malloc_calls:
    print(f"  {hex(addr)}: {target} (user_code={in_range})")
print(f"\nMemcpy calls: {len(memcpy_calls)}")
for addr, target, in_range in memcpy_calls:
    print(f"  {hex(addr)}: {target} (user_code={in_range})")
