import sys, os
sys.path.insert(0, r'C:\Users\Administrator\Desktop\BinMind\deemo')

from modules.analysis.static.disasm_util import disassemble_binary

path = r"C:\Users\Administrator\Desktop\BinMind\deemo\modules\analysis\eval\build_tmp_uaf\reg_cve_2019_2215_binder_uaf_O2.exe"
instructions, fmt, main_addr, user_ranges = disassemble_binary(path)
print(f"main_addr=0x{main_addr:x}")
print(f"user_ranges ({len(user_ranges)}):")
for lo, hi in user_ranges[:20]:
    print(f"  0x{lo:x} - 0x{hi:x}")
# Check if init/cleanup/use are covered
for name, addr in [("init", 0x140001760), ("cleanup", 0x140001780), ("use", 0x1400017a0), ("main", main_addr)]:
    found = any(lo <= addr < hi for lo, hi in user_ranges)
    print(f"  {name} at 0x{addr:x}: user_code={found}")
