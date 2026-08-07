import sys
sys.path.insert(0, r'C:\Users\Administrator\Desktop\BinMind\deemo')
from modules.analysis.static.uaf_path_analyzer import PathAnalyzer
from modules.analysis.eval.batch_test_uaf import _disassemble

binary = r'C:\Users\Administrator\Desktop\BinMind\deemo\modules\analysis\eval\build_tmp_uaf\cve_2018_7566_alsa_O2.exe'
insns = _disassemble(binary)
pa = PathAnalyzer()
pa.build_scope_map(insns)

# Check mutual exclusion between path1 null and path2 UAF
print("are_mutually_exclusive(0x1400017c4, 0x1400017ea):", pa.are_mutually_exclusive(0x1400017c4, 0x1400017ea))
print("are_mutually_exclusive(0x1400017bf, 0x1400017e0):", pa.are_mutually_exclusive(0x1400017bf, 0x1400017e0))
print("are_mutually_exclusive(0x1400017bf, 0x1400017ea):", pa.are_mutually_exclusive(0x1400017bf, 0x1400017ea))

# Print scope map near the trigger function
for addr in sorted(pa._scope_map.keys()):
    if 0x140001760 <= addr <= 0x1400017f0:
        print(f"  scope[{hex(addr)}] = {pa._scope_map[addr]}")

# Print branch ranges
if hasattr(pa, '_branch_ranges'):
    for lo, hi in sorted(pa._branch_ranges):
        if 0x140001760 <= lo <= 0x1400017f0 or 0x140001760 <= hi <= 0x1400017f0:
            print(f"  branch_range: {hex(lo)}-{hex(hi)}")
