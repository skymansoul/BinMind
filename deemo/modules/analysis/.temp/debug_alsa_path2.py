import sys
sys.path.insert(0, r'C:\Users\Administrator\Desktop\BinMind\deemo')
from modules.analysis.static.uaf_path_analyzer import PathAnalyzer, BranchScope
from modules.analysis.eval.batch_test_uaf import _disassemble

binary = r'C:\Users\Administrator\Desktop\BinMind\deemo\modules\analysis\eval\build_tmp_uaf\cve_2018_7566_alsa_O2.exe'
insns = _disassemble(binary)
pa = PathAnalyzer()
pa.build_scope_map(insns)

# 打印0x140001760-0x1400017f0范围内的scope
print("=== Scopes covering alsa trigger region ===")
for s in pa._scopes:
    t_lo, t_hi = s.taken_range
    f_lo, f_hi = s.fallthrough_range
    if (0x140001760 <= t_lo <= 0x1400017f0 or
        0x140001760 <= f_lo <= 0x1400017f0):
        print(f"  jcc={hex(s.jcc_addr)} target={hex(s.target)} ft={hex(s.fallthrough)}")
        print(f"    merge={hex(s.merge_addr)} ret={s.ret_addr and hex(s.ret_addr)} jmp={s.jmp_addr and hex(s.jmp_addr)}")
        print(f"    taken_range=({hex(t_lo)}, {hex(t_hi)})")
        print(f"    fallthrough_range=({hex(f_lo)}, {hex(f_hi)})")

# 验证互斥判定
nulled_at = 0x1400017c4
uaf_at = 0x1400017ea
free1 = 0x1400017bf
free2 = 0x1400017e0

print(f"\nare_mutually_exclusive(nulled@{hex(nulled_at)}, uaf@{hex(uaf_at)}):",
      pa.are_mutually_exclusive(nulled_at, uaf_at))
print(f"are_mutually_exclusive(free1@{hex(free1)}, free2@{hex(free2)}):",
      pa.are_mutually_exclusive(free1, free2))
print(f"are_mutually_exclusive(free1@{hex(free1)}, uaf@{hex(uaf_at)}):",
      pa.are_mutually_exclusive(free1, uaf_at))
print(f"are_mutually_exclusive(free2@{hex(free2)}, uaf@{hex(uaf_at)}):",
      pa.are_mutually_exclusive(free2, uaf_at))

# 打印地址映射覆盖
print("\n=== _addr_to_scopes coverage ===")
for addr in sorted(pa._addr_to_scopes.keys()):
    if 0x1400017b0 <= addr <= 0x1400017f0:
        scopes = pa._addr_to_scopes[addr]
        print(f"  {hex(addr)}: {[hex(s.jcc_addr) for s in scopes]}")
