import sys
sys.path.insert(0, r'C:\Users\Administrator\Desktop\BinMind\deemo')
from modules.analysis.static.uaf_path_analyzer import PathAnalyzer
from modules.analysis.eval.batch_test_uaf import _disassemble

binary = r'C:\Users\Administrator\Desktop\BinMind\deemo\modules\analysis\eval\build_tmp_uaf\cve_2018_7566_alsa_O2.exe'
insns = _disassemble(binary)
pa = PathAnalyzer()
pa.build_scope_map(insns)

print("Scopes:")
for s in pa._scopes:
    if 0x140001760 <= s.jcc_addr <= 0x1400017f0:
        print(f"  jcc={hex(s.jcc_addr)} target={hex(s.target)} ft={hex(s.fallthrough)} merge={hex(s.merge_addr)}")
        print(f"    taken_range=({hex(s.taken_range[0])}, {hex(s.taken_range[1])})")
        print(f"    fallthrough_range=({hex(s.fallthrough_range[0])}, {hex(s.fallthrough_range[1])})")

print("\nare_mutually_exclusive(0x1400017c4, 0x1400017ea):", pa.are_mutually_exclusive(0x1400017c4, 0x1400017ea))

# Check scopes for each address
for addr in [0x1400017bf, 0x1400017c4, 0x1400017d8, 0x1400017e0, 0x1400017e5, 0x1400017ea]:
    scopes = pa._addr_to_scopes.get(addr, [])
    inner = pa._find_innermost_scope(addr)
    print(f"\n  {hex(addr)}: scopes={[ (hex(s.jcc_addr), hex(s.merge_addr)) for s in scopes ]} innermost={hex(inner.jcc_addr) if inner else None}")
    if inner:
        in_taken = pa._in_taken_path(addr, inner)
        print(f"    in_taken={in_taken} target={hex(inner.target)} ft={hex(inner.fallthrough)} merge={hex(inner.merge_addr)}")
