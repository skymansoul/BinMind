import sys
sys.path.insert(0, r'C:\Users\Administrator\Desktop\BinMind\deemo')
from modules.analysis.static.uaf_path_analyzer import PathAnalyzer
from modules.analysis.eval.batch_test_uaf import _disassemble

binary = r'C:\Users\Administrator\Desktop\BinMind\deemo\modules\analysis\benchmark\samples_uaf_safe\build\struct_field_safe_O0.exe'
insns = _disassemble(binary)
pa = PathAnalyzer()
pa.build_scope_map(insns)

# 打印所有scope
for s in pa._scopes:
    print(f"jcc@{hex(s.jcc_addr)} target={hex(s.target)} ft={hex(s.fallthrough)} merge={hex(s.merge_addr)} "
          f"taken_range=({hex(s.taken_range[0])},{hex(s.taken_range[1])}) "
          f"ft_range=({hex(s.fallthrough_range[0])},{hex(s.fallthrough_range[1])})")

# 检查double_free判定
print()
first_free = 0x1400017b6
second_free = 0x1400017e9
third_free = 0x1400017f5

print(f"are_mutually_exclusive({hex(first_free)}, {hex(second_free)}): {pa.are_mutually_exclusive(first_free, second_free)}")
print(f"are_mutually_exclusive({hex(first_free)}, {hex(third_free)}): {pa.are_mutually_exclusive(first_free, third_free)}")
print(f"are_mutually_exclusive({hex(second_free)}, {hex(third_free)}): {pa.are_mutually_exclusive(second_free, third_free)}")

# 检查每个地址的scope
for addr in [first_free, second_free, third_free]:
    scopes = pa._addr_to_scopes.get(addr, [])
    print(f"\naddr {hex(addr)}: {len(scopes)} scopes")
    for s in scopes:
        in_taken = PathAnalyzer._in_taken_path(addr, s)
        print(f"  jcc@{hex(s.jcc_addr)} target={hex(s.target)} ft={hex(s.fallthrough)} merge={hex(s.merge_addr)} in_taken={in_taken}")
