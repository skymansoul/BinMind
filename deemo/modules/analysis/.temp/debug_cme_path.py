import sys
sys.path.insert(0, r'C:\Users\Administrator\Desktop\BinMind\deemo')
from modules.analysis.static.uaf_path_analyzer import PathAnalyzer
from modules.analysis.eval.batch_test_uaf import _disassemble

binary = r'C:\Users\Administrator\Desktop\BinMind\deemo\modules\analysis\benchmark\samples_uaf_safe\build\conditional_mutual_ex_vuln_O2.exe'
insns = _disassemble(binary)
pa = PathAnalyzer()
pa.build_scope_map(insns)

# 打印trigger函数区域的scope
for s in pa._scopes:
    if 0x140001760 <= s.jcc_addr <= 0x1400017a0:
        print(f"jcc={hex(s.jcc_addr)} target={hex(s.target)} ft={hex(s.fallthrough)}")
        print(f"  merge={hex(s.merge_addr)} ret={s.ret_addr and hex(s.ret_addr)} jmp={s.jmp_addr and hex(s.jmp_addr)}")
        print(f"  taken_range=({hex(s.taken_range[0])}, {hex(s.taken_range[1])})")
        print(f"  fallthrough_range=({hex(s.fallthrough_range[0])}, {hex(s.fallthrough_range[1])})")

free_addr = 0x140001782
deref_addr = 0x14000178c
print(f"\nare_mutually_exclusive(free@{hex(free_addr)}, deref@{hex(deref_addr)}):",
      pa.are_mutually_exclusive(free_addr, deref_addr))

# 检查每个地址的scope
for a in (free_addr, deref_addr):
    scope = pa._find_innermost_scope(a)
    if scope:
        in_taken = pa._in_taken_path(a, scope)
        print(f"  {hex(a)}: scope.jcc={hex(scope.jcc_addr)} in_taken={in_taken}")
    else:
        print(f"  {hex(a)}: no scope")
