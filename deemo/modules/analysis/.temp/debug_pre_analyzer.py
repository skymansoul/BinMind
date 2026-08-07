import sys
sys.path.insert(0, r'C:\Users\Administrator\Desktop\BinMind\deemo')
from modules.analysis.static.uaf_pre_analyzer import UAFPreAnalyzer
from modules.analysis.eval.batch_test_uaf import _disassemble

binary = r'C:\Users\Administrator\Desktop\BinMind\deemo\modules\analysis\benchmark\samples_uaf_safe\build\different_object_safe_O0.exe'
insns = _disassemble(binary)

pa = UAFPreAnalyzer()
pa.analyze_from_instructions(insns)

print("user_func_addrs:", [hex(a) for a in sorted(pa._user_func_addrs)])
print("user_func_ranges:", [(hex(lo), hex(hi)) for lo, hi in pa._user_func_ranges])

# 找出哪些call指令贡献了0x140003030附近的地址
for ins in insns:
    if ins.get("mnemonic") == "call" and ins.get("operands"):
        callee = ins["operands"][-1]
        try:
            addr_part = callee.split()[0]
            target = int(addr_part, 16)
            if 0x140003000 <= target <= 0x140003400:
                print(f"  call at {hex(ins['address'])}: target={hex(target)} callee={callee}")
        except (ValueError, IndexError):
            pass
