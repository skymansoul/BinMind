import sys
sys.path.insert(0, r'C:\Users\Administrator\Desktop\BinMind\deemo')
from modules.analysis.static.uaf_detect import UAFDetector
from modules.analysis.eval.batch_test_uaf import _disassemble

binary = r'C:\Users\Administrator\Desktop\BinMind\deemo\modules\analysis\benchmark\samples_uaf_safe\build\different_object_safe_O0.exe'
insns = _disassemble(binary)

det = UAFDetector(use_win64_abi=True)
det.pre_analyze(insns)
for ins in insns:
    det.analyze_instruction(ins)

print("user_func_ranges:", [(hex(lo), hex(hi)) for lo, hi in det._user_func_ranges])
print(f"is_user_code(0x14000304c): {det._is_user_code(0x14000304c)}")
print(f"is_crt_code(0x14000304c): {det._is_crt_code(0x14000304c)}")

# 看0x14000304c附近的指令
for ins in insns:
    if 0x140003040 <= ins['address'] <= 0x140003060:
        print(f"  {hex(ins['address'])}: {ins['mnemonic']} {ins['operands']}")
