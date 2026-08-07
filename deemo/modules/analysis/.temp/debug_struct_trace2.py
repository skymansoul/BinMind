import sys
sys.path.insert(0, r'C:\Users\Administrator\Desktop\BinMind\deemo')
from modules.analysis.eval.batch_test_uaf import _disassemble

binary = r'C:\Users\Administrator\Desktop\BinMind\deemo\modules\analysis\benchmark\samples_uaf_safe\build\struct_field_safe_O0.exe'
insns = _disassemble(binary)

# 打印 trigger 函数区的指令
for ins in insns:
    a = ins['address']
    if 0x140001760 <= a <= 0x140001820:
        print(f"  {hex(a)}: {ins['mnemonic']} {ins['operands']}")
