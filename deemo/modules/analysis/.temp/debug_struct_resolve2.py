import sys
sys.path.insert(0, r'C:\Users\Administrator\Desktop\BinMind\deemo')
from modules.analysis.static.uaf_detect import UAFDetector
from modules.analysis.static.disasm_util import norm_reg
from modules.analysis.eval.batch_test_uaf import _disassemble

binary = r'C:\Users\Administrator\Desktop\BinMind\deemo\modules\analysis\benchmark\samples_uaf_safe\build\struct_field_safe_O0.exe'
insns = _disassemble(binary)

det = UAFDetector(use_win64_abi=True)
det.pre_analyze(insns)

# 跟踪关键地址的状态
watch_addrs = {0x14000176d, 0x140001772, 0x140001792, 0x1400017a6, 0x1400017c5, 0x1400017e2, 0x1400017e6, 0x1400017e9, 0x1400017ee, 0x1400017f2, 0x1400017f5}

for ins in insns:
    det.analyze_instruction(ins)
    a = ins['address']
    if a in watch_addrs:
        print(f"  {hex(a)}: {ins['mnemonic']} {ins['operands']}")
        print(f"    reg_to_obj: {dict((k,v) for k,v in det._reg_to_obj.items())}")
        print(f"    stack_to_obj: {dict(det._stack_to_obj)}")
        rcx_oid = det._reg_to_obj.get('rcx')
        if a == 0x1400017f5:
            resolved = det._resolve_free_arg(ins, a)
            print(f"    _resolve_free_arg(0x1400017f5) = {resolved}")
            # 手动回溯
            arg0 = det._arg_regs[0]
            print(f"    arg0={arg0}, reg_to_obj[{arg0}]={det._reg_to_obj.get(arg0)}")

print("\n=== Final objects ===")
for oid, obj in det._objects.items():
    print(f"  obj{oid}: alloc={hex(obj.alloc_addr)} freed={[hex(x) for x in obj.freed_at]}")
