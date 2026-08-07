import sys, json
sys.path.insert(0, r'C:\Users\Administrator\Desktop\BinMind\deemo')
from modules.analysis.static.uaf_detect import UAFDetector
from modules.analysis.eval.batch_test_uaf import _disassemble

binary = r'C:\Users\Administrator\Desktop\BinMind\deemo\modules\analysis\benchmark\samples_uaf_safe\build\struct_field_safe_O0.exe'
insns = _disassemble(binary)
det = UAFDetector(use_win64_abi=True)
det.pre_analyze(insns)
for ins in insns:
    det.analyze_instruction(ins)
findings = det.finalize(insns)

# 打印对象状态
for oid, obj in sorted(det._objects.items()):
    print(f"obj_id={oid} alloc@{hex(obj.alloc_addr)} freed_at={[hex(a) for a in obj.freed_at]} nulled={obj.nulled_after_free}")
print()
print("findings:", json.dumps(findings, indent=2, default=str))
print()
# 追踪寄存器到对象的映射变化
# 找到关键地址范围
trigger_start = 0x140001760
trigger_end = 0x1400017fe
for ins in insns:
    addr = ins.get("address", 0)
    if trigger_start <= addr <= trigger_end:
        mnem = ins.get("mnemonic","")
        ops = ins.get("operands",[])
        print(f"{hex(addr)}: {mnem} {ops}")
