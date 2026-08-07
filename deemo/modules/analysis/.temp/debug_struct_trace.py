import sys, json
sys.path.insert(0, r'C:\Users\Administrator\Desktop\BinMind\deemo')
from modules.analysis.static.uaf_detect import UAFDetector
from modules.analysis.eval.batch_test_uaf import _disassemble

binary = r'C:\Users\Administrator\Desktop\BinMind\deemo\modules\analysis\benchmark\samples_uaf_safe\build\struct_field_safe_O0.exe'
insns = _disassemble(binary)
det = UAFDetector(use_win64_abi=True)
det.pre_analyze(insns)

trigger_start = 0x140001760
trigger_end = 0x1400017fe

for ins in insns:
    addr = ins.get("address", 0)
    if not (trigger_start <= addr <= trigger_end):
        det.analyze_instruction(ins)
        continue
    mnem = ins.get("mnemonic","")
    ops = ins.get("operands",[])
    print(f"\n--- {hex(addr)}: {mnem} {ops} ---")
    det.analyze_instruction(ins)
    print(f"  reg_to_obj: {dict(det._reg_to_obj)}")
    print(f"  stack_to_obj: {dict(det._stack_to_obj)}")
    print(f"  addr_to_obj: {{ {', '.join(f'{hex(k)}:{v}' for k,v in det._addr_to_obj.items())} }}")

print("\n=== OBJECTS ===")
for oid, obj in sorted(det._objects.items()):
    print(f"obj_id={oid} alloc@{hex(obj.alloc_addr)} freed_at={[hex(a) for a in obj.freed_at]} nulled={obj.nulled_after_free}")

print("\n=== FINDINGS (raw) ===")
for f in det._findings:
    print(f)

findings = det.finalize(insns)
print("\n=== FINDINGS (after finalize) ===")
print(json.dumps(findings, indent=2, default=str))
