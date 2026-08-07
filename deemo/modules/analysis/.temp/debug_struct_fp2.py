import sys
sys.path.insert(0, r'C:\Users\Administrator\Desktop\BinMind\deemo')
from modules.analysis.static.uaf_detect import UAFDetector
from modules.analysis.eval.batch_test_uaf import _disassemble

binary = r'C:\Users\Administrator\Desktop\BinMind\deemo\modules\analysis\benchmark\samples_uaf_safe\build\struct_field_safe_O0.exe'
insns = _disassemble(binary)

det = UAFDetector(use_win64_abi=True)
det.pre_analyze(insns)
for ins in insns:
    det.analyze_instruction(ins)

raw = list(det._findings)
findings = det.finalize(insns)
print(f"raw={len(raw)} final={len(findings)}")
print(f"user_func_ranges: {[(hex(lo), hex(hi)) for lo, hi in det._user_func_ranges]}")

for f in raw:
    print(f"  RAW: type={f['type']} addr={hex(f['address'])} obj_id={f.get('obj_id')} freed_at={hex(f.get('freed_at',0))}")
for f in findings:
    print(f"  FINAL: type={f['type']} addr={hex(f['address'])} obj_id={f.get('obj_id')} freed_at={hex(f.get('freed_at',0))}")

for oid, obj in det._objects.items():
    print(f"  obj{oid}: alloc={hex(obj.alloc_addr)} freed={[hex(a) for a in obj.freed_at]} nulled={obj.nulled_after_free} nulled_at={obj.nulled_at and hex(obj.nulled_at)} uses={[hex(a) for a in obj.use_after_free_at]}")

# 看safe.c源码
import os
src = r'C:\Users\Administrator\Desktop\BinMind\deemo\modules\analysis\benchmark\samples_uaf_safe\struct_field\safe.c'
if os.path.exists(src):
    with open(src) as f:
        print(f"\n=== safe.c ===\n{f.read()}")
