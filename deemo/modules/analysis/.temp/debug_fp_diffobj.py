import sys
sys.path.insert(0, r'C:\Users\Administrator\Desktop\BinMind\deemo')
from modules.analysis.static.uaf_detect import UAFDetector
from modules.analysis.eval.batch_test_uaf import _disassemble

binary = r'C:\Users\Administrator\Desktop\BinMind\deemo\modules\analysis\benchmark\samples_uaf_safe\different_object\build\different_object_safe_O0.exe'
insns = _disassemble(binary)

det = UAFDetector(use_win64_abi=True)
det.pre_analyze(insns)
for ins in insns:
    det.analyze_instruction(ins)

print("=== Raw findings ===")
for f in det._findings:
    print(f"  type={f['type']} addr={hex(f['address'])} obj_id={f.get('obj_id')} freed_at={hex(f.get('freed_at',0))}")

findings = det.finalize(insns)
print(f"\n=== Finalized findings: {len(findings)} ===")
for f in findings:
    print(f"  type={f['type']} addr={hex(f['address'])} obj_id={f.get('obj_id')} freed_at={hex(f.get('freed_at',0))}")

print(f"\n=== Objects ===")
for oid, obj in det._objects.items():
    print(f"  obj {oid}: alloc={hex(obj.alloc_addr)} freed={[hex(a) for a in obj.freed_at]} nulled={obj.nulled_after_free} nulled_at={obj.nulled_at and hex(obj.nulled_at)}")
