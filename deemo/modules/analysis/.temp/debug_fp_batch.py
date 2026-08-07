import sys
sys.path.insert(0, r'C:\Users\Administrator\Desktop\BinMind\deemo')
from modules.analysis.static.uaf_detect import UAFDetector
from modules.analysis.eval.batch_test_uaf import _disassemble

samples = [
    ("different_object_safe_O0", r'C:\Users\Administrator\Desktop\BinMind\deemo\modules\analysis\benchmark\samples_uaf_safe\build\different_object_safe_O0.exe'),
    ("conditional_mutual_ex_safe_O0", r'C:\Users\Administrator\Desktop\BinMind\deemo\modules\analysis\benchmark\samples_uaf_safe\build\conditional_mutual_ex_safe_O0.exe'),
    ("conditional_mutual_ex_vuln_O2", r'C:\Users\Administrator\Desktop\BinMind\deemo\modules\analysis\benchmark\samples_uaf_safe\build\conditional_mutual_ex_vuln_O2.exe'),
    ("conditional_mutual_ex_vuln_Os", r'C:\Users\Administrator\Desktop\BinMind\deemo\modules\analysis\benchmark\samples_uaf_safe\build\conditional_mutual_ex_vuln_Os.exe'),
]

for name, binary in samples:
    try:
        insns = _disassemble(binary)
        if not insns:
            print(f"=== {name}: NO INSTRUCTIONS ===")
            continue
    except Exception as e:
        print(f"=== {name}: ERROR {e} ===")
        continue
    
    det = UAFDetector(use_win64_abi=True)
    det.pre_analyze(insns)
    for ins in insns:
        det.analyze_instruction(ins)
    
    raw = list(det._findings)
    findings = det.finalize(insns)
    
    print(f"=== {name}: raw={len(raw)} final={len(findings)} ===")
    for f in findings:
        print(f"  type={f['type']} addr={hex(f['address'])} obj_id={f.get('obj_id')} freed_at={hex(f.get('freed_at',0))}")
    for oid, obj in det._objects.items():
        print(f"  obj{oid}: alloc={hex(obj.alloc_addr)} freed={[hex(a) for a in obj.freed_at]} nulled={obj.nulled_after_free} nulled_at={obj.nulled_at and hex(obj.nulled_at)}")
