import sys
sys.path.insert(0, r'C:\Users\Administrator\Desktop\BinMind\deemo')
from modules.analysis.static.uaf_detect import UAFDetector
from modules.analysis.eval.batch_test_uaf import _disassemble

binary = r'C:\Users\Administrator\Desktop\BinMind\deemo\modules\analysis\eval\build_tmp_uaf\cve_2018_7566_alsa_O2.exe'
insns = _disassemble(binary)

det = UAFDetector(use_win64_abi=True)
det.pre_analyze(insns)
for ins in insns:
    det.analyze_instruction(ins)
findings = det.finalize(insns)

print(f"Findings: {len(findings)}")
for f in findings:
    print(f"  type={f['type']} addr={hex(f['address'])} obj_id={f.get('obj_id')} freed_at={hex(f.get('freed_at',0))}")
print(f"Stats: {det.stats()}")
