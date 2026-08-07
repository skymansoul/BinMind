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

addr = 0x1400017e0
print('Reg-to-obj at call free (0x1400017e0):', dict(det._reg_to_obj))
result = det._resolve_free_arg(det._ins_snapshot[addr], addr)
print('_resolve_free_arg result:', result)

result2 = det._trace_reg_chain('rcx', addr)
print('_trace_reg_chain rcx result:', result2)

for a in sorted(det._ins_snapshot.keys()):
    if 0x140001760 <= a <= 0x1400017f0:
        ins = det._ins_snapshot[a]
        mnem = ins.get("mnemonic","")
        ops = ins.get("operands",[])
        print(f"  {hex(a)}: {mnem} {ops}")
