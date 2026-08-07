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

print("Snapshot size:", len(det._ins_snapshot))
print("Snapshot addr range:", hex(min(det._ins_snapshot.keys())), "to", hex(max(det._ins_snapshot.keys())))

# Check if 0x1400017e0 is in the original instructions
target = 0x1400017e0
found = [i for i in insns if i.get("address") == target]
print(f"\nInstruction at {hex(target)}: {found}")

# Find nearby snapshots
nearby = [a for a in sorted(det._ins_snapshot.keys()) if 0x140001760 <= a <= 0x1400017f0]
print(f"\nSnapshots in 0x140001760-0x1400017f0: {len(nearby)}")
for a in nearby:
    ins = det._ins_snapshot[a]
    print(f"  {hex(a)}: {ins.get('mnemonic','')} {ins.get('operands',[])}")

# Check the total number of instructions
print(f"\nTotal instructions: {len(insns)}")
