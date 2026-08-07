import sys
sys.path.insert(0, r'C:\Users\Administrator\Desktop\BinMind\deemo')
from modules.analysis.static.uaf_detect import UAFDetector

# Monkey-patch to add debug
original_resolve = UAFDetector._resolve_free_arg
def patched_resolve(self, ins, addr):
    result = original_resolve(self, ins, addr)
    if addr == 0x1400017e0:
        print(f"\n=== _resolve_free_arg at {hex(addr)} ===")
        print(f"  reg_to_obj: {dict(self._reg_to_obj)}")
        print(f"  result: {result}")
        print(f"  snapshot size: {len(self._ins_snapshot)}")
        print(f"  snapshot range: {hex(min(self._ins_snapshot.keys()))} - {hex(max(self._ins_snapshot.keys()))}")
        # Check what _trace_reg_chain finds
        rcx_val = self._reg_to_obj.get('rcx')
        print(f"  rcx in reg_to_obj: {rcx_val}")
        # Check if 0x1400017d8 is in snapshot
        for a in [0x1400017d8, 0x1400017db, 0x1400017d4, 0x1400017b1, 0x14000176c]:
            ins_at = self._ins_snapshot.get(a)
            if ins_at:
                print(f"  snapshot[{hex(a)}]: {ins_at.get('mnemonic','')} {ins_at.get('operands',[])}")
            else:
                print(f"  snapshot[{hex(a)}]: NOT IN SNAPSHOT")
    return result
UAFDetector._resolve_free_arg = patched_resolve

original_handle_call = UAFDetector._handle_call
def patched_handle_call(self, ins, ops, addr):
    if addr == 0x1400017e0:
        print(f"\n=== _handle_call at {hex(addr)} ===")
        print(f"  ops: {ops}")
        print(f"  reg_to_obj before: {dict(self._reg_to_obj)}")
    original_handle_call(self, ins, ops, addr)
    if addr == 0x1400017e0:
        print(f"  reg_to_obj after: {dict(self._reg_to_obj)}")
UAFDetector._handle_call = patched_handle_call

from modules.analysis.eval.batch_test_uaf import _disassemble

binary = r'C:\Users\Administrator\Desktop\BinMind\deemo\modules\analysis\eval\build_tmp_uaf\cve_2018_7566_alsa_O2.exe'
insns = _disassemble(binary)
det = UAFDetector(use_win64_abi=True)
det.pre_analyze(insns)
for ins in insns:
    det.analyze_instruction(ins)

print("\n=== FINAL RESULTS ===")
for oid, obj in sorted(det._objects.items()):
    print(f"obj_id={oid} freed_at={[hex(a) for a in obj.freed_at]} nulled={obj.nulled_after_free}")
findings = det.finalize(insns)
print(f"Findings: {len(findings)}")
for f in findings:
    print(f)
