import sys
sys.path.insert(0, r'C:\Users\Administrator\Desktop\BinMind\deemo')
from modules.analysis.static.uaf_global_free_scanner import GlobalFreeScanner
from modules.analysis.static.uaf_detect import UAFDetector
from modules.analysis.eval.batch_test_uaf import _disassemble

binary = r'C:\Users\Administrator\Desktop\BinMind\deemo\modules\analysis\eval\build_tmp_uaf\cve_2018_7566_alsa_O2.exe'
insns = _disassemble(binary)
det = UAFDetector(use_win64_abi=True)
det.pre_analyze(insns)
for ins in insns:
    det.analyze_instruction(ins)

print("Before finalize:")
for oid, obj in sorted(det._objects.items()):
    print(f"  obj_id={oid} alloc@{hex(obj.alloc_addr)} freed_at={[hex(a) for a in obj.freed_at]}")
print(f"  addr_to_obj: {{ {', '.join(f'{hex(k)}:{v}' for k,v in det._addr_to_obj.items())} }}")
print(f"  findings: {len(det._findings)}")

# Check global free scanner
scanner = GlobalFreeScanner(det)
global_findings = scanner.scan(insns)
print(f"\nGlobal free scanner findings: {len(global_findings)}")
for f in global_findings:
    print(f"  {f}")

# The path2 free at 0x1400017e0 — check if it's traced to g_buf
print("\nChecking free at 0x1400017e0:")
# Find the instruction
for idx, ins in enumerate(insns):
    if ins.get("address") == 0x1400017e0:
        print(f"  Found at instruction index {idx}")
        global_addr = scanner._trace_free_to_global(insns, idx, 0x1400017e0)
        print(f"  _trace_free_to_global: {hex(global_addr) if global_addr else None}")
        break
