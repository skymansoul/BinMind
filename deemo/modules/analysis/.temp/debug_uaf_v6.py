"""调试 different_object 和 early_return_guard 的UAF检测."""
import sys, subprocess
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind\deemo")
from modules.analysis.static.uaf_detect import UAFDetector

def disasm(binary):
    out = subprocess.run(["objdump", "-d", "-M", "intel", binary],
                         capture_output=True, text=True, timeout=30).stdout
    insns = []
    for line in out.split("\n"):
        parts = line.strip().split("\t")
        if len(parts) >= 3:
            try:
                addr = int(parts[0].strip().rstrip(":"), 16)
                mnem_parts = parts[2].split()
                mnem = mnem_parts[0] if mnem_parts else ""
                ops = [o.strip() for o in " ".join(mnem_parts[1:]).split(",") if o.strip()] if len(mnem_parts) > 1 else []
                insns.append({"address": addr, "mnemonic": mnem, "operands": ops})
            except ValueError:
                pass
    return insns

# Test different_object
print("=== different_object_vuln ===")
insns = disasm(r"C:\Users\Administrator\Desktop\BinMind\deemo\modules\analysis\benchmark\samples_uaf_safe\build\different_object_vuln_O0.exe")
det = UAFDetector(use_win64_abi=True)
det.pre_analyze(insns)
for ins in insns:
    det.analyze_instruction(ins)
findings = det.finalize(insns)
print(f"  Findings: {len(findings)}")
for f in findings:
    print(f"    {f}")
print(f"  Stats: {det.stats()}")
print(f"  Objects: {det._objects}")
print(f"  Reg->Obj: {det._reg_to_obj}")

# Test early_return_guard
print("\n=== early_return_guard_vuln ===")
insns2 = disasm(r"C:\Users\Administrator\Desktop\BinMind\deemo\modules\analysis\benchmark\samples_uaf_safe\build\early_return_guard_vuln_O0.exe")
det2 = UAFDetector(use_win64_abi=True)
det2.pre_analyze(insns2)
for ins in insns2:
    det2.analyze_instruction(ins)
findings2 = det2.finalize(insns2)
print(f"  Findings: {len(findings2)}")
for f in findings2:
    print(f"    {f}")
print(f"  Stats: {det2.stats()}")

# Check path analyzer scopes
print(f"\n  Path scopes: {len(det2._path_analyzer._scopes)}")
for s in det2._path_analyzer._scopes:
    print(f"    jcc=0x{s.jcc_addr:x} target=0x{s.target:x} ft=0x{s.fallthrough:x} merge=0x{s.merge_addr:x}")
