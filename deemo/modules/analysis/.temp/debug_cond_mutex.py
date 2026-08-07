"""验证 conditional_mutual_ex_safe 和 vuln 的检测."""
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

def test_binary(binary, label):
    insns = disasm(binary)
    det = UAFDetector(use_win64_abi=True)
    det.pre_analyze(insns)
    for ins in insns:
        det.analyze_instruction(ins)
    findings = det.finalize(insns)
    
    print(f"\n=== {label} ===")
    print(f"  Findings: {len(findings)}")
    for f in findings:
        print(f"    {f}")
    
    # 检查path analyzer的关键地址
    pa = det._path_analyzer
    if det._objects:
        for oid, obj in det._objects.items():
            if obj.freed_at and obj.use_after_free_at:
                free_a = obj.freed_at[-1]
                use_a = obj.use_after_free_at[-1]
                me = pa.are_mutually_exclusive(free_a, use_a)
                free_scope = pa._find_innermost_scope(free_a)
                use_scope = pa._find_innermost_scope(use_a)
                print(f"  obj{oid}: free=0x{free_a:x} use=0x{use_a:x} exclusive={me}")
                if free_scope:
                    print(f"    free_scope: jcc=0x{free_scope.jcc_addr:x} target=0x{free_scope.target:x} ft=0x{free_scope.fallthrough:x} merge=0x{free_scope.merge_addr:x}")
                if use_scope:
                    print(f"    use_scope: jcc=0x{use_scope.jcc_addr:x} target=0x{use_scope.target:x} ft=0x{use_scope.fallthrough:x} merge=0x{use_scope.merge_addr:x}")
    return len(findings)

base = r"C:\Users\Administrator\Desktop\BinMind\deemo\modules\analysis\benchmark\samples_uaf_safe\build"
safe_f = test_binary(f"{base}\\conditional_mutual_ex_safe_O0.exe", "SAFE")
vuln_f = test_binary(f"{base}\\conditional_mutual_ex_vuln_O0.exe", "VULN")

print(f"\n=== Result ===")
print(f"  safe: {safe_f} findings (expected 0)")
print(f"  vuln: {vuln_f} findings (expected 1)")
