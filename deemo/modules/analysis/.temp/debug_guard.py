"""验证 early_return_guard_vuln 修复后的检测."""
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

binary = r"C:\Users\Administrator\Desktop\BinMind\deemo\modules\analysis\benchmark\samples_uaf_safe\build\early_return_guard_vuln_O0.exe"
insns = disasm(binary)

det = UAFDetector(use_win64_abi=True)
det.pre_analyze(insns)

# 查找 trigger_guard_vuln 函数范围
out = subprocess.run(["objdump", "-d", "-M", "intel", binary],
                     capture_output=True, text=True, timeout=30).stdout
func_start = None
for line in out.split("\n"):
    if "trigger_guard_vuln" in line and "<" in line:
        import re
        m = re.search(r'^([0-9a-f]+)\s+<', line.strip())
        if m:
            func_start = int(m.group(1), 16)
            break

print(f"Function start: 0x{func_start:x}" if func_start else "Function not found")

func_insns = [i for i in insns if func_start and func_start <= i["address"] < func_start + 0x100]
print(f"Function instructions: {len(func_insns)}")

for ins in func_insns:
    addr = ins["address"]
    mnem = ins["mnemonic"]
    ops = ins["operands"]
    det.analyze_instruction(ins)
    reg_obj = {k: v for k, v in det._reg_to_obj.items() if v is not None}
    ops_str = ", ".join(ops)
    print(f"  0x{addr:x} {mnem:6s} {ops_str:45s} reg={reg_obj} findings={len(det._findings)}")

findings = det.finalize(insns)
print(f"\nFindings: {len(findings)}")
for f in findings:
    print(f"  {f}")

# 也检查 path_analyzer 的关键地址
pa = det._path_analyzer
print(f"\nPath scopes covering function area:")
for s in pa._scopes:
    if func_start and func_start <= s.jcc_addr < func_start + 0x100:
        ft_in_taken = pa._in_taken_path(s.fallthrough, s)
        print(f"  jcc=0x{s.jcc_addr:x} target=0x{s.target:x} ft=0x{s.fallthrough:x} merge=0x{s.merge_addr:x}")
        # 检查 free 和 use 地址
        if det._objects:
            for oid, obj in det._objects.items():
                if obj.freed_at:
                    me = pa.are_mutually_exclusive(obj.freed_at[-1], addr)
