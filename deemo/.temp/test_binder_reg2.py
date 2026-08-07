import sys, os, subprocess, re
sys.path.insert(0, r'C:\Users\Administrator\Desktop\BinMind\deemo')

from modules.analysis.static.uaf_pre_analyzer import UAFPreAnalyzer

def _disassemble(binary_path):
    out = subprocess.run(
        ["objdump", "-d", "-M", "intel", binary_path],
        capture_output=True, text=True, timeout=30
    ).stdout
    insns = []
    for line in out.split("\n"):
        parts = line.strip().split("\t")
        if len(parts) < 3:
            continue
        try:
            addr = int(parts[0].strip().rstrip(":"), 16)
            mnem_part = parts[2].split()
            mnem = mnem_part[0] if mnem_part else ""
            ops = []
            if len(mnem_part) > 1:
                for o in " ".join(mnem_part[1:]).split(","):
                    ops.append(o.strip())
            insns.append({"address": addr, "mnemonic": mnem, "operands": ops})
        except (ValueError, IndexError):
            continue
    return insns

path = r"C:\Users\Administrator\Desktop\BinMind\deemo\modules\analysis\eval\build_tmp_uaf\reg_cve_2019_2215_binder_uaf_O2.exe"
instructions = _disassemble(path)

pa = UAFPreAnalyzer()
pa.analyze_from_instructions(instructions)

print(f"user_func_ranges: {[(hex(a), hex(b)) for a, b in pa.user_func_ranges]}")
print(f"user_func_addrs: {[hex(a) for a in sorted(pa._user_func_addrs)]}")
print(f"all_func_starts: {[hex(a) for a in sorted(pa._all_func_starts)]}")

# Check which called functions are considered user vs CRT
for ins in instructions:
    if ins.get("mnemonic") == "call" and ins.get("operands"):
        callee = ins["operands"][-1]
        name_match = re.search(r'<([^>]+)>', callee)
        if name_match:
            name = name_match.group(1).split("@")[0]
            if name in ("init", "cleanup", "use", "main"):
                print(f"  call to {name} at 0x{ins['address']:x} -> {callee}")
