import sys, os, subprocess
sys.path.insert(0, r'C:\Users\Administrator\Desktop\BinMind\deemo')

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

from modules.analysis.static.uaf_detect import UAFDetector

tests = [
    (r"benchmark\samples_uaf_safe\build\different_object_safe_O0.exe", "SAFE"),
    (r"benchmark\samples_uaf_safe\build\different_object_safe_O2.exe", "SAFE"),
    (r"benchmark\samples_uaf_safe\build\different_object_safe_Os.exe", "SAFE"),
    (r"benchmark\samples_uaf_safe\build\different_object_vuln_O0.exe", "UAF"),
    (r"benchmark\samples_uaf_safe\build\different_object_vuln_O2.exe", "UAF"),
    (r"benchmark\samples_uaf_safe\build\different_object_vuln_Os.exe", "UAF"),
    (r"eval\build_tmp_uaf\cve_2018_7566_alsa_O2.exe", "UAF"),
]

base = r"C:\Users\Administrator\Desktop\BinMind\deemo\modules\analysis"

for rel, expected in tests:
    path = os.path.join(base, rel)
    if not os.path.exists(path):
        print(f"SKIP {os.path.basename(path)}: not found")
        continue
    instructions = _disassemble(path)
    det = UAFDetector(use_win64_abi=True)
    det.pre_analyze(instructions)
    for ins in instructions:
        det.analyze_instruction(ins)
    findings = det.finalize(instructions)
    uaf = [f for f in findings if f.get("type") == "use_after_free"]
    result = "UAF" if uaf else "SAFE"
    ok = "OK" if result == expected else "*** FAIL ***"
    print(f"{ok} {os.path.basename(path)}: {result} ({len(uaf)} findings) expected={expected}")
    for f in uaf:
        print(f"  addr=0x{f['address']:x} freed_at=0x{f['freed_at']:x}")
