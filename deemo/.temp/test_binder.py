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
    r"eval\build_tmp_uaf\cve_2019_2215_binder_O2.exe",
    r"eval\build_tmp_uaf\cve_2019_2215_binder_Os.exe",
    r"eval\build_tmp_uaf\reg_cve_2019_2215_binder_uaf_O2.exe",
]

base = r"C:\Users\Administrator\Desktop\BinMind\deemo\modules\analysis"

for rel in tests:
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
    df = [f for f in findings if f.get("type") == "double_free"]
    print(f"\n{os.path.basename(path)}:")
    print(f"  UAF={len(uaf)} DF={len(df)} user_funcs={len(det._user_func_ranges)}")
    print(f"  objects={len(det._objects)}")
    for oid, obj in det._objects.items():
        print(f"    obj {oid}: alloc=0x{obj.alloc_addr:x} freed_at={[hex(a) for a in obj.freed_at]}")
    for f in findings:
        print(f"  {f.get('type')}: addr=0x{f['address']:x} freed_at=0x{f.get('freed_at',0):x}")
