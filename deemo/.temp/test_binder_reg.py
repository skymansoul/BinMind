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

path = r"C:\Users\Administrator\Desktop\BinMind\deemo\modules\analysis\eval\build_tmp_uaf\reg_cve_2019_2215_binder_uaf_O2.exe"
instructions = _disassemble(path)
det = UAFDetector(use_win64_abi=True)
det.pre_analyze(instructions)

print(f"user_func_ranges: {[(hex(a), hex(b)) for a, b in det._user_func_ranges]}")
print(f"ALLOC_FUNCS: {det.ALLOC_FUNCS}")

# Find malloc calls in user code
for i, ins in enumerate(instructions):
    mnem = ins.get("mnemonic", "").lower()
    ops = ins.get("operands", [])
    if mnem == "call" and ops:
        func = ops[0]
        if "malloc" in func.lower():
            addr = ins["address"]
            is_user = det._is_user_code(addr)
            print(f"  malloc call at 0x{addr:x} user={is_user} func={func}")
    if mnem == "call" and ops:
        func = ops[0]
        if "free" in func.lower() and "freedtoa" not in func.lower() and "Bfree" not in func.lower():
            addr = ins["address"]
            is_user = det._is_user_code(addr)
            print(f"  free call at 0x{addr:x} user={is_user} func={func}")

# Run analyze to see what happens
for ins in instructions:
    det.analyze_instruction(ins)
findings = det.finalize(instructions)
print(f"\nAfter full run: objects={len(det._objects)} findings={len(findings)}")
for oid, obj in det._objects.items():
    print(f"  obj {oid}: alloc=0x{obj.alloc_addr:x} freed_at={[hex(a) for a in obj.freed_at]}")
