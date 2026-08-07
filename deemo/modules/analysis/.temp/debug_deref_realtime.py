"""在 0x140001794 处检查 check_deref 调用时的实时状态."""
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

binary = r"C:\Users\Administrator\Desktop\BinMind\deemo\modules\analysis\benchmark\samples_uaf_safe\build\different_object_vuln_O0.exe"
insns = disasm(binary)

det = UAFDetector(use_win64_abi=True)
det.pre_analyze(insns)

# Monkey-patch DerefChecker.check_deref to add verbose logging
original_check_deref = det._deref_checker.check_deref
def logged_check_deref(ops, addr):
    if addr == 0x140001794:
        print(f"\n*** check_deref called at 0x{addr:x} ***")
        print(f"  ops = {ops}")
        print(f"  reg_to_obj = {dict(det._reg_to_obj)}")
        print(f"  objects = {[(oid, o.freed_at, o.nulled_after_free) for oid, o in det._objects.items()]}")
        # 模拟check_deref内部逻辑
        for op in ops:
            op_s = op.strip().lower()
            for prefix in det._deref_checker._PTR_PREFIXES:
                if op_s.startswith(prefix):
                    op_s = op_s[len(prefix):]
                    break
            if not (op_s.startswith("[") and "]" in op_s):
                continue
            inner = op_s[op_s.find("[") + 1:op_s.rfind("]")]
            base = inner.split("+")[0].split("-")[0].split("*")[0].strip()
            oid = det._reg_to_obj.get(base)
            print(f"  op='{op}' → base='{base}' oid={oid}")
            if oid is not None and oid in det._objects:
                obj = det._objects[oid]
                if obj.freed_at and not obj.nulled_after_free:
                    me = det._path_analyzer.are_mutually_exclusive(obj.freed_at[-1], addr)
                    print(f"  obj{oid} freed_at={obj.freed_at} → mutually_exclusive={me}")
    return original_check_deref(ops, addr)

det._deref_checker.check_deref = logged_check_deref

for ins in insns:
    det.analyze_instruction(ins)

findings = det.finalize(insns)
print(f"\nFindings: {findings}")
