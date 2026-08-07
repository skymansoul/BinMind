"""调试 cross_function_vuln 的 interproc_free 摘要."""
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

binary = r"C:\Users\Administrator\Desktop\BinMind\deemo\modules\analysis\benchmark\samples_uaf_safe\build\cross_function_vuln_O0.exe"
insns = disasm(binary)

det = UAFDetector(use_win64_abi=True)
det.pre_analyze(insns)

# 检查 interproc_free 的摘要
ip = det._interproc
print("=== InterprocFree summaries ===")
print(f"  Summaries: {list(ip._summaries.keys())}")
for name, s in ip._summaries.items():
    print(f"  {name}: freed_params={s.freed_params} has_direct_free={s.has_direct_free} "
          f"calls_free_like={s.calls_free_like}")

# 检查 user func ranges
print(f"\n=== User func ranges ===")
for lo, hi in det._user_func_ranges:
    print(f"  [0x{lo:x}, 0x{hi:x})")

# 检查 cross_free 函数是否被识别
print(f"\n=== Checking cross_free detection ===")
print(f"  _addr_to_name: {ip._addr_to_name}")
print(f"  cross_free in summaries: {'cross_free' in ip._summaries}")

# 逐指令追踪 trigger_cross_vuln
func_insns = [i for i in insns if 0x14000177e <= i["address"] <= 0x1400017c0]
print(f"\n=== Tracing trigger_cross_vuln ({len(func_insns)} insns) ===")
for ins in func_insns:
    addr = ins["address"]
    mnem = ins["mnemonic"]
    ops = ins["operands"]
    det.analyze_instruction(ins)
    reg_obj = {k: v for k, v in det._reg_to_obj.items() if v is not None}
    addr_obj = dict(det._addr_to_obj) if det._addr_to_obj else {}
    ops_str = ", ".join(ops)
    print(f"  0x{addr:x} {mnem:6s} {ops_str:50s} reg={reg_obj} addr_obj={addr_obj} findings={len(det._findings)}")

findings = det.finalize(insns)
print(f"\n=== Findings: {len(findings)} ===")
for f in findings:
    print(f"  {f}")
print(f"\n=== Objects ===")
for oid, obj in det._objects.items():
    print(f"  obj{oid}: alloc=0x{obj.alloc_addr:x} freed={obj.freed_at} uaf={obj.use_after_free_at} nulled={obj.nulled_after_free}")
