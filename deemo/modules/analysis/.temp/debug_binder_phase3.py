# 调试binder_uaf Phase3扫描
import sys, subprocess
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
_PROJECT_ROOT = BASE.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

binary = str(BASE / "eval" / "build_tmp_uaf" / "reg_cve_2019_2215_binder_uaf_O0.exe")

out = subprocess.run(
    ["objdump", "-d", "-M", "intel", binary],
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

from modules.analysis.static.uaf_detect import UAFDetector
from modules.analysis.static.uaf_global_free_scanner import GlobalFreeScanner

detector = UAFDetector(use_win64_abi=True)
detector.pre_analyze(insns)

for ins in insns:
    detector.analyze_instruction(ins)

# 检查finalize前的状态
g_ptr_addr = 0x14000f080
print("=== Before finalize ===")
print(f"_addr_to_obj has g_ptr: {g_ptr_addr in detector._addr_to_obj}")
for oid, obj in detector._objects.items():
    print(f"  obj#{oid}: alloc={hex(obj.alloc_addr)} freed_at={[hex(a) for a in obj.freed_at]} "
          f"nulled={obj.nulled_after_free} nulled_at={hex(obj.nulled_at) if obj.nulled_at else None}")
print(f"  _findings: {len(detector._findings)}")
for f in detector._findings:
    print(f"    {f}")

# 手动运行GlobalFreeScanner
print("\n=== GlobalFreeScanner Phase ===")
scanner = GlobalFreeScanner(detector)
global_findings = scanner.scan(insns)
print(f"  Global findings: {len(global_findings)}")
for f in global_findings:
    print(f"    {f}")

# 检查free_sites构建
print("\n=== Phase1: global_to_obj ===")
for k, v in scanner._det._addr_to_obj.items():
    print(f"  {hex(k)} → obj#{v}")

print("\n=== Phase2: free_sites ===")
# 重新执行scan逻辑来追踪
from modules.analysis.static.disasm_util import resolve_rip_relative, extract_func_name, norm_reg
FREE_FUNCS = {"free", "_ZdlPv", "_ZdaPv", "operator_delete", "g_free", "ExFreePool", "__builtin_free"}

for idx, ins in enumerate(insns):
    mnem = ins.get("mnemonic", "").lower()
    ops = ins.get("operands", [])
    addr = ins.get("address", 0)
    if mnem != "call" or not ops:
        continue
    callee = extract_func_name(ops[0])
    if callee not in FREE_FUNCS:
        continue
    if not detector._is_user_code(addr):
        continue
    print(f"  Free call at 0x{addr:x} (idx={idx})")
    global_addr = scanner._trace_free_to_global(insns, idx, addr)
    print(f"    global_addr: {hex(global_addr) if global_addr else None}")
    if global_addr is not None:
        oid = scanner._find_obj_at_free(insns, idx, global_addr)
        print(f"    obj_id: {oid}")
        if oid and oid in detector._objects:
            obj = detector._objects[oid]
            print(f"    obj freed_at: {[hex(a) for a in obj.freed_at]}")
            print(f"    obj nulled: {obj.nulled_after_free}")

print("\n=== Finalize ===")
final = detector.finalize(insns)
print(f"  Final findings: {len(final)}")
for f in final:
    print(f"    {f}")
