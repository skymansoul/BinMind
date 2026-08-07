# 调试binder_uaf回归样本FN根因
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

detector = UAFDetector(use_win64_abi=True)
detector.pre_analyze(insns)

# 逐指令追踪关键状态
TARGET_RANGE = range(0x140001760, 0x140001820)

for ins in insns:
    addr = ins.get("address", 0)
    if addr not in TARGET_RANGE:
        detector.analyze_instruction(ins)
        continue

    # 记录状态前快照
    mnem = ins.get("mnemonic", "")
    ops = ins.get("operands", [])

    detector.analyze_instruction(ins)

    # 输出关键指令后的状态
    g_ptr_addr = 0x14000f080
    addr_map = detector._addr_to_obj.get(g_ptr_addr)
    reg_rcx = detector._reg_to_obj.get("rcx")
    reg_rax = detector._reg_to_obj.get("rax")

    # 找所有objects的freed_at
    freed_objs = {oid: {"freed_at": o.freed_at, "nulled": o.nulled_after_free,
                        "nulled_at": o.nulled_at}
                  for oid, o in detector._objects.items()}

    ops_str = ", ".join(ops) if ops else ""
    print(f"0x{addr:x} {mnem:8s} {ops_str:60s} | g_ptr→obj={addr_map} rcx={reg_rcx} rax={reg_rax}")
    if freed_objs:
        for oid, info in freed_objs.items():
            if info["freed_at"] or info["nulled"]:
                print(f"    obj#{oid}: freed_at={[hex(a) for a in info['freed_at']]} "
                      f"nulled={info['nulled']} nulled_at={hex(info['nulled_at']) if info['nulled_at'] else None}")

print("\n=== Findings ===")
for f in detector._findings:
    print(f"  {f}")
