# 精确追踪binder_uaf Phase3的deref_checker扫描
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
from modules.analysis.static.uaf_global_deref import GlobalDerefChecker

detector = UAFDetector(use_win64_abi=True)
detector.pre_analyze(insns)

for ins in insns:
    detector.analyze_instruction(ins)

# 找free地址
free_addr = 0x1400017aa
free_idx = None
for idx, ins in enumerate(insns):
    if ins.get("address") == free_addr:
        free_idx = idx
        break

print(f"Free at idx={free_idx}, addr=0x{free_addr:x}")

# 找start_idx (Phase3逻辑)
start_idx = None
for idx, ins in enumerate(insns):
    addr = ins.get("address", 0)
    if addr > free_addr and detector._is_user_code(addr):
        start_idx = idx
        break

print(f"start_idx={start_idx}, addr=0x{insns[start_idx]['address']:x}")

# 手动执行deref_checker的前50条
global_addr = 0x14000f080
oid = 1
checker = GlobalDerefChecker(detector)

loaded_reg = None
print(f"\nScanning from idx={start_idx} to {min(start_idx + 50, len(insns))}:")
for j in range(start_idx, min(start_idx + 50, len(insns))):
    ins = insns[j]
    mnem = ins.get("mnemonic", "").lower()
    ops = ins.get("operands", [])
    addr = ins.get("address", 0)
    user_code = detector._is_user_code(addr)

    if not user_code:
        print(f"  [{j}] 0x{addr:x} {mnem} {','.join(ops):50s} | NON-USER, skip")
        continue

    is_reassign = checker._is_reassign_to_new(insns, j, ins, ops, mnem, addr, global_addr, start_idx)
    new_loaded = checker._track_global_load(mnem, ops, addr, global_addr, loaded_reg)
    if new_loaded != loaded_reg:
        loaded_reg = new_loaded

    deref = checker._check_deref(mnem, ops, addr, loaded_reg)
    call_deref = checker._check_call_deref(mnem, ops, addr, loaded_reg)

    ops_str = ",".join(ops)
    print(f"  [{j}] 0x{addr:x} {mnem:8s} {ops_str:55s} | user={user_code} "
          f"loaded_reg={loaded_reg} reassign={is_reassign} deref={deref} call_deref={call_deref}")

    if is_reassign:
        print("    → STOP (reassign)")
        break
    if deref is not None:
        print(f"    → UAF at 0x{deref:x}")
        break
    if call_deref is not None:
        print(f"    → UAF via call at 0x{call_deref:x}")
        break

    if mnem == "ret":
        loaded_reg = None
        print("    → ret, clear loaded_reg")
