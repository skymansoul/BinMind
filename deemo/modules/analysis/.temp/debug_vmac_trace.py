# vmac FN详细追踪：逐指令跟踪寄存器和对象状态
import sys, subprocess
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]  # modules/analysis/
_PROJECT_ROOT = BASE.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from modules.analysis.static.uaf_detect import UAFDetector
from modules.analysis.static.uaf_pre_analyzer import UAFPreAnalyzer

def disasm(binary):
    out = subprocess.run(["objdump", "-d", "-M", "intel", binary],
                         capture_output=True, text=True, timeout=30).stdout
    insns = []
    for line in out.split("\n"):
        parts = line.strip().split("\t")
        if len(parts) < 3:
            continue
        try:
            addr = int(parts[0].strip().rstrip(":"), 16)
            mp = parts[2].split()
            mnem = mp[0] if mp else ""
            ops = []
            if len(mp) > 1:
                for o in " ".join(mp[1:]).split(","):
                    ops.append(o.strip())
            insns.append({"address": addr, "mnemonic": mnem, "operands": ops,
                          "raw": parts[2].strip()})
        except:
            continue
    return insns

binary = str(BASE / "benchmark" / "samples_uaf" / "cve_2018_17182_vmac" / "cve_2018_17182_vmac_uaf_O0.exe")
insns = disasm(binary)

pre = UAFPreAnalyzer()
pre.analyze_from_instructions(insns)
ranges = pre.user_func_ranges

detector = UAFDetector(use_win64_abi=True)
detector.pre_analyze(insns)

# 跟踪用户函数范围
print(f"用户函数范围: {[(hex(lo), hex(hi)) for lo, hi in ranges]}")
print(f"detector._user_func_ranges: {[(hex(lo), hex(hi)) for lo, hi in detector._user_func_ranges]}")
print(f"_addr_to_obj初始: {dict(detector._addr_to_obj)}")
print()

# 只追踪用户函数范围内的指令
user_insns = [i for i in insns if detector._is_user_code(i.get("address", 0))]

for ins in user_insns:
    addr = ins["address"]
    mnem = ins.get("mnemonic", "")
    ops = ins.get("operands", [])
    raw = ins.get("raw", "")

    # 记录处理前状态
    rax = detector._reg_to_obj.get("rax", "-")
    rcx = detector._reg_to_obj.get("rcx", "-")
    addr_obj = dict(detector._addr_to_obj)

    detector.analyze_instruction(ins)

    # 记录处理后的状态变化
    new_rax = detector._reg_to_obj.get("rax", "-")
    new_rcx = detector._reg_to_obj.get("rcx", "-")
    new_addr_obj = dict(detector._addr_to_obj)

    changes = []
    if rax != new_rax:
        changes.append(f"rax: {rax} -> {new_rax}")
    if rcx != new_rcx:
        changes.append(f"rcx: {rcx} -> {new_rcx}")
    if addr_obj != new_addr_obj:
        changes.append(f"_addr_to_obj: {addr_obj} -> {new_addr_obj}")

    # 检查是否在关键指令
    is_key = mnem in ("call", "mov", "ret") and ("free" in raw or "malloc" in raw or "g_obj" in raw or "[rip" in raw)
    
    if changes or is_key:
        print(f"0x{addr:x}: {raw}")
        if changes:
            for c in changes:
                print(f"  -> {c}")
        # 检查free调用
        if mnem == "call" and ops:
            func_name = ops[0]
            if "free" in func_name.lower() or "malloc" in func_name.lower():
                freed_oid = None
                arg0 = detector._arg_regs[0]
                freed_oid = detector._reg_to_obj.get(arg0)
                print(f"  -> call {func_name}: arg0({arg0})={freed_oid}")
                # 检查_resolve_free_arg
                resolved = detector._resolve_free_arg(ins, addr)
                print(f"  -> _resolve_free_arg = {resolved}")
        print()

# 最终状态
stats = detector.stats()
print(f"\n最终统计: {stats}")
print(f"_addr_to_obj: {dict(detector._addr_to_obj)}")
print(f"_reg_to_obj: {dict(detector._reg_to_obj)}")
for k, v in detector._objects.items():
    print(f"  obj {k}: freed_at={[hex(a) for a in v.freed_at]}, nulled={v.nulled_after_free}")
