# ebpf interproc_free摘要检查
import sys, subprocess
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
_PROJECT_ROOT = BASE.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from modules.analysis.static.uaf_detect import UAFDetector
from modules.analysis.static.uaf_interproc_free import InterprocFreeAnalyzer

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
            insns.append({"address": addr, "mnemonic": mnem, "operands": ops, "raw": parts[2].strip()})
        except:
            continue
    return insns

binary = str(BASE / "benchmark" / "samples_uaf" / "cve_2021_34866_ebpf" / "cve_2021_34866_ebpf_uaf_O0.exe")
insns = disasm(binary)

# 单独测试interproc
ipf = InterprocFreeAnalyzer(use_win64_abi=True)
ipf.build_summaries(insns, None)

print("InterprocFree摘要:")
for name, summary in ipf._summaries.items():
    print(f"  {name}: freed_params={summary.freed_params}, has_direct_free={summary.has_direct_free}, calls_free_like={summary.calls_free_like}")

print(f"\n_addr_to_name: {ipf._addr_to_name}")

# 检查cleanup函数
print(f"\nget_freed_params('v_2021_34866_ebpf_cleanup'): {ipf.get_freed_params('v_2021_34866_ebpf_cleanup')}")
print(f"is_free_like('v_2021_34866_ebpf_cleanup'): {ipf.is_free_like('v_2021_34866_ebpf_cleanup')}")

# 运行完整检测器
detector = UAFDetector(use_win64_abi=True)
detector.pre_analyze(insns)

for ins in insns:
    detector.analyze_instruction(ins)
    # 关键：检查v_2021_34866_ebpf_run中的call指令
    if ins.get("mnemonic") == "call" and ins.get("operands"):
        callee = ins["operands"][0]
        if "ebpf_cleanup" in callee or "ebpf_log" in callee:
            addr = ins["address"]
            rcx = detector._reg_to_obj.get("rcx", "-")
            obj = detector._objects.get(rcx) if rcx != "-" else None
            freed = obj.freed_at if obj else []
            print(f"\n0x{addr:x}: {ins['raw']}")
            print(f"  rcx={rcx}, obj.freed_at={freed}")
            fp = ipf.get_freed_params("v_2021_34866_ebpf_cleanup")
            print(f"  interproc cleanup freed_params={fp}")

findings = detector.finalize(insns)
stats = detector.stats()
print(f"\n最终: stats={stats}, findings={len(findings)}")
for k, v in detector._objects.items():
    print(f"  obj {k}: alloc=0x{v.alloc_addr:x}, freed_at={[hex(a) for a in v.freed_at]}, nulled={v.nulled_after_free}")
