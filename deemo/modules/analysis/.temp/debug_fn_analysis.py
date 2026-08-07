# FN根因分析调试脚本：追踪检测器内部状态
import sys, os, subprocess, json
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]  # modules/analysis/  (parents[0]=.temp, parents[1]=analysis)
_PROJECT_ROOT = BASE.parent.parent  # deemo/
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from modules.analysis.static.uaf_detect import UAFDetector
from modules.analysis.static.uaf_pre_analyzer import UAFPreAnalyzer
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
            insns.append({"address": addr, "mnemonic": mnem, "operands": ops})
        except:
            continue
    return insns


def trace_sample(name, binary_path):
    print(f"\n{'='*70}")
    print(f"FN样本: {name}")
    print(f"{'='*70}")

    insns = disasm(binary_path)
    if not insns:
        print("  反汇编失败")
        return

    # 标记函数边界
    pre = UAFPreAnalyzer()
    pre.analyze_from_instructions(insns)
    func_ranges = pre.user_func_ranges
    print(f"用户函数范围 ({len(func_ranges)}个):")
    for fr in func_ranges:
        print(f"  0x{fr[0]:x}-0x{fr[1]:x}")

    # 运行检测器
    detector = UAFDetector(use_win64_abi=True)
    detector.pre_analyze(insns)

    global_free_addrs = []
    for i, ins in enumerate(insns):
        # 手动检查free调用前的指令
        if ins["mnemonic"] == "call":
            for op in ins["operands"]:
                if "free" in str(op).lower() and "do_global" not in str(op).lower():
                    # 回溯看free的参数(rcx)
                    ctx_start = max(0, i - 6)
                    ctx = insns[ctx_start:i+1]
                    print(f"\n  free调用 @ 0x{ins['address']:x}:")
                    for c in ctx:
                        print(f"    0x{c['address']:x}: {c['mnemonic']:8s} {', '.join(c['operands'])}")
                    global_free_addrs.append(ins["address"])

    for ins in insns:
        detector.analyze_instruction(ins)

    findings = detector.finalize(insns)

    stats = detector.stats()
    print(f"\n检测器统计:")
    print(f"  objects_allocated: {stats['objects_allocated']}")
    print(f"  objects_freed: {stats['objects_freed']}")
    print(f"  uaf_detected: {stats['uaf_detected']}")
    print(f"  double_free_detected: {stats['double_free_detected']}")
    print(f"  findings: {len(findings)}")

    # 检查freed_objects
    if hasattr(detector, '_freed_objects'):
        print(f"\n  _freed_objects详情:")
        for k, v in detector._freed_objects.items():
            print(f"    {k}: {v}")

    # 检查object_map
    if hasattr(detector, '_objects'):
        print(f"\n  _objects详情:")
        for k, v in detector._objects.items():
            print(f"    {k}: {v}")

    # 检查interproc_free
    if hasattr(detector, '_interproc_free'):
        ipf = detector._interproc_free
        if hasattr(ipf, '_func_table'):
            print(f"\n  InterprocFree函数表:")
            for ft in ipf._func_table:
                print(f"    {ft}")
        if hasattr(ipf, '_summaries'):
            print(f"\n  InterprocFree摘要:")
            for k, v in ipf._summaries.items():
                print(f"    0x{k:x}: {v}")


# 6个FN样本
samples = [
    ("vmac", r"benchmark\samples_uaf\cve_2018_17182_vmac\cve_2018_17182_vmac_uaf_O0.exe"),
    ("alsa", r"benchmark\samples_uaf\cve_2018_7566_alsa\cve_2018_7566_alsa_uaf_O0.exe"),
    ("brcm", r"benchmark\samples_uaf\cve_2019_15291_brcm\cve_2019_15291_brcm_uaf_O0.exe"),
    ("binder_bench", r"benchmark\samples_uaf\cve_2019_2215_binder\cve_2019_2215_binder_uaf_O0.exe"),
    ("ebpf", r"benchmark\samples_uaf\cve_2021_34866_ebpf\cve_2021_34866_ebpf_uaf_O0.exe"),
]

for name, rel in samples:
    path = BASE / rel
    if path.exists():
        trace_sample(name, str(path))
    else:
        print(f"\n跳过 {name}: 文件不存在 {path}")

# regression binder
reg_path = BASE / "eval" / "build_tmp_uaf" / "reg_cve_2019_2215_binder_uaf_O0.exe"
if reg_path.exists():
    trace_sample("binder_reg", str(reg_path))
else:
    print(f"\n跳过 binder_reg: 文件不存在 {reg_path}")
