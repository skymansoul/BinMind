# FP调试：追踪3个safe样本的findings来源
import sys, subprocess
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
_PROJECT_ROOT = BASE.parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from modules.analysis.static.uaf_detect import UAFDetector

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

samples = [
    ("reassign_safe", str(BASE / "benchmark" / "samples_uaf_safe" / "build" / "reassign_after_free_safe_O0.exe")),
    ("struct_field_safe", str(BASE / "benchmark" / "samples_uaf_safe" / "build" / "struct_field_safe_O0.exe")),
    ("early_return_safe", str(BASE / "benchmark" / "samples_uaf_safe" / "build" / "early_return_guard_safe_O0.exe")),
]

for name, path in samples:
    print(f"\n{'='*60}")
    print(f"FP样本: {name}")
    print(f"{'='*60}")
    insns = disasm(path)
    detector = UAFDetector(use_win64_abi=True)
    detector.pre_analyze(insns)
    for ins in insns:
        detector.analyze_instruction(ins)
    findings = detector.finalize(insns)
    print(f"  findings={len(findings)}")
    for f in findings:
        print(f"    {f}")
    for k, v in detector._objects.items():
        print(f"  obj {k}: alloc=0x{v.alloc_addr:x}, freed_at={[hex(a) for a in v.freed_at]}, nulled={v.nulled_after_free}, use_at={[hex(a) for a in v.use_after_free_at]}")
    print(f"  _addr_to_obj: {dict(detector._addr_to_obj)}")
