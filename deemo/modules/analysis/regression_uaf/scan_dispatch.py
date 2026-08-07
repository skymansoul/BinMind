# UAF扫描调度 — 运行UAFDetector于单个二进制.
# 复用堆回归的 disassemble_binary + resolve_call_targets 管线.
# 创建: 2026-07-13

import sys
import time
from pathlib import Path

_BINMIND = Path(r"C:\Users\Administrator\Desktop\BinMind")
for p in (str(_BINMIND), str(_BINMIND / "deemo")):
    if p not in sys.path:
        sys.path.insert(0, p)


def scan_uaf(binary_path, use_win64_abi: bool = True) -> dict:
    from modules.analysis.static.disasm_util import disassemble_binary
    from modules.analysis.static.import_resolver import resolve_call_targets
    from modules.analysis.static.uaf_detect import UAFDetector

    t0 = time.perf_counter()
    instructions, fmt, main, ranges = disassemble_binary(binary_path)
    instructions = resolve_call_targets(binary_path, instructions, fmt)
    det = UAFDetector(use_win64_abi=use_win64_abi)
    det.set_user_func_ranges(ranges)
    det.pre_analyze(instructions)
    for ins in instructions:
        det.analyze_instruction(ins)
    findings = det.finalize(instructions)
    elapsed = (time.perf_counter() - t0) * 1000
    return {
        "count": len(findings),
        "findings": [dict(f) for f in findings],
        "time_ms": round(elapsed, 2),
        "types": sorted({f.get("type", "") for f in findings}),
    }


if __name__ == "__main__":
    p = sys.argv[1]
    r = scan_uaf(p)
    print({k: v for k, v in r.items() if k != "findings"})
    for f in r["findings"][:10]:
        print("  ", f.get("type"), f.get("address"),
              (str(f.get("function", ""))[:30]))
