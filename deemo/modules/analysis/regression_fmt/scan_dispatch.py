# fmt扫描调度 - 运行BinaryFmtDetector于单个二进制.

import sys
import time
from pathlib import Path

_BINMIND = Path(r"C:\Users\Administrator\Desktop\BinMind")
for p in (str(_BINMIND), str(_BINMIND / "deemo")):
    if p not in sys.path:
        sys.path.insert(0, p)


def scan_fmt(binary_path, use_win64_abi: bool = True) -> dict:
    from modules.analysis.static.disasm_util import disassemble_binary
    from modules.analysis.static.import_resolver import resolve_call_targets
    from modules.analysis.static.rodata_extract import extract_rodata_bytes
    from modules.analysis.static.fmt_binary_detect import BinaryFmtDetector

    t0 = time.perf_counter()
    instructions, fmt, main, ranges = disassemble_binary(binary_path)
    instructions = resolve_call_targets(binary_path, instructions, fmt)
    det = BinaryFmtDetector(use_win64_abi=use_win64_abi)
    det.set_rodata(extract_rodata_bytes(binary_path))
    det.set_user_ranges(ranges)
    findings = det.analyze(instructions)
    return {
        "count": len(findings),
        "findings": [dict(f) for f in findings],
        "time_ms": round((time.perf_counter() - t0) * 1000, 2),
        "types": sorted({f.get("type", "") for f in findings}),
    }


if __name__ == "__main__":
    import json
    r = scan_fmt(sys.argv[1])
    print({k: v for k, v in r.items() if k != "findings"})
    for f in r["findings"][:10]:
        print("  ", f.get("type"), f.get("severity"),
              str(f.get("reason", ""))[:50])
