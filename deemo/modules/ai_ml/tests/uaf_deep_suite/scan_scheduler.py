# UAF深度套件——扫描调度模块
# 用BinaryScanner(含跨函数地图)扫描, 统计uaf_confirmed/likely/cross_func
import json
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

BASE = Path(__file__).parent.parent.parent
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

BUILD_ROOT = Path(__file__).parent / "build"
OUT_JSON = Path(__file__).parent / "scan_results.json"


@dataclass
class UafScan:
    sample: str
    opt: str
    detected: bool
    uaf_cross: int = 0
    uaf_confirmed: int = 0
    uaf_likely: int = 0
    time_ms: float = 0.0
    reasons: list = field(default_factory=list)
    error: str = ""


def scan_binary(exe: Path) -> UafScan:
    from src.detect.binary_scanner import BinaryScanner
    sample = exe.stem.rsplit("_", 1)[0]
    opt = exe.stem.rsplit("_", 1)[-1]
    t0 = time.perf_counter()
    try:
        rep = BinaryScanner().scan_binary(str(exe))
        reasons = [f["reason"][:80] for f in rep.findings
                   if f["combined"].startswith("uaf")]
        det = (rep.uaf_confirmed > 0 or rep.uaf_likely > 0
               or rep.uaf_cross_func > 0)
        return UafScan(sample=sample, opt=opt, detected=det,
                       uaf_cross=rep.uaf_cross_func,
                       uaf_confirmed=rep.uaf_confirmed,
                       uaf_likely=rep.uaf_likely,
                       time_ms=(time.perf_counter() - t0) * 1000,
                       reasons=reasons)
    except Exception as e:
        return UafScan(sample=sample, opt=opt, detected=False,
                       error=str(e)[:200])


def main() -> int:
    if not BUILD_ROOT.exists():
        print("[uaf scan] 无编译产物, 先运行 compile_samples.py")
        return 1
    results = []
    for exe in sorted(BUILD_ROOT.glob("*.exe")):
        r = scan_binary(exe)
        st = "DETECTED" if r.detected else "clean"
        print(f"  {exe.stem}: {st} ({r.time_ms:.0f}ms)")
        results.append(r)
    OUT_JSON.write_text(
        json.dumps([asdict(r) for r in results], indent=2), encoding="utf-8")
    print(f"[uaf scan] {len(results)} 样本 → {OUT_JSON}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
