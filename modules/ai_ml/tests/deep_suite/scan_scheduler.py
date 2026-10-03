# 深度样本扫描调度模块——对编译产物执行完整检测管线
# 输入: tests/deep_suite/build/*.exe; 输出: tests/deep_suite/scan_results.json
# 记录每个样本的检出状态/裁决/耗时/触发阶段(用于消融分析)

from __future__ import annotations

import json
import subprocess
import sys
import time
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import List, Dict

BASE = Path(__file__).parent.parent.parent
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))

BUILD_ROOT = Path(__file__).parent / "build"
OUT_JSON = Path(__file__).parent / "scan_results.json"

_HEAP_POS = ('confirmed', 'likely', 'new_finding', 'heap_cross_func')


@dataclass
class ScanOutcome:
    sample: str
    opt: str
    detected: bool
    verdicts: List[str] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)
    heap_reports: int = 0
    time_ms: float = 0.0
    error: str = ""


def scan_binary(exe_path: Path) -> ScanOutcome:
    from src.disasm.objdump_parser import ObjdumpParser
    from src.detect.pipeline_bridge import DetectionPipeline

    sample = exe_path.stem.rsplit("_", 1)[0]
    opt = exe_path.stem.rsplit("_", 1)[-1]
    t0 = time.perf_counter()
    try:
        r = subprocess.run(["objdump", "-d", "-M", "intel", str(exe_path)],
                           capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            return ScanOutcome(sample=sample, opt=opt, detected=False,
                               error="objdump_failed")
        funcs = ObjdumpParser()._parse_output(r.stdout)
        pipe = DetectionPipeline()
        verdicts: List[str] = []
        reasons: List[str] = []
        heap_pos = 0
        for fn in funcs:
            if len(fn.instructions) < 3:
                continue
            try:
                reps = pipe.scan_function(
                    fn.instructions, fn.bb_boundaries, fn.cfg_edges, fn.name)
            except Exception:
                continue
            for rep in reps:
                v = rep.combined_verdict.value
                verdicts.append(v)
                if v in _HEAP_POS:
                    heap_pos += 1
                reasons.append(f"{v}::{rep.reason[:160]}")
        detected = heap_pos > 0
        return ScanOutcome(sample=sample, opt=opt, detected=detected,
                           verdicts=verdicts, reasons=reasons,
                           heap_reports=heap_pos,
                           time_ms=(time.perf_counter() - t0) * 1000)
    except Exception as e:
        return ScanOutcome(sample=sample, opt=opt, detected=False,
                           error=str(e)[:200])


def main() -> int:
    if not BUILD_ROOT.exists():
        print("[scan_scheduler] 无编译产物, 请先运行 compile_samples.py")
        return 1
    exes = sorted(BUILD_ROOT.glob("*.exe"))
    results = []
    for exe in exes:
        r = scan_binary(exe)
        st = "DETECTED" if r.detected else "clean"
        print(f"  {exe.stem}: {st} ({r.time_ms:.1f}ms)")
        results.append(r)
    OUT_JSON.write_text(
        json.dumps([asdict(r) for r in results], indent=2), encoding="utf-8")
    print(f"\n[scan_scheduler] {len(results)} 个样本扫描完成 → {OUT_JSON}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
