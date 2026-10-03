# UAF 多工具对比主实验 - 统一 CSV 基准测试.
#
# 决策逻辑:
#   对 regression_uaf/build 下全部编译产物运行三类工具:
#     BinMind-UAF-ULPR (本工作, 含生命周期来源复核)
#     BinMind-UAF-Base  (同管线, 关闭 ULPR)
#     angr-uaf         (CFG 层 free->use 模式探测)
#   输出 eval/results/uaf_benchmark.csv 与 uaf_benchmark.json,
#   含: 工具名、样本ID、优化档、检出数、误报数、漏报数、耗时、峰值内存.
#

import csv
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BUILD = ROOT.parent / "regression_uaf" / "build"
RESULTS_DIR = ROOT / "results"


def _ensure_paths():
    deemo = ROOT.parent.parent.parent
    for p in (str(deemo), str(deemo.parent), str(ROOT.parent),
              str(ROOT.parent / "regression_uaf")):
        if p not in sys.path:
            sys.path.insert(0, p)


def run_binmind_uaf(binary, use_ulp: bool):
    from modules.analysis.static.disasm_util import disassemble_binary
    from modules.analysis.static.import_resolver import resolve_call_targets
    from modules.analysis.static.uaf_detect import UAFDetector
    t0 = time.perf_counter()
    instructions, fmt, _m, ranges = disassemble_binary(binary)
    if not instructions:
        return [], 0.0, "disasm failed"
    instructions = resolve_call_targets(binary, instructions, fmt)
    det = UAFDetector(use_win64_abi=("pei" in fmt.lower()))
    det.set_user_func_ranges(ranges)
    det._ulp_enabled = use_ulp
    det.pre_analyze(instructions)
    for ins in instructions:
        det.analyze_instruction(ins)
    confirmed = det.finalize(instructions)
    return confirmed, (time.perf_counter() - t0) * 1000, ""


def collect_binaries() -> list:
    manifest_path = BUILD / "manifest_build.json"
    if not manifest_path.exists():
        print(f"build manifest not found: {manifest_path}. "
              "Run regression_uaf/compile_uaf.py first.")
        return []
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    items = []
    for sample in manifest:
        for opt in ("O0", "O2"):
            rec = sample.get(f"compiled_{opt}", {})
            binary = rec.get("binary", "")
            if rec.get("compiled") and os.path.exists(binary):
                items.append({"binary": binary, "sample": sample["sample_id"],
                              "opt": opt, "gt": sample["ground_truth"]})
    return items


def _classify(gt: str, detected: bool) -> str:
    if gt == "vulnerable":
        return "TP" if detected else "FN"
    return "FP" if detected else "TN"


def main():
    _ensure_paths()
    items = collect_binaries()
    if not items:
        return

    from eval.angr_explorer import explore_uaf, angr_available
    _angr_ok = angr_available()

    rows = []
    for i, it in enumerate(items, 1):
        binary = it["binary"]
        print(f"[{i}/{len(items)}] {it['sample']} {it['opt']}")
        for tool, use_ulp in (("BinMind-UAF-ULPR", True),
                              ("BinMind-UAF-Base", False)):
            confirmed, elapsed, error = run_binmind_uaf(binary, use_ulp)
            # 度量口径: ULPR 启用时仅 ulp_verdict=confirmed 计入检出.
            detected = any(
                f.get("type") == "use_after_free" and
                (not use_ulp or f.get("ulp_verdict") == "confirmed")
                for f in confirmed)
            rows.append({
                "tool": tool, "sample": it["sample"], "opt": it["opt"],
                "ground_truth": it["gt"], "detected": detected,
                "confirmed": len(confirmed),
                "verdict": _classify(it["gt"], detected),
                "time_ms": round(elapsed, 2),
                "error": error,
            })
        if _angr_ok:
            from eval.angr_explorer import explore_uaf as _e
            res = _e(binary)
            detected = res["detected"]
            rows.append({
                "tool": "angr-uaf", "sample": it["sample"], "opt": it["opt"],
                "ground_truth": it["gt"], "detected": detected,
                "confirmed": len(res["findings"]),
                "verdict": _classify(it["gt"], detected),
                "time_ms": round(res["elapsed_ms"], 2),
                "error": res["error"],
            })
        else:
            rows.append({
                "tool": "angr-uaf", "sample": it["sample"], "opt": it["opt"],
                "ground_truth": it["gt"], "detected": False,
                "confirmed": 0, "verdict": "NA",
                "time_ms": 0.0, "error": "angr not installed",
            })

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    csv_path = RESULTS_DIR / "uaf_benchmark.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["tool", "sample_id", "opt", "ground_truth", "detected",
                    "confirmed_count", "verdict", "time_ms", "error"])
        for r in rows:
            w.writerow([r["tool"], r["sample"], r["opt"], r["ground_truth"],
                        "Y" if r["detected"] else "N", r["confirmed"],
                        r["verdict"], r["time_ms"], r["error"]])
    (RESULTS_DIR / "uaf_benchmark.json").write_text(
        json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nuaf_benchmark.csv -> {csv_path} ({len(rows)} rows)")


if __name__ == "__main__":
    main()
