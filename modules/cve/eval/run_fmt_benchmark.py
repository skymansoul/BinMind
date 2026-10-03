# 格式化字符串多工具对比主实验 - 统一 CSV 基准测试.
#
# 决策逻辑:
#   对 regression_fmt/build 下全部编译产物运行三类工具:
#     BinMind-Fmt-FAPV  (本工作, 含格式串来源三级判定)
#     BinMind-Fmt-Base  (旧启发式: 格式串寄存器最后定义非字面量即告警)
#     angr-fmt         (CFG 层 printf 族调用探测)
#   输出 eval/results/fmt_benchmark.csv 与 fmt_benchmark.json.
#

import csv
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BUILD = ROOT.parent / "regression_fmt" / "build"
RESULTS_DIR = ROOT / "results"


def _ensure_paths():
    deemo = ROOT.parent.parent.parent
    for p in (str(deemo), str(deemo.parent), str(ROOT.parent),
              str(ROOT.parent / "regression_fmt")):
        if p not in sys.path:
            sys.path.insert(0, p)


def run_binmind_fmt(binary, enhanced: bool):
    from regression_fmt.scan_fmt import scan_binary_fmt
    t0 = time.perf_counter()
    verdicts, bdet, edet, err = scan_binary_fmt(binary)
    detected = edet if enhanced else bdet
    return detected, (time.perf_counter() - t0) * 1000, err


def collect_binaries() -> list:
    manifest_path = BUILD / "manifest_build.json"
    if not manifest_path.exists():
        print(f"build manifest not found: {manifest_path}. "
              "Run regression_fmt/compile_fmt.py first.")
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
    from eval.angr_explorer import explore_fmt, angr_available
    _angr_ok = angr_available()

    rows = []
    for i, it in enumerate(items, 1):
        binary = it["binary"]
        print(f"[{i}/{len(items)}] {it['sample']} {it['opt']}")
        for tool, enhanced in (("BinMind-Fmt-FAPV", True),
                               ("BinMind-Fmt-Base", False)):
            detected, elapsed, err = run_binmind_fmt(binary, enhanced)
            rows.append({
                "tool": tool, "sample": it["sample"], "opt": it["opt"],
                "ground_truth": it["gt"], "detected": detected,
                "confirmed": 1 if detected else 0,
                "verdict": _classify(it["gt"], detected),
                "time_ms": round(elapsed, 2), "error": err,
            })
        if _angr_ok:
            res = explore_fmt(binary)
            detected = res["detected"]
            rows.append({
                "tool": "angr-fmt", "sample": it["sample"], "opt": it["opt"],
                "ground_truth": it["gt"], "detected": detected,
                "confirmed": len(res["findings"]),
                "verdict": _classify(it["gt"], detected),
                "time_ms": round(res["elapsed_ms"], 2),
                "error": res["error"],
            })
        else:
            rows.append({
                "tool": "angr-fmt", "sample": it["sample"], "opt": it["opt"],
                "ground_truth": it["gt"], "detected": False,
                "confirmed": 0, "verdict": "NA",
                "time_ms": 0.0, "error": "angr not installed",
            })

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    csv_path = RESULTS_DIR / "fmt_benchmark.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["tool", "sample_id", "opt", "ground_truth", "detected",
                    "confirmed_count", "verdict", "time_ms", "error"])
        for r in rows:
            w.writerow([r["tool"], r["sample"], r["opt"], r["ground_truth"],
                        "Y" if r["detected"] else "N", r["confirmed"],
                        r["verdict"], r["time_ms"], r["error"]])
    (RESULTS_DIR / "fmt_benchmark.json").write_text(
        json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nfmt_benchmark.csv -> {csv_path} ({len(rows)} rows)")


if __name__ == "__main__":
    main()
