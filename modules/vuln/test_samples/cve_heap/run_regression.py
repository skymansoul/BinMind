# coding: utf-8
#
"""
一键回归: compile → scan → collect → report。

用法:
  python run_regression.py            # 全流程
  python run_regression.py --quick    # 跳过编译
  python run_regression.py --json P   # 额外输出 benchmark JSON
"""

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

SAMPLE_DIR = Path(__file__).resolve().parent


def run_step(name: str, script: str) -> bool:
    p = SAMPLE_DIR / script
    if not p.exists():
        print(f"  [SKIP] {script} not found")
        return False
    print(f"\n===== {name} =====")
    r = subprocess.run([sys.executable, str(p)], cwd=str(SAMPLE_DIR))
    return r.returncode == 0


def main() -> int:
    ap = argparse.ArgumentParser(description="CVE heap one-click regression")
    ap.add_argument("--quick", action="store_true", help="skip compile")
    ap.add_argument("--json", type=str, default=None,
                    help="emit benchmark JSON")
    args = ap.parse_args()

    t0 = time.perf_counter()
    if not args.quick:
        if not run_step("Compile", "sample_compiler.py"):
            print("compile failed — abort")
            return 1
    if not run_step("Scan", "scan_scheduler.py"):
        print("scan failed — abort")
        return 1
    if not run_step("Collect", "result_collector.py"):
        return 1
    print(f"\nregression done in {time.perf_counter() - t0:.1f}s")

    if args.json:
        rep_file = SAMPLE_DIR / "regression_report.json"
        if rep_file.exists():
            rep = json.loads(rep_file.read_text(encoding="utf-8"))
            out = {
                "n_samples": rep["n_samples"],
                "metrics": {
                    "recall": rep["gasri"]["recall"],
                    "precision": rep["gasri"]["precision"],
                    "f1": rep["gasri"]["f1"],
                    "fpr": rep["gasri"]["fpr"],
                    "fp_reduction_pct": rep["fp_reduction_pct"],
                    "tp": rep["gasri"]["tp"], "tn": rep["gasri"]["tn"],
                    "fp": rep["gasri"]["fp"], "fn": rep["gasri"]["fn"],
                    "naive": rep["naive"],
                },
                "results": [
                    {"sample_id": s["sample_id"],
                     "expected": s.get("expected", ""),
                     "verdict": "TP" if s.get("detected") else "TN",
                     "detected": s.get("detected", False),
                     "elapsed_ms": s.get("gasri_ms", 0)}
                    for s in rep.get("results", [])
                ],
            }
            # results 不在 rep 中, 需另读 scan_results.json
            scan = json.loads((SAMPLE_DIR / "scan_results.json")
                              .read_text(encoding="utf-8"))
            out["results"] = [
                {"sample_id": r["sample_id"],
                 "expected": r.get("expected", ""),
                 "verdict": "TP" if r.get("detected") else "TN",
                 "detected": r.get("detected", False),
                 "elapsed_ms": r.get("gasri_ms", 0)}
                for r in scan
            ]
            Path(args.json).write_text(
                json.dumps(out, indent=2, ensure_ascii=False),
                encoding="utf-8")
            print(f"benchmark JSON: {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
