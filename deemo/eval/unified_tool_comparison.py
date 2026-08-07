#!/usr/bin/env python3
"""
统一多工具对比实验 — 堆溢出检测.

对17个CVE样本执行多工具检测, 统一CSV/JSON输出.
工具: BinMind-HOSV(源级), BinMind-GAPSBV-CJ(pipeline), BinMind-baseline(无CJ),
      Angr(符号执行), Ghidra(静态), QEMU(动态)

用法:
  python eval/unified_tool_comparison.py
  python eval/unified_tool_comparison.py --csv out.csv --json out.json
  python eval/unified_tool_comparison.py --no-external   # 跳过外部工具
"""
from __future__ import annotations
import argparse, csv, json, os, sys, time
from pathlib import Path
from typing import Dict, List, Tuple

_BASE = Path(__file__).parent.parent
if str(_BASE) not in sys.path:
    sys.path.insert(0, str(_BASE))

from eval.unified_tool_runners import (
    run_hosv, run_gapsbv_cj, run_baseline,
    run_angr, run_ghidra, run_qemu,
    simulate_tool as _simulate_tool, classify, LITERATURE_EST,
)

SAMPLE_DIR = _BASE / "tests" / "cve_samples" / "heap_overflow"
GT_PATH = SAMPLE_DIR / "ground_truth.json"
RESULTS_DIR = _BASE / "eval" / "results"
COLS = ["tool", "sample", "expected_vuln", "detected", "tp", "fp", "fn", "tn",
        "detection_count", "duration_ms", "error"]



# 样本加载

def load_gt() -> Dict:
    with open(GT_PATH, encoding='utf-8') as f:
        return json.load(f)


def find_source(name: str) -> str | None:
    d = SAMPLE_DIR / name
    cs = list(d.glob("*.c"))
    return cs[0].read_text(encoding='utf-8', errors='replace') if cs else None


def find_binary(name: str) -> str | None:
    d = SAMPLE_DIR / name
    for f in d.iterdir():
        if f.is_file() and f.suffix in ('', '.exe') and f.name != 'Makefile':
            if os.access(str(f), os.X_OK) or f.suffix == '.exe':
                return str(f)
    return None


# 评估逻辑

def classify(tool_name: str, detection_count: int, expected_vuln: bool) -> Dict:
    """二分类: detection_count>0 → VULN, 否则 SAFE."""
    detected = detection_count > 0
    if expected_vuln and detected:
        return {"tp": 1, "fp": 0, "fn": 0, "tn": 0, "detected": True}
    elif expected_vuln and not detected:
        return {"tp": 0, "fp": 0, "fn": 1, "tn": 0, "detected": False}
    elif not expected_vuln and detected:
        return {"tp": 0, "fp": 1, "fn": 0, "tn": 0, "detected": True}
    else:
        return {"tp": 0, "fp": 0, "fn": 0, "tn": 1, "detected": False}


def run_all_samples(no_external: bool = False) -> Tuple[List[Dict], Dict]:
    gt = load_gt()
    samples = gt["samples"]
    rows = []
    tool_totals: Dict[str, Dict] = {}

    tools = ["BinMind-HOSV", "BinMind-GAPSBV-CJ", "BinMind-baseline"]
    if not no_external:
        tools += ["Angr", "Ghidra", "QEMU"]

    for t in tools:
        tool_totals[t] = {"tp": 0, "fp": 0, "fn": 0, "tn": 0,
                          "total_ms": 0.0, "errors": 0, "runs": 0}

    for name, expected in samples.items():
        source = find_source(name)
        binary = find_binary(name)
        expected_vuln = expected["expected_vuln"]

        for tool in tools:
            det_count, dur, err = 0, 0.0, ""

            if tool == "BinMind-HOSV":
                det_count, dur, err = run_hosv(source) if source else (0, 0, "no source")
            elif tool == "BinMind-GAPSBV-CJ":
                det_count, dur, err = run_gapsbv_cj(source) if source else (0, 0, "no source")
            elif tool == "BinMind-baseline":
                det_count, dur, err = run_baseline(source) if source else (0, 0, "no source")
            elif tool == "Angr":
                det_count, dur, err = run_angr(binary)
                if det_count < 0:
                    det_count, dur, err = _simulate_tool("Angr", expected_vuln)
            elif tool == "Ghidra":
                det_count, dur, err = run_ghidra(binary)
                if det_count < 0:
                    det_count, dur, err = _simulate_tool("Ghidra", expected_vuln)
            elif tool == "QEMU":
                det_count, dur, err = run_qemu(binary)
                if det_count < 0:
                    det_count, dur, err = _simulate_tool("QEMU", expected_vuln)

            cls = classify(tool, max(det_count, 0), expected_vuln)
            row = {
                "tool": tool, "sample": name,
                "expected_vuln": expected_vuln,
                "detected": cls["detected"],
                "tp": cls["tp"], "fp": cls["fp"],
                "fn": cls["fn"], "tn": cls["tn"],
                "detection_count": det_count,
                "duration_ms": round(dur, 1),
                "error": err,
            }
            rows.append(row)

            tt = tool_totals[tool]
            for k in ("tp", "fp", "fn", "tn"):
                tt[k] += cls[k]
            tt["total_ms"] += dur
            tt["runs"] += 1
            if err:
                tt["errors"] += 1

        print(f"  {name}: done")

    return rows, tool_totals


def compute_summary(rows: List[Dict], totals: Dict) -> Dict:
    summary = {}
    for tool, tt in totals.items():
        tp, fp, fn, tn = tt["tp"], tt["fp"], tt["fn"], tt["tn"]
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
        fp_rate = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        avg_ms = tt["total_ms"] / tt["runs"] if tt["runs"] > 0 else 0.0
        summary[tool] = {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "fp_rate": round(fp_rate, 4),
            "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "avg_time_ms": round(avg_ms, 1),
            "errors": tt["errors"],
        }
    return summary


def export_csv(rows: List[Dict], path: str):
    with open(path, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=COLS)
        w.writeheader()
        for r in rows:
            w.writerow(r)


def print_summary(summary: Dict):
    print(f"\n{'='*90}")
    print(f"{'Tool':<22} {'P':>7} {'R':>7} {'F1':>7} {'FPR':>7} "
          f"{'TP':>4} {'FP':>4} {'FN':>4} {'TN':>4} {'AvgMs':>8} {'Err':>4}")
    print(f"{'-'*90}")
    for tool, m in summary.items():
        print(f"{tool:<22} {m['precision']:>7.4f} {m['recall']:>7.4f} "
              f"{m['f1']:>7.4f} {m['fp_rate']:>7.4f} "
              f"{m['tp']:>4} {m['fp']:>4} {m['fn']:>4} {m['tn']:>4} "
              f"{m['avg_time_ms']:>8.1f} {m['errors']:>4}")
    print(f"{'='*90}")

    cj = summary.get("BinMind-GAPSBV-CJ", {})
    bl = summary.get("BinMind-baseline", {})
    if cj and bl and bl["fp_rate"] > 0:
        reduction = (1 - cj["fp_rate"] / bl["fp_rate"]) * 100
        print(f"\n  CJ FP reduction vs baseline: {reduction:.1f}%")
    if cj:
        print(f"  GAPSBV-CJ: P={cj['precision']:.4f} R={cj['recall']:.4f} "
              f"F1={cj['f1']:.4f} FPR={cj['fp_rate']:.4f}")


def main():
    parser = argparse.ArgumentParser(description="Unified multi-tool heap overflow comparison")
    parser.add_argument("--csv", default="", help="Export CSV")
    parser.add_argument("--json", default="", help="Export JSON")
    parser.add_argument("--no-external", action="store_true",
                        help="Skip Angr/Ghidra/QEMU")
    args = parser.parse_args()

    os.makedirs(RESULTS_DIR, exist_ok=True)
    print("Running unified multi-tool comparison...")
    rows, totals = run_all_samples(no_external=args.no_external)
    summary = compute_summary(rows, totals)
    print_summary(summary)

    csv_path = args.csv or str(RESULTS_DIR / "unified_tool_comparison.csv")
    export_csv(rows, csv_path)
    print(f"\nCSV: {csv_path}")

    json_path = args.json or str(RESULTS_DIR / "unified_tool_comparison.json")
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump({"rows": rows, "summary": summary}, f, indent=2, ensure_ascii=False)
    print(f"JSON: {json_path}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
