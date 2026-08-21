# 结果收集与对比模块.
#
# 决策逻辑:
#   读取 scan_results.json (PcWBI 增强结果), 并重新以 use_pcwbi=False
#   扫描同一批二进制获得基线结果, 计算两组 TP/FP/FN/TN 与
#   Recall/Precision/FPR/F1, 量化 PcWBI 的误报抑制贡献.
#   输出: results/metrics.csv, results/summary.json, 控制台汇总表.
#

import csv
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"
SCAN_JSON = RESULTS / "scan_results.json"


def _ensure_paths():
    deemo = ROOT.parent.parent.parent
    for p in (str(deemo), str(deemo.parent), str(ROOT.parent)):
        if p not in sys.path:
            sys.path.insert(0, p)


def _confusion(rows):
    tp = sum(1 for r in rows if r["verdict"] == "TP")
    fp = sum(1 for r in rows if r["verdict"] == "FP")
    fn = sum(1 for r in rows if r["verdict"] == "FN")
    tn = sum(1 for r in rows if r["verdict"] == "TN")
    return tp, fp, fn, tn


def _metrics(tp, fp, fn, tn):
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    prec = tp / (tp + fp) if (tp + fp) else 1.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    f1 = (2 * prec * recall / (prec + recall)) if (prec + recall) else 0.0
    return round(recall, 4), round(prec, 4), round(fpr, 4), round(f1, 4)


def collect(rebuild_baseline: bool = True) -> dict:
    """收集增强结果与基线结果, 返回汇总."""
    _ensure_paths()
    if not SCAN_JSON.exists():
        print(f"scan results not found: {SCAN_JSON}. Run run_scan.py first.")
        return {}

    rows = json.loads(SCAN_JSON.read_text(encoding="utf-8"))

    baseline_rows = []
    if rebuild_baseline:
        from heapdet.scan import scan_binary
        manifest = json.loads(
            (ROOT / "build" / "manifest_build.json")
            .read_text(encoding="utf-8"))
        print("scanning baseline (PcWBI disabled)...")
        for sample in manifest:
            gt = sample["ground_truth"]
            for opt in ("O0", "O2"):
                rec = sample.get(f"compiled_{opt}", {})
                binary = rec.get("binary", "")
                if not rec.get("compiled") or not os.path.exists(binary):
                    continue
                report = scan_binary(binary, use_pcwbi=False)
                detected = report.has_overflow()
                verdict = ("TP" if gt == "vulnerable" else "FP") \
                    if detected else ("FN" if gt == "vulnerable" else "TN")
                baseline_rows.append({
                    "sample_id": sample["sample_id"],
                    "opt": opt, "verdict": verdict,
                    "confirmed_count": len(report.confirmed),
                })
        (RESULTS / "baseline_results.json").write_text(
            json.dumps(baseline_rows, indent=2), encoding="utf-8")

    summary = {
        "enhanced": dict(zip(
            ("TP", "FP", "FN", "TN"), _confusion(rows))),
        "baseline": dict(zip(
            ("TP", "FP", "FN", "TN"), _confusion(baseline_rows))),
    }
    etp, efp, efn, etn = summary["enhanced"].values()
    btp, bfp, bfn, btn = summary["baseline"].values()
    summary["enhanced_metrics"] = dict(zip(
        ("Recall", "Precision", "FPR", "F1"), _metrics(etp, efp, efn, etn)))
    summary["baseline_metrics"] = dict(zip(
        ("Recall", "Precision", "FPR", "F1"), _metrics(btp, bfp, bfn, btn)))
    summary["fp_reduction"] = round(
        1.0 - (efp / max(1, bfp)), 4) if bfp else 1.0

    # 统一 CSV: 工具名、样本ID、检出数、误报数、漏报数、耗时
    csv_path = RESULTS / "metrics.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["tool", "sample_id", "opt", "verdict",
                         "confirmed", "suspected", "time_ms"])
        for r in rows:
            writer.writerow(["BinMind-PcWBI", r["sample_id"], r["opt"],
                             r["verdict"], r["confirmed_count"],
                             r["suspected_count"], r["elapsed_ms"]])
        for r in baseline_rows:
            writer.writerow(["BinMind-Baseline", r["sample_id"], r["opt"],
                             r["verdict"], r["confirmed_count"], 0, ""])

    (RESULTS / "summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    return summary


def print_summary(summary: dict):
    """控制台输出汇总表."""
    print("\n=== Regression Summary ===")
    print(f"{'config':<18}{'TP':>4}{'FP':>4}{'FN':>4}{'TN':>4}"
          f"{'Recall':>8}{'Prec':>8}{'FPR':>8}{'F1':>8}")
    for key in ("baseline", "enhanced"):
        c = summary[key]
        m = summary[f"{key}_metrics"]
        print(f"{key:<18}{c['TP']:>4}{c['FP']:>4}{c['FN']:>4}{c['TN']:>4}"
              f"{m['Recall']:>8.3f}{m['Precision']:>8.3f}"
              f"{m['FPR']:>8.3f}{m['F1']:>8.3f}")
    print(f"\nFP reduction (PcWBI vs baseline): "
          f"{summary['fp_reduction']*100:.1f}%")


if __name__ == "__main__":
    summary = collect()
    if summary:
        print_summary(summary)
