# coding: utf-8
#
"""
结果收集与对比模块: 读取 scan_results.json + expected.csv,
计算 GASRI 与朴素基线的 TP/TN/FP/FN、Precision/Recall/F1/FPR,
输出 regression_report.json / regression_report.md / regression_report.csv。

判定: detected=True 且 expected=TP → TP; detected=False 且 TN → TN; 等。
"""

import csv
import json
import sys
from pathlib import Path

SAMPLE_DIR = Path(__file__).resolve().parent


def load_expected() -> dict:
    gt = {}
    f = SAMPLE_DIR / "expected.csv"
    if f.exists():
        with open(f, newline="", encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                gt[row["sample_id"]] = row["expected"]
    return gt


def _metrics(tp, tn, fp, fn):
    total = tp + tn + fp + fn
    precision = tp / max(1, tp + fp)
    recall = tp / max(1, tp + fn)
    f1 = 2 * precision * recall / max(0.001, precision + recall)
    fpr = fp / max(1, fp + tn)
    return {
        "n": total, "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "precision": round(precision, 4), "recall": round(recall, 4),
        "f1": round(f1, 4), "fpr": round(fpr, 4),
    }


def _confusion(results, gt, key: str) -> dict:
    tp = tn = fp = fn = 0
    per = {}
    for r in results:
        sid = r.get("sample_id", "")
        exp = gt.get(sid, "TP")
        det = r.get(key, False)
        if exp == "TP":
            v = "TP" if det else "FN"
        else:
            v = "FP" if det else "TN"
        per[sid] = v
        tp += (v == "TP"); tn += (v == "TN")
        fp += (v == "FP"); fn += (v == "FN")
    m = _metrics(tp, tn, fp, fn)
    m["per_sample"] = per
    return m


def main() -> int:
    gt = load_expected()
    results_file = SAMPLE_DIR / "scan_results.json"
    if not results_file.exists():
        print("scan_results.json not found — run scan_scheduler.py first")
        return 1
    results = json.loads(results_file.read_text(encoding="utf-8"))

    gasri = _confusion(results, gt, "detected")
    naive = _confusion(results, gt, "naive_detected")

    fp_abs_g = gasri["fp"]
    fp_abs_n = naive["fp"]
    fp_reduction = 0.0
    if fp_abs_n > 0:
        fp_reduction = (fp_abs_n - fp_abs_g) / fp_abs_n * 100

    report = {
        "gasri": gasri,
        "naive": naive,
        "fp_reduction_pct": round(fp_reduction, 1),
        "n_samples": len(results),
        "rule_stats": {},
    }
    for r in results:
        for rule, cnt in (r.get("per_rule") or {}).items():
            report["rule_stats"][rule] = \
                report["rule_stats"].get(rule, 0) + cnt

    (SAMPLE_DIR / "regression_report.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    md = _render_md(report, results, gt)
    (SAMPLE_DIR / "regression_report.md").write_text(md, encoding="utf-8")

    _render_csv(report, results, gt)

    print("=== GASRI ===")
    print(f"  TP={gasri['tp']} TN={gasri['tn']} FP={gasri['fp']} "
          f"FN={gasri['fn']}  P={gasri['precision']:.3f} "
          f"R={gasri['recall']:.3f} F1={gasri['f1']:.3f} "
          f"FPR={gasri['fpr']:.3f}")
    print("=== Naive baseline ===")
    print(f"  TP={naive['tp']} TN={naive['tn']} FP={naive['fp']} "
          f"FN={naive['fn']}  P={naive['precision']:.3f} "
          f"R={naive['recall']:.3f} F1={naive['f1']:.3f} "
          f"FPR={naive['fpr']:.3f}")
    print(f"\nFP reduction: {report['fp_reduction_pct']}% "
          f"(naive {fp_abs_n} → gasri {fp_abs_g})")
    print(f"rule stats: {report['rule_stats']}")
    return 0


def _render_md(report: dict, results: list, gt: dict) -> str:
    g, n = report["gasri"], report["naive"]
    lines = [
        "# CVE Heap Corpus — Regression Report",
        "",
        f"Generated: {__import__('datetime').datetime.now().isoformat()}",
        f"Samples: {report['n_samples']} (12 TP + 4 TN)",
        "",
        "## GASRI (Guard-Aware Size-Region Inference)",
        f"- TP={g['tp']} TN={g['tn']} FP={g['fp']} FN={g['fn']}",
        f"- Precision={g['precision']:.3f} Recall={g['recall']:.3f} "
        f"F1={g['f1']:.3f} FPR={g['fpr']:.3f}",
        "",
        "## Naive Baseline (constant compare, no guard/padding/link)",
        f"- TP={n['tp']} TN={n['tn']} FP={n['fp']} FN={n['fn']}",
        f"- Precision={n['precision']:.3f} Recall={n['recall']:.3f} "
        f"F1={n['f1']:.3f} FPR={n['fpr']:.3f}",
        "",
        f"## FP Reduction",
        f"- FP 绝对值: naive {n['fp']} → GASRI {g['fp']} "
        f"(相对降幅 {report['fp_reduction_pct']}%)",
        f"- 过滤规则分布: {report['rule_stats']}",
        "",
        "## Per-sample",
        "| sample | expected | gasri | naive | pairs | safe | overflow | suspicious |",
        "|--------|----------|-------|-------|-------|------|-----------|------------|",
    ]
    for r in results:
        sid = r.get("sample_id", "")
        lines.append(
            f"| {sid} | {gt.get(sid,'?')} | {g['per_sample'].get(sid,'?')} "
            f"| {n['per_sample'].get(sid,'?')} | {r.get('n_pairs',0)} "
            f"| {r.get('n_safe',0)} | {r.get('n_overflow',0)} "
            f"| {r.get('n_suspicious',0)} |")
    return "\n".join(lines)


def _render_csv(report: dict, results: list, gt: dict) -> None:
    import csv as _csv
    g, n = report["gasri"], report["naive"]
    with open(SAMPLE_DIR / "regression_report.csv", "w", newline="",
              encoding="utf-8") as fh:
        w = _csv.writer(fh)
        w.writerow(["sample_id", "expected", "gasri", "naive",
                    "n_pairs", "n_safe", "n_overflow", "n_suspicious",
                    "fp_reduction_pct"])
        for r in results:
            sid = r.get("sample_id", "")
            w.writerow([sid, gt.get(sid, "?"),
                        g["per_sample"].get(sid, "?"),
                        n["per_sample"].get(sid, "?"),
                        r.get("n_pairs", 0), r.get("n_safe", 0),
                        r.get("n_overflow", 0), r.get("n_suspicious", 0),
                        r.get("fp_reduction_pct", 0)])


if __name__ == "__main__":
    sys.exit(main())
