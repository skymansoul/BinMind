# coding: utf-8
#
"""结果收集: TP/TN/FP/FN + P/R/F1/FPR, 输出 JSON/MD/CSV."""

import csv
import json
import sys
from datetime import datetime
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
    return {"n": total, "tp": tp, "tn": tn, "fp": fp, "fn": fn,
            "precision": round(precision, 4), "recall": round(recall, 4),
            "f1": round(f1, 4), "fpr": round(fpr, 4)}


def _confusion(results, gt, key):
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
    f = SAMPLE_DIR / "scan_results.json"
    if not f.exists():
        print("scan_results.json not found")
        return 1
    results = json.loads(f.read_text(encoding="utf-8"))

    prov = _confusion(results, gt, "detected")
    naive = _confusion(results, gt, "naive_detected")
    fp_reduction = 0.0
    if naive["fp"] > 0:
        fp_reduction = (naive["fp"] - prov["fp"]) / naive["fp"] * 100

    report = {
        "prov": prov, "naive": naive,
        "fp_reduction_pct": round(fp_reduction, 1),
        "n_samples": len(results),
        "class_stats": {},
    }
    for r in results:
        for cls, cnt in (r.get("per_class") or {}).items():
            report["class_stats"][cls] = report["class_stats"].get(cls, 0) + cnt

    (SAMPLE_DIR / "regression_report.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    (SAMPLE_DIR / "regression_report.md").write_text(
        _render_md(report, results, gt), encoding="utf-8")
    _render_csv(report, results, gt)

    print("=== FMTPROV ===")
    print(f"  TP={prov['tp']} TN={prov['tn']} FP={prov['fp']} "
          f"FN={prov['fn']} P={prov['precision']:.3f} "
          f"R={prov['recall']:.3f} F1={prov['f1']:.3f} "
          f"FPR={prov['fpr']:.3f}")
    print("=== Naive (literal-hint only) ===")
    print(f"  TP={naive['tp']} TN={naive['tn']} FP={naive['fp']} "
          f"FN={naive['fn']} P={naive['precision']:.3f} "
          f"R={naive['recall']:.3f} F1={naive['f1']:.3f} "
          f"FPR={naive['fpr']:.3f}")
    print(f"\nFP reduction: {report['fp_reduction_pct']}% "
          f"(naive {naive['fp']} → prov {prov['fp']})")
    print(f"class stats: {report['class_stats']}")
    return 0


def _render_md(report, results, gt) -> str:
    p, n = report["prov"], report["naive"]
    lines = [
        "# Format-String Corpus — Regression Report",
        "",
        f"Generated: {datetime.now().isoformat()}",
        f"Samples: {report['n_samples']} (12 VULN + 4 SAFE)",
        "",
        "## FMTPROV (constant-folding + taint provenance)",
        f"- TP={p['tp']} TN={p['tn']} FP={p['fp']} FN={p['fn']}",
        f"- P={p['precision']:.3f} R={p['recall']:.3f} "
        f"F1={p['f1']:.3f} FPR={p['fpr']:.3f}",
        "",
        "## Naive baseline (literal hint in 5 preceding insns)",
        f"- TP={n['tp']} TN={n['tn']} FP={n['fp']} FN={n['fn']}",
        f"- P={n['precision']:.3f} R={n['recall']:.3f} "
        f"F1={n['f1']:.3f} FPR={n['fpr']:.3f}",
        "",
        f"## FP Reduction",
        f"- FP: naive {n['fp']} → FMTPROV {p['fp']} "
        f"(相对降幅 {report['fp_reduction_pct']}%)",
        f"- 分类分布: {report['class_stats']}",
        "",
        "## Per-sample",
        "| sample | expected | prov | naive | calls | safe | vuln |",
        "|--------|----------|------|-------|-------|------|------|",
    ]
    for r in results:
        sid = r.get("sample_id", "")
        lines.append(
            f"| {sid} | {gt.get(sid,'?')} | {p['per_sample'].get(sid,'?')} "
            f"| {n['per_sample'].get(sid,'?')} | {r.get('n_calls',0)} "
            f"| {r.get('n_safe',0)} | {r.get('n_vuln',0)} |")
    return "\n".join(lines)


def _render_csv(report, results, gt) -> None:
    p, n = report["prov"], report["naive"]
    with open(SAMPLE_DIR / "regression_report.csv", "w", newline="",
              encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["sample_id", "expected", "prov", "naive", "n_calls",
                    "n_safe", "n_vuln", "fp_reduction_pct"])
        for r in results:
            sid = r.get("sample_id", "")
            w.writerow([sid, gt.get(sid, "?"),
                        p["per_sample"].get(sid, "?"),
                        n["per_sample"].get(sid, "?"),
                        r.get("n_calls", 0), r.get("n_safe", 0),
                        r.get("n_vuln", 0), r.get("fp_reduction_pct", 0)])


if __name__ == "__main__":
    sys.exit(main())
