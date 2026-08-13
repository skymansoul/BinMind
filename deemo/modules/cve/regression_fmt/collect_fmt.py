# 格式化字符串结果收集与对比模块.
#
# 决策逻辑:
#   读取 fmt_scan_results.json, 按 基线/增强 分组计算 TP/FP/FN/TN
#   与 Recall/Precision/FPR/F1, 量化 FAPV 来源验证的误报抑制贡献.
#
# 创建: 2025-05-12

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"
SCAN_JSON = RESULTS / "fmt_scan_results.json"


def _confusion(rows, key):
    return (
        sum(1 for r in rows if r[f"{key}_verdict"] == "TP"),
        sum(1 for r in rows if r[f"{key}_verdict"] == "FP"),
        sum(1 for r in rows if r[f"{key}_verdict"] == "FN"),
        sum(1 for r in rows if r[f"{key}_verdict"] == "TN"),
    )


def _metrics(tp, fp, fn, tn):
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    prec = tp / (tp + fp) if (tp + fp) else 1.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    f1 = (2 * prec * recall / (prec + recall)) if (prec + recall) else 0.0
    return round(recall, 4), round(prec, 4), round(fpr, 4), round(f1, 4)


def collect() -> dict:
    if not SCAN_JSON.exists():
        print(f"scan results not found: {SCAN_JSON}. Run scan_fmt.py first.")
        return {}
    rows = json.loads(SCAN_JSON.read_text(encoding="utf-8"))
    summary = {
        "enhanced": dict(zip(("TP", "FP", "FN", "TN"),
                             _confusion(rows, "enhanced"))),
        "baseline": dict(zip(("TP", "FP", "FN", "TN"),
                             _confusion(rows, "baseline"))),
    }
    etp, efp, efn, etn = summary["enhanced"].values()
    btp, bfp, bfn, btn = summary["baseline"].values()
    summary["enhanced_metrics"] = dict(zip(
        ("Recall", "Precision", "FPR", "F1"), _metrics(etp, efp, efn, etn)))
    summary["baseline_metrics"] = dict(zip(
        ("Recall", "Precision", "FPR", "F1"), _metrics(btp, bfp, bfn, btn)))
    summary["fp_reduction"] = round(1.0 - (efp / max(1, bfp)), 4) if bfp else 1.0
    (RESULTS / "fmt_summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    return summary


def print_summary(summary: dict):
    print("\n=== Format String Regression Summary ===")
    print(f"{'config':<12}{'TP':>4}{'FP':>4}{'FN':>4}{'TN':>4}"
          f"{'Recall':>8}{'Prec':>8}{'FPR':>8}{'F1':>8}")
    for key in ("baseline", "enhanced"):
        c = summary[key]
        m = summary[f"{key}_metrics"]
        print(f"{key:<12}{c['TP']:>4}{c['FP']:>4}{c['FN']:>4}{c['TN']:>4}"
              f"{m['Recall']:>8.3f}{m['Precision']:>8.3f}"
              f"{m['FPR']:>8.3f}{m['F1']:>8.3f}")
    print(f"\nFP reduction (FAPV vs baseline): "
          f"{summary['fp_reduction'] * 100:.1f}%")


if __name__ == "__main__":
    s = collect()
    if s:
        print_summary(s)
