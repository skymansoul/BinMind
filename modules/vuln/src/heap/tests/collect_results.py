"""堆区间证据消歧回归测试 — 结果汇总与指标计算.

读取 run_scanner.py 生成的 scan_results.json,
按样本类型分组计算 TP/FP/TN/FN, 输出 LaTeX 表格和 CSV.

用法:
  python collect_results.py
  python collect_results.py --csv results.csv

创建: 2025-03-28
"""
import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Dict, List, Tuple


RESULTS_DIR = Path(__file__).resolve().parent / "results"

# Ground truth: 每个样本是否有真正的堆溢出
# True = 应该有 finding (vuln), False = 不应该有 finding (safe)
GROUND_TRUTH = {
    "cve_2016_10190": True,
    "cve_2017_5638": True,
    "cve_2018_6485": True,
    "cve_2018_1000001": True,
    "cve_2019_13143": True,
    "cve_2019_15794": True,
    "cve_2019_15846": True,
    "cve_2020_10713": True,
    "cve_2020_24586": True,
    "cve_2021_3156": True,
    "cve_2021_20226": True,
    "cve_2022_27666": True,
    "cve_2022_3602": True,
    "cve_2023_2513": True,
    "cve_2023_38545": True,
    "cve_2023_44445": True,
    "safe_same_expr": False,       # 安全对照: s ≤ s+1
    "safe_disjoint_allocs": False,  # 安全对照: 独立 allocs
}

# 样本分组
SAMPLE_GROUPS = {
    "truncation": ["cve_2016_10190", "cve_2020_24586"],
    "size_mismatch": ["cve_2017_5638", "cve_2018_1000001", "cve_2020_10713",
                      "cve_2019_15846", "cve_2021_3156", "cve_2023_38545"],
    "integer_overflow": ["cve_2018_6485"],
    "off_by_one": ["cve_2019_13143", "cve_2023_2513"],
    "expression_error": ["cve_2021_20226", "cve_2022_27666", "cve_2022_3602",
                         "cve_2023_44445"],
    "bounds_violation": ["cve_2019_15794"],
    "safe_controls": ["safe_same_expr", "safe_disjoint_allocs"],
}


def load_results() -> List[dict]:
    """加载扫描结果."""
    path = RESULTS_DIR / "scan_results.json"
    if not path.exists():
        print(f"  [ERROR] {path} not found. Run 'python run_scanner.py' first.")
        return []
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def compute_metrics(results: List[dict]) -> dict:
    """计算 TP/FP/TN/FN 和 F1."""
    tp = fp = tn = fn = 0
    per_sample = {}

    for r in results:
        name = r['sample']
        # 去除 _heap_overflow 后缀
        for suffix in ['_heap_overflow', '_memcpy_heap_overflow']:
            if name.endswith(suffix):
                name = name.replace(suffix, '')

        gt = GROUND_TRUTH.get(name)
        if gt is None:
            print(f"  [WARN] no ground truth for {name}, skipping")
            continue

        has_finding = r['final_count'] > 0

        if gt and has_finding:
            tp += 1
            label = "TP"
        elif gt and not has_finding:
            fn += 1
            label = "FN"
        elif not gt and has_finding:
            fp += 1
            label = "FP"
        else:
            tn += 1
            label = "TN"

        per_sample[name] = {
            'label': label,
            'raw_count': r['raw_count'],
            'final_count': r['final_count'],
            'filtered_count': r['filtered_count'],
            'shield_engine': r.get('shield', {}).get('verdicts', [{}])[0].get('engine', '') if r.get('shield', {}).get('verdicts') else '',
        }

    total = tp + fp + tn + fn
    recall = tp / max(1, tp + fn)
    precision = tp / max(1, tp + fp)
    f1 = 2 * recall * precision / max(0.001, recall + precision)
    fpr = fp / max(1, fp + tn)  # false positive rate

    return {
        'tp': tp, 'fp': fp, 'tn': tn, 'fn': fn, 'total': total,
        'recall': recall, 'precision': precision, 'f1': f1, 'fpr': fpr,
        'per_sample': per_sample,
    }


def print_table(metrics: dict):
    """打印汇总表格."""
    print(f"""
  ╔══════════════════════════════════════╗
  ║     SHIELD Regression Results       ║
  ╠══════════════════════════════════════╣
  ║  Total Samples:  {metrics['total']:>2}                  ║
  ║  TP={metrics['tp']:>2}  FP={metrics['fp']:>2}  TN={metrics['tn']:>2}  FN={metrics['fn']:>2}           ║
  ╠══════════════════════════════════════╣
  ║  Recall:    {metrics['recall']:.1%}                 ║
  ║  Precision: {metrics['precision']:.1%}                 ║
  ║  F1 Score:  {metrics['f1']:.3f}                 ║
  ║  FPR:       {metrics['fpr']:.1%}                 ║
  ╚══════════════════════════════════════╝
""")

    print("  Per-Sample Results:")
    print(f"  {'Sample':<30} {'GT':>5} {'Raw':>5} {'Final':>6} {'Filtered':>8} {'Result':>6}")
    print(f"  {'-'*30} {'-'*5} {'-'*5} {'-'*6} {'-'*8} {'-'*6}")
    for name, info in sorted(metrics['per_sample'].items()):
        gt = "VULN" if GROUND_TRUTH.get(name, False) else "SAFE"
        print(f"  {name:<30} {gt:>5} {info['raw_count']:>5} "
              f"{info['final_count']:>6} {info['filtered_count']:>8} {info['label']:>6}")


def export_csv(metrics: dict, path: str):
    """导出 CSV."""
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["Sample", "GroundTruth", "RawFindings", "FinalFindings",
                     "Filtered", "ShieldEngine", "Result"])
        for name, info in sorted(metrics['per_sample'].items()):
            gt = "VULN" if GROUND_TRUTH.get(name, False) else "SAFE"
            w.writerow([name, gt, info['raw_count'], info['final_count'],
                        info['filtered_count'], info['shield_engine'],
                        info['label']])
        w.writerow([])
        w.writerow(["Metric", "Value"])
        for k in ['tp', 'fp', 'tn', 'fn', 'recall', 'precision', 'f1', 'fpr']:
            w.writerow([k, f"{metrics[k]:.4f}" if isinstance(metrics[k], float) else str(metrics[k])])
    print(f"  CSV exported to {path}")


def export_latex(metrics: dict, path: str):
    """导出 LaTeX 表格."""
    lines = [
        r"\begin{table}[h]",
        r"\centering",
        r"\caption{SHIELD Heap Overflow Detection Results}",
        r"\label{tab:shield_results}",
        r"\begin{tabular}{lccccc}",
        r"\toprule",
        r"Sample & Ground Truth & Raw & SHIELD & Filtered & Result \\",
        r"\midrule",
    ]
    for name, info in sorted(metrics['per_sample'].items()):
        gt = "VULN" if GROUND_TRUTH.get(name, False) else "SAFE"
        lines.append(
            f"  {name} & {gt} & {info['raw_count']} & "
            f"{info['final_count']} & {info['filtered_count']} & "
            f"{info['label']} \\\\")
    lines.extend([
        r"\midrule",
        r"\multicolumn{6}{l}{Metrics} \\",
        f"  Recall & {metrics['recall']:.1%} \\\\",
        f"  Precision & {metrics['precision']:.1%} \\\\",
        f"  F1 Score & {metrics['f1']:.3f} \\\\",
        f"  FPR & {metrics['fpr']:.1%} \\\\",
        r"\bottomrule",
        r"\end{tabular}",
        r"\end{table}",
    ])
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"  LaTeX table exported to {path}")


def main():
    parser = argparse.ArgumentParser(description="SHIELD 结果汇总")
    parser.add_argument("--csv", type=str, default="", help="CSV 导出路径")
    parser.add_argument("--latex", type=str, default="", help="LaTeX 导出路径")
    args = parser.parse_args()

    results = load_results()
    if not results:
        sys.exit(1)

    metrics = compute_metrics(results)
    print_table(metrics)

    if args.csv:
        export_csv(metrics, args.csv)
    else:
        csv_path = RESULTS_DIR / "shield_metrics.csv"
        export_csv(metrics, str(csv_path))

    latex_path = args.latex if args.latex else str(RESULTS_DIR / "shield_metrics.tex")
    export_latex(metrics, latex_path)


if __name__ == "__main__":
    main()
