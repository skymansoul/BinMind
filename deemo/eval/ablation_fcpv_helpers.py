"""
FCPV消融实验辅助模块 — 样本预期映射、指标计算、表格输出、结果保存、图表生成.
"""
import json, os, csv
from pathlib import Path
from typing import Dict, Any

_BASE = Path(__file__).resolve().parent.parent
RESULTS_DIR = _BASE / "eval" / "results"
FMT_SAMPLES_DIR = _BASE / "samples" / "format_string"

FMT_EXPECTED: Dict[str, bool] = {
    'sample_fmt_01': True, 'sample_fmt_02': False,
    'sample_fmt_03': True, 'sample_fmt_04': True,
    'sample_fmt_05': True, 'sample_fmt_06': False,
    'sample_fmt_07': True, 'sample_fmt_08': True,
    'sample_fmt_09': False, 'sample_fmt_10': True,
    'sample_fmt_11': True, 'sample_fmt_12': True,
    'sample_fmt_13': True, 'sample_fmt_14': True,
    'sample_fmt_15': True,
}

CONFIGS = ["Baseline", "+FCPV", "+FCPV+PCFC", "+FCPV+PCFC+Rule9"]


def compute_metrics(results, configs=None):
    cfgs = configs or CONFIGS
    metrics = {}
    for cfg in cfgs:
        tp = fp = tn = fn = 0
        for r in results:
            v = r[f"{cfg}_verdict"]
            if r["expected_vuln"]:
                if v == "VULN": tp += 1
                else: fn += 1
            else:
                if v == "FP": fp += 1
                else: tn += 1
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2*prec*rec/(prec+rec) if (prec+rec) > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        metrics[cfg] = {
            "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1": round(f1, 4),
            "fpr": round(fpr, 4),
        }
    return metrics


def print_table(results, metrics):
    print(f"\n{'='*85}")
    print(f" FCPV Ablation: Baseline vs +FCPV vs +FCPV+PCFC vs +FCPV+PCFC+Rule9")
    print(f"{'='*85}")
    print(f" Samples: {len(results)} (format string)")
    print(f"\n{'Config':<22} {'TP':>4} {'FP':>4} {'TN':>4} {'FN':>4} "
          f"{'Prec':>8} {'Recall':>8} {'F1':>8} {'FPR':>8}")
    print("-" * 85)
    for cfg in CONFIGS:
        m = metrics[cfg]
        print(f"{cfg:<22} {m['tp']:>4} {m['fp']:>4} {m['tn']:>4} "
              f"{m['fn']:>4} {m['precision']:>8.4f} {m['recall']:>8.4f} "
              f"{m['f1']:>8.4f} {m['fpr']:>8.4f}")
    bl = metrics["Baseline"]
    full = metrics["+FCPV+PCFC+Rule9"]
    if bl["fpr"] > 0:
        red = (1 - full["fpr"] / bl["fpr"]) * 100
        print(f"\n FPR reduction (Baseline -> Full): "
              f"{bl['fpr']:.4f} -> {full['fpr']:.4f} ({red:.1f}% down)")
    if bl["f1"] > 0:
        f1_gain = (full["f1"] / bl["f1"] - 1) * 100
        print(f" F1 improvement: {bl['f1']:.4f} -> {full['f1']:.4f} "
              f"({f1_gain:+.1f}%)")
    print(f"{'='*85}")


def save_results(results, metrics):
    os.makedirs(RESULTS_DIR, exist_ok=True)
    csv_path = RESULTS_DIR / "ablation_fcpv.csv"
    with open(csv_path, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(["sample", "expected"] + CONFIGS +
                    [f"{c}_v" for c in CONFIGS])
        for r in results:
            w.writerow([r["sample"], r["expected_vuln"]] +
                       [r[c] for c in CONFIGS] +
                       [r[f"{c}_verdict"] for c in CONFIGS])
    print(f" CSV: {csv_path}")
    json_path = RESULTS_DIR / "ablation_fcpv.json"
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump({"results": results, "metrics": metrics}, f, indent=2)
    print(f" JSON: {json_path}")


def generate_chart(metrics):
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        import numpy as np
    except ImportError:
        print(" matplotlib not available, skipping chart")
        return
    x = np.arange(len(CONFIGS))
    width = 0.18
    fig, ax1 = plt.subplots(figsize=(10, 5.5))
    precs = [metrics[c]["precision"] for c in CONFIGS]
    recs = [metrics[c]["recall"] for c in CONFIGS]
    f1s = [metrics[c]["f1"] for c in CONFIGS]
    fprs = [metrics[c]["fpr"] for c in CONFIGS]
    b1 = ax1.bar(x-1.5*width, precs, width, label='Precision', color='#2196F3')
    b2 = ax1.bar(x-0.5*width, recs, width, label='Recall', color='#4CAF50')
    b3 = ax1.bar(x+0.5*width, f1s, width, label='F1', color='#FF9800')
    b4 = ax1.bar(x+1.5*width, fprs, width, label='FPR', color='#F44336')
    ax1.set_ylabel('Score', fontsize=12)
    ax1.set_xticks(x)
    ax1.set_xticklabels(CONFIGS, fontsize=9)
    ax1.set_ylim(-0.05, 1.15)
    ax1.legend(loc='upper left', fontsize=10)
    ax1.set_title(
        'FCPV Ablation: Precision/Recall/F1/FPR across 4 configs',
        fontsize=13)
    ax1.axhline(y=1.0, color='gray', linestyle='--', alpha=0.3)
    for bars in [b1, b2, b3, b4]:
        for bar in bars:
            h = bar.get_height()
            if h > 0.01:
                ax1.text(bar.get_x()+bar.get_width()/2., h+0.01,
                         f'{h:.2f}', ha='center', va='bottom', fontsize=7)
    chart_path = RESULTS_DIR / "ablation_fcpv_chart.png"
    fig.tight_layout()
    fig.savefig(chart_path, dpi=150)
    plt.close(fig)
    print(f" Chart: {chart_path}")
