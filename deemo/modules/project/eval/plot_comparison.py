# 对比实验可视化: 精确率/召回率/F1对比柱状图, FP reduction证据
# 输出PNG/SVG, 直接可用于论文, matplotlib不可用时使用ASCII fallback
import json, sys
from pathlib import Path
from typing import Dict

_PROJ_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJ_ROOT))

try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import numpy as np
    _MPL = True
except ImportError:
    _MPL = False


def plot_metrics(metrics: Dict[str, Dict], out_dir: str = "eval/"):
    """生成精度/召回率/F1/FPR对比图."""
    tools = list(metrics.keys())
    recalls = [metrics[t].get('recall', 0) for t in tools]
    precisions = [metrics[t].get('precision', 0) for t in tools]
    f1s = [metrics[t].get('f1', 0) for t in tools]
    fprs = [metrics[t].get('fpr', 0) for t in tools]

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    if _MPL:
        fig, axes = plt.subplots(1, 2, figsize=(14, 5))
        x = np.arange(len(tools)); w = 0.25
        axes[0].bar(x - w, recalls, w, label='Recall', color='#2ecc71')
        axes[0].bar(x, precisions, w, label='Precision', color='#3498db')
        axes[0].bar(x + w, f1s, w, label='F1', color='#e74c3c')
        axes[0].set_xticks(x); axes[0].set_xticklabels(tools, rotation=15)
        axes[0].set_ylim(0, 1.15); axes[0].legend(); axes[0].grid(axis='y', alpha=0.3)
        axes[0].set_title('Recall / Precision / F1')

        colors = ['#2ecc71' if f < 0.1 else '#f39c12' if f < 0.3 else '#e74c3c' for f in fprs]
        axes[1].bar(tools, fprs, color=colors, edgecolor='white')
        axes[1].set_title('False Positive Rate (lower is better)')
        axes[1].grid(axis='y', alpha=0.3)
        for i, f in enumerate(fprs):
            axes[1].text(i, f + 0.01, f'{f:.1%}', ha='center', fontsize=10)

        plt.tight_layout()
        p = str(out_dir / 'metrics_comparison.png')
        plt.savefig(p, dpi=150, bbox_inches='tight')
        print(f'图表: {p}')

    # ASCII汇总 (始终打印)
    print(f"\n{'='*60}")
    print(f"{'Tool':<15} {'Recall':>8} {'Prec':>8} {'F1':>8} {'FPR':>8}")
    print("-" * 50)
    for t, r, p, f, fp in zip(tools, recalls, precisions, f1s, fprs):
        print(f"{t:<15} {r:7.1%} {p:7.1%} {f:7.1%} {fp:7.1%}")

    # FP reduction计算
    binmind = metrics.get('BinMind', metrics.get('our_method', {}))
    if binmind:
        bm_fpr = binmind.get('fpr', 0)
        print(f"\nBinMind FPR: {bm_fpr:.1%}")
        for t in tools:
            if t in ('BinMind', 'our_method'):
                continue
            other_fpr = metrics[t].get('fpr', 0)
            if other_fpr > 0 and bm_fpr < other_fpr:
                red = 1 - bm_fpr / other_fpr
                print(f"  vs {t}: FPR Reduction = {red:.0%}")


def generate_all(report_path: str = "eval/benchmark_report.json"):
    """从JSON报告生成所有图表."""
    rp = _PROJ_ROOT / report_path
    if not rp.exists():
        print(f"No report at {rp}, trying cve_samples/build/")
        rp = _PROJ_ROOT / "cve_samples/build/regression_report.json"
    if not rp.exists():
        print("No report found. Run benchmark first.")
        return

    with open(rp, 'r', encoding='utf-8') as f:
        data = json.load(f)

    tools_data = data.get('tools', {})
    all_m = {}
    for tool, td in tools_data.items():
        all_m[tool] = td.get('metrics', {})
    if not all_m:
        print("No tool metrics in report.")
        return

    plot_metrics(all_m)


def plot_grouped_comparison(csv_path: str, out_dir: str = "eval_output"):
    """加壳/未加壳分组的检出率/误报率对比柱状图.

    数据源: fp_benchmark_results.csv (工具 × 样本 × 分组).
    分组: plain (未加壳/-O0) 与 packed (加壳代理/-O2 release).
    计算逻辑复用 eval.plot_fp_comparison, 仅绘图入口不同.
    """
    from eval.plot_fp_comparison import load_results, metrics_for

    results = load_results(Path(csv_path))
    tools = ["our_method", "our_base", "naive", "regex", "angr"]
    groups = ["plain", "packed"]
    by_tool_group = {
        t: {g: metrics_for(results, t, g) for g in groups} for t in tools
    }

    if not _MPL:
        print("matplotlib 不可用, 仅输出 ASCII 汇总")
    else:
        fig, axes = plt.subplots(2, 2, figsize=(15, 10))
        for gi, g in enumerate(groups):
            recalls = [by_tool_group[t][g]['recall'] for t in tools]
            fprs = [by_tool_group[t][g]['fpr'] for t in tools]
            ax = axes[0][gi]
            x = np.arange(len(tools)); w = 0.35
            ax.bar(x - w / 2, recalls, w, label='Recall', color='#2ecc71')
            ax.bar(x + w / 2, fprs, w, label='FPR', color='#e74c3c')
            ax.set_xticks(x)
            ax.set_xticklabels(tools, rotation=15)
            ax.set_ylim(0, 1.15)
            ax.legend(); ax.grid(axis='y', alpha=0.3)
            ax.set_title(f'{g} — Recall / FPR')
        plt.suptitle('Heap Overflow Detection: FP-Reduction '
                     'Multi-Tool Comparison (grouped)', fontsize=13)
        plt.tight_layout(rect=(0, 0, 1, 0.96))
        out = Path(out_dir)
        out.mkdir(parents=True, exist_ok=True)
        png = out / 'comparison_grouped.png'
        plt.savefig(png, dpi=150, bbox_inches='tight')
        print(f'图表: {png}')

    print("\n分组指标 (Recall / FPR):")
    for g in groups:
        print(f"  [{g}] " + "  ".join(
            f"{t}={by_tool_group[t][g]['recall']:.0%}/{by_tool_group[t][g]['fpr']:.0%}"
            for t in tools))


if __name__ == '__main__':
    csv_path = _PROJ_ROOT / "eval_output" / "fp_benchmark_results.csv"
    if csv_path.exists():
        plot_grouped_comparison(str(csv_path))
    else:
        generate_all()
