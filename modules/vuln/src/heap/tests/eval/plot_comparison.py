"""堆区间证据消歧对比实验 — 可视化.

从 benchmark_summary.json 读取多工具对比数据,
生成: 柱状图 (findings对比), 散点图 (time vs recall), 混淆矩阵.

用法:
  python plot_comparison.py

创建: 2024-10-11
"""
import json
import sys
from pathlib import Path
from typing import Dict, List, Optional


RESULTS_DIR = Path(__file__).resolve().parent.parent / "results"
OUTPUT_DIR = RESULTS_DIR / "plots"
OUTPUT_DIR.mkdir(exist_ok=True)


def load_benchmark() -> Optional[dict]:
    path = RESULTS_DIR / "benchmark_summary.json"
    if not path.exists():
        print(f"  [ERROR] {path} not found. Run 'python run_benchmark.py' first.")
        return None
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def plot_bar_chart(data: dict, output_path: str):
    """柱状图: 各工具的 findings 数量 (原始 vs 过滤后)."""
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        import numpy as np
    except ImportError:
        print("  [WARN] matplotlib not installed, skipping bar chart.")
        _save_placeholder_text(output_path, "Bar chart: matplotlib not installed")
        return

    tools_data = data.get("tools", {})
    names = list(tools_data.keys())
    raw_findings = []
    filtered_findings = []

    for name in names:
        td = tools_data[name]
        if "error" in td:
            raw_findings.append(0)
            filtered_findings.append(0)
        elif "total_findings_raw" in td:
            raw_findings.append(td["total_findings_raw"])
            filtered_findings.append(td.get("total_findings_filtered", 0))
        else:
            raw_findings.append(td.get("total_findings", 0))
            filtered_findings.append(td.get("total_findings", 0))

    x = np.arange(len(names))
    width = 0.35

    fig, ax = plt.subplots(figsize=(10, 6))
    bars1 = ax.bar(x - width/2, raw_findings, width, label='Raw Findings',
                   color='#e74c3c', alpha=0.8)
    bars2 = ax.bar(x + width/2, filtered_findings, width, label='After Filtering',
                   color='#2ecc71', alpha=0.8)

    ax.set_ylabel('Number of Findings')
    ax.set_title('Heap Overflow Detection — Multi-Tool Comparison')
    ax.set_xticks(x)
    ax.set_xticklabels(names, rotation=15)
    ax.legend()
    ax.grid(axis='y', alpha=0.3)

    for bar in bars1:
        height = bar.get_height()
        ax.annotate(f'{int(height)}', xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 3), textcoords="offset points", ha='center', va='bottom', fontsize=8)
    for bar in bars2:
        height = bar.get_height()
        ax.annotate(f'{int(height)}', xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 3), textcoords="offset points", ha='center', va='bottom', fontsize=8)

    plt.tight_layout()
    plt.savefig(output_path, dpi=150)
    plt.close()
    print(f"  [OK] Bar chart: {output_path}")


def plot_time_scatter(data: dict, output_path: str):
    """散点图: 分析时间 vs 检测率."""
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
    except ImportError:
        _save_placeholder_text(output_path, "Scatter plot: matplotlib not installed")
        return

    tools_data = data.get("tools", {})
    fig, ax = plt.subplots(figsize=(8, 6))

    colors = {'shield': '#2ecc71', 'angr': '#e74c3c',
              'qemu': '#3498db', 'ghidra': '#f39c12'}
    markers = {'shield': 'o', 'angr': 's', 'qemu': '^', 'ghidra': 'D'}

    for name, td in tools_data.items():
        if "error" in td:
            continue
        time_val = td.get("avg_time_ms", 0)
        # recall 代理: 对于堆区间证据消歧用 filter_rate, 其他用 findings/samples
        if "avg_filter_rate" in td:
            y_val = td["avg_filter_rate"] * 100
        else:
            y_val = td.get("total_findings", 0) / max(1, td.get("samples", 1)) * 100

        ax.scatter(time_val, y_val, c=colors.get(name, '#999'),
                   marker=markers.get(name, 'o'), s=150,
                   label=name.upper(), edgecolors='black', linewidth=1)
        ax.annotate(name, (time_val, y_val), textcoords="offset points",
                    xytext=(8, 5), fontsize=9)

    ax.set_xlabel('Analysis Time (ms)')
    ax.set_ylabel('Detection Score')
    ax.set_title('Speed vs Detection — Multi-Tool Comparison')
    ax.legend(loc='lower right')
    ax.grid(alpha=0.3)

    plt.tight_layout()
    plt.savefig(output_path, dpi=150)
    plt.close()
    print(f"  [OK] Scatter plot: {output_path}")


def plot_confusion_matrix(metrics: dict, output_path: str):
    """混淆矩阵: TP/FP/TN/FN."""
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        import numpy as np
    except ImportError:
        _save_placeholder_text(output_path, "Confusion matrix: matplotlib not installed")
        return

    cm = np.array([
        [metrics.get('tp', 0), metrics.get('fp', 0)],
        [metrics.get('fn', 0), metrics.get('tn', 0)],
    ])

    fig, ax = plt.subplots(figsize=(5, 5))
    im = ax.imshow(cm, cmap='RdYlGn')

    ax.set_xticks([0, 1])
    ax.set_yticks([0, 1])
    ax.set_xticklabels(['Predicted Positive', 'Predicted Negative'])
    ax.set_yticklabels(['Actual Positive', 'Actual Negative'])

    for i in range(2):
        for j in range(2):
            text = ax.text(j, i, str(cm[i, j]),
                          ha="center", va="center", fontsize=20,
                          fontweight="bold", color="white" if cm[i, j] > cm.max()/2 else "black")

    ax.set_title(f'SHIELD Confusion Matrix\n'
                 f'Recall={metrics.get("recall", 0):.1%} '
                 f'Precision={metrics.get("precision", 0):.1%} '
                 f'F1={metrics.get("f1", 0):.3f}')

    plt.tight_layout()
    plt.savefig(output_path, dpi=150)
    plt.close()
    print(f"  [OK] Confusion matrix: {output_path}")


def _save_placeholder_text(path: str, msg: str):
    """保存占位文本 (matplotlib 未安装时)."""
    Path(path).write_text(msg)


def main():
    data = load_benchmark()
    if data is None:
        sys.exit(1)

    plot_bar_chart(data, str(OUTPUT_DIR / "findings_comparison.png"))
    plot_time_scatter(data, str(OUTPUT_DIR / "time_vs_detection.png"))

    # 尝试加载堆区间证据消歧 metrics
    metrics_path = RESULTS_DIR / "shield_metrics.json"
    # collect_results.py generates this; use scan_results as fallback
    scan_path = RESULTS_DIR / "scan_results.json"
    if scan_path.exists():
        with open(scan_path, encoding="utf-8") as f:
            scan_data = json.load(f)
        total_raw = sum(r.get('raw_count', 0) for r in scan_data)
        total_final = sum(r.get('final_count', 0) for r in scan_data)
        total_filtered = total_raw - total_final
        print(f"\n  Quick stats from scan results:")
        print(f"    Raw findings: {total_raw}")
        print(f"    After SHIELD: {total_final}")
        print(f"    Filtered: {total_filtered} ({100*total_filtered/max(1,total_raw):.0f}%)")

    print(f"\n  Plots saved to: {OUTPUT_DIR}")


if __name__ == "__main__":
    main()
