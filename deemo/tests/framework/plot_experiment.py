"""
创建: 2026-06-08

对比实验绘图脚本 — 从 experiment_results.json 读取数据,
生成检出率/耗时/误报率柱状图 (matplotlib), 直接用于论文。

用法: python plot_experiment.py [results.json] [output.png]
"""

import json
import os
import sys
from collections import defaultdict
from typing import Dict, List


def load_results(path: str) -> List[dict]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def aggregate(results: List[dict]) -> Dict[str, dict]:
    """按工具聚合: {tool: {avg_detections, avg_time, samples}}"""
    agg: Dict[str, dict] = defaultdict(lambda: {
        "findings": [], "times": [], "samples": set(),
    })
    for r in results:
        tool = r["tool"]
        agg[tool]["findings"].append(r["findings"])
        agg[tool]["times"].append(r["elapsed_sec"])
        agg[tool]["samples"].add(r["sample"])
    return agg


def plot_comparison(results_path: str, output_path: str = "comparison.png") -> None:
    """生成三面板柱状图: 检出数, 耗时, 误报率。"""
    try:
        import matplotlib.pyplot as plt
        import matplotlib
        matplotlib.use('Agg')
    except ImportError:
        print("matplotlib not installed. pip install matplotlib")
        return

    results = load_results(results_path)
    agg = aggregate(results)

    tools = sorted(agg.keys())
    avg_findings = [sum(agg[t]["findings"]) / max(len(agg[t]["findings"]), 1) for t in tools]
    avg_times = [sum(agg[t]["times"]) / max(len(agg[t]["times"]), 1) for t in tools]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))

    # 面板1: 平均检出数
    colors = ['#2196F3', '#FF9800', '#4CAF50', '#F44336']
    bars1 = ax1.bar(tools, avg_findings, color=colors[:len(tools)], edgecolor='black')
    ax1.set_ylabel('Average Detections per Sample', fontsize=12)
    ax1.set_title('Detection Count Comparison', fontsize=14, fontweight='bold')
    for bar, val in zip(bars1, avg_findings):
        ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.2,
                 f'{val:.1f}', ha='center', fontsize=11)

    # 面板2: 平均耗时
    bars2 = ax2.bar(tools, avg_times, color=colors[:len(tools)], edgecolor='black')
    ax2.set_ylabel('Average Time (seconds)', fontsize=12)
    ax2.set_title('Runtime Comparison', fontsize=14, fontweight='bold')
    for bar, val in zip(bars2, avg_times):
        ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1,
                 f'{val:.1f}s', ha='center', fontsize=11)

    fig.suptitle('BinMind vs. Baseline Tools: Detection & Performance',
                 fontsize=16, fontweight='bold')
    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    print(f"Plot saved to: {output_path}")


if __name__ == "__main__":
    results_path = sys.argv[1] if len(sys.argv) > 1 else "tests/experiment_results.json"
    output_path = sys.argv[2] if len(sys.argv) > 2 else "tests/comparison_plot.png"
    if os.path.isfile(results_path):
        plot_comparison(results_path, output_path)
    else:
        print(f"No results file at {results_path}")
        print("Run experiment_runner.py first to generate comparison data.")
