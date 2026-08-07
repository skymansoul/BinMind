"""DP-TVRA多工具对比可视化 — matplotlib三面板图表.

面板1: 检出率柱状图 (Recall %)
面板2: 误报率柱状图 (FP %)
面板3: F1分数 vs 时间散点图 (size=time)

设计决策:
  Angr/Ghidra数据为ESTIMATED(Windows不可用), 图表上用斜线填充标记。
  DP-TVRA和PatternMatch为实测数据, 实心填充。
"""
import json
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent.parent.parent
RESULTS_DIR = BASE_DIR / "modules" / "vuln" / "detection" / "tests" / "results"


def plot_comparison(json_path: str = None) -> str:
    """绘制三面板对比图."""
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        import matplotlib.patches as mpatches
        import numpy as np
    except ImportError:
        print("[!] matplotlib not installed; generating placeholder")
        return _generate_placeholder()

    # 数据 — DP-TVRA实测, 其他为文献参考值+估算
    tools = ['DP-TVRA', 'PatternMatch', 'Mango\n(USENIX)', 'Angr\n(S&P)', 'Ghidra']
    recall = [74.3, 85.0, 82.0, 90.0, 85.0]
    precision = [100.0, 40.0, 72.0, 40.0, 65.0]
    f1_scores = [85.3, 54.0, 77.0, 55.0, 74.0]
    time_ms = [45, 20, 180000, 3200, 4500]
    fp_rate = [0.0, 60.0, 28.0, 60.0, 35.0]

    # 颜色: 实测=蓝色, 估算=橙色斜线
    real_mask = [True, True, False, False, False]
    colors = ['#2196F3' if r else '#FF9800' for r in real_mask]
    hatches = ['', '', '//', '//', '//']

    fig, axes = plt.subplots(1, 3, figsize=(16, 5.5))
    fig.suptitle('Heap Overflow Detection — Multi-Tool Comparison (DP-TVRA Benchmark)',
                 fontsize=14, fontweight='bold', y=1.01)

    x = np.arange(len(tools))
    width = 0.5

# Panel 1: Detection Rate & FP Rate
    ax1 = axes[0]
    bars_recall = ax1.bar(x - width/3, recall, width * 0.55,
                          label='Recall %', color='#4CAF50',
                          edgecolor='#2E7D32', linewidth=1.2)
    bars_prec = ax1.bar(x + width/3, precision, width * 0.55,
                        label='Precision %', color='#2196F3',
                        edgecolor='#1565C0', linewidth=1.2)

    # 斜线标记估算值
    for i, (bar_r, bar_p) in enumerate(zip(bars_recall, bars_prec)):
        if not real_mask[i]:
            bar_r.set_hatch('//')
            bar_p.set_hatch('//')

    ax1.set_ylabel('Percentage (%)')
    ax1.set_title('Recall & Precision', fontweight='bold')
    ax1.set_xticks(x)
    ax1.set_xticklabels(tools, fontsize=9)
    ax1.set_ylim(0, 110)
    ax1.legend(loc='lower right', fontsize=8)
    ax1.grid(axis='y', alpha=0.3, linestyle='--')

    # 在柱子上标注数值
    for bar in bars_recall:
        ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1,
                 f'{bar.get_height():.1f}', ha='center', va='bottom',
                 fontsize=7, fontweight='bold')
    for bar in bars_prec:
        ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1,
                 f'{bar.get_height():.1f}', ha='center', va='bottom',
                 fontsize=7, fontweight='bold')

# Panel 2: F1 Score
    ax2 = axes[1]
    bars_f1 = ax2.bar(x, f1_scores, width * 0.8, color=colors,
                      edgecolor='#333', linewidth=1.2)
    for i, bar in enumerate(bars_f1):
        if not real_mask[i]:
            bar.set_hatch('//')

    ax2.set_ylabel('F1 Score (%)')
    ax2.set_title('F1 Score (Harmonic Mean)', fontweight='bold')
    ax2.set_xticks(x)
    ax2.set_xticklabels(tools, fontsize=9)
    ax2.set_ylim(0, 100)
    ax2.grid(axis='y', alpha=0.3, linestyle='--')

    for bar in bars_f1:
        ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1,
                 f'{bar.get_height():.1f}', ha='center', va='bottom',
                 fontsize=8, fontweight='bold')

    # 图例
    legend_elements = [
        mpatches.Patch(facecolor='#2196F3', label='Measured'),
        mpatches.Patch(facecolor='#FF9800', hatch='//', label='Estimated'),
    ]
    ax2.legend(handles=legend_elements, loc='lower right', fontsize=8)

# Panel 3: Time per Sample (log scale)
    ax3 = axes[2]
    bar_colors_time = ['#2196F3' if t < 1000 else '#FF5722'
                       for t in time_ms]
    bars_time = ax3.bar(x, time_ms, width * 0.8, color=bar_colors_time,
                        edgecolor='#333', linewidth=1.2)
    for i, bar in enumerate(bars_time):
        if not real_mask[i]:
            bar.set_hatch('//')

    ax3.set_ylabel('Time per Sample (ms)')
    ax3.set_title('Analysis Speed (log scale)', fontweight='bold')
    ax3.set_xticks(x)
    ax3.set_xticklabels(tools, fontsize=9)
    ax3.set_yscale('log')
    ax3.grid(axis='y', alpha=0.3, linestyle='--')

    for bar in bars_time:
        label = f'{bar.get_height():.0f}' if bar.get_height() < 1000 \
                else f'{bar.get_height()/1000:.1f}s'
        if bar.get_height() >= 100000:
            label = f'{bar.get_height()/60000:.1f}m'
        ax3.text(bar.get_x() + bar.get_width()/2, bar.get_height() * 1.3,
                 label, ha='center', va='bottom', fontsize=7,
                 fontweight='bold')

    # 速度分界线
    ax3.axhline(y=1000, color='grey', linestyle='--', alpha=0.4)
    ax3.text(len(tools) - 0.2, 1200, '1s threshold', fontsize=7,
             color='grey', ha='right')

    plt.tight_layout()
    png_path = RESULTS_DIR / "comparison_chart.png"
    fig.savefig(str(png_path), dpi=150, bbox_inches='tight',
                facecolor='white', edgecolor='none')
    plt.close(fig)
    print(f"  Chart: {png_path}")
    return str(png_path)


def _generate_placeholder() -> str:
    """matplotlib不可用时生成文本替代."""
    placeholder = RESULTS_DIR / "comparison_chart.txt"
    content = """
Multi-Tool Comparison (text-only, matplotlib not available)
==========================================================

Recall & Precision:
    Tool          Recall%  Precision%
    DP-TVRA       74.3     100.0
    PatternMatch  85.0     40.0
    Mango(USENIX) 82.0     72.0   [ESTIMATED]
    Angr(S&P)     90.0     40.0   [ESTIMATED]
    Ghidra        85.0     65.0   [ESTIMATED]

F1 Score & Speed:
    Tool          F1       Time/sample
    DP-TVRA       85.3     45ms       <-- BEST overall
    PatternMatch  54.0     20ms
    Mango         77.0     3min       [ESTIMATED]
    Angr          55.0     3.2s       [ESTIMATED]
    Ghidra        74.0     4.5s       [ESTIMATED]
"""
    with open(placeholder, 'w') as f:
        f.write(content.strip())
    print(f"  Text chart: {placeholder}")
    return str(placeholder)


if __name__ == "__main__":
    p = plot_comparison()
    print(f"Done → {p}")
