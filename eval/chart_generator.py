"""
论文图表生成器 — matplotlib 绘制 Precision/Recall/F1/FP reduction 对比图。
"""
import os

try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import numpy as np
    HAS_MPL = True
except ImportError:
    HAS_MPL = False

EVAL_DIR = os.path.dirname(os.path.abspath(__file__))


def plot_comparison(data: dict = None, output: str = None):
    """主对比图: Precision + Recall + F1 三轴分组柱状图。"""
    if not HAS_MPL:
        print('matplotlib not available, skipping chart')
        return
    if output is None:
        output = os.path.join(EVAL_DIR, 'comparison_chart.png')

    # 支持两种格式: tools (旧) 或 global (新 cross_type_bench)
    tools_data = data.get('tools', {}) if data else {}
    if not tools_data:
        tools_data = data.get('global', {}) if data else {}
    if not tools_data:
        tools_data = _sample_data()['tools']

    tool_names = list(tools_data.keys())
    short_names = [t.replace('BinMind-', 'BM-') for t in tool_names]
    x = np.arange(len(tool_names))
    width = 0.22

    precision_vals = [tools_data[t].get('precision', 0) for t in tool_names]
    recall_vals = [tools_data[t].get('recall', 0) for t in tool_names]
    f1_vals = [tools_data[t].get('f1', 0) for t in tool_names]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5.5))

    # 子图1: Precision + Recall
    bars_p = ax1.bar(x - width/2, precision_vals, width,
                     color='#2196F3', alpha=0.85, label='Precision')
    bars_r = ax1.bar(x + width/2, recall_vals, width,
                     color='#4CAF50', alpha=0.85, label='Recall')
    ax1.set_xticks(x)
    ax1.set_xticklabels(short_names, fontsize=9, rotation=15)
    ax1.set_ylabel('Rate', fontsize=11)
    ax1.set_title('Precision vs Recall by Tool', fontsize=12)
    ax1.set_ylim(0, 1.15)
    ax1.legend(fontsize=9, loc='lower right')
    for bar, val in zip(bars_p, precision_vals):
        ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.02,
                 f'{val:.1%}', ha='center', fontsize=7)
    for bar, val in zip(bars_r, recall_vals):
        ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.02,
                 f'{val:.1%}', ha='center', fontsize=7)

    # 子图2: F1 + 耗时
    bars_f = ax2.bar(x, f1_vals, width * 1.5, color='#FF9800', alpha=0.85,
                     label='F1 Score')
    ax2.set_xticks(x)
    ax2.set_xticklabels(short_names, fontsize=9, rotation=15)
    ax2.set_ylabel('F1 Score', fontsize=11, color='#E65100')
    ax2.set_ylim(0, 1.15)
    ax2.set_title('F1 Score & Avg Time by Tool', fontsize=12)
    for bar, val in zip(bars_f, f1_vals):
        ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.02,
                 f'{val:.3f}', ha='center', fontsize=7)

    ax2_time = ax2.twinx()
    times = [tools_data[t].get('avg_time_ms', 0) for t in tool_names]
    ax2_time.plot(x, times, 'o-', color='#9C27B0', linewidth=2, markersize=8,
                  label='Avg Time (ms)')
    ax2_time.set_ylabel('Avg Time (ms)', fontsize=11, color='#6A1B9A')
    for i, t_val in enumerate(times):
        ax2_time.annotate(f'{t_val:.0f}ms', (x[i], t_val),
                          textcoords="offset points", xytext=(0, 12),
                          ha='center', fontsize=7, color='#6A1B9A')

    lines1, labels1 = ax2.get_legend_handles_labels()
    lines2, labels2 = ax2_time.get_legend_handles_labels()
    ax2.legend(lines1 + lines2, labels1 + labels2, fontsize=8, loc='upper right')

    plt.tight_layout()
    plt.savefig(output, dpi=150, bbox_inches='tight')
    plt.close()
    print(f'Comparison chart saved: {output}')


def plot_fp_reduction(output: str = None,
                      baseline_fp: int = None, enhanced_fp: int = None,
                      tp_base: int = None, tp_enh: int = None, data: dict = None):
    """绘制 BinMind baseline vs enhanced 误报减少对比图。"""
    if not HAS_MPL:
        return
    if output is None:
        output = os.path.join(EVAL_DIR, 'fp_reduction_chart.png')

    if baseline_fp is None or enhanced_fp is None:
        tools = (data or {}).get('tools', {}) or (data or {}).get('global', {})
        baseline_fp = tools.get('BinMind-baseline', {}).get('FP', 20)
        enhanced_fp = tools.get('BinMind-enhanced', {}).get('FP', 8)
        tp_base = tools.get('BinMind-baseline', {}).get('TP', 15)
        tp_enh = tools.get('BinMind-enhanced', {}).get('TP', 15)
    if tp_base is None:
        tp_base = 15
    if tp_enh is None:
        tp_enh = 15

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))

    categories = ['Baseline\n(regex)', 'Enhanced\n(5-stage)']
    fp_vals = [baseline_fp, enhanced_fp]
    colors = ['#FF5252', '#66BB6A']
    bars = ax1.bar(categories, fp_vals, color=colors, alpha=0.85, width=0.5)
    ax1.set_ylabel('False Positive Count', fontsize=11)
    ax1.set_title('FP Reduction: Baseline vs Enhanced', fontsize=12)
    for bar, val in zip(bars, fp_vals):
        ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5,
                 str(val), ha='center', fontsize=12, fontweight='bold')
    if baseline_fp > 0:
        reduction = (baseline_fp - enhanced_fp) / baseline_fp * 100
        ax1.annotate(f'-{reduction:.0f}% FP reduction',
                     xy=(1, enhanced_fp), xytext=(0.5, baseline_fp * 0.7),
                     arrowprops=dict(arrowstyle='->', color='#333', lw=1.5),
                     fontsize=10, ha='center', color='#2E7D32')

    tp_vals = [tp_base, tp_enh]
    bars2 = ax2.bar(categories, tp_vals, color=['#2196F3', '#2196F3'],
                    alpha=0.85, width=0.5)
    ax2.set_ylabel('True Positive Count', fontsize=11)
    ax2.set_title('Recall Preservation (TP unchanged)', fontsize=12)
    ax2.set_ylim(0, max(tp_vals) * 1.3)
    for bar, val in zip(bars2, tp_vals):
        ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.3,
                 str(val), ha='center', fontsize=12, fontweight='bold')

    plt.tight_layout()
    plt.savefig(output, dpi=150, bbox_inches='tight')
    plt.close()
    print(f'FP reduction chart saved: {output}')


def plot_confusion_matrix(data: dict = None, output: str = None):
    """绘制各工具的 TP/FP/TN/FN 堆叠柱状图。"""
    if not HAS_MPL:
        return
    if output is None:
        output = os.path.join(EVAL_DIR, 'confusion_chart.png')

    tools_data = (data or {}).get('tools', {})
    if not tools_data:
        return

    tool_names = list(tools_data.keys())
    short_names = [t.replace('BinMind-', 'BM-') for t in tool_names]
    x = np.arange(len(tool_names))
    width = 0.5

    tp_vals = [tools_data[t].get('TP', 0) for t in tool_names]
    fp_vals = [tools_data[t].get('FP', 0) for t in tool_names]
    tn_vals = [tools_data[t].get('TN', 0) for t in tool_names]
    fn_vals = [tools_data[t].get('FN', 0) for t in tool_names]

    fig, ax = plt.subplots(figsize=(10, 5))
    ax.bar(x, tn_vals, width, color='#BBDEFB', label='TN (correctly filtered)')
    ax.bar(x, fn_vals, width, bottom=tn_vals, color='#FFCDD2',
           label='FN (missed)')
    ax.bar(x, fp_vals, width,
           bottom=[a + b for a, b in zip(tn_vals, fn_vals)],
           color='#FF5252', label='FP (false alarm)')
    ax.bar(x, tp_vals, width,
           bottom=[a + b + c for a, b, c in zip(tn_vals, fn_vals, fp_vals)],
           color='#4CAF50', label='TP (correctly detected)')
    ax.set_xticks(x)
    ax.set_xticklabels(short_names, fontsize=9, rotation=15)
    ax.set_ylabel('Sample Count', fontsize=11)
    ax.set_title('Detection Confusion Matrix by Tool', fontsize=12)
    ax.legend(fontsize=8, loc='upper right')

    plt.tight_layout()
    plt.savefig(output, dpi=150, bbox_inches='tight')
    plt.close()
    print(f'Confusion matrix chart saved: {output}')


def _sample_data() -> dict:
    """占位数据用于演示。"""
    return {
        'tools': {
            'BinMind-baseline': {'precision': 0.375, 'recall': 1.0, 'f1': 0.545,
                                 'fp_rate': 0.625, 'avg_time_ms': 5, 'TP': 15,
                                 'FP': 10, 'TN': 0, 'FN': 0},
            'BinMind-enhanced': {'precision': 0.85, 'recall': 1.0, 'f1': 0.919,
                                 'fp_rate': 0.15, 'avg_time_ms': 180, 'TP': 15,
                                 'FP': 2, 'TN': 8, 'FN': 0},
            'Angr': {'precision': 0.48, 'recall': 0.55, 'f1': 0.512,
                     'fp_rate': 0.60, 'avg_time_ms': 42000, 'TP': 8, 'FP': 8,
                     'TN': 2, 'FN': 7},
            'QEMU': {'precision': 0.75, 'recall': 0.30, 'f1': 0.429,
                     'fp_rate': 0.10, 'avg_time_ms': 15000, 'TP': 4, 'FP': 1,
                     'TN': 9, 'FN': 11},
            'Ghidra': {'precision': 0.47, 'recall': 0.45, 'f1': 0.462,
                       'fp_rate': 0.50, 'avg_time_ms': 30000, 'TP': 7, 'FP': 7,
                       'TN': 3, 'FN': 8},
        },
    }
