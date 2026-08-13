"""多类型对比图 — 四类型 F1 对比子图矩阵.

创建: 2025-01-13
"""

from datetime import datetime
from pathlib import Path

_HAS_MPL = False
try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    _HAS_MPL = True
except ImportError:
    pass

try:
    from .plot_data import MIMO_DEFAULTS
except ImportError:
    from plot_data import MIMO_DEFAULTS


def plot_multi_type(output_dir: str = None, results_dir=None):
    """绘制四类型 F1 对比图 — 展示 MIMO v3.3.0 在各漏洞类型上的表现."""
    if not _HAS_MPL:
        print('[!] matplotlib 未安装, 跳过')
        return

    types = list(MIMO_DEFAULTS.keys())
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    axes = axes.flatten()

    for ax, vtype in zip(axes, types):
        tools_data = MIMO_DEFAULTS[vtype]
        tool_names = [t['tool'] for t in tools_data]
        f1_vals = [t['f1'] for t in tools_data]
        precision_vals = [t['precision'] for t in tools_data]
        recall_vals = [t['recall'] for t in tools_data]

        x = range(len(tool_names))
        w = 0.25
        ax.bar([i - w for i in x], recall_vals, w, label='Recall',
               color='#2196F3', alpha=0.85)
        ax.bar(x, precision_vals, w, label='Precision',
               color='#4CAF50', alpha=0.85)
        ax.bar([i + w for i in x], f1_vals, w, label='F1',
               color='#FF5722', alpha=0.85)

        ax.set_title(vtype.replace('_', ' ').title(), fontsize=12, fontweight='bold')
        ax.set_xticks(x)
        ax.set_xticklabels(tool_names, fontsize=9, rotation=15)
        ax.set_ylim(0, 115)
        ax.grid(axis='y', alpha=0.3)
        if vtype == 'heap_overflow':
            ax.legend(loc='lower right', fontsize=8)

    fig.suptitle('MIMO v3.3.0 — Multi-Type Vulnerability Detection Comparison\n'
                 'BinMind vs Angr / QEMU / Ghidra across 4 vulnerability classes',
                 fontsize=14, fontweight='bold')
    plt.tight_layout()

    out_dir = Path(output_dir or results_dir
                   or Path(__file__).resolve().parent / 'results')
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    path = str(out_dir / f'mimo_multi_type_{ts}.png')
    plt.savefig(path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f'多类型图表: {path}')
    return path
