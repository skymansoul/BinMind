"""
PC-BVF综合对比实验: 整合消融数据+多工具数据, 生成论文级对比表和图表.

输出:
  - pcbvf_comprehensive_comparison.csv  (CSV对比表)
  - pcbvf_comprehensive_comparison.json (JSON完整数据)
  - pcbvf_comprehensive_chart.png       (论文级图表)
  - pcbvf_comparison_table.tex          (LaTeX表格)
"""
import os, sys, json, csv
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS_DIR = os.path.join(BASE, 'eval', 'results')
EVAL_DIR = os.path.join(BASE, 'eval')

# 数据源1: PC-BVF消融实验
import io

def _load_json(path):
    """安全加载JSON(处理编码)."""
    if not os.path.exists(path):
        return {}
    with open(path, 'r', encoding='utf-8', errors='replace') as f:
        return json.load(f)

pcbvf_ablation = _load_json(os.path.join(RESULTS_DIR, 'ablation_pcbvf.json'))

# 数据源2: BVF消融实验(已有)
bvf_ablation_path = os.path.join(EVAL_DIR, 'ablation_study.json')
bvf_data = _load_json(bvf_ablation_path)

# 数据源3: 已有多工具对比(123样本)
multi_tool_path = os.path.join(EVAL_DIR, 'final_multi_tool_comparison.json')
multi_tool = _load_json(multi_tool_path)

# 数据源4: 40 CVE样本多工具对比
cve_tool_path = os.path.join(EVAL_DIR, 'cve_multi_tool_20260808_224241.json')
cve_tool = _load_json(cve_tool_path)


def build_comparison():
    """构建综合对比数据."""
    comparison = {
        'pcbvf_ablation': pcbvf_ablation['metrics'],
        'bvf_ablation': None,
        'multi_tool_123': None,
        'cve_multi_tool_16': None,
    }

    # BVF消融数据
    bvf_abl_path = os.path.join(RESULTS_DIR, 'ablation_bvf.json')
    if os.path.exists(bvf_abl_path):
        bvf = json.load(open(bvf_abl_path))
        if 'metrics' in bvf:
            comparison['bvf_ablation'] = bvf['metrics']

    # 123样本多工具
    if multi_tool and 'tools' in multi_tool:
        comparison['multi_tool_123'] = multi_tool['tools']

    # 16 CVE样本多工具
    if cve_tool and 'metrics' in cve_tool:
        comparison['cve_multi_tool_16'] = cve_tool['metrics']

    return comparison


def save_csv(comparison):
    """保存CSV: PC-BVF消融对比."""
    path = os.path.join(RESULTS_DIR, 'pcbvf_comprehensive_comparison.csv')
    with open(path, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['Configuration', 'TP', 'FP', 'TN', 'FN',
                    'Precision', 'Recall', 'F1', 'FPR'])
        for cfg in ['Baseline', 'CJ', 'CJ+BVF', 'CJ+BVF+PC-BVF']:
            m = comparison['pcbvf_ablation'][cfg]
            w.writerow([cfg, m['tp'], m['fp'], m['tn'], m['fn'],
                        f"{m['precision']:.4f}", f"{m['recall']:.4f}",
                        f"{m['f1']:.4f}", f"{m['fpr']:.4f}"])

        # 追加123样本对比
        if comparison.get('multi_tool_123'):
            w.writerow([])
            w.writerow(['--- 123-Sample Cross-Type Comparison ---'])
            w.writerow(['Tool', 'TP', 'FP', 'TN', 'FN',
                        'Precision', 'Recall', 'F1', 'FPR', 'Avg_ms'])
            for tool, m in comparison['multi_tool_123'].items():
                w.writerow([tool, m['tp_count'], m['fp_count'],
                            m['tn_count'], m['fn_count'],
                            f"{m['precision']:.3f}", f"{m['recall']:.3f}",
                            f"{m['f1']:.3f}", f"{m['fp_rate']:.3f}",
                            m['avg_time_ms']])

    print(f'CSV saved: {path}')
    return path


def save_json(comparison):
    """保存JSON."""
    path = os.path.join(RESULTS_DIR, 'pcbvf_comprehensive_comparison.json')
    with open(path, 'w') as f:
        json.dump(comparison, f, indent=2, ensure_ascii=False)
    print(f'JSON saved: {path}')
    return path


def save_latex(comparison):
    """保存LaTeX表格."""
    path = os.path.join(RESULTS_DIR, 'pcbvf_comparison_table.tex')
    with open(path, 'w') as f:
        # 表1: PC-BVF消融
        f.write(r'\begin{table}[htbp]' + '\n')
        f.write(r'\centering' + '\n')
        f.write(r'\caption{PC-BVF Ablation Study (12 samples: 4 VULN + 8 SAFE)}' + '\n')
        f.write(r'\label{tab:pcbvf-ablation}' + '\n')
        f.write(r'\begin{tabular}{lrrrrrrr}' + '\n')
        f.write(r'\toprule' + '\n')
        f.write(r'Config & TP & FP & TN & FN & Prec. & Rec. & F1 \\' + '\n')
        f.write(r'\midrule' + '\n')
        for cfg in ['Baseline', 'CJ', 'CJ+BVF', 'CJ+BVF+PC-BVF']:
            m = comparison['pcbvf_ablation'][cfg]
            f.write(f'{cfg} & {m["tp"]} & {m["fp"]} & {m["tn"]} & {m["fn"]} '
                    f'& {m["precision"]:.2f} & {m["recall"]:.2f} '
                    f'& {m["f1"]:.2f} \\\\\n')
        f.write(r'\bottomrule' + '\n')
        f.write(r'\end{tabular}' + '\n')
        f.write(r'\end{table}' + '\n\n')

        # 表2: 多工具123样本
        if comparison.get('multi_tool_123'):
            f.write(r'\begin{table}[htbp]' + '\n')
            f.write(r'\centering' + '\n')
            f.write(r'\caption{Multi-Tool Comparison (123 samples)}' + '\n')
            f.write(r'\label{tab:multi-tool-123}' + '\n')
            f.write(r'\begin{tabular}{lrrrrrr}' + '\n')
            f.write(r'\toprule' + '\n')
            f.write(r'Tool & TP & FP & TN & FN & F1 & Avg ms \\' + '\n')
            f.write(r'\midrule' + '\n')
            for tool, m in comparison['multi_tool_123'].items():
                f.write(f'{tool} & {m["tp_count"]} & {m["fp_count"]} '
                        f'& {m["tn_count"]} & {m["fn_count"]} '
                        f'& {m["f1"]:.3f} & {m["avg_time_ms"]} \\\\\n')
            f.write(r'\bottomrule' + '\n')
            f.write(r'\end{tabular}' + '\n')
            f.write(r'\end{table}' + '\n')

    print(f'LaTeX saved: {path}')
    return path


def generate_chart(comparison):
    """生成论文级综合图表."""
    fig, axes = plt.subplots(1, 3, figsize=(18, 5.5))

    # (a) PC-BVF消融: P/R/F1/FPR
    ax = axes[0]
    configs = ['Baseline', 'CJ', 'CJ+BVF', 'CJ+BVF+PC-BVF']
    metrics_data = comparison['pcbvf_ablation']
    x = np.arange(len(configs))
    width = 0.2
    precisions = [metrics_data[c]['precision'] for c in configs]
    recalls = [metrics_data[c]['recall'] for c in configs]
    f1s = [metrics_data[c]['f1'] for c in configs]
    fprs = [metrics_data[c]['fpr'] for c in configs]

    ax.bar(x - 1.5*width, precisions, width, label='Precision', color='#2196F3', alpha=0.85)
    ax.bar(x - 0.5*width, recalls, width, label='Recall', color='#4CAF50', alpha=0.85)
    ax.bar(x + 0.5*width, f1s, width, label='F1', color='#FF9800', alpha=0.85)
    ax.bar(x + 1.5*width, fprs, width, label='FPR', color='#F44336', alpha=0.85)
    ax.set_ylabel('Score')
    ax.set_title('(a) PC-BVF Ablation (12 samples)')
    ax.set_xticks(x)
    ax.set_xticklabels(configs, rotation=20, ha='right', fontsize=8)
    ax.legend(fontsize=7, loc='upper left')
    ax.set_ylim(-0.05, 1.15)
    for i, (p, r, f1, fpr) in enumerate(zip(precisions, recalls, f1s, fprs)):
        for val, off in [(p, -1.5), (r, -0.5), (f1, 0.5), (fpr, 1.5)]:
            if val > 0:
                ax.text(i + off*width, val + 0.02, f'{val:.1f}',
                        ha='center', fontsize=6)

    # (b) PC-BVF消融: TP/FP/TN/FN
    ax = axes[1]
    tps = [metrics_data[c]['tp'] for c in configs]
    fps = [metrics_data[c]['fp'] for c in configs]
    tns = [metrics_data[c]['tn'] for c in configs]
    fns = [metrics_data[c]['fn'] for c in configs]
    ax.bar(x - 1.5*width, tps, width, label='TP', color='#4CAF50')
    ax.bar(x - 0.5*width, fps, width, label='FP', color='#F44336')
    ax.bar(x + 0.5*width, tns, width, label='TN', color='#2196F3')
    ax.bar(x + 1.5*width, fns, width, label='FN', color='#FF9800')
    ax.set_ylabel('Count')
    ax.set_title('(b) Confusion Matrix per Config')
    ax.set_xticks(x)
    ax.set_xticklabels(configs, rotation=20, ha='right', fontsize=8)
    ax.legend(fontsize=7)
    ax.set_ylim(0, 13)
    for i, (tp, fp, tn, fn) in enumerate(zip(tps, fps, tns, fns)):
        for val, off in [(tp, -1.5), (fp, -0.5), (tn, 0.5), (fn, 1.5)]:
            if val > 0:
                ax.text(i + off*width, val + 0.15, str(val),
                        ha='center', fontsize=7, fontweight='bold')

    # (c) 123样本多工具F1对比
    ax = axes[2]
    if comparison.get('multi_tool_123'):
        tools = list(comparison['multi_tool_123'].keys())
        f1_vals = [comparison['multi_tool_123'][t]['f1'] for t in tools]
        fpr_vals = [comparison['multi_tool_123'][t]['fp_rate'] for t in tools]
        x2 = np.arange(len(tools))
        width2 = 0.35
        bars1 = ax.bar(x2 - width2/2, f1_vals, width2, label='F1', color='#4CAF50', alpha=0.85)
        bars2 = ax.bar(x2 + width2/2, fpr_vals, width2, label='FPR', color='#F44336', alpha=0.85)
        ax.set_ylabel('Score')
        ax.set_title('(c) Multi-Tool Comparison (123 samples)')
        ax.set_xticks(x2)
        ax.set_xticklabels(tools, rotation=15, ha='right', fontsize=7)
        ax.legend(fontsize=8)
        ax.set_ylim(-0.05, 1.15)
        for bar, val in zip(bars1, f1_vals):
            ax.text(bar.get_x() + bar.get_width()/2, val + 0.02,
                    f'{val:.2f}', ha='center', fontsize=7)
        for bar, val in zip(bars2, fpr_vals):
            if val > 0:
                ax.text(bar.get_x() + bar.get_width()/2, val + 0.02,
                        f'{val:.2f}', ha='center', fontsize=7)
    else:
        ax.text(0.5, 0.5, 'No multi-tool data', ha='center', va='center',
                transform=ax.transAxes)
        ax.set_title('(c) Multi-Tool Comparison')

    plt.tight_layout()
    path = os.path.join(RESULTS_DIR, 'pcbvf_comprehensive_chart.png')
    plt.savefig(path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f'Chart saved: {path}')
    return path


def main():
    print('=' * 72)
    print('PC-BVF Comprehensive Comparison Generator')
    print('=' * 72)

    comparison = build_comparison()

    csv_path = save_csv(comparison)
    json_path = save_json(comparison)
    tex_path = save_latex(comparison)
    chart_path = generate_chart(comparison)

    print(f'\nAll outputs generated in: {RESULTS_DIR}')
    print(f'  CSV:   {os.path.basename(csv_path)}')
    print(f'  JSON:  {os.path.basename(json_path)}')
    print(f'  LaTeX: {os.path.basename(tex_path)}')
    print(f'  Chart: {os.path.basename(chart_path)}')


if __name__ == '__main__':
    main()
