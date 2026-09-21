"""
CVE样本多工具对比基准 — BinMind vs Angr vs 正则基线.

在 16 个 CVE 堆溢出样本上运行对比:
  BinMind-Full  — 完整C源码管线 (source_scanner + 仿射边界验证 + 守卫推断)
  Regex-Base   — 纯正则基线 (模拟 Flawfinder 的简单模式匹配)
  Heuristic    — 启发式: malloc附近有memcpy且size不匹配

输出: JSON/CSV/LaTeX 表 + matplotlib 图表.
"""

import os, sys, json, time, csv
from pathlib import Path
from typing import List

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)
CVE_ROOT = os.path.join(BASE, 'samples', 'cve_heap_overflow')
OUT_DIR  = os.path.join(BASE, 'eval')

from eval.cve_multi_tool_tools import (
    run_binmind_csa, run_regex_baseline, run_heuristic,
    run_angr_if_available, compute_metrics, compile_cve_sample,
)


# 主流程

def main():
    print('=' * 72)
    print('CVE 样本多工具对比基准测试')
    print('=' * 72)

    # 发现CVE样本
    samples = []
    for d in sorted(Path(CVE_ROOT).iterdir()):
        if not d.is_dir():
            continue
        c_files = list(d.glob('*.c'))
        if not c_files:
            continue
        samples.append({
            'name': d.name,
            'src_path': str(c_files[0]),
            'binary_path': str(d / (d.name.replace('cve_', '') + '.exe')),
        })

    print(f'\n发现 {len(samples)} 个 CVE 样本')
    tools = ['BinMind-Full', 'Regex-Base', 'Heuristic', 'Angr-CFG']
    print(f'工具: {", ".join(tools)}')

    all_results = {t: [] for t in tools}

    for i, s in enumerate(samples):
        name = s['name']
        # 读源码
        try:
            with open(s['src_path'], encoding='utf-8', errors='replace') as f:
                source = f.read()
        except Exception as e:
            print(f'  [{i+1:2d}/{len(samples)}] ERROR: {name}: {e}')
            continue

        # 运行所有工具
        binary_path = s['binary_path']
        r1 = run_binmind_csa(source, name, binary_path)
        r2 = run_regex_baseline(source, name)
        r3 = run_heuristic(source, name)

        # Angr需要编译
        if not os.path.exists(binary_path):
            compile_cve_sample(s['src_path'], binary_path)
        r4 = run_angr_if_available(binary_path, name)

        all_results['BinMind-Full'].append(r1)
        all_results['Regex-Base'].append(r2)
        all_results['Heuristic'].append(r3)
        all_results['Angr-CFG'].append(r4)

        # 打印进度
        markers = [
            '!' if r1.get('detected') else ' ',
            '!' if r2.get('detected') else ' ',
            '!' if r3.get('detected') else ' ',
            '!' if r4.get('detected') else ' ',
        ]
        print(f'  [{i+1:2d}/{len(samples)}] '
              f'BinMind={markers[0]} Regex={markers[1]} '
              f'Heur={markers[2]} Angr={markers[3]} '
              f'{name}')

    # 计算并打印指标
    print(f'\n{"=" * 72}')
    print('对比结果')
    print(f'{"=" * 72}')

    header = (f'{"Tool":<20s} {"TP":>4s} {"FN":>4s} '
              f'{"Recall":>7s} {"Prec":>7s} {"F1":>7s} {"Avg ms":>8s}')
    print(header)
    print('-' * len(header))

    all_metrics = {}
    for tool in tools:
        m = compute_metrics(all_results[tool])
        all_metrics[tool] = m
        avg_ms = int(sum(r.get('duration_ms', 0) for r in all_results[tool])
                     / max(len(all_results[tool]), 1))
        print(f'{tool:<20s} {m["TP"]:>4d} {m["FN"]:>4d} '
              f'{m["recall"]:>6.1%} {m["precision"]:>6.1%} '
              f'{m["f1"]:>7.4f} {avg_ms:>7d}')

    # 保存输出
    timestamp = time.strftime('%Y%m%d_%H%M%S')
    _save_outputs(all_metrics, all_results, timestamp)
    _generate_cve_chart(all_metrics, all_results, timestamp)

    return all_metrics


def _save_outputs(all_metrics, all_results, timestamp):
    """保存 JSON / CSV / LaTeX."""
    json_path = os.path.join(OUT_DIR, f'cve_multi_tool_{timestamp}.json')
    with open(json_path, 'w') as f:
        json.dump({
            'metrics': all_metrics,
            'results': {t: [{k: v for k, v in r.items() if k != 'details'}
                           for r in all_results[t]]
                        for t in all_results},
            'generated_at': time.strftime('%Y-%m-%d %H:%M:%S'),
        }, f, indent=2, ensure_ascii=False)

    csv_path = os.path.join(OUT_DIR, f'cve_multi_tool_{timestamp}.csv')
    with open(csv_path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Tool', 'TP', 'FN', 'Recall', 'Precision', 'F1'])
        for tool, m in all_metrics.items():
            writer.writerow([tool, m['TP'], m['FN'],
                            f"{m['recall']:.4f}", f"{m['precision']:.4f}",
                            f"{m['f1']:.4f}"])

    tex_path = os.path.join(OUT_DIR, f'cve_multi_tool_table_{timestamp}.tex')
    with open(tex_path, 'w') as f:
        f.write(r'\begin{table}[htbp]' + '\n')
        f.write(r'\centering' + '\n')
        f.write(r'\caption{CVE Heap Overflow: Multi-Tool Detection Comparison}' + '\n')
        f.write(r'\label{tab:cve-multi-tool}' + '\n')
        f.write(r'\begin{tabular}{lrrrrr}' + '\n')
        f.write(r'\toprule' + '\n')
        f.write(r'Tool & TP & FN & Recall & Precision & F1 \\' + '\n')
        f.write(r'\midrule' + '\n')
        for tool in ['BinMind-Full', 'Regex-Base', 'Heuristic', 'Angr-CFG']:
            m = all_metrics[tool]
            f.write(f'{tool} & {m["TP"]} & {m["FN"]} & '
                    f'{m["recall"]:.1%} & {m["precision"]:.1%} & '
                    f'{m["f1"]:.4f} \\\\\n')
        f.write(r'\bottomrule' + '\n')
        f.write(r'\end{tabular}' + '\n')
        f.write(r'\end{table}' + '\n')

    print(f'\n报告已保存:')
    print(f'  JSON: {json_path}')
    print(f'  CSV:  {csv_path}')
    print(f'  LaTeX: {tex_path}')


def _generate_cve_chart(all_metrics, all_results, timestamp):
    """生成对比图表."""
    try:
        from eval.cve_multi_tool_chart import generate_cve_chart
        generate_cve_chart(all_metrics, all_results, timestamp, OUT_DIR)
    except ImportError:
        print('  (matplotlib 不可用, 跳过图表生成)')


if __name__ == '__main__':
    main()
