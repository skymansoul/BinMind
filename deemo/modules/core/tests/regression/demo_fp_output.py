#!/usr/bin/env python3
# coding: utf-8
"""
FP reduction demo 输出工具 — ASCII 表格打印 + LaTeX 表生成 + JSON 导出.
"""

import json, os
from typing import List
from tests.regression.demo_fp_reduction import LayerResult


def print_layer_table(layers: List[LayerResult]):
    """打印逐层 FP 削减 ASCII 表格."""
    print()
    print('=' * 95)
    print('FP Reduction by Layer (cumulative)')
    print('=' * 95)
    header = (f'{"Layer":<22} {"In":>5} {"Out":>5} {"FP-Cut":>7} '
              f'{"TP-Retained":>12} {"FP%":>7} {"Cum.FP%":>8}')
    print(header)
    print('-' * 95)
    for l in layers:
        if l.name in ('L6_summary', 'FINAL', 'METRICS'):
            continue
        cum_str = f'{l.cumulative_reduction:.1%}' if l.cumulative_reduction > 0 else '-'
        print(f'{l.name:<22} {l.candidates_in:>5} {l.candidates_out:>5} '
              f'{l.fp_filtered:>7} {l.tp_retained:>12} '
              f'{l.reduction_pct:>6.1%} {cum_str:>8}')
    print('-' * 95)

    final_layer = [l for l in layers if l.name == 'FINAL']
    if final_layer:
        f = final_layer[0]
        tp, fp, fn = f.candidates_in, f.candidates_out, f.fp_filtered
        prec = tp / max(1, tp + fp)
        rec = tp / max(1, tp + fn)
        f1 = 2 * prec * rec / max(0.001, prec + rec)
        fp_rate = fp / max(1, fp + tp)
        print(f'\nFinal Metrics:')
        print(f'  TP={tp}  FP={fp}  FN={fn}')
        print(f'  Precision={prec:.1%}  Recall={rec:.1%}  F1={f1:.3f}  '
              f'FP_Rate={fp_rate:.1%}')
        print(f'  Overall FP Reduction: {(1-fp_rate):.1%}')


def generate_latex_layer_table(layers: List[LayerResult], output_path: str):
    """生成 LaTeX 格式的逐层过滤表."""
    lines = [
        '% Auto-generated FP reduction layer table',
        '\\begin{table}[htbp]',
        '  \\centering',
        '  \\caption{False Positive Reduction by Detection Layer}',
        '  \\label{tab:fp_reduction_layers}',
        '  \\begin{tabular}{lrrrrr}',
        '    \\toprule',
        '    \\textbf{Layer} & \\textbf{In} & \\textbf{Out} & '
        '\\textbf{FP Cut} & \\textbf{TP Ret.} & \\textbf{Cum.\\ FP} \\\\',
        '    \\midrule',
    ]
    for l in layers:
        if l.name in ('L6_summary', 'FINAL', 'METRICS'):
            continue
        cum = f'{l.cumulative_reduction:.1%}' if l.cumulative_reduction > 0 else '--'
        lines.append(
            f'    {l.name} & {l.candidates_in} & {l.candidates_out} & '
            f'{l.fp_filtered} & {l.tp_retained} & {cum} \\\\')
    lines.extend([
        '    \\bottomrule',
        '  \\end{tabular}',
        '\\end{table}',
    ])
    with open(output_path, 'w') as f:
        f.write('\n'.join(lines))
    print(f'LaTeX table: {output_path}')


def save_demo_json(layers: List[LayerResult], tp_initial: int,
                   fp_initial: int, output_dir: str):
    """保存原始数据为 JSON (供绘图)."""
    os.makedirs(output_dir, exist_ok=True)
    data = {
        'initial_tp': tp_initial, 'initial_fp': fp_initial,
        'layers': [
            {'name': l.name, 'in': l.candidates_in, 'out': l.candidates_out,
             'fp_cut': l.fp_filtered, 'tp_retained': l.tp_retained,
             'fp_reduction': l.reduction_pct}
            for l in layers if l.name not in ('L6_summary', 'FINAL', 'METRICS')
        ],
    }
    json_path = os.path.join(output_dir, 'fp_reduction_data.json')
    with open(json_path, 'w') as f:
        json.dump(data, f, indent=2)
    print(f'JSON data: {json_path}')
