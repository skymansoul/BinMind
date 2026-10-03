#!/usr/bin/env python3
"""
ASIP源码级消融实验 — 量化五引擎(E1-E5)对误报削减的增量贡献.

六种配置逐引擎启用:
  B0: 无引擎(全部报VULN) — 基线FP率
  B1: +E1 guard过滤
  B2: +E2 clamp过滤
  B3: +E3 路径条件
  B4: +E4 alloc=write配对
  B5: +E5 取模保护
  B6: Full(全引擎) — 完整ASIP v5

在55个堆溢出样本上运行, 计算P/R/F1/FPR.

拆分: 配置→asip_ablation_config, 引擎评估→asip_ablation_engine
"""
from __future__ import annotations

import sys
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind")
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind\deemo")

from typing import Dict, List

from eval.asip_ablation_config import AblationConfig, CONFIGS
from eval.asip_ablation_engine import _evaluate_write_ablation
from eval.asip_cve_samples import ALL_SAMPLES

from core.asip_source_extract import (
    _extract_allocs, _extract_guard_limits,
    _extract_clamp_limits, _extract_loop_bounds, _extract_reallocs,
    _extract_cross_function_writes, _extract_modulo_protections,
    _extract_alloc_size_var, _extract_path_conditions,
)
from core.asip_source_writes import _extract_writes


def run_ablation_config(
    cfg: AblationConfig, samples,
) -> Dict:
    """在样本集上运行指定配置, 返回指标."""
    tp, fp, fn, tn = 0, 0, 0, 0
    details = []

    for name, source, expected in samples:
        expected_vuln = (expected == 'VULN')
        lines = source.strip().split('\n')
        allocs = _extract_allocs(lines)
        if not allocs:
            detected = False
        else:
            guard_limits = _extract_guard_limits(lines)
            clamp_limits = _extract_clamp_limits(lines)
            loop_bounds = _extract_loop_bounds(lines)
            reallocs = _extract_reallocs(lines)
            cross_writes = _extract_cross_function_writes(lines)
            modulo_protected = _extract_modulo_protections(lines)
            alloc_var_to_size_var = _extract_alloc_size_var(lines)
            path_conditions = _extract_path_conditions(lines)

            candidates = []
            for alloc in allocs:
                effective_size = alloc.size_arg
                if alloc.result_var in reallocs:
                    effective_size = reallocs[alloc.result_var]
                writes = _extract_writes(lines, alloc)
                if alloc.result_var in cross_writes:
                    for cw in cross_writes[alloc.result_var]:
                        writes.append(cw)
                for store, write_size in writes:
                    cand = _evaluate_write_ablation(
                        alloc, store, write_size, effective_size,
                        guard_limits, clamp_limits, loop_bounds,
                        alloc_var_to_size_var, modulo_protected,
                        path_conditions, cfg,
                    )
                    if cand is not None:
                        candidates.append(cand)

            detected = len(candidates) > 0

        ok = (detected == expected_vuln)
        if expected_vuln and detected:
            tp += 1
        elif not expected_vuln and not detected:
            tn += 1
        elif expected_vuln and not detected:
            fn += 1
        elif not expected_vuln and detected:
            fp += 1

        details.append((name, expected, detected, ok))

    # 计算指标
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    return {
        'config': cfg.name,
        'tp': tp, 'fp': fp, 'fn': fn, 'tn': tn,
        'precision': prec, 'recall': rec, 'f1': f1, 'fpr': fpr,
        'details': details,
    }


def main():
    """运行全部配置并输出结果."""
    print("=" * 72)
    print("ASIP源码级消融实验: 五引擎(E1-E5)增量贡献")
    print("=" * 72)

    results = []
    for cfg in CONFIGS:
        result = run_ablation_config(cfg, ALL_SAMPLES)
        results.append(result)
        r = result
        print(f"\n  {r['config']:25s}  P={r['precision']:.4f}  "
              f"R={r['recall']:.4f}  F1={r['f1']:.4f}  "
              f"FPR={r['fpr']:.4f}  "
              f"(TP={r['tp']} FP={r['fp']} FN={r['fn']} TN={r['tn']})")

    # 逐配置增量分析
    print("\n" + "=" * 72)
    print("引擎增量贡献:")
    print("-" * 72)
    _print_deltas(results)

    # 识别关键引擎
    deltas = _compute_deltas(results)
    max_idx = deltas.index(max(deltas[1:], default=0)) + 1
    print(f"\n  关键引擎: {CONFIGS[max_idx].name} "
          f"(ΔF1={deltas[max_idx]:+.4f})")

    _write_latex(results)
    print("\n消融实验完成.")


def _compute_deltas(results):
    deltas = []
    prev = 0.0
    for r in results:
        deltas.append(r['f1'] - prev)
        prev = r['f1']
    return deltas


def _print_deltas(results):
    prev_f1 = 0.0
    for i, r in enumerate(results):
        delta = r['f1'] - prev_f1
        name = CONFIGS[i].name
        if i == 0:
            print(f"  {name:25s}  F1={r['f1']:.4f}  (基线)")
        else:
            print(f"  {name:25s}  F1={r['f1']:.4f}  ΔF1={delta:+.4f}")
        prev_f1 = r['f1']


def _write_latex(results: List[Dict]):
    """生成LaTeX消融表格."""
    lines = [
        r'\begin{table}[htbp]',
        r'\centering',
        r'\caption{ASIP源码级消融实验: 五引擎增量贡献 (55样本)}',
        r'\label{tab:asip_ablation}',
        r'\begin{tabular}{lrrrrrr}',
        r'\toprule',
        r'配置 & TP & FP & FN & TN & F1 & FPR \\',
        r'\midrule',
    ]
    for r in results:
        lines.append(
            f"{r['config']} & {r['tp']} & {r['fp']} & {r['fn']} "
            f"& {r['tn']} & {r['f1']:.4f} & {r['fpr']:.4f} \\\\"
        )
    lines.extend([
        r'\bottomrule',
        r'\end{tabular}',
        r'\end{table}',
    ])
    out_path = r"C:\Users\Administrator\Desktop\BinMind\deemo\eval\asip_ablation_table.tex"
    with open(out_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))
    print(f"  LaTeX表格已写入: {out_path}")


if __name__ == '__main__':
    main()
