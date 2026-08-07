"""
GAPSBV 七阶段消融基准测试 — 在全部堆样本上逐阶段测量FP削减效果.

与 gapsbv_benchmark.py 的关系:
  - gapsbv_benchmark: baseline(regex) vs enhanced(unified_pipeline) 二分类对比
  - 本脚本: 七阶段级联, 逐阶段统计, 生成消融表 (论文 Table 2)
  - 直接消费 analysis.fp_reduction_integrator.FPReductionIntegrator

与 validate_fp_reduction.py 的关系:
  - validate_fp_reduction: 17样本精确回归 (ground truth字典)
  - 本脚本: 大规模自动标注 (启发式ground truth), 全量137样本

输出: eval/gapsbv_ablation.json + eval/gapsbv_ablation_table.tex
"""

from __future__ import annotations

import json, os, sys, time
from typing import Dict, List

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

from eval.gapsbv_ablation_helpers import (
    SampleMeta, discover_heap_samples, apply_stage as _apply_stage,
    get_source_lines as _get_source_lines,
    compute_cross_fp as _compute_cross_fp,
    generate_latex_table as _generate_latex_table,
)


def run_gapsbv_ablation(samples: List[SampleMeta] = None) -> Dict:
    """运行 GAPSBV 七阶段消融基准测试.

    对每个样本: 运行 c_source_analyzer → FPReductionIntegrator.run()
    逐阶段记录 TP/FP/TN/FN.
    """
    if samples is None:
        samples = discover_heap_samples()

    from analysis.c_source_conservative import analyze_c_source_conservative
    from analysis.fp_reduction_integrator import FPReductionIntegrator, StageStats

    integrator = FPReductionIntegrator()
    stage_names = [
        'S0_Baseline', 'S1_AllocatorSemantics', 'S2_GuardAwareWrites',
        'S3_SizeConstraints', 'S4_ProofObligations',
        'S5_SlackSpace', 'S6_ValueRange', 'S7_NonHeapFilter',
    ]
    stages: List[StageStats] = []

    # 收集所有样本的候选
    all_candidates: Dict[str, List] = {}
    sample_results: Dict[str, Dict] = {}
    total_evaluated = 0

    for s in samples:
        candidates = analyze_c_source_conservative(s.source)
        all_candidates[s.name] = candidates
        if candidates:
            total_evaluated += 1
        sample_results[s.name] = {
            'name': s.name, 'is_vuln': s.is_vuln,
            'vuln_type': s.vuln_type,
            'baseline_count': len(candidates),
            'stage_counts': [],
            'final_count': 0,
        }

    print(f'Discovered {len(samples)} samples, {total_evaluated} with candidates')

    # S0: 基线
    s0 = StageStats(name='S0_Baseline', input_count=0)
    s0.output_count = sum(len(v) for v in all_candidates.values())
    for name, candidates in all_candidates.items():
        meta = sample_results[name]
        if meta['is_vuln'] and candidates:
            s0.tp_retained += 1
        elif not meta['is_vuln'] and candidates:
            s0.tp_retained += 0  # FP
    stages.append(s0)

    # 逐阶段运行
    current = dict(all_candidates)
    for stage_idx in range(1, 8):
        s = StageStats(name=stage_names[stage_idx])
        next_candidates: Dict[str, List] = {}
        total_hard = 0
        total_soft = 0

        for name, candidates in current.items():
            if not candidates:
                next_candidates[name] = []
                continue
            src_lines = _get_source_lines(samples, name)

            # 运行对应阶段 (C源码版)
            filtered, hard, soft = _apply_stage(
                integrator, stage_idx, candidates, src_lines)
            next_candidates[name] = filtered
            total_hard += hard
            total_soft += soft

        s.input_count = sum(len(v) for v in current.values())
        s.output_count = sum(len(v) for v in next_candidates.values())
        s.hard_filtered = s.input_count - s.output_count
        s.soft_adjusted = total_soft

        # 逐样本分类
        for name, filtered in next_candidates.items():
            meta = sample_results[name]
            before = current.get(name, [])
            meta['stage_counts'].append(len(filtered))

            if meta['is_vuln']:
                if filtered:
                    s.tp_retained += 1
                # else: TP被过滤 = 潜在漏报 (保守: 应保留)
            else:
                if not filtered and before:
                    s.fp_removed += 1  # FP被正确过滤

        stages.append(s)
        current = next_candidates

    # 计算每个阶段的完整指标
    total_vuln = sum(1 for s in samples if s.is_vuln)
    total_safe = sum(1 for s in samples if not s.is_vuln)

    stage_metrics = []
    for s in stages:
        tp = s.tp_retained
        out = s.output_count
        fp = out - tp
        fn = total_vuln - tp
        tn = total_safe - fp
        precision = tp / out if out > 0 else 0.0
        recall = tp / total_vuln if total_vuln > 0 else 0.0
        f1 = (2 * precision * recall / (precision + recall)
              if (precision + recall) > 0 else 0.0)

        stage_metrics.append({
            'stage': s.name,
            'input_count': s.input_count,
            'output_count': s.output_count,
            'hard_filtered': s.hard_filtered,
            'soft_adjusted': s.soft_adjusted,
            'TP': tp, 'FP': fp, 'TN': tn, 'FN': fn,
            'precision': round(precision, 4),
            'recall': round(recall, 4),
            'f1': round(f1, 4),
            'fp_removed': s.fp_removed,
        })

    # 按样本类型的交叉误报统计
    cross_fp = _compute_cross_fp(sample_results, samples)

    return {
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'total_samples': len(samples),
        'vuln_samples': total_vuln,
        'safe_samples': total_safe,
        'stages': stage_metrics,
        'cross_fp_analysis': cross_fp,
        'per_sample': list(sample_results.values()),
    }



def main():
    print('GAPSBV Seven-Stage Ablation Benchmark')
    print('=' * 60)

    samples = discover_heap_samples()
    print(f'Discovered {len(samples)} heap-related samples')

    report = run_gapsbv_ablation(samples)

    out_json = os.path.join(BASE, 'eval', 'gapsbv_ablation.json')
    with open(out_json, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    out_tex = os.path.join(BASE, 'eval', 'gapsbv_ablation_table.tex')
    _generate_latex_table(report, out_tex)

    # 控制台输出
    print(f"\n{'Stage':<24} {'In':>4} {'Out':>4} {'Hard':>4} {'Soft':>4} "
          f"{'TP':>4} {'FP':>4} {'TN':>4} {'FN':>4} "
          f"{'Prec':>7} {'Recall':>7} {'F1':>7}")
    print('-' * 82)
    for s in report['stages']:
        print(f"{s['stage']:<24} {s['input_count']:>4} {s['output_count']:>4} "
              f"{s['hard_filtered']:>4} {s['soft_adjusted']:>4} "
              f"{s['TP']:>4} {s['FP']:>4} "
              f"{s['TN']:>4} {s['FN']:>4} "
              f"{s['precision']:>7.4f} {s['recall']:>7.4f} {s['f1']:>7.4f}")

    print(f"\nJSON → {out_json}")
    print(f"LaTeX → {out_tex}")

    return 0


if __name__ == '__main__':
    sys.exit(main())
