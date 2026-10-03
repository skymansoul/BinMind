"""DRIFT UAF回归测试 — 编译→扫描→收集→报告.

支持从C源码编译样本或直接分析已有二进制.
输出Markdown + JSON报告, 计算precision/recall/F1.

创建: 2024-09-02
"""
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Tuple

_cur_dir = os.path.dirname(os.path.abspath(__file__))
if _cur_dir not in sys.path:
    sys.path.insert(0, _cur_dir)

from .drift_orchestrator import analyze_uaf, DriftReport
from .ground_truth import UAF_GROUND_TRUTH, get_available_samples

PROJ_ROOT = Path(__file__).resolve().parent.parent.parent.parent.parent
OUTPUT_DIR = PROJ_ROOT / 'modules' / 'vuln' / 'src' / 'uaf' / 'tests'
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def run_regression(test_dirs: List[str] = None) -> dict:
    """对所有可用样本运行DRIFT并计算指标."""
    if test_dirs is None:
        test_dirs = [
            str(PROJ_ROOT / 'modules' / 'exploit' / 'tests' /
                'regression' / 'build' / 'gcc' / 'O0'),
            str(PROJ_ROOT / 'modules' / 'vuln' / 'src' / 'uaf' /
                'tests' / 'samples'),
        ]

    available = get_available_samples(test_dirs)
    if not available:
        return {'error': 'no samples found'}

    results = []
    tp = fp = tn = fn = 0
    total_gt_uaf = 0
    total_detected = 0

    for binary_path, (expected_uaf, expected_df, category) in sorted(available.items()):
        if not os.path.isfile(binary_path):
            continue

        t0 = time.time()
        report = analyze_uaf(binary_path)
        elapsed_ms = round((time.time() - t0) * 1000, 1)

        # DRIFT判定: temporal_verified/df_verified=强证据, confirmed/likely=保守保留
        detected_uaf = 0
        detected_df = 0
        for f in report.findings:
            d = f.get('decision', '')
            tv = f.get('temporal_verified', False)
            dfv = f.get('double_free_verified', False)
            ts = f.get('temporal_skipped', False)
            if tv or dfv:
                detected_uaf += 1
                if dfv:
                    detected_df += 1
            elif ts:
                continue  # 时间验证无法进行 → 不计数
            elif d in ('confirmed_uaf', 'likely_uaf') and d != 'temporal_filtered':
                detected_uaf += 1  # 保守保留

        # 与ground truth比较
        gt_has_uaf = expected_uaf > 0
        pred_has_uaf = detected_uaf > 0

        if gt_has_uaf and pred_has_uaf:
            tp += 1
        elif gt_has_uaf and not pred_has_uaf:
            fn += 1
        elif not gt_has_uaf and pred_has_uaf:
            fp += 1
        else:
            tn += 1

        total_gt_uaf += expected_uaf
        total_detected += detected_uaf

        sample_name = os.path.basename(binary_path).replace('.exe', '')
        results.append({
            'sample': sample_name,
            'category': category,
            'expected_uaf': expected_uaf,
            'expected_df': expected_df,
            'detected_uaf': detected_uaf,
            'detected_df': detected_df,
            'confirmed': report.confirmed,
            'likely': report.likely,
            'filtered_fp': report.filtered_fp,
            'temporal_filtered': report.temporal_filtered,
            'fp_reduction_pct': report.fp_reduction_pct,
            'total_objects': report.total_objects,
            'elapsed_ms': elapsed_ms,
            'match': pred_has_uaf == gt_has_uaf,
            'findings': [
                {'obj_id': f['obj_id'], 'confidence': f['confidence'],
                 'decision': f['decision'], 'evidence': f['evidence']}
                for f in report.findings[:5]
            ],
        })

    # 计算指标
    precision = tp / max(1, tp + fp)
    recall = tp / max(1, tp + fn)
    f1 = 2 * precision * recall / max(0.001, precision + recall)

    summary = {
        'generated': time.strftime('%Y-%m-%d %H:%M:%S'),
        'total_samples': len(results),
        'tp': tp, 'fp': fp, 'tn': tn, 'fn': fn,
        'precision': round(precision, 4),
        'recall': round(recall, 4),
        'f1': round(f1, 4),
        'total_expected_uaf': total_gt_uaf,
        'total_detected_uaf': total_detected,
        'results': results,
    }

    # 保存JSON
    json_path = OUTPUT_DIR / 'drift_regression_results.json'
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=2, default=str)
    print(f"[DRIFT regression] JSON: {json_path}")

    # 打印Markdown报告
    md = _generate_markdown(summary)
    md_path = OUTPUT_DIR / 'drift_regression_report.md'
    with open(md_path, 'w', encoding='utf-8') as f:
        f.write(md)
    print(f"[DRIFT regression] MD:  {md_path}")

    return summary


def _generate_markdown(summary: dict) -> str:
    """生成Markdown格式报告."""
    lines = [
        '# DRIFT UAF Detection — Regression Report',
        '',
        f'**Generated**: {summary["generated"]}',
        '',
        '## Summary Metrics',
        '',
        '| Metric | Value |',
        '|--------|-------|',
        f'| Samples | {summary["total_samples"]} |',
        f'| TP | {summary["tp"]} |',
        f'| FP | {summary["fp"]} |',
        f'| TN | {summary["tn"]} |',
        f'| FN | {summary["fn"]} |',
        f'| **Precision** | **{summary["precision"]:.2%}** |',
        f'| **Recall** | **{summary["recall"]:.2%}** |',
        f'| **F1** | **{summary["f1"]:.3f}** |',
        f'| Expected UAFs | {summary["total_expected_uaf"]} |',
        f'| Detected UAFs | {summary["total_detected_uaf"]} |',
        '',
        '## Per-Sample Results',
        '',
        '| Sample | Category | Expected | Detected | Conf | Likely | FP%↓ | Time | Match |',
        '|--------|----------|----------|----------|------|--------|------|------|-------|',
    ]

    for r in summary['results']:
        match_icon = '✓' if r['match'] else '✗'
        lines.append(
            f'| {r["sample"]} | {r["category"]} | {r["expected_uaf"]} '
            f'| {r["detected_uaf"]} | {r["confirmed"]} | {r["likely"]} '
            f'| {r["fp_reduction_pct"]}% | {r["elapsed_ms"]:.1f}ms '
            f'| {match_icon} |')

    lines.extend([
        '',
        '## Category Breakdown',
        '',
        '| Category | Samples | Correct | Accuracy |',
        '|----------|---------|---------|----------|',
    ])

    by_cat = {}
    for r in summary['results']:
        cat = r['category']
        by_cat.setdefault(cat, {'total': 0, 'correct': 0})
        by_cat[cat]['total'] += 1
        if r['match']:
            by_cat[cat]['correct'] += 1

    for cat, stats in sorted(by_cat.items()):
        acc = stats['correct'] / max(1, stats['total'])
        lines.append(
            f'| {cat} | {stats["total"]} | {stats["correct"]} '
            f'| {acc:.1%} |')

    return '\n'.join(lines)


def main():
    print("=" * 60)
    print("DRIFT UAF Detection — Regression Test Suite")
    print("=" * 60)

    summary = run_regression()

    print(f"\n{'=' * 60}")
    print(f"Precision: {summary['precision']:.2%}")
    print(f"Recall:    {summary['recall']:.2%}")
    print(f"F1:        {summary['f1']:.3f}")
    print(f"TP={summary['tp']} FP={summary['fp']} "
          f"TN={summary['tn']} FN={summary['fn']}")
    print(f"{'=' * 60}")
    print("[OK] DRIFT regression complete")


if __name__ == '__main__':
    main()
