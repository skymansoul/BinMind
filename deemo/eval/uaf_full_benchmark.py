#!/usr/bin/env python3
"""
UAF HOIG+PCOL 全量基准测试 — 40+样本验证PCOL在扩展CVE样本集上的效果.

对比:
  HOIG-only:  仅对象身份追踪 (无路径条件分析)
  HOIG+PCOL:  对象身份 + 路径条件对象生命周期

输出: JSON + CSV + 控制台报告
"""
from __future__ import annotations
import csv, json, os, sys, time
from pathlib import Path
from typing import Dict, List, Tuple

_DEEMO = Path(__file__).resolve().parent.parent
if str(_DEEMO) not in sys.path:
    sys.path.insert(0, str(_DEEMO))

from analysis.uaf_hoig_builder import HoigBuilder
from analysis.uaf_pcol_bridge import verify_with_pcol
from analysis.uaf_pcol_verifier import filter_uaf_by_pcol
from eval.uaf_cve_samples import (
    ALL_UAF_CVE_SAMPLES, get_sample_count, get_category_stats,
)

OUTPUT_DIR = _DEEMO / "eval" / "results"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def run_hoig_only(code: str, name: str) -> str:
    """仅HOIG Builder判定."""
    builder = HoigBuilder()
    _, _, verdicts = builder.build(code, name)
    if any(v.verdict == 'CONFIRMED' for v in verdicts):
        return 'CONFIRMED'
    return 'SAFE'


def run_hoig_pcol(code: str, name: str) -> str:
    """HOIG + PCOL联合判定."""
    v = verify_with_pcol(code, name)
    return v.verdict


def _metrics(records, pred_key):
    tp = sum(1 for r in records
             if r['expected'] == 'CONFIRMED' and r[pred_key] == 'CONFIRMED')
    fp = sum(1 for r in records
             if r['expected'] == 'SAFE' and r[pred_key] == 'CONFIRMED')
    tn = sum(1 for r in records
             if r['expected'] == 'SAFE' and r[pred_key] == 'SAFE')
    fn = sum(1 for r in records
             if r['expected'] == 'CONFIRMED' and r[pred_key] != 'CONFIRMED')
    p = tp / max(1, tp + fp)
    r = tp / max(1, tp + fn)
    f1 = 2 * p * r / max(0.001, p + r)
    fpr = fp / max(1, fp + tn)
    return {'tp': tp, 'fp': fp, 'tn': tn, 'fn': fn,
            'precision': round(p, 4), 'recall': round(r, 4),
            'f1': round(f1, 4), 'fpr': round(fpr, 4)}


def run_benchmark():
    n = get_sample_count()
    cats = get_category_stats()

    print("=" * 70)
    print(f"UAF HOIG+PCOL Full Benchmark — {n} samples")
    print("=" * 70)
    print(f"  Categories: {cats}")
    print()

    records = []
    for name, code, expected, category in ALL_UAF_CVE_SAMPLES:
        t0 = time.perf_counter()
        hoig_result = run_hoig_only(code, name)
        hoig_time = time.perf_counter() - t0

        t1 = time.perf_counter()
        pcol_result = run_hoig_pcol(code, name)
        pcol_time = time.perf_counter() - t1

        records.append({
            'sample': name,
            'category': category,
            'expected': expected,
            'hoig_only': hoig_result,
            'hoig_correct': hoig_result == expected,
            'pcol': pcol_result,
            'pcol_correct': pcol_result == expected,
            'hoig_time_ms': round(hoig_time * 1000, 3),
            'pcol_time_ms': round(pcol_time * 1000, 3),
        })

    hoig_m = _metrics(records, 'hoig_only')
    pcol_m = _metrics(records, 'pcol')

    print(f"\n  HOIG-only:  TP={hoig_m['tp']} FP={hoig_m['fp']} "
          f"TN={hoig_m['tn']} FN={hoig_m['fn']}")
    print(f"              P={hoig_m['precision']:.4f} "
          f"R={hoig_m['recall']:.4f} F1={hoig_m['f1']:.4f} "
          f"FPR={hoig_m['fpr']:.4f}")

    print(f"\n  HOIG+PCOL:  TP={pcol_m['tp']} FP={pcol_m['fp']} "
          f"TN={pcol_m['tn']} FN={pcol_m['fn']}")
    print(f"              P={pcol_m['precision']:.4f} "
          f"R={pcol_m['recall']:.4f} F1={pcol_m['f1']:.4f} "
          f"FPR={pcol_m['fpr']:.4f}")

    fp_improvement = 0.0
    if hoig_m['fpr'] > 0:
        fp_improvement = (hoig_m['fpr'] - pcol_m['fpr']) / hoig_m['fpr']
    print(f"\n  FPR reduction: {hoig_m['fpr']:.4f} → {pcol_m['fpr']:.4f} "
          f"({fp_improvement*100:.1f}% relative reduction)")
    print(f"  F1 improvement: {hoig_m['f1']:.4f} → {pcol_m['f1']:.4f}")

    # Per-category breakdown
    print("\n  Per-category (HOIG-only vs HOIG+PCOL):")
    print(f"  {'Category':<15s} {'N':>3s} "
          f"{'HOIG FP':>8s} {'PCOL FP':>8s} "
          f"{'HOIG FN':>8s} {'PCOL FN':>8s}")
    for cat in sorted(cats.keys()):
        cat_records = [r for r in records if r['category'] == cat]
        h_fp = sum(1 for r in cat_records
                   if r['expected'] == 'SAFE' and r['hoig_only'] == 'CONFIRMED')
        p_fp = sum(1 for r in cat_records
                   if r['expected'] == 'SAFE' and r['pcol'] == 'CONFIRMED')
        h_fn = sum(1 for r in cat_records
                   if r['expected'] == 'CONFIRMED' and r['hoig_only'] != 'CONFIRMED')
        p_fn = sum(1 for r in cat_records
                   if r['expected'] == 'CONFIRMED' and r['pcol'] != 'CONFIRMED')
        print(f"  {cat:<15s} {len(cat_records):>3d} "
              f"{h_fp:>8d} {p_fp:>8d} "
              f"{h_fn:>8d} {p_fn:>8d}")

    # Detail
    print("\n  Details:")
    print(f"  {'Sample':<20s} {'Cat':<15s} "
          f"{'HOIG':>10s} {'PCOL':>10s} {'Exp':>10s} {'Status':>8s}")
    print("  " + "-" * 80)
    for r in records:
        hoig_s = 'PASS' if r['hoig_correct'] else 'FAIL'
        pcol_s = 'PASS' if r['pcol_correct'] else 'FAIL'
        print(f"  {r['sample']:<20s} {r['category']:<15s} "
              f"{r['hoig_only']:>10s} {r['pcol']:>10s} "
              f"{r['expected']:>10s} {hoig_s}/{pcol_s:>5s}")

    # Save JSON
    report = {
        'module': 'UAF HOIG + PCOL Full Benchmark',
        'total_samples': n,
        'categories': cats,
        'hoig_only': hoig_m,
        'hoig_pcol': pcol_m,
        'fpr_reduction_pct': round(fp_improvement * 100, 2),
        'f1_improvement': round(pcol_m['f1'] - hoig_m['f1'], 4),
        'details': records,
    }
    json_path = OUTPUT_DIR / 'uaf_full_benchmark.json'
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"\n  JSON: {json_path}")

    # Save CSV
    csv_path = OUTPUT_DIR / 'uaf_full_benchmark.csv'
    with open(csv_path, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=['sample', 'category',
                                          'expected', 'hoig_only',
                                          'hoig_correct', 'pcol',
                                          'pcol_correct',
                                          'hoig_time_ms', 'pcol_time_ms'])
        w.writeheader()
        w.writerows(records)
    print(f"  CSV:  {csv_path}")

    print("\n" + "=" * 70)
    return report


if __name__ == '__main__':
    run_benchmark()
