"""基线 DP-TVRA 管线 vs PCFV — 在语料库上的误报率/召回率对比.

创建: 2024-06-24
用法: python eval/fp_cve_experiment/compare_baseline.py [--json out.json]
输出: 逐样本两管线判定 + 汇总对比 (precision/recall/f1/fp_rate)
"""
import argparse
import glob
import json
import os
import sys
import time
from _common import HERE as _HERE, list_samples, setup_paths
setup_paths(with_format=False)
from orchestrator import analyze_heap as analyze_heap_baseline
from pcfv import analyze_heap_pcfv
from orchestrator import analyze_heap as analyze_heap_baseline

CORPUS = os.path.join(_HERE, 'corpus')


def run_baseline(exe: str) -> dict:
    t0 = time.time()
    r = analyze_heap_baseline(exe, timeout_s=60)
    dt = time.time() - t0
    kept = r.confirmed + r.likely + r.uncertain
    return {'kept': kept, 'confirmed': r.confirmed, 'likely': r.likely,
            'uncertain': r.uncertain, 'filtered': r.filtered_fp,
            'raw': r.raw_findings, 'time_ms': round(dt * 1000, 1)}


def run_pcfv(exe: str) -> dict:
    t0 = time.time()
    r = analyze_heap_pcfv(exe)
    dt = time.time() - t0
    kept = r.confirmed + r.likely + r.uncertain
    return {'kept': kept, 'confirmed': r.confirmed, 'likely': r.likely,
            'uncertain': r.uncertain, 'filtered': r.filtered_fp,
            'raw': r.raw_findings, 'time_ms': round(dt * 1000, 1)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--json', default='')
    ap.add_argument('--exe', default='vuln.exe',
                    help='variante: vuln.exe / vuln_O2.exe')
    args = ap.parse_args()

    rows = []
    for d, truth in list_samples(CORPUS):
        exe = os.path.join(d, args.exe)
        if not os.path.exists(exe):
            continue
        b = run_baseline(exe)
        p = run_pcfv(exe)
        rows.append({
            'id': truth['id'], 'expected_vuln': truth['expected_vuln'],
            'baseline': b, 'pcfv': p,
        })

    def metrics(rows, key):
        tp = sum(1 for r in rows
                 if r['expected_vuln'] and r[key]['kept'] > 0)
        fn = sum(1 for r in rows
                 if r['expected_vuln'] and r[key]['kept'] == 0)
        fp = sum(1 for r in rows
                 if not r['expected_vuln'] and r[key]['kept'] > 0)
        tn = sum(1 for r in rows
                 if not r['expected_vuln'] and r[key]['kept'] == 0)
        prec = tp / (tp + fp) if tp + fp else 0.0
        rec = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
        fp_rate = fp / (fp + tn) if fp + tn else 0.0
        return {'tp': tp, 'fn': fn, 'fp': fp, 'tn': tn,
                'precision': round(prec, 4), 'recall': round(rec, 4),
                'f1': round(f1, 4), 'fp_rate': round(fp_rate, 4),
                'total_kept': sum(r[key]['kept'] for r in rows),
                'total_filtered': sum(r[key]['filtered'] for r in rows)}

    mb = metrics(rows, 'baseline')
    mp = metrics(rows, 'pcfv')

    print('%-32s %-9s %-9s' % ('sample', 'baseline', 'pcfv'))
    for r in rows:
        print('%-32s kept=%2d/filt=%2d kept=%2d/filt=%2d' % (
            r['id'], r['baseline']['kept'], r['baseline']['filtered'],
            r['pcfv']['kept'], r['pcfv']['filtered']))
    print('=' * 70)
    print('baseline: TP=%d FN=%d FP=%d TN=%d | P=%.4f R=%.4f F1=%.4f fp_rate=%.4f'
          % (mb['tp'], mb['fn'], mb['fp'], mb['tn'], mb['precision'],
             mb['recall'], mb['f1'], mb['fp_rate']))
    print('pcfv    : TP=%d FN=%d FP=%d TN=%d | P=%.4f R=%.4f F1=%.4f fp_rate=%.4f'
          % (mp['tp'], mp['fn'], mp['fp'], mp['tn'], mp['precision'],
             mp['recall'], mp['f1'], mp['fp_rate']))
    fp_reduction = 0.0
    if mb['fp'] > 0:
        fp_reduction = (mb['fp'] - mp['fp']) / mb['fp'] * 100
    print('FP绝对值: %d → %d (降低 %.1f%%)' % (mb['fp'], mp['fp'], fp_reduction))
    print('筛选量  : %d → %d' % (mb['total_filtered'], mp['total_filtered']))

    if args.json:
        out = {'exe': args.exe, 'rows': rows,
               'metrics': {'baseline': mb, 'pcfv': mp,
                           'fp_reduction_pct': round(fp_reduction, 1)}}
        with open(args.json, 'w', encoding='utf-8') as f:
            json.dump(out, f, indent=2)
        print('saved ->', args.json)


if __name__ == '__main__':
    main()
