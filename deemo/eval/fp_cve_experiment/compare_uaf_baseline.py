"""UAF 基线 vs TOVS 对比 — 在 corpus_uaf 上的误报/召回对比.

创建: 2024-04-03
用法: python eval/fp_cve_experiment/compare_uaf_baseline.py [--json out.json]
"""
import argparse
import glob
import json
import os
import sys
import time
from _common import HERE as _HERE, list_samples, setup_paths
setup_paths(with_format=False)
from uaf_orchestrator import analyze_uaf as analyze_uaf_baseline
from uaf_tovs import analyze_uaf_tovs

CORPUS = os.path.join(_HERE, 'corpus_uaf')


def run_baseline(exe: str) -> dict:
    t0 = time.time()
    r = analyze_uaf_baseline(exe, timeout_s=60)
    dt = time.time() - t0
    kept = r.confirmed_uaf + r.possible_uaf
    return {'kept': kept, 'confirmed': r.confirmed_uaf,
            'possible': r.possible_uaf, 'filtered': r.filtered_safe,
            'time_ms': round(dt * 1000, 1)}


def run_tovs(exe: str) -> dict:
    t0 = time.time()
    r = analyze_uaf_tovs(exe)
    dt = time.time() - t0
    kept = r.confirmed + r.possible
    return {'kept': kept, 'confirmed': r.confirmed,
            'possible': r.possible, 'filtered': r.filtered,
            'time_ms': round(dt * 1000, 1)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--json', default='')
    ap.add_argument('--exe', default='vuln.exe')
    args = ap.parse_args()

    rows = []
    for d, truth in list_samples(CORPUS):
        exe = os.path.join(d, args.exe)
        if not os.path.exists(exe):
            continue
        rows.append({'id': truth['id'],
                     'expected_vuln': truth['expected_vuln'],
                     'baseline': run_baseline(exe),
                     'tovs': run_tovs(exe)})

    def metrics(key):
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
        return {'tp': tp, 'fn': fn, 'fp': fp, 'tn': tn,
                'precision': round(prec, 4), 'recall': round(rec, 4),
                'f1': round(f1, 4)}

    mb = metrics('baseline')
    mt = metrics('tovs')

    print('%-30s %-14s %-14s' % ('sample', 'baseline', 'tovs'))
    for r in rows:
        print('%-30s kept=%2d/filt=%2d kept=%2d/filt=%2d' % (
            r['id'], r['baseline']['kept'], r['baseline']['filtered'],
            r['tovs']['kept'], r['tovs']['filtered']))
    print('=' * 70)
    print('baseline: TP=%d FN=%d FP=%d TN=%d | P=%.4f R=%.4f F1=%.4f'
          % (mb['tp'], mb['fn'], mb['fp'], mb['tn'], mb['precision'],
             mb['recall'], mb['f1']))
    print('tovs    : TP=%d FN=%d FP=%d TN=%d | P=%.4f R=%.4f F1=%.4f'
          % (mt['tp'], mt['fn'], mt['fp'], mt['tn'], mt['precision'],
             mt['recall'], mt['f1']))
    fp_red = ((mb['fp'] - mt['fp']) / mb['fp'] * 100) if mb['fp'] else 0.0
    rec_delta = mt['recall'] - mb['recall']
    print('FP: %d → %d (%.1f%%), recall: %+.4f' % (
        mb['fp'], mt['fp'], fp_red, rec_delta))

    if args.json:
        out = {'exe': args.exe, 'rows': rows,
               'metrics': {'baseline': mb, 'tovs': mt,
                           'fp_reduction_pct': round(fp_red, 1),
                           'recall_delta': round(rec_delta, 4)}}
        with open(args.json, 'w', encoding='utf-8') as f:
            json.dump(out, f, indent=2)
        print('saved ->', args.json)


if __name__ == '__main__':
    main()
