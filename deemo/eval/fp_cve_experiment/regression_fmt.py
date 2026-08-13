"""FMT-SAC 回归 — 对 corpus_fmt 全部样本运行并与 truth 比对.

创建: 2024-06-17
用法: python eval/fp_cve_experiment/regression_fmt.py [--json out.json]
"""
import argparse
import glob
import json
import os
import sys
import time
from _common import HERE as _HERE, list_samples, setup_paths
setup_paths(with_format=True)
from fmt_sac import analyze_fmt_sac
CORPUS = os.path.join(_HERE, 'corpus_fmt')


def run_one(sample_dir: str) -> dict:
    with open(os.path.join(sample_dir, 'truth.json'), encoding='utf-8') as f:
        truth = json.load(f)
    result = {'id': truth['id'], 'expected_vuln': truth['expected_vuln'],
              'mode': truth.get('mode', ''), 'variants': {}}
    for exe_name in ('vuln.exe', 'vuln_O2.exe'):
        exe = os.path.join(sample_dir, exe_name)
        if not os.path.exists(exe):
            continue
        t0 = time.time()
        r = analyze_fmt_sac(exe)
        dt = time.time() - t0
        kept = r.confirmed + r.likely + r.possible
        result['variants'][exe_name] = {
            'kept': kept, 'confirmed': r.confirmed, 'likely': r.likely,
            'possible': r.possible, 'filtered': r.filtered,
            'calls': r.n_calls, 'time_ms': round(dt * 1000, 1),
            'detected': kept > 0,
        }
    det_o0 = result['variants'].get('vuln.exe', {}).get('detected', False)
    det_o2 = result['variants'].get('vuln_O2.exe', {}).get('detected', False)
    result['detected'] = det_o0 or det_o2
    result['tp'] = result['expected_vuln'] and result['detected']
    result['fn'] = result['expected_vuln'] and not result['detected']
    result['fp'] = not result['expected_vuln'] and result['detected']
    result['tn'] = not result['expected_vuln'] and not result['detected']
    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--json', default='')
    args = ap.parse_args()

    results = []
    for d, _truth in list_samples(CORPUS):
        results.append(run_one(d))

    tp = sum(r['tp'] for r in results)
    fn = sum(r['fn'] for r in results)
    fp = sum(r['fp'] for r in results)
    tn = sum(r['tn'] for r in results)
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0

    print('%-30s %-6s %-6s %-6s %-6s' % ('sample', 'expect', 'det', 'kept',
                                          'filt'))
    for r in results:
        tag = 'TP' if r['tp'] else ('FN' if r['fn'] else (
            'FP' if r['fp'] else 'TN'))
        for v, vd in r['variants'].items():
            print('%-30s %-6s %-6s %-6d %-6d %s' % (
                r['id'] + '/' + v, str(bool(r['expected_vuln'])).lower(),
                str(vd['detected']).lower(), vd['kept'], vd['filtered'],
                tag))
    print('=' * 70)
    print('TP=%d FN=%d FP=%d TN=%d' % (tp, fn, fp, tn))
    print('precision=%.4f recall=%.4f f1=%.4f' % (prec, rec, f1))
    print('fp_rate=%.4f' % (fp / (fp + tn) if fp + tn else 0.0))

    if args.json:
        out = {'results': results,
               'metrics': {'tp': tp, 'fn': fn, 'fp': fp, 'tn': tn,
                           'precision': round(prec, 4),
                           'recall': round(rec, 4), 'f1': round(f1, 4)}}
        with open(args.json, 'w', encoding='utf-8') as f:
            json.dump(out, f, indent=2)
        print('saved ->', args.json)


if __name__ == '__main__':
    main()
