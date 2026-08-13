"""FMT 基线 vs FMT-SAC 对比 — 在 corpus_fmt 上的误报/召回对比.

创建: 2023-06-02
用法: python eval/fp_cve_experiment/compare_fmt_baseline.py [--json out.json]
"""
import argparse
import glob
import json
import os
import sys
import time

from _common import HERE as _HERE, list_samples, DEEMO as _DEEMO, setup_paths
setup_paths(with_format=True)
sys.path.insert(0, os.path.join(_DEEMO, 'modules', 'vuln', 'detection'))

from fmt_sac import analyze_fmt_sac
from format_string_detector import detect_format_string

CORPUS = os.path.join(_HERE, 'corpus_fmt')


def disasm_lines(binary: str) -> list:
    """objdump 反汇编指令文本列表 (基线接口期望的符号格式)."""
    import subprocess
    proc = subprocess.run(['objdump', '-d', '-M', 'intel', binary],
                          capture_output=True, text=True, timeout=60)
    lines = []
    for line in proc.stdout.splitlines():
        m = None
        for pat in (r'^\s*[0-9a-fA-F]+:\s+[0-9a-fA-F ]+\s+(.*)$',):
            import re
            m = re.match(pat, line)
            if m:
                lines.append(m.group(1).strip())
                break
    return lines


def run_baseline(exe: str) -> dict:
    t0 = time.time()
    insns = disasm_lines(exe)
    findings = detect_format_string(insns)
    dt = time.time() - t0
    kept = len(findings)
    return {'kept': kept, 'time_ms': round(dt * 1000, 1)}


def run_sac(exe: str) -> dict:
    t0 = time.time()
    r = analyze_fmt_sac(exe)
    dt = time.time() - t0
    kept = r.confirmed + r.likely + r.possible
    return {'kept': kept, 'confirmed': r.confirmed, 'likely': r.likely,
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
                     'sac': run_sac(exe)})

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
    ms = metrics('sac')

    print('%-30s %-14s %-14s' % ('sample', 'baseline', 'sac'))
    for r in rows:
        print('%-30s kept=%2d/filt=%2d kept=%2d/filt=%2d' % (
            r['id'], r['baseline']['kept'], 0,
            r['sac']['kept'], r['sac']['filtered']))
    print('=' * 70)
    print('baseline: TP=%d FN=%d FP=%d TN=%d | P=%.4f R=%.4f F1=%.4f'
          % (mb['tp'], mb['fn'], mb['fp'], mb['tn'], mb['precision'],
             mb['recall'], mb['f1']))
    print('sac     : TP=%d FN=%d FP=%d TN=%d | P=%.4f R=%.4f F1=%.4f'
          % (ms['tp'], ms['fn'], ms['fp'], ms['tn'], ms['precision'],
             ms['recall'], ms['f1']))
    fp_red = ((mb['fp'] - ms['fp']) / mb['fp'] * 100) if mb['fp'] else 0.0
    print('FP: %d → %d (%.1f%%)' % (mb['fp'], ms['fp'], fp_red))

    if args.json:
        out = {'exe': args.exe, 'rows': rows,
               'metrics': {'baseline': mb, 'sac': ms,
                           'fp_reduction_pct': round(fp_red, 1)}}
        with open(args.json, 'w', encoding='utf-8') as f:
            json.dump(out, f, indent=2)
        print('saved ->', args.json)


if __name__ == '__main__':
    main()
