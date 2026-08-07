#!/usr/bin/env python3
"""DFC-PV Benchmark — 31 样本基准测试, 输出 JSON + CSV.

样本集:
  - double_free_01~15: 原始样本 (14 VULN + 1 SAFE)
  - df_adv_16~31: 对抗样本 (20 VULN + 5 SAFE)

入口: python eval/dfc_pv_benchmark.py
"""
from __future__ import annotations

import csv, json, os, sys, time
from pathlib import Path
from typing import Dict, List, Tuple

_DEEMO = Path(__file__).resolve().parent.parent
if str(_DEEMO) not in sys.path:
    sys.path.insert(0, str(_DEEMO))

from analysis.dfc_pv_pipeline import detect_double_free_dfc

SAMPLES_DIR = _DEEMO / 'tests' / 'cve_samples'
OUTPUT_DIR = _DEEMO / 'eval' / 'results'
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# Ground Truth
GT: Dict[str, int] = {}
for i in range(1, 16):
    GT[f'double_free_{i:02d}'] = 0 if i == 7 else 1
_ADV_SAFE = {18, 21, 24, 27, 29}
for i in range(16, 32):
    GT[f'df_adv_{i}'] = 0 if i in _ADV_SAFE else 1


def run_benchmark() -> Dict:
    results = {}
    for name in sorted(GT):
        src_path = SAMPLES_DIR / name / 'vuln.c'
        if not src_path.is_file():
            continue
        source = src_path.read_text(encoding='utf-8', errors='replace')
        t0 = time.perf_counter()
        findings = detect_double_free_dfc(source)
        dt = (time.perf_counter() - t0) * 1000
        detected = 1 if findings else 0
        exp = GT[name]
        results[name] = {
            'expected': exp,
            'detected': detected,
            'correct': detected == exp,
            'tp': detected == 1 and exp == 1,
            'fp': detected == 1 and exp == 0,
            'fn': detected == 0 and exp == 1,
            'tn': detected == 0 and exp == 0,
            'time_ms': round(dt, 3),
            'findings': findings,
        }

    tp = sum(1 for v in results.values() if v['tp'])
    fp = sum(1 for v in results.values() if v['fp'])
    fn = sum(1 for v in results.values() if v['fn'])
    tn = sum(1 for v in results.values() if v['tn'])
    p = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    r = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * p * r / (p + r) if (p + r) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    metrics = {'precision': p, 'recall': r, 'f1': f1, 'fpr': fpr,
               'tp': tp, 'fp': fp, 'fn': fn, 'tn': tn}

    print(f'\n{"=" * 60}')
    print(f'DFC-PV Benchmark ({len(results)} samples)')
    print(f'{"=" * 60}')
    print(f'TP={tp}  FP={fp}  FN={fn}  TN={tn}')
    print(f'P={p:.4f}  R={r:.4f}  F1={f1:.4f}  FPR={fpr:.4f}')
    print(f'\n{"Sample":<22s} {"Exp":>3s} {"Det":>3s} {"OK":>2s} '
          f'{"Time":>7s}  Detail')
    print('-' * 70)
    for name in sorted(results):
        v = results[name]
        ok = 'Y' if v['correct'] else 'N'
        det = ''
        if v['findings']:
            f0 = v['findings'][0]
            det = f'L{f0["first_free_line"]} {f0["pattern"]} {f0["variable"]}'
        print(f'{name:<22s} {v["expected"]:>3d} {v["detected"]:>3d} '
              f'{ok:>2s} {v["time_ms"]:>7.1f}  {det}')

    # JSON
    out = {'metrics': metrics, 'results': results}
    json_path = OUTPUT_DIR / 'dfc_pv_benchmark.json'
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
    print(f'\nJSON: {json_path}')

    # CSV
    csv_path = OUTPUT_DIR / 'dfc_pv_benchmark.csv'
    with open(csv_path, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['sample', 'expected', 'detected', 'correct',
                     'tp', 'fp', 'fn', 'tn', 'time_ms'])
        for name in sorted(results):
            v = results[name]
            w.writerow([name, v['expected'], v['detected'],
                        v['correct'], int(v['tp']), int(v['fp']),
                        int(v['fn']), int(v['tn']), v['time_ms']])
    print(f'CSV:  {csv_path}')
    return out


if __name__ == '__main__':
    run_benchmark()
