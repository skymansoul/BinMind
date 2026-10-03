"""Double-Free (DFC-PV) 回归测试套件.

覆盖 31 个样本 (15 原始 + 16 对抗), 分为:
  - 直接双释放 (direct)
  - 循环内释放 (loop)
  - 跨函数包装链 (cross_func / wrapper)
  - 回调双释放 (callback_df)
  - 悬垂字段释放 (dangling_field)
  - 别名链双释放 (alias_chain)
  - 安全模式: NULL/宏/realloc/互斥路径/freed flag/union

入口: python tests/regression/run_df_suite.py
"""
from __future__ import annotations

import json, os, sys, time
from pathlib import Path
from typing import Dict, List, Tuple

_PROJECT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_PROJECT))

from analysis.dfc_pv_pipeline import detect_double_free_dfc

SAMPLES_DIR = _PROJECT / 'tests' / 'cve_samples'

# Ground Truth: 1 = VULN, 0 = SAFE
GT: Dict[str, int] = {}
for i in range(1, 16):
    name = f'double_free_{i:02d}'
    GT[name] = 0 if i == 7 else 1
_ADV_SAFE = {18, 21, 24, 27, 29}
for i in range(16, 32):
    name = f'df_adv_{i}'
    GT[name] = 0 if i in _ADV_SAFE else 1


def run_suite() -> Dict:
    results = {}
    for name in sorted(GT):
        src_path = SAMPLES_DIR / name / 'vuln.c'
        if not src_path.is_file():
            results[name] = {'expected': GT[name], 'detected': -1,
                             'error': 'missing'}
            continue
        source = src_path.read_text(encoding='utf-8', errors='replace')
        t0 = time.perf_counter()
        findings = detect_double_free_dfc(source)
        dt = (time.perf_counter() - t0) * 1000
        detected = 1 if findings else 0
        results[name] = {
            'expected': GT[name],
            'detected': detected,
            'tp': detected == 1 and GT[name] == 1,
            'fp': detected == 1 and GT[name] == 0,
            'fn': detected == 0 and GT[name] == 1,
            'tn': detected == 0 and GT[name] == 0,
            'time_ms': round(dt, 3),
            'findings': findings,
        }
    _print_report(results)
    return results


def _print_report(results: Dict):
    tp = sum(1 for v in results.values() if v.get('tp'))
    fp = sum(1 for v in results.values() if v.get('fp'))
    fn = sum(1 for v in results.values() if v.get('fn'))
    tn = sum(1 for v in results.values() if v.get('tn'))
    p = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    r = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * p * r / (p + r) if (p + r) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    print('\n' + '=' * 60)
    print('DFC-PV Regression Suite (31 samples)')
    print('=' * 60)
    print(f'TP={tp}  FP={fp}  FN={fn}  TN={tn}')
    print(f'Precision={p:.4f}  Recall={r:.4f}  F1={f1:.4f}  FPR={fpr:.4f}')
    print(f'\n{"Sample":<22s} {"Exp":>3s} {"Det":>3s} {"Status":>6s} '
          f'{"Time(ms)":>9s}  Pattern')
    print('-' * 70)
    for name in sorted(results):
        v = results[name]
        st = 'TP' if v.get('tp') else 'FP' if v.get('fp') else \
            'FN' if v.get('fn') else 'TN'
        pat = ''
        if v.get('findings'):
            pat = f'L{v["findings"][0]["first_free_line"]} ' \
                  f'{v["findings"][0]["pattern"]}'
        print(f'{name:<22s} {v["expected"]:>3d} {v["detected"]:>3d} '
              f'{st:>6s} {v.get("time_ms", 0):>9.1f}  {pat}')
    print('-' * 70)
    status = 'PASS' if f1 == 1.0 and fpr == 0.0 else 'FAIL'
    print(f'Overall: {status}  (F1={f1:.4f}, FPR={fpr:.4f})')


if __name__ == '__main__':
    run_suite()
