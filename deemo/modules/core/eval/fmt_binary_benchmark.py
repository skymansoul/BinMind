#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
格式串二进制级基准 — 对 tests/fmt_samples 的真实编译二进制执行
格式串检测 (compat/fmt_binary), 输出逐样本检出与 TP/FP 指标.

用法:
  python fmt_binary_benchmark.py [--samples ../tests/fmt_samples]
"""

import json, os, sys, time, argparse
from pathlib import Path

_CORE = Path(__file__).resolve().parent.parent
for p in (_CORE.parent.parent, _CORE):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from modules.core.compat.binir_frontend import analyze_binary  # noqa: E402
from modules.core.compat.fmt_binary import (  # noqa: E402
    analyze_fmt_binary, summarize)

# CRT 内部格式化路径 (matherr/report_error) 不纳入用户判定
_CRT_NOISE = {'matherr', 'report_error', '__mingw_invalidParameterHandler'}


def find_binaries(samples_dir: str) -> list:
    out = []
    for entry in sorted(os.listdir(samples_dir)):
        sub = os.path.join(samples_dir, entry)
        if os.path.isdir(sub):
            for f in sorted(os.listdir(sub)):
                if f.endswith('.exe') or f.endswith('.elf'):
                    out.append((entry, os.path.join(sub, f)))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--samples', default=str(_CORE / 'tests' / 'fmt_samples'))
    ap.add_argument('--output', default=str(_CORE / 'benchmark_results'))
    args = ap.parse_args()

    gt_path = os.path.join(args.samples, 'ground_truth.json')
    gt = {}
    if os.path.exists(gt_path):
        with open(gt_path, 'r', encoding='utf-8') as f:
            gt = {k: v.get('fmt_vuln', False)
                  for k, v in json.load(f).items()}

    binaries = find_binaries(args.samples)
    tp = fp = tn = fn = 0
    rows = []
    print('=' * 60)
    print('FORMAT STRING BINARY BENCHMARK (real compiled binaries)')
    print('=' * 60)
    for sid, exe in binaries:
        expected = gt.get(sid, False)
        t0 = time.perf_counter()
        ir = analyze_binary(exe)
        findings = [f for f in analyze_fmt_binary(ir, exe)
                    if f.func not in _CRT_NOISE]
        wall = (time.perf_counter() - t0) * 1000
        detected = any(f.dangerous for f in findings)
        if expected and detected: v, tp = 'TP', tp + 1
        elif not expected and detected: v, fp = 'FP', fp + 1
        elif not expected and not detected: v, tn = 'TN', tn + 1
        else: v, fn = 'FN', fn + 1
        print(f'  {v:2s} {sid:20s} dangerous={sum(1 for f in findings if f.dangerous):2d} '
              f'({wall:.0f}ms)')
        rows.append({'sample_id': sid, 'expected': expected,
                     'detected': detected,
                     'findings': [{'func': f.func_name, 'kind': f.fmt_kind,
                                   'write_spec': f.write_spec,
                                   'dangerous': f.dangerous,
                                   'detail': f.detail}
                                  for f in findings]})

    precision = tp / max(1, tp + fp)
    recall = tp / max(1, tp + fn)
    f1 = 2 * precision * recall / max(0.001, precision + recall)
    fp_rate = fp / max(1, fp + tn)
    print('\n' + '=' * 60)
    print(f'  TP={tp}  FP={fp}  TN={tn}  FN={fn}')
    print(f'  Precision={precision:.1%}  Recall={recall:.1%}  F1={f1:.3f}')
    print(f'  FP Rate={fp_rate:.1%}')
    print('=' * 60)

    os.makedirs(args.output, exist_ok=True)
    report = {
        'summary': {'tp': tp, 'fp': fp, 'tn': tn, 'fn': fn,
                    'precision': round(precision, 4),
                    'recall': round(recall, 4), 'f1': round(f1, 4),
                    'fp_rate': round(fp_rate, 4)},
        'samples': rows,
    }
    out_path = os.path.join(args.output, 'fmt_binary_benchmark.json')
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f'\nJSON -> {out_path}')

    sys.exit(0 if (fn == 0 and fp == 0) else 1)


if __name__ == '__main__':
    main()
