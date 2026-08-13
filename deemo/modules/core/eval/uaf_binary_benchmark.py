#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
UAF 二进制级基准 — 对 tests/uaf_samples 的真实编译二进制执行
生命周期检测 (compat/uaf_binary), 输出逐样本检出与 TP/FP 指标.

用法:
  python uaf_binary_benchmark.py [--samples ../tests/uaf_samples]
"""

import json, os, sys, time, argparse
from pathlib import Path

_CORE = Path(__file__).resolve().parent.parent
for p in (_CORE.parent.parent, _CORE):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from modules.core.compat.binir_frontend import analyze_binary  # noqa: E402
from modules.core.compat.uaf_binary import (  # noqa: E402
    analyze_uaf_binary, summarize)

# CRT 启动/线程清理中的良性 free→deref 模式, 不纳入用户函数判定
_CRT_NOISE = {
    'w64_mingwthr_remove_key_dtor', '__mingw_invalidParameterHandler',
    'mingw_tlscallback',
}


def find_binaries(samples_dir: str) -> list:
    out = []
    for entry in sorted(os.listdir(samples_dir)):
        sub = os.path.join(samples_dir, entry)
        if os.path.isdir(sub):
            for f in sorted(os.listdir(sub)):
                if f.endswith('.exe') or f.endswith('.elf'):
                    out.append((entry, os.path.join(sub, f)))
    return out


def user_findings(findings):
    return [f for f in findings if f.func not in _CRT_NOISE]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--samples', default=str(_CORE / 'tests' / 'uaf_samples'))
    ap.add_argument('--output', default=str(_CORE / 'benchmark_results'))
    args = ap.parse_args()

    gt_path = os.path.join(args.samples, 'ground_truth.json')
    gt = {}
    if os.path.exists(gt_path):
        with open(gt_path, 'r', encoding='utf-8') as f:
            gt = {k: v.get('uaf', False) for k, v in json.load(f).items()}

    binaries = find_binaries(args.samples)
    tp = fp = tn = fn = 0
    rows = []
    print('=' * 60)
    print('UAF BINARY BENCHMARK (real compiled binaries)')
    print('=' * 60)
    for sid, exe in binaries:
        expected = gt.get(sid, False)
        t0 = time.perf_counter()
        ir = analyze_binary(exe)
        findings = user_findings(analyze_uaf_binary(ir))
        wall = (time.perf_counter() - t0) * 1000
        detected = len(findings) > 0
        if expected and detected: v, tp = 'TP', tp + 1
        elif not expected and detected: v, fp = 'FP', fp + 1
        elif not expected and not detected: v, tn = 'TN', tn + 1
        else: v, fn = 'FN', fn + 1
        print(f'  {v:2s} {sid:22s} findings={len(findings):2d} '
              f'({wall:.0f}ms)')
        rows.append({'sample_id': sid, 'expected': expected,
                     'detected': detected, 'findings': len(findings),
                     'detail': [{'kind': f.kind, 'free': hex(f.free_site),
                                 'use': hex(f.use_site), 'func': f.func}
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
    out_path = os.path.join(args.output, 'uaf_binary_benchmark.json')
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f'\nJSON -> {out_path}')

    sys.exit(0 if (fn == 0 and fp == 0) else 1)


if __name__ == '__main__':
    main()
