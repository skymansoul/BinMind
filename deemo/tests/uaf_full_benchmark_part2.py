"""
UAF全量20样本基准测试 — Temporal Path + Dominator 双验证器.
"""
from __future__ import annotations

import sys, time, re, json, importlib.util, importlib
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

PROJECT_ROOT = Path(__file__).parent.parent

# 通过importlib直接加载, 避免触发 analysis/__init__.py 的级联导入

def run_dominator(source: str) -> dict:
    """运行UAFDominatorVerifier."""
    UAFDominatorVerifier = _uaf_dominator.UAFDominatorVerifier
    pairs = _find_free_use_pairs(source)
    if not pairs:
        return {'verdict': 'NONE', 'reason': 'no free-use pairs', 'findings': []}

    verifier = UAFDominatorVerifier()
    findings = []
    worst = 'SAFE'
    for fl, ul, pv in pairs:
        r = verifier.verify(source, fl, ul, pv)
        findings.append({
            'verdict': r.verdict, 'ptr': r.ptr_var,
            'free_line': r.free_line, 'use_line': r.use_line,
            'free_dominates_use': r.free_dominates_use,
            'nullify_postdom_free': r.nullify_postdom_free,
            'guard_protected': r.guard_protected,
            'reason': r.reason})
        if r.verdict in ('CONFIRMED',):
            worst = 'UAF'
        elif r.verdict == 'UNCERTAIN' and worst == 'SAFE':
            worst = 'UNCERTAIN'
    return {'verdict': worst, 'reason': findings[0]['reason'] if findings else '',
            'findings': findings}


def is_alarm(verdict: str) -> bool:
    return verdict in ('UAF', 'DOUBLE_FREE')


def main():
    uaf_dir = PROJECT_ROOT / 'samples' / 'uaf'
    if not uaf_dir.exists():
        print(f"UAF sample dir not found: {uaf_dir}")
        return 1

    sample_dirs = sorted(
        [d for d in uaf_dir.iterdir() if d.is_dir()],
        key=lambda d: d.name)

    tp = tn = fp = fn = 0
    tp_dom = tn_dom = fp_dom = fn_dom = 0
    rows = []

    header = f"{'Sample':22s} {'Truth':6s} {'Temporal':12s} {'Dom':10s} {'Result':8s} {'DomRes':8s} {'Path':10s}"
    print(header)
    print("-" * 90)

    for sd in sample_dirs:
        sid = sd.name
        sf = find_sample_file(sd)
        if not sf:
            print(f"  SKIP {sid}: no source found")
            continue
        source = sf.read_text(encoding='utf-8', errors='replace')
        truth = UAF_TRUTH.get(sid, True)

        # Temporal Path
        t0 = time.perf_counter()
        temporal = run_temporal(source)
        t_elapsed = (time.perf_counter() - t0) * 1000

        # Dominator
        t0 = time.perf_counter()
        dom = run_dominator(source)
        d_elapsed = (time.perf_counter() - t0) * 1000

        t_verdict = temporal['verdict']
        d_verdict = dom['verdict']

        # Temporal判定 (NONE=未发现任何free→安全样本正确不告警)
        t_alarm = is_alarm(t_verdict)
        if truth:
            if t_alarm:
                tp += 1; res = 'TP'
            elif t_verdict in ('SAFE', 'NONE'):
                fn += 1; res = 'FN'
            else:
                res = 'UNC'
        else:
            if t_alarm:
                fp += 1; res = 'FP'
            elif t_verdict in ('SAFE', 'NONE'):
                tn += 1; res = 'TN'
            else:
                res = 'UNC'

        # Dominator判定
        d_alarm = is_alarm(d_verdict)
        if truth:
            if d_alarm:
                tp_dom += 1; dres = 'TP'
            elif d_verdict == 'SAFE':
                fn_dom += 1; dres = 'FN'
            else:
                dres = 'UNC'
        else:
            if d_alarm:
                fp_dom += 1; dres = 'FP'
            elif d_verdict == 'SAFE':
                tn_dom += 1; dres = 'TN'
            else:
                dres = 'UNC'

        # 取一个代表性finding的路径信息
        t_findings = temporal.get('findings', [])
        path_str = ''
        if t_findings:
            f0 = t_findings[0]
            path_str = f"{f0.get('uaf_paths',0)}/{f0.get('total_paths',0)}"

        truth_s = 'UAF' if truth else 'SAFE'
        print(f"{sid:22s} {truth_s:6s} {t_verdict:12s} {d_verdict:10s} "
              f"{res:8s} {dres:8s} {path_str:10s}")

        rows.append({
            'sample': sid, 'truth': truth, 'temporal': t_verdict,
            'dominator': d_verdict, 't_result': res, 'd_result': dres,
            't_ms': t_elapsed, 'd_ms': d_elapsed,
            't_findings': t_findings, 'd_findings': dom.get('findings', []),
        })

    # 计算指标
    def metrics(tp, tn, fp, fn):
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
        return prec, rec, f1

    p_t, r_t, f1_t = metrics(tp, tn, fp, fn)
    p_d, r_d, f1_d = metrics(tp_dom, tn_dom, fp_dom, fn_dom)

    print()
    print("=" * 60)
    print("  UAF Full Benchmark — 20 Samples")
    print("=" * 60)
    print(f"  Temporal Path:  TP={tp} TN={tn} FP={fp} FN={fn}")
    print(f"                   Precision={p_t:.4f} Recall={r_t:.4f} F1={f1_t:.4f}")
    print()
    print(f"  Dominator:       TP={tp_dom} TN={tn_dom} FP={fp_dom} FN={fn_dom}")
    print(f"                   Precision={p_d:.4f} Recall={r_d:.4f} F1={f1_d:.4f}")
    print()

    # 保存详细结果
    out = PROJECT_ROOT / 'eval' / 'uaf_benchmark_results.json'
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps({
        'temporal': {'tp': tp, 'tn': tn, 'fp': fp, 'fn': fn,
                     'precision': p_t, 'recall': r_t, 'f1': f1_t},
        'dominator': {'tp': tp_dom, 'tn': tn_dom, 'fp': fp_dom, 'fn': fn_dom,
                      'precision': p_d, 'recall': r_d, 'f1': f1_d},
        'samples': rows,
    }, indent=2, ensure_ascii=False), encoding='utf-8')
    print(f"  Detailed results: {out}")

    return 0 if fn == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
