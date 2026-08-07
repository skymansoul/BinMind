# coding: utf-8
"""
统一基准测试 — 同时运行 9 个检测器的基准, 产出统一指标报告.
覆盖: Heap/UAF/FMT/INT/OBO/DF/TC/UM/BU.
"""

import sys, os, time, json
from pathlib import Path
from typing import Dict

_CORE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_CORE_DIR))


def run_unified_benchmark() -> Dict:
    """运行所有 9 个检测器的统一基准测试."""
    t0 = time.perf_counter()
    results = {}

    # ── Heap (16-sample CVE benchmark: 7-layer pipeline, F1=1.0000) ──
    try:
        from eval.heap_cve_benchmark import run_heap_cve_benchmark
        _, heap_stats = run_heap_cve_benchmark()
        results['heap'] = {'f1': heap_stats.get('f1', 0),
                          'precision': heap_stats.get('precision', 0),
                          'recall': heap_stats.get('recall', 0), 'status': 'ok'}
    except Exception as e:
        results['heap'] = {'f1': 0, 'status': f'err: {e}'}

# UAF
    try:
        from eval.uaf_benchmark import run_uaf_benchmark
        _, uaf_stats = run_uaf_benchmark()
        results['uaf'] = {'f1': uaf_stats.get('f1', 0),
                          'precision': uaf_stats.get('precision', 0),
                          'recall': uaf_stats.get('recall', 0), 'status': 'ok'}
    except Exception as e:
        results['uaf'] = {'f1': 0, 'status': f'err: {e}'}

# FMT
    try:
        from eval.fmt_benchmark import run_fmt_benchmark
        _, fmt_stats = run_fmt_benchmark()
        results['fmt'] = {'f1': fmt_stats.get('f1', 0),
                         'precision': fmt_stats.get('precision', 0),
                         'recall': fmt_stats.get('recall', 0), 'status': 'ok'}
    except Exception as e:
        results['fmt'] = {'f1': 0, 'status': f'err: {e}'}

# INT
    try:
        from eval.int_benchmark import run_int_benchmark
        _, int_stats = run_int_benchmark()
        results['int'] = {'f1': int_stats.get('f1', 0),
                         'precision': int_stats.get('precision', 0),
                         'recall': int_stats.get('recall', 0), 'status': 'ok'}
    except Exception as e:
        results['int'] = {'f1': 0, 'status': f'err: {e}'}

# OBO
    try:
        from eval.obo_benchmark import run_obo_benchmark
        _, obo_stats = run_obo_benchmark()
        results['obo'] = {'f1': obo_stats.get('f1', 0),
                         'precision': obo_stats.get('precision', 0),
                         'recall': obo_stats.get('recall', 0), 'status': 'ok'}
    except Exception as e:
        results['obo'] = {'f1': 0, 'status': f'err: {e}'}

# DF
    try:
        from eval.df_benchmark import run_df_benchmark
        _, df_stats = run_df_benchmark()
        results['df'] = {'f1': df_stats.get('f1', 0),
                        'precision': df_stats.get('precision', 0),
                        'recall': df_stats.get('recall', 0), 'status': 'ok'}
    except Exception as e:
        results['df'] = {'f1': 0, 'status': f'err: {e}'}

# TC
    try:
        from eval.tc_benchmark import run_tc_benchmark
        _, tc_stats = run_tc_benchmark()
        results['tc'] = {'f1': tc_stats.get('f1', 0),
                        'precision': tc_stats.get('precision', 0),
                        'recall': tc_stats.get('recall', 0), 'status': 'ok'}
    except Exception as e:
        results['tc'] = {'f1': 0, 'status': f'err: {e}'}

# UM
    try:
        from eval.um_benchmark import run_um_benchmark
        _, um_stats = run_um_benchmark()
        results['um'] = {'f1': um_stats.get('f1', 0),
                        'precision': um_stats.get('precision', 0),
                        'recall': um_stats.get('recall', 0), 'status': 'ok'}
    except Exception as e:
        results['um'] = {'f1': 0, 'status': f'err: {e}'}

# BU
    try:
        from eval.bu_benchmark import run_bu_benchmark
        _, bu_stats = run_bu_benchmark()
        results['bu'] = {'f1': bu_stats.get('f1', 0),
                        'precision': bu_stats.get('precision', 0),
                        'recall': bu_stats.get('recall', 0), 'status': 'ok'}
    except Exception as e:
        results['bu'] = {'f1': 0, 'status': f'err: {e}'}

    elapsed = (time.perf_counter() - t0) * 1000
    valid = {k: v for k, v in results.items() if v['status'] == 'ok'}
    if valid:
        avg_f1 = sum(v['f1'] for v in valid.values()) / len(valid)
        avg_precision = sum(v.get('precision', v['f1']) for v in valid.values()) / len(valid)
        avg_recall = sum(v.get('recall', v['f1']) for v in valid.values()) / len(valid)
    else:
        avg_f1 = avg_precision = avg_recall = 0

    return {
        'detectors': results,
        'summary': {
            'avg_f1': round(avg_f1, 4),
            'avg_precision': round(avg_precision, 4),
            'avg_recall': round(avg_recall, 4),
            'detectors_ok': len(valid),
            'detectors_total': len(results),
            'elapsed_ms': round(elapsed, 1),
        },
    }


def print_unified_report(report: Dict):
    print(f"\n{'='*60}")
    print(f"UNIFIED BENCHMARK — 9 Detectors (Heap+UAF+FMT+INT+OBO+DF+TC+UM+BU)")
    print(f"{'='*60}")

    for name, r in report['detectors'].items():
        status = '[OK]' if r['status'] == 'ok' else '[ERR]'
        f1 = r.get('f1', 0)
        p = r.get('precision', f1)
        r_val = r.get('recall', f1)
        print(f"  {status} {name:6s}: F1={f1:.4f}  P={p:.1%}  R={r_val:.1%}")

    s = report['summary']
    print(f"\n  Summary: {s['detectors_ok']}/{s['detectors_total']} detectors ok")
    print(f"  Avg F1={s['avg_f1']:.4f}  Avg P={s['avg_precision']:.1%}  "
          f"Avg R={s['avg_recall']:.1%}")
    print(f"  Elapsed: {s['elapsed_ms']:.1f}ms")


if __name__ == '__main__':
    report = run_unified_benchmark()
    print_unified_report(report)

    out_dir = _CORE_DIR / 'benchmark_results'
    out_dir.mkdir(exist_ok=True)
    with open(out_dir / 'unified_benchmark.json', 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2)
    print(f'\n  JSON -> {out_dir / "unified_benchmark.json"}')
