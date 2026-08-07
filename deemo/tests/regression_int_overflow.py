"""
Regression test for integer overflow detection with FP filter.
Tests 15 samples (12 TP + 3 TN) through the IntOverflowFpFilter pipeline.

Usage:
  python -m tests.regression_int_overflow
  python -m tests.regression_int_overflow --verbose
"""

from __future__ import annotations
import sys, json, time, pathlib
from typing import Any, Dict, List


BASE = pathlib.Path(__file__).resolve().parent.parent / 'samples' / 'int_overflow'

MANIFEST = [
    ('sample_io_01', True), ('sample_io_02', True),
    ('sample_io_03', True), ('sample_io_04', True),
    ('sample_io_05', True), ('sample_io_06', False),
    ('sample_io_07', True), ('sample_io_08', True),
    ('sample_io_09', True), ('sample_io_10', True),
    ('sample_io_11', True), ('sample_io_12', True),
    ('sample_io_safe_01', False),
    ('sample_io_safe_02', False),
    ('sample_io_safe_03', False),
]


def run(verbose: bool = False) -> Dict[str, Any]:
    from core.source_ir_extractor import extract_from_file
    from core.int_overflow_depth import IntOverflowDepthAnalyzer
    from core.int_overflow_fp_filter import IntOverflowFpFilter
    from core.int_overflow_detector import IntOverflowDetector

    baseline = IntOverflowDetector()
    depth_analyzer = IntOverflowDepthAnalyzer()
    fp_filter = IntOverflowFpFilter()
    t0 = time.time()

    results = []
    tp_b = fp_b = tn_b = fn_b = 0
    tp_d = fp_d = tn_d = fn_d = 0
    tp_e = fp_e = tn_e = fn_e = 0

    for dirname, is_real in MANIFEST:
        cfile = BASE / dirname / 'vuln.c'
        if not cfile.exists():
            continue

        ir = extract_from_file(str(cfile))
        if not ir:
            continue

        # Baseline: regex-only detection
        base_cands = baseline.detect('\n'.join(ir))
        base_detected = len(base_cands) > 0

        # Depth: 3-dimensional semantic analysis
        depth_results = depth_analyzer.analyze(ir)
        depth_kept = [r for r in depth_results
                      if r.verdict in ('CONFIRMED', 'REVIEW')]
        depth_detected = len(depth_kept) > 0

        # Ensemble: depth detection + FP filter
        from core.int_overflow_fp_filter import \
            extract_int_overflow_candidates
        io_cands = extract_int_overflow_candidates(ir)
        fp_decisions = fp_filter.filter(ir, io_cands)
        fp_kept = [d for d in fp_decisions if d.verdict == 'KEEP']

        # Combined: depth OR (fp_filter kept)
        ens_detected = depth_detected or len(fp_kept) > 0

        # Metrics
        if is_real and base_detected: tp_b += 1
        elif is_real: fn_b += 1
        elif not is_real and not base_detected: tn_b += 1
        else: fp_b += 1

        if is_real and depth_detected: tp_d += 1
        elif is_real: fn_d += 1
        elif not is_real and not depth_detected: tn_d += 1
        else: fp_d += 1

        if is_real and ens_detected: tp_e += 1
        elif is_real: fn_e += 1
        elif not is_real and not ens_detected: tn_e += 1
        else: fp_e += 1

        results.append({
            'sample': dirname, 'is_real_bug': is_real,
            'base_detected': base_detected,
            'depth_detected': depth_detected,
            'ens_detected': ens_detected,
            'depth_kept': len(depth_kept),
            'fp_suppressed': sum(1 for d in fp_decisions
                               if d.verdict == 'SUPPRESS'),
        })

    def metrics(tp, fp, tn, fn):
        prec = tp / (tp + fp) if tp + fp > 0 else 0
        rec = tp / (tp + fn) if tp + fn > 0 else 0
        f1 = 2 * prec * rec / (prec + rec) if prec + rec > 0 else 0
        fp_r = fp / (fp + tn) if fp + tn > 0 else 0
        return {'TP': tp, 'FP': fp, 'TN': tn, 'FN': fn,
                'precision': round(prec, 4), 'recall': round(rec, 4),
                'f1': round(f1, 4), 'fp_rate': round(fp_r, 4)}

    bm = metrics(tp_b, fp_b, tn_b, fn_b)
    dm = metrics(tp_d, fp_d, tn_d, fn_d)
    em = metrics(tp_e, fp_e, tn_e, fn_e)

    elapsed = round(time.time() - t0, 2)
    fp_red_b = round((1 - em['fp_rate'] / bm['fp_rate']) * 100, 1) \
        if bm['fp_rate'] > 0 else 0
    rec_gain = round((em['recall'] - bm['recall']) * 100, 1)

    print(f"\n{'='*62}")
    print(f"  Int Overflow Depth — Regression ({len(results)} samples)")
    print(f"{'='*62}")
    print(f"  {'':18s} {'Baseline':>10s} "
          f"{'+Depth':>10s} {'+Ensemble':>11s}")
    print(f"  {'-'*52}")
    for k in ['precision', 'recall', 'f1', 'fp_rate']:
        print(f"  {k:18s} {bm[k]:>9.4f}  "
              f"{dm[k]:>9.4f}  {em[k]:>10.4f}")
    print(f"  {'-'*52}")
    print(f"  FP Reduction vs baseline: {fp_red_b}%")
    print(f"  Recall gain vs baseline: {rec_gain}%")
    print(f"  ({bm['TP']}->{em['TP']} TP, {bm['FP']}->{em['FP']} FP)")

    if verbose:
        print(f"\n  Per-sample:")
        for r in results:
            ok = 'OK' if r['is_real_bug'] == r['ens_detected'] else 'XX'
            print(f"  {r['sample']:25s} regex={r['base_detected']} "
                  f"depth={r['depth_detected']} "
                  f"ens={r['ens_detected']} {ok}")

    out_path = BASE.parent.parent / 'eval' / 'regression_int_overflow.json'
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump({'baseline': bm, 'depth_analyzer': dm,
                   'ensemble_filtered': em,
                   'fp_reduction_pct': fp_red_b,
                   'recall_gain_pct': rec_gain,
                   'elapsed_sec': elapsed,
                   'per_sample': results}, f, indent=2, ensure_ascii=False)
    print(f"\n  Results -> {out_path}")
    return {'baseline': bm, 'depth': dm, 'ensemble': em,
            'per_sample': results}


if __name__ == '__main__':
    verbose = '--verbose' in sys.argv or '-v' in sys.argv
    run(verbose=verbose)
