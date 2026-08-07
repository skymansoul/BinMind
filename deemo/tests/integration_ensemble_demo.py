"""
Integration demo: ensemble FP filter on relaxed-mode GAPSBV pipeline.
Shows FP reduction when pipeline runs in review mode (CONFIRMED+UNCERTAIN).

This demonstrates the ensemble's value: the relaxed pipeline has higher recall
but also FPs; the ensemble filter suppresses FPs while keeping TPs.

Usage: python -m tests.integration_ensemble_demo
"""

from __future__ import annotations
import sys, time, json
from typing import List, Dict, Any


def demo_ensemble_fp_reduction():
    """Run relaxed pipeline + ensemble on all CVE samples, show FP reduction."""
    from core.source_ir_extractor import extract_from_file
    from core.heap_overflow_enhanced import EnhancedHeapOverflowDetector
    from core.ensemble_fp_filter import EnsembleFpFilter
    import pathlib

    BASE = pathlib.Path(__file__).resolve().parent.parent / 'samples' / 'cve'

    # Sample manifest with ground truth
    MANIFEST = [
        ('heap_overflow_01_malloc_memcpy',    True),
        ('heap_overflow_02_loop_overflow',    True),
        ('heap_overflow_03_alias_ptr',        True),
        ('heap_overflow_04_calloc',           True),
        ('heap_overflow_05_realloc',          True),
        ('heap_overflow_06_strcpy',           True),
        ('heap_overflow_07_sprintf',          True),
        ('heap_overflow_08_user_input',       True),
        ('heap_overflow_09_offset_write',     True),
        ('heap_overflow_10_nested_loop',      True),
        ('heap_safe_01_alignment_absorbed',   False),
        ('heap_safe_02_same_size',            False),
        ('heap_safe_03_smaller_write',        False),
        ('heap_safe_04_guarded',              False),
        ('heap_safe_05_realloc_expand',       False),
        ('heap_fp_01_early_return',           False),
        ('heap_fp_02_const_guarded',          False),
        ('heap_fp_03_tainted_double_guard',   False),
        ('heap_fp_04_alias_diff_buf',         False),
        ('heap_fp_05_multi_path_overflow',    True),
    ]

    detector = EnhancedHeapOverflowDetector()
    ensemble = EnsembleFpFilter()
    t0 = time.time()

    results = []
    for dirname, is_real_bug in MANIFEST:
        cfile = BASE / dirname / 'vuln.c'
        if not cfile.exists():
            continue
        ir = extract_from_file(str(cfile))
        if not ir:
            continue

        # Get pipeline candidates
        cands = detector.detect(ir)

        # Use review mode: CONFIRMED + UNCERTAIN (higher recall, more FPs)
        review = [c for c in cands if c.verdict in ('CONFIRMED', 'UNCERTAIN')]
        pipeline_detected = len(review) > 0

        # Run ensemble filter on review candidates
        if review:
            from core.heap_ensemble_detector import _extract_size_var, _best_alloc_size
            cand_dicts = [{
                'line': c.write_site.loc,
                'alloc_var': c.alloc_site.var_name,
                'alloc_size': _best_alloc_size(c),
                'size_var': _extract_size_var(ir, c.write_site.loc),
                'write_func': 'memcpy',
            } for c in review]
            decisions = ensemble.filter(ir, cand_dicts)

            # After ensemble: only KEEP or REVIEW verdicts
            kept = [d for i, d in enumerate(decisions)
                    if d.verdict != 'SUPPRESS' and i < len(review)]
            ensemble_detected = len(kept) > 0
            suppressed = sum(1 for d in decisions if d.verdict == 'SUPPRESS')
        else:
            decisions, ensemble_detected, suppressed = [], pipeline_detected, 0

        results.append({
            'sample': dirname, 'is_real_bug': is_real_bug,
            'pipeline_detected': pipeline_detected,
            'ensemble_detected': ensemble_detected,
            'suppressed': suppressed,
            'candidates': len(cands), 'review': len(review),
        })

    # Compute metrics
    # Pipeline (review mode)
    p_tp = sum(1 for r in results if r['is_real_bug'] and r['pipeline_detected'])
    p_fp = sum(1 for r in results if not r['is_real_bug'] and r['pipeline_detected'])
    p_tn = sum(1 for r in results if not r['is_real_bug'] and not r['pipeline_detected'])
    p_fn = sum(1 for r in results if r['is_real_bug'] and not r['pipeline_detected'])

    # Ensemble-filtered
    e_tp = sum(1 for r in results if r['is_real_bug'] and r['ensemble_detected'])
    e_fp = sum(1 for r in results if not r['is_real_bug'] and r['ensemble_detected'])
    e_tn = sum(1 for r in results if not r['is_real_bug'] and not r['ensemble_detected'])
    e_fn = sum(1 for r in results if r['is_real_bug'] and not r['ensemble_detected'])

    def m(tp, fp, tn, fn):
        prec = tp / (tp + fp) if tp + fp > 0 else 0
        rec = tp / (tp + fn) if tp + fn > 0 else 0
        f1 = 2 * prec * rec / (prec + rec) if prec + rec > 0 else 0
        fp_rate = fp / (fp + tn) if fp + tn > 0 else 0
        return {'TP': tp, 'FP': fp, 'TN': tn, 'FN': fn,
                'precision': round(prec, 4), 'recall': round(rec, 4),
                'f1': round(f1, 4), 'fp_rate': round(fp_rate, 4)}

    pipeline_m = m(p_tp, p_fp, p_tn, p_fn)
    ensemble_m = m(e_tp, e_fp, e_tn, e_fn)

    fp_reduction_pct = round(
        (1 - ensemble_m['fp_rate'] / pipeline_m['fp_rate']) * 100, 1
    ) if pipeline_m['fp_rate'] > 0 else 0

    elapsed = round(time.time() - t0, 2)

    # Print report
    print(f"\n{'='*65}")
    print(f"  Ensemble FP Filter — Integration Demo")
    print(f"  {len(results)} samples | {elapsed}s")
    print(f"{'='*65}")
    print(f"\n  {'':20s} {'Pipeline':>14s} {'+Ensemble':>14s} {'Delta':>10s}")
    print(f"  {'-'*60}")
    for k in ['precision', 'recall', 'f1', 'fp_rate']:
        pv = pipeline_m[k]; ev = ensemble_m[k]
        delta = ev - pv
        print(f"  {k:20s} {pv:>14.4f} {ev:>14.4f} {delta:>+10.4f}")
    print(f"  {'-'*60}")
    print(f"  {'FP Count':20s} {pipeline_m['FP']:>14d} {ensemble_m['FP']:>14d} "
          f"{ensemble_m['FP'] - pipeline_m['FP']:>+10d}")
    print(f"  {'TN Count':20s} {pipeline_m['TN']:>14d} {ensemble_m['TN']:>14d} "
          f"{ensemble_m['TN'] - pipeline_m['TN']:>+10d}")
    print(f"\n  FP Reduction: {fp_reduction_pct}%")
    print(f"  (Pipeline FP rate {pipeline_m['fp_rate']:.3f} -> "
          f"Ensemble FP rate {ensemble_m['fp_rate']:.3f})")

    # Per-sample suppressed
    fp_suppressed = [r for r in results
                     if r['suppressed'] > 0 and not r['is_real_bug']]
    tp_kept = [r for r in results
               if r['is_real_bug'] and r['ensemble_detected']]
    tp_lost = [r for r in results
               if r['is_real_bug'] and r['pipeline_detected'] and not r['ensemble_detected']]

    if fp_suppressed:
        print(f"\n  FP correctly suppressed: {len(fp_suppressed)}")
        for r in fp_suppressed:
            print(f"    OK {r['sample']}: {r['suppressed']} candidate(s) suppressed")

    if tp_lost:
        print(f"\n  TP incorrectly suppressed: {len(tp_lost)}")
        for r in tp_lost:
            print(f"    XX {r['sample']}: lost detection")

    print()

    # Save detailed results
    out_path = pathlib.Path(__file__).resolve().parent.parent / 'eval' / 'integration_demo.json'
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump({
            'pipeline_review': pipeline_m,
            'ensemble_filtered': ensemble_m,
            'fp_reduction_pct': fp_reduction_pct,
            'per_sample': results,
            'elapsed_sec': elapsed,
        }, f, indent=2, ensure_ascii=False)
    print(f"  Results saved -> {out_path}")


if __name__ == '__main__':
    demo_ensemble_fp_reduction()
