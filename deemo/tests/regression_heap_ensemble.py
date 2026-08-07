"""
Automated regression test for heap overflow ensemble detection.
Tests all CVE samples through the GAPSBV + Ensemble pipeline and reports
per-sample metrics: TP/FP/TN/FN, precision, recall, F1, FP rate.

Usage:
  python -m tests.regression_heap_ensemble          # run all
  python -m tests.regression_heap_ensemble --verbose # per-sample details
  python -m tests.regression_heap_ensemble --quick   # samples only, no ensemble

Ground truth: EXPECT_OVERFLOW / EXPECT_SAFE markers in vuln.c comments.
"""

from __future__ import annotations
import sys, os, json, time, re, pathlib
from typing import Any, Dict, List, Tuple


# sample manifest

BASE = pathlib.Path(__file__).resolve().parent.parent / 'samples' / 'cve'

MANIFEST = [
    # (dir, expected_label)
    # TP = True Positive (real overflow, should detect)
    # FP_check = False Positive check (safe code, should NOT flag)
    ('heap_overflow_01_malloc_memcpy',    'TP'),
    ('heap_overflow_02_loop_overflow',    'TP'),
    ('heap_overflow_03_alias_ptr',        'TP'),
    ('heap_overflow_04_calloc',           'TP'),
    ('heap_overflow_05_realloc',          'TP'),
    ('heap_overflow_06_strcpy',           'TP'),
    ('heap_overflow_07_sprintf',          'TP'),
    ('heap_overflow_08_user_input',       'TP'),
    ('heap_overflow_09_offset_write',     'TP'),
    ('heap_overflow_10_nested_loop',      'TP'),
    ('heap_safe_01_alignment_absorbed',   'TN'),
    ('heap_safe_02_same_size',            'TN'),
    ('heap_safe_03_smaller_write',        'TN'),
    ('heap_safe_04_guarded',              'TN'),
    ('heap_safe_05_realloc_expand',       'TN'),
    ('CVE-2014-0160_heartbleed',          'TP'),
    ('CVE-2021-3156_sudo_heap',           'TP'),
    ('CVE-2022-23222_bpf_heap',           'TP'),
    ('CVE-2023-3269_heap',                'TP'),
    ('CVE-2024-21762_fortios',            'TP'),
    # New FP-targeted samples
    ('heap_fp_01_early_return',           'TN'),
    ('heap_fp_02_const_guarded',          'TN'),
    ('heap_fp_03_tainted_double_guard',   'TN'),
    ('heap_fp_04_alias_diff_buf',         'TN'),
    ('heap_fp_05_multi_path_overflow',    'TP'),
    # Edge case boundary stress tests — affine pipeline corner cases
    ('heap_edge_11_multilevel_ptr',       'TN'),
    ('heap_edge_12_struct_field',         'TP'),
    ('heap_edge_13_ternary_alloc',        'TN'),
    ('heap_edge_14_dynamic_loop',         'TP'),
    ('heap_edge_15_realloc_shrink',       'TP'),
]

EXPECT_MAP = {'TP': 'CONFIRMED', 'TN': 'FILTERED'}


# IR extraction

def extract_ir(c_path: str) -> List[str]:
    """Extract simplified IR from C source for analysis."""
    ir = []
    with open(c_path, 'r', encoding='utf-8', errors='replace') as f:
        lines = f.readlines()

    _assign = re.compile(r'(\*?\w[\w.]*(?:\s*\[[^\]]+\])?\s*)\s*=\s*(.+)')
    _call   = re.compile(r'\b(malloc|calloc|realloc|memcpy|memmove|strcpy|strncpy|'
                         r'sprintf|snprintf|free|fgets|gets|recv|getenv)\s*\(')
    _ifpat  = re.compile(r'\bif\s*\(.+\)')
    _forpat = re.compile(r'\bfor\s*\(.+\)')
    _retpat = re.compile(r'\breturn\b')

    for line in lines:
        s = line.strip()
        if not s or s.startswith('//') or s.startswith('/*') or s == '}':
            continue
        if s.startswith('#'):
            continue
        # Emit relevant lines
        if any(p.search(s) for p in (_assign, _call, _ifpat, _forpat, _retpat)):
            # Strip comments and normalize
            s = re.sub(r'/\*.*?\*/', '', s)
            s = re.sub(r'//.*', '', s)
            s = s.strip()
            if s:
                ir.append(s)
    return ir


# test runner

def run_regression(verbose: bool = False, quick: bool = False) -> Dict[str, Any]:
    """Run full regression on all samples. Returns metrics dict."""
    from core.source_ir_extractor import extract_from_file
    from core.heap_ensemble_detector import HeapEnsembleDetector
    from core.heap_overflow_enhanced import EnhancedHeapOverflowDetector

    det = HeapEnsembleDetector()
    baseline = EnhancedHeapOverflowDetector()

    results: List[Dict] = []
    tp = fp = tn = fn = 0
    tp_base = fp_base = tn_base = fn_base = 0
    t0 = time.time()

    for dirname, expected in MANIFEST:
        sample_dir = BASE / dirname
        c_file = sample_dir / 'vuln.c'
        if not c_file.exists():
            if verbose:
                print(f'  SKIP {dirname}: no vuln.c')
            continue

        # Extract IR
        try:
            ir_lines = extract_from_file(str(c_file))
        except Exception:
            ir_lines = extract_ir(str(c_file))
        if not ir_lines:
            if verbose:
                print(f'  SKIP {dirname}: empty IR')
            continue

        # Resolve sizeof/string-literal sizes from source
        try:
            from core.ir_size_resolver import resolve_ir
            with open(c_file, 'r', encoding='utf-8', errors='replace') as f:
                c_src = f.read()
            ir_lines = resolve_ir(c_src, ir_lines)
        except Exception:
            pass

        # Baseline detection
        base_cands = baseline.detect(ir_lines)
        base_confirmed = [c for c in base_cands if c.verdict == 'CONFIRMED']
        base_detected = len(base_confirmed) > 0

        # Ensemble detection
        if not quick:
            cands, decisions, stats = det.detect(ir_lines)
            confirmed = [c for c in cands if c.verdict == 'CONFIRMED']
            suppressed = stats.get('ensemble_suppressed', 0)
            detected = len(confirmed) > 0
        else:
            cands, decisions, stats = [], [], {}
            detected = base_detected
            suppressed = 0

        # Classification
        is_real_bug = (expected == 'TP')
        if is_real_bug and detected:
            tp += 1
            result_verdict = 'TP'
        elif is_real_bug and not detected:
            fn += 1
            result_verdict = 'FN'
        elif not is_real_bug and not detected:
            tn += 1
            result_verdict = 'TN'
        else:  # not real bug but detected
            fp += 1
            result_verdict = 'FP'

        # Baseline classification
        if is_real_bug and base_detected:
            tp_base += 1
        elif is_real_bug and not base_detected:
            fn_base += 1
        elif not is_real_bug and not base_detected:
            tn_base += 1
        else:
            fp_base += 1

        results.append({
            'sample': dirname, 'expected': expected,
            'result': result_verdict,
            'candidates': len(cands),
            'confirmed': len(confirmed),
            'suppressed': suppressed,
            'base_verdict': 'CONFIRMED' if base_detected else 'FILTERED',
        })

    elapsed = round(time.time() - t0, 2)
    total = tp + fp + tn + fn

    # Metrics
    def safe_div(a, b):
        return round(a / b, 4) if b > 0 else 0.0

    precision = safe_div(tp, tp + fp)
    recall = safe_div(tp, tp + fn)
    f1 = safe_div(2 * precision * recall, precision + recall)
    fp_rate = safe_div(fp, fp + tn)
    accuracy = safe_div(tp + tn, total)

    precision_base = safe_div(tp_base, tp_base + fp_base)
    recall_base = safe_div(tp_base, tp_base + fn_base)
    f1_base = safe_div(2 * precision_base * recall_base, precision_base + recall_base)
    fp_rate_base = safe_div(fp_base, fp_base + tn_base)

    metrics = {
        'test_date': time.strftime('%Y-%m-%d'),
        'total_samples': total,
        'ensemble': {
            'TP': tp, 'FP': fp, 'TN': tn, 'FN': fn,
            'precision': precision, 'recall': recall,
            'f1': f1, 'fp_rate': fp_rate, 'accuracy': accuracy,
        },
        'baseline_gapsbv': {
            'TP': tp_base, 'FP': fp_base, 'TN': tn_base, 'FN': fn_base,
            'precision': precision_base, 'recall': recall_base,
            'f1': f1_base, 'fp_rate': fp_rate_base,
        },
        'fp_reduction': {
            'baseline_fp': fp_base,
            'ensemble_fp': fp,
            'baseline_fp_rate': fp_rate_base,
            'ensemble_fp_rate': fp_rate,
            'reduction_pct': round((1 - fp_rate / fp_rate_base) * 100, 1) if fp_rate_base > 0 else 0,
        },
        'elapsed_sec': elapsed,
        'per_sample': results,
    }

    # Print report
    _print_report(metrics, verbose)
    return metrics


def _print_report(m: Dict, verbose: bool):
    """Print formatted regression report."""
    print(f"\n{'='*65}")
    print(f"  Heap Overflow Ensemble Regression Test")
    print(f"  {m['test_date']} | {m['total_samples']} samples | {m['elapsed_sec']}s")
    print(f"{'='*65}")

    e = m['ensemble']
    b = m['baseline_gapsbv']
    r = m['fp_reduction']

    print(f"\n  {'':20s} {'Baseline':>12s} {'Ensemble':>12s} {'Δ':>10s}")
    print(f"  {'-'*55}")
    print(f"  {'Precision':20s} {b['precision']:>11.4f}  {e['precision']:>11.4f}  {e['precision']-b['precision']:>+9.4f}")
    print(f"  {'Recall':20s} {b['recall']:>11.4f}  {e['recall']:>11.4f}  {e['recall']-b['recall']:>+9.4f}")
    print(f"  {'F1 Score':20s} {b['f1']:>11.4f}  {e['f1']:>11.4f}  {e['f1']-b['f1']:>+9.4f}")
    print(f"  {'FP Rate':20s} {b['fp_rate']:>11.4f}  {e['fp_rate']:>11.4f}  {e['fp_rate']-b['fp_rate']:>+9.4f}")
    print(f"  {'FP Count':20s} {b['FP']:>11d}  {e['FP']:>11d}  {e['FP']-b['FP']:>+9d}")
    print(f"  {'-'*55}")
    print(f"  FP Reduction: {r['reduction_pct']}%")

    if verbose and m.get('per_sample'):
        print(f"\n  Per-sample results:")
        print(f"  {'Sample':40s} {'Expected':10s} {'Result':10s} {'Cands':6s} {'Suppr':6s}")
        print(f"  {'-'*72}")
        for s in m['per_sample']:
            flag = ' OK' if s['expected'] == s['result'] else ' XX'
            print(f"  {s['sample']:40s} {s['expected']:10s} {s['result']:10s} "
                  f"{s['candidates']:<6d} {s['suppressed']:<6d}{flag}")

    print()


# main

if __name__ == '__main__':
    verbose = '--verbose' in sys.argv or '-v' in sys.argv
    quick = '--quick' in sys.argv or '-q' in sys.argv

    print(f"Running regression test ({'quick' if quick else 'full ensemble'})...")
    metrics = run_regression(verbose=verbose, quick=quick)

    # Save to file
    out_path = BASE.parent.parent / 'eval' / 'regression_heap_ensemble.json'
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(metrics, f, indent=2, ensure_ascii=False)
    print(f"Results saved to {out_path}")
