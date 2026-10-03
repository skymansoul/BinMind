"""
Regression test for format string detection with FP depth filter.
Tests 12 samples through detect_format_string_enhanced + FmtFpDepthFilter.

Usage:
  python -m tests.regression_format_string
  python -m tests.regression_format_string --verbose
"""

from __future__ import annotations
import sys, json, time, pathlib
from typing import Any, Dict, List, Tuple

BASE = pathlib.Path(__file__).resolve().parent.parent / 'samples' / 'format_string'

MANIFEST: List[Tuple[str, str]] = [
    ('sample_fmt_01', 'TP'),  # fgets->printf(buf)
    ('sample_fmt_02', 'TN'),  # safe: printf("%s", buf)
    ('sample_fmt_03', 'TP'),  # sprintf(dst, buf)
    ('sample_fmt_04', 'TP'),  # fprintf(stderr, buf)
    ('sample_fmt_05', 'TP'),  # syslog(LOG_INFO, buf)
    ('sample_fmt_06', 'TN'),  # safe wrapper: safe_print->printf("%s",s)
    ('sample_fmt_07', 'TP'),  # argv[1]->printf
    ('sample_fmt_08', 'TP'),  # fgets->printf (%%n injectable)
    ('sample_fmt_09', 'TN'),  # constant: printf("hello %s", name)
    ('sample_fmt_10', 'TP'),  # indirect vuln: snprintf("%s")透传%→printf(dst)
    ('sample_fmt_11', 'TP'),  # getenv->printf
    ('sample_fmt_12', 'TP'),  # recv->printf (network)
]


def run(verbose: bool = False) -> Dict[str, Any]:
    from core.source_ir_extractor import extract_from_file
    from core.format_string_enhanced import detect_format_string_enhanced
    from core.fmt_fp_depth_filter import FmtFpDepthFilter

    fp_filter = FmtFpDepthFilter()
    t0 = time.time()
    results = []
    tp_b = fp_b = tn_b = fn_b = 0
    tp_e = fp_e = tn_e = fn_e = 0

    def _find_source(d: pathlib.Path, name: str) -> pathlib.Path | None:
        candidates = [d / 'vuln.c', d / f'{name}.c']
        for c in candidates:
            if c.exists():
                return c
        return None

    for dirname, is_real in MANIFEST:
        cfile = _find_source(BASE / dirname, dirname)
        if cfile is None:
            continue

        ir = extract_from_file(str(cfile))
        if not ir:
            continue

        # Baseline: FORMAT enhanced detector returns (candidates, stats)
        candidates, fmt_stats = detect_format_string_enhanced(ir)
        base_detected = len(candidates) > 0

        # Convert FmtCandidate namedtuples to dicts for FP filter
        cand_dicts = []
        for c in candidates:
            d = {
                'line': getattr(c, 'src_line', 0),
                'text': ir[getattr(c, 'src_line', 0)] if getattr(c, 'src_line', 0) < len(ir) else '',
                'func': getattr(c, 'fmt_func', ''),
                'fmt_arg': getattr(c, 'fmt_arg', ''),
                'verdict': getattr(c, 'verdict', ''),
                'confidence': getattr(c, 'confidence', 0.50),
            }
            cand_dicts.append(d)

        # Run FP depth filter; integrate decision with FORMAT verdict
        decisions = fp_filter.filter(ir, cand_dicts)
        kept = []
        for i, d in enumerate(decisions):
            fmt_verdict = candidates[i].verdict if i < len(candidates) else ''
            # Deep confidence filtering: suppress only UNCERTAIN + depth says review
            if d.verdict == 'SUPPRESS' and fmt_verdict != 'CONFIRMED':
                continue  # SUPPRESS
            if d.verdict == 'SUPPRESS' and fmt_verdict == 'CONFIRMED':
                kept.append(d)  # Override: confirmed by FORMAT pipeline
            elif d.verdict == 'KEEP':
                kept.append(d)
            elif fmt_verdict == 'CONFIRMED':
                kept.append(d)  # FORMAT says confirmed, trust it
            # REVIEW + UNCERTAIN/FILTERED → suppress (potential FP)

        ens_detected = len(kept) > 0

        # Baseline metrics
        if is_real == 'TP' and base_detected: tp_b += 1
        elif is_real == 'TP': fn_b += 1
        elif is_real == 'TN' and not base_detected: tn_b += 1
        else: fp_b += 1

        # Ensemble metrics
        if is_real == 'TP' and ens_detected: tp_e += 1
        elif is_real == 'TP': fn_e += 1
        elif is_real == 'TN' and not ens_detected: tn_e += 1
        else: fp_e += 1

        results.append({
            'sample': dirname, 'is_real_bug': is_real,
            'base_detected': base_detected,
            'ens_detected': ens_detected,
            'base_candidates': len(candidates),
            'kept': len(kept),
            'suppressed': sum(1 for d in decisions
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
    em = metrics(tp_e, fp_e, tn_e, fn_e)
    elapsed = round(time.time() - t0, 2)

    fp_red = round((1 - em['fp_rate'] / bm['fp_rate']) * 100, 1) \
        if bm['fp_rate'] > 0 else 0

    print(f"\n{'='*60}")
    print(f"  Format String FP Filter — Regression "
          f"({len(results)} samples)")
    print(f"{'='*60}")
    print(f"  {'':18s} {'Baseline':>12s} {'+DepthFilt':>12s} {'Delta':>10s}")
    print(f"  {'-'*55}")
    for k in ['precision', 'recall', 'f1', 'fp_rate']:
        print(f"  {k:18s} {bm[k]:>11.4f}  {em[k]:>11.4f}  "
              f"{em[k]-bm[k]:>+9.4f}")
    print(f"  {'-'*55}")
    print(f"  FP Reduction: {fp_red}%")
    print(f"  ({bm['FP']} FP -> {em['FP']} FP, {bm['TN']} TN -> {em['TN']} TN)")

    if verbose:
        print(f"\n  Per-sample:")
        for r in results:
            ok = 'OK' if (
                (r['is_real_bug'] == 'TP' and r['ens_detected']) or
                (r['is_real_bug'] == 'TN' and not r['ens_detected'])
            ) else 'XX'
            print(f"  {r['sample']:20s} base={r['base_detected']} "
                  f"ens={r['ens_detected']} "
                  f"k={r['kept']} supp={r['suppressed']} {ok}")

    out_path = BASE.parent.parent / 'eval' / 'regression_format_string.json'
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump({
            'baseline': bm, 'depth_filtered': em,
            'fp_reduction_pct': fp_red, 'elapsed_sec': elapsed,
            'per_sample': results,
        }, f, indent=2, ensure_ascii=False)
    print(f"\n  Results -> {out_path}")
    return {'baseline': bm, 'ensemble': em, 'per_sample': results}


if __name__ == '__main__':
    verbose = '--verbose' in sys.argv or '-v' in sys.argv
    run(verbose=verbose)
