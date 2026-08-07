"""
Regression test for UAF detection with temporal distance scoring.
Tests 20 samples through EnhancedUafDetector + temporal distance pipeline.

Usage:
  python -m tests.regression_uaf_ensemble
  python -m tests.regression_uaf_ensemble --verbose
"""

from __future__ import annotations
import sys, json, time, pathlib
from typing import Any, Dict, List, Tuple

BASE = pathlib.Path(__file__).resolve().parent.parent / 'samples' / 'uaf'

MANIFEST: List[Tuple[str, str]] = [
    # (dir, expected_label)
    # Ground truth from samples/uaf/README.md
    ('sample_uaf_01', 'TP'),  # DEF_TP: basic UAF
    ('sample_uaf_02', 'TN'),  # DEF_FP: NULL-zeroed after free
    ('sample_uaf_03', 'TP'),  # DEF_TP: alias UAF q=p;free(p);use(q)
    ('sample_uaf_04', 'TN'),  # DEF_FP: immediate realloc reuse
    ('sample_uaf_05', 'TP'),  # DOUBLE_FREE (CWE-415)
    ('sample_uaf_06', 'TP'),  # DEF_TP: conditional branch free
    ('sample_uaf_07', 'TP'),  # DEF_TP: loop array index UAF
    ('sample_uaf_08', 'TP'),  # DEF_TP: cross-function UAF
    ('sample_uaf_09', 'TP'),  # DEF_TP: global pointer UAF
    ('sample_uaf_10', 'TP'),  # DEF_TP: struct member ptr UAF
    ('sample_uaf_11', 'TP'),  # DEF_TP: multi-level alias chain
    ('sample_uaf_12', 'TP'),  # DEF_TP: realloc old-ptr UAF
    ('sample_uaf_13', 'TN'),  # DEF_FP: double ptr NULL zeroed
    ('sample_uaf_14', 'TP'),  # DEF_TP: switch-case control flow
    ('sample_uaf_15', 'TP'),  # DEF_TP: alias not NULL-zeroed
    # CVE-based samples (16-20)
    ('sample_uaf_cve_16', 'TP'), ('sample_uaf_cve_17', 'TP'),
    ('sample_uaf_cve_18', 'TP'), ('sample_uaf_cve_19', 'TP'),
    ('sample_uaf_cve_20', 'TP'),
]


def run(verbose: bool = False) -> Dict[str, Any]:
    from core.source_ir_extractor import extract_from_file
    from core.uaf_enhanced import EnhancedUafDetector
    from core.uaf_temporal_distance import score_uaf_with_distance

    detector = EnhancedUafDetector()
    t0 = time.time()
    results = []
    tp_b = fp_b = tn_b = fn_b = 0
    tp_e = fp_e = tn_e = fn_e = 0

    def _find_source(d: pathlib.Path, name: str) -> pathlib.Path | None:
        """Samples use either vuln.c or sample_XX.c naming."""
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

        # Baseline: TARPS EnhancedUafDetector
        base_cands = detector.detect(ir)
        base_detected = len(base_cands) > 0

        # Ensemble: integrate temporal distance with TARPS confidence
        # TARPS already does high-quality filtering (A-E stages).
        # Temporal distance MODULATES confidence rather than replacing.
        free_sites = []
        for c in base_cands:
            fe = getattr(c, 'free_event', None)
            if fe is not None:
                fl = getattr(fe, 'line_idx', 0)
                pn = getattr(c, 'ptr_name', 'ptr')
                free_sites.append((fl, pn))

        temporal_scores = score_uaf_with_distance(ir, free_sites,
                                                   func_length=len(ir))
        # Build temporal lookup: ptr_name → exploitability
        ts_map = {td.ptr_name: td.exploitability for td in temporal_scores}

        # Keep if: TARPS CONFIRMED with confidence > 0.50, OR
        #          temporal says high exploitability (> 0.60)
        kept = []
        for c in base_cands:
            ts = ts_map.get(c.ptr_name, 0.50)
            tarps_conf = getattr(c, 'confidence', 0.50)
            verdict = getattr(c, 'verdict', 'UNCERTAIN')

            if verdict == 'FILTERED':
                continue  # Trust TARPS when it says filtered

            # Combined: TARPS confidence weighted by temporal exploitability
            combined = tarps_conf * 0.60 + ts * 0.40
            if combined >= 0.40:
                kept.append(c)

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
            'base_candidates': len(base_cands),
            'temporal_scores': [(td.ptr_name, td.exploitability,
                                  td.dist_normalized) for td in temporal_scores],
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
    print(f"  UAF Ensemble — Temporal Distance Regression "
          f"({len(results)} samples)")
    print(f"{'='*60}")
    print(f"  {'':18s} {'Baseline':>12s} {'+Temporal':>12s} {'Delta':>10s}")
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
            print(f"  {r['sample']:25s} base={r['base_detected']} "
                  f"ens={r['ens_detected']} {ok}")

    out_path = BASE.parent.parent / 'eval' / 'regression_uaf_ensemble.json'
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump({
            'baseline': bm, 'ensemble_temporal': em,
            'fp_reduction_pct': fp_red, 'elapsed_sec': elapsed,
            'per_sample': results,
        }, f, indent=2, ensure_ascii=False)
    print(f"\n  Results -> {out_path}")
    return {'baseline': bm, 'ensemble': em, 'per_sample': results}


if __name__ == '__main__':
    verbose = '--verbose' in sys.argv or '-v' in sys.argv
    run(verbose=verbose)
