#!/usr/bin/env python3
# coding: utf-8
"""
GAPSBV-CJ 端到端基准测试 — 使用cve_gapsbv样本集验证CJ+BVF+PC-BVF管线.
直接从源码提取候选, 无需编译.
"""
from __future__ import annotations
import json, os, sys, time
from pathlib import Path
from typing import Dict, List, Tuple

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)
sys.path.insert(0, os.path.join(BASE, 'tests'))
sys.path.insert(0, os.path.join(BASE, 'eval'))

SAMPLES_DIR = os.path.join(BASE, 'samples', 'cve_gapsbv')
GROUND_TRUTH = os.path.join(SAMPLES_DIR, 'ground_truth.json')


def load_ground_truth() -> Dict:
    with open(GROUND_TRUTH, 'r', encoding='utf-8') as f:
        return json.load(f)


def run_cj_pipeline(code: str) -> Dict:
    from core.cj_solver import solve_candidate
    from core.cj_constraint_types import SolverVerdict
    # 优先使用强化版候选提取器(8种写入模式), 回退到原版(5种)
    try:
        from core.source_level_candidate_extractor import extract_candidates_from_code
    except ImportError:
        from bvf_candidate_extractor import extract_candidates_from_code
    candidates, ir_lines = extract_candidates_from_code(code)
    result = {
        'detected': False, 'candidates': len(candidates),
        'verdict': 'inconclusive', 'reason': '', 'confidence': 0.0,
    }
    for c in candidates:
        res, _ = solve_candidate(c, ir_lines, code)
        if res.verdict == SolverVerdict.PROVEN_OVERFLOW:
            result['detected'] = True
            result['verdict'] = 'overflow'
            result['confidence'] = max(result['confidence'],
                                       res.confidence_delta or 0.5)
            result['reason'] = res.reason[:120]
            break
        if res.verdict == SolverVerdict.PROVEN_SAFE:
            result['verdict'] = 'safe'
            result['reason'] = res.reason[:120]
    return result


def run_baseline(code: str) -> bool:
    import re
    alloc_m = re.findall(r'(?:malloc|calloc|realloc)\s*\(\s*(\d+)', code)
    write_m = re.findall(r'memcpy\s*\([^,]+,[^,]+,\s*(\d+)', code)
    for a in alloc_m:
        for w in write_m:
            if int(w) > int(a):
                return True
    has_malloc = bool(re.search(r'\b(?:malloc|calloc|realloc)\s*\(', code))
    has_write = bool(re.search(r'\b(?:memcpy|strcpy|strncpy)\s*\(', code))
    if has_malloc and has_write:
        return not any(kw in code for kw in ['if (n >', 'if (size >', 'if (len >'])
    return False


def main():
    gt = load_ground_truth()
    samples = []
    for name, info in gt.items():
        vuln_c = os.path.join(SAMPLES_DIR, name, 'vuln.c')
        if not os.path.exists(vuln_c):
            continue
        samples.append({
            'name': name,
            'source': vuln_c,
            'is_vuln': info.get('is_vuln', True),
            'cve': info.get('cve', ''),
            'pattern': info.get('vuln_pattern', ''),
        })

    print('GAPSBV-CJ Benchmark (%d samples)' % len(samples))
    print('=' * 70)

    baseline_res = []
    enhanced_res = []

    for s in samples:
        # heap_relevant=false的样本(UAF/verifier/stack)不参与堆溢出评估
        info = gt.get(s['name'], {})
        if not info.get('heap_relevant', True):
            continue
        code = open(s['source'], 'r', encoding='utf-8', errors='replace').read()
        expected = s['is_vuln']

        b_det = run_baseline(code)
        e_res = run_cj_pipeline(code)
        e_det = e_res['detected']

        b_class = _classify(expected, b_det)
        e_class = _classify(expected, e_det)

        baseline_res.append({'name': s['name'], 'class': b_class, 'detected': b_det})
        enhanced_res.append({
            'name': s['name'], 'class': e_class, 'detected': e_det,
            'verdict': e_res['verdict'], 'reason': e_res['reason'],
            'candidates': e_res['candidates'], 'cve': s['cve'],
        })

        status = 'OK' if (expected == e_det) else 'MISMATCH'
        print('  [%s] %-35s expect=%-5s got=%-5s %s' % (
            status, s['name'][:35],
            'VULN' if expected else 'SAFE',
            'VULN' if e_det else 'SAFE',
            e_res['reason'][:40]))

    b_m = _metrics(baseline_res)
    e_m = _metrics(enhanced_res)
    fp_red = 0.0
    if b_m['FP'] > 0:
        fp_red = (b_m['FP'] - e_m['FP']) / b_m['FP'] * 100

    print()
    print('-' * 70)
    print('%-20s %12s %12s %12s' % ('Metric', 'Baseline', 'Enhanced', 'Change'))
    print('-' * 70)
    for key, label in [('precision', 'Precision'), ('recall', 'Recall'),
                       ('f1', 'F1 Score'), ('fp_rate', 'FP Rate')]:
        bv, ev = b_m[key], e_m[key]
        ch = ev - bv
        print('%-20s %12.4f %12.4f %+12.4f' % (label, bv, ev, ch))
    print('-' * 70)
    print('%-20s %12s %12s' % ('TP', b_m['TP'], e_m['TP']))
    print('%-20s %12s %12s' % ('FP', b_m['FP'], e_m['FP']))
    print('%-20s %12s %12s' % ('FN', b_m['FN'], e_m['FN']))
    print('%-20s %12s %12s' % ('TN', b_m['TN'], e_m['TN']))
    print('-' * 70)
    print('FP Reduction: %.1f%%' % fp_red)
    print()

    output = {
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'sample_count': len(samples),
        'baseline': b_m,
        'enhanced': e_m,
        'fp_reduction_percent': round(fp_red, 1),
        'details': enhanced_res,
    }
    out_path = os.path.join(BASE, 'eval', 'gapsbv_cj_benchmark_results.json')
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print('Results: %s' % out_path)


def _classify(should: bool, detected: bool) -> str:
    if should and detected:
        return 'TP'
    if should and not detected:
        return 'FN'
    if not should and detected:
        return 'FP'
    return 'TN'


def _metrics(results: List[dict]) -> Dict:
    tp = sum(1 for r in results if r['class'] == 'TP')
    fp = sum(1 for r in results if r['class'] == 'FP')
    fn = sum(1 for r in results if r['class'] == 'FN')
    tn = sum(1 for r in results if r['class'] == 'TN')
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    return {
        'TP': tp, 'FP': fp, 'FN': fn, 'TN': tn,
        'precision': round(prec, 4), 'recall': round(rec, 4),
        'f1': round(f1, 4), 'fp_rate': round(fpr, 4),
    }


if __name__ == '__main__':
    main()
