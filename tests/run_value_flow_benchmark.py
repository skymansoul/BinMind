#!/usr/bin/env python3
"""
DD-后向值流全量回归测试 — 对后向值流样本集运行 solve_candidate 管线.
输出 TP/FP/TN/FN + Precision/Recall/F1 + 后向值流 vs Baseline对比.
"""
import sys, os, json
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind")
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind\deemo")

from pathlib import Path
from core.constraint_solver import solve_candidate
from core.constraint_constraint_types import SolverVerdict
from tests.value_flow_candidate_extractor import extract_candidates_from_code

BVF_SAMPLES_DIR = Path(__file__).parent / 'bvf_samples'

BVF_EXPECTED = {
    'bvf_01_shared_var_safe': False,
    'bvf_02_shared_var_overflow': True,
    'bvf_03_arith_safe': False,
    'bvf_04_arith_overflow': True,
    'bvf_05_multihop_chain': False,
    'bvf_06_no_shared_unrelated': False,
    'bvf_07_offset_safe': False,
    'bvf_08_offset_overflow': True,
    'bvf_09_taint_unbounded': True,
    'bvf_10_guard_capped_safe': False,
    'bvf_11_calloc_safe': False,
    'bvf_12_calloc_overflow': True,
    'bvf_13_realloc_expand_safe': False,
    'bvf_14_realloc_noexpand_overflow': True,
    'bvf_15_loop_accum_overflow': True,
    'bvf_16_loop_safe': False,
    'bvf_17_struct_field_safe': False,
    'bvf_18_struct_field_overflow': True,
}


def run_bvf_benchmark():
    """对后向值流样本集运行DD-后向值流+管线."""
    results = []

    for sample_dir in sorted(BVF_SAMPLES_DIR.iterdir()):
        if not sample_dir.is_dir():
            continue
        vuln_c = sample_dir / 'vuln.c'
        if not vuln_c.exists():
            continue

        code = vuln_c.read_text(encoding='utf-8', errors='replace')
        name = sample_dir.name
        should_detect = BVF_EXPECTED.get(name, None)
        if should_detect is None:
            continue

        candidates, ir_lines = extract_candidates_from_code(code)
        if not candidates:
            detected = False
            verdict_str = "no_candidates"
        else:
            detected = False
            verdict_str = "inconclusive"
            for c in candidates:
                result, _ = solve_candidate(c, ir_lines, code)
                if result.verdict == SolverVerdict.PROVEN_OVERFLOW:
                    detected = True
                    verdict_str = result.reason[:80]
                    break
                if result.verdict == SolverVerdict.PROVEN_SAFE:
                    verdict_str = result.reason[:80]

        if should_detect and detected:
            cls = 'TP'
        elif should_detect and not detected:
            cls = 'FN'
        elif not should_detect and detected:
            cls = 'FP'
        else:
            cls = 'TN'

        results.append({
            'name': name, 'expected': should_detect,
            'detected': detected, 'class': cls,
            'verdict': verdict_str,
        })

    tp = sum(1 for r in results if r['class'] == 'TP')
    fp = sum(1 for r in results if r['class'] == 'FP')
    fn = sum(1 for r in results if r['class'] == 'FN')
    tn = sum(1 for r in results if r['class'] == 'TN')

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)
          if (precision + recall) > 0 else 0.0)
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    print(f"\n{'='*70}")
    print(f"DD-BVF Benchmark Results ({len(results)} samples)")
    print(f"{'='*70}")
    print(f"{'Sample':<40} {'Expected':>10} {'Detected':>10} {'Class':>6}")
    print(f"{'-'*70}")
    for r in results:
        exp = 'VULN' if r['expected'] else 'SAFE'
        det = 'YES' if r['detected'] else 'NO'
        print(f"{r['name']:<40} {exp:>10} {det:>10} {r['class']:>6}")
    print(f"{'-'*70}")
    print(f"{'TP':<40} {tp:>10}")
    print(f"{'FP':<40} {fp:>10}")
    print(f"{'FN':<40} {fn:>10}")
    print(f"{'TN':<40} {tn:>10}")
    print(f"{'-'*70}")
    print(f"{'Precision':<40} {precision:>10.4f}")
    print(f"{'Recall':<40} {recall:>10.4f}")
    print(f"{'F1':<40} {f1:>10.4f}")
    print(f"{'FP Rate':<40} {fpr:>10.4f}")
    print(f"{'='*70}")

    out_path = Path(__file__).parent / 'bvf_benchmark_results.json'
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump({
            'results': results,
            'metrics': {
                'TP': tp, 'FP': fp, 'FN': fn, 'TN': tn,
                'precision': round(precision, 4),
                'recall': round(recall, 4),
                'f1': round(f1, 4),
                'fp_rate': round(fpr, 4),
            },
        }, f, indent=2)
    print(f"\nResults saved to {out_path}")

    return tp == len([r for r in results if r['expected']]) and fp == 0


if __name__ == '__main__':
    ok = run_bvf_benchmark()
    sys.exit(0 if ok else 1)
