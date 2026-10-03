#!/usr/bin/env python3
"""
跨上下文分配-写溯源端到端benchmark — 上下文敏感仿射证明器的完整管线测试.

测试跨上下文分配-写溯源在各场景下的表现:
  上下文区分、调用链传播、calloc乘积、常数差、taint传播、
  偏移安全、系数比、多变量子集、realloc缩小、包装函数间接调用.

输出: TP/FP/TN/FN + Precision/Recall/F1 + 跨上下文分配-写溯源 vs Baseline对比.
"""
import sys, os, json
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind")
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind\deemo")

from pathlib import Path
from core.constraint_solver import solve_candidate
from core.constraint_constraint_types import SolverVerdict
from tests.value_flow_candidate_extractor import extract_candidates_from_code

CAAWP_SAMPLES_DIR = Path(__file__).parent / 'caawp_samples'

CAAWP_EXPECTED = {
    'caawp_01_ctx_safe': False,
    'caawp_02_ctx_overflow': True,
    'caawp_03_ctx_dual_safe_overflow': True,
    'caawp_04_callchain_deep_safe': False,
    'caawp_05_callchain_deep_overflow': True,
    'caawp_06_calloc_product_overflow': True,
    'caawp_07_calloc_product_safe': False,
    'caawp_08_const_diff_safe': False,
    'caawp_09_const_diff_overflow': True,
    'caawp_10_taint_fixed_alloc_overflow': True,
    'caawp_11_taint_var_alloc_safe': False,
    'caawp_12_offset_const_safe': False,
    'caawp_13_offset_const_overflow': True,
    'caawp_14_coefficient_ratio_safe': False,
    'caawp_15_coefficient_ratio_overflow': True,
    'caawp_16_multivar_subset_safe': False,
    'caawp_17_multivar_independent_overflow': True,
    'caawp_18_realloc_shrink_overflow': True,
    'caawp_19_wrapper_indirect_overflow': True,
    'caawp_20_wrapper_indirect_safe': False,
}


def run_caawp_benchmark():
    """对跨上下文分配-写溯源样本集运行完整管线."""
    results = []

    for sample_dir in sorted(CAAWP_SAMPLES_DIR.iterdir()):
        if not sample_dir.is_dir():
            continue
        vuln_c = sample_dir / 'vuln.c'
        if not vuln_c.exists():
            continue

        code = vuln_c.read_text(encoding='utf-8', errors='replace')
        name = sample_dir.name
        should_detect = CAAWP_EXPECTED.get(name, None)
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
            'name': name,
            'expected': should_detect,
            'detected': detected,
            'class': cls,
            'verdict': verdict_str,
        })

    tp = sum(1 for r in results if r['class'] == 'TP')
    fp = sum(1 for r in results if r['class'] == 'FP')
    fn = sum(1 for r in results if r['class'] == 'FN')
    tn = sum(1 for r in results if r['class'] == 'TN')

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) \
        if (precision + recall) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    print("\n" + "=" * 70)
    print(f"跨上下文分配-写溯源 Benchmark Results ({len(results)} samples)")
    print("=" * 70)
    print(f"{'Sample':<45} {'Expected':<10} {'Detected':<10} {'Class'}")
    print("-" * 70)
    for r in results:
        exp = "VULN" if r['expected'] else "SAFE"
        det = "YES" if r['detected'] else "NO"
        print(f"{r['name']:<45} {exp:<10} {det:<10} {r['class']}")
    print("-" * 70)
    print(f"{'TP':<45} {tp}")
    print(f"{'FP':<45} {fp}")
    print(f"{'FN':<45} {fn}")
    print(f"{'TN':<45} {tn}")
    print("-" * 70)
    print(f"{'Precision':<45} {precision:.4f}")
    print(f"{'Recall':<45} {recall:.4f}")
    print(f"{'F1':<45} {f1:.4f}")
    print(f"{'FP Rate':<45} {fpr:.4f}")
    print("=" * 70)

    output_path = Path(__file__).parent / 'alloc_write_cross_benchmark_results.json'
    with open(output_path, 'w') as f:
        json.dump({
            'results': results,
            'metrics': {
                'tp': tp, 'fp': fp, 'fn': fn, 'tn': tn,
                'precision': precision, 'recall': recall,
                'f1': f1, 'fpr': fpr,
            }
        }, f, indent=2)
    print(f"\nResults saved to {output_path}")

    return results


if __name__ == '__main__':
    run_caawp_benchmark()
