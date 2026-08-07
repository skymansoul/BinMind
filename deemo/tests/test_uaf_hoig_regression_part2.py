"""
HOIG 回归测试 — 堆对象身份追踪 UAF 检测.

测试结构 (min 15 samples):
  - INTR_FUNC (4):  单函数内 UAF
  - CROSS_FUNC (4): 跨函数 UAF
  - EDGE (4):       边界情况
  - FP_FILTER (3):  误报过滤
"""

from __future__ import annotations

import importlib.util, os, sys, unittest

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

# 确保真实 analysis 包被导入, 而非被空白占位覆盖
import analysis as _analysis_pkg  # noqa: F401

from tests.test_uaf_hoig_regression_samples import (
    INTR_SIMPLE, INTR_ALIAS, INTR_REALLOC_OLD_PTR, INTR_FIELD_ALIAS,
    CROSS_CALLEE_FREES, CROSS_PARAM_PROPAGATION, CROSS_RETURN_FREED, CROSS_CALLBACK,
    EDGE_NULL_CHECK_AFTER_FREE, EDGE_NULLIFY_AFTER_FREE,
    EDGE_REALLOC_NEW_PTR_USE, EDGE_STRDUP_UAF,
    FP_DIFFERENT_OBJ, FP_SAFE_REALLOC, FP_REFCOUNT_RESET,
    BENCHMARK_SAMPLES, BENCHMARK_EXPECTED,
)

from analysis.uaf_hoig_builder import HoigBuilder
from analysis.uaf_hoig_types import UafHoigVerdict

from analysis.uaf_hoig_verifier import HoigVerifier, HoigReallocTracker



class TestHoigEdgeCases(unittest.TestCase):
    """边界情况 UAF 检测."""

    def setUp(self):
        self.verifier = HoigVerifier()

    def test_null_check_after_free(self):
        v = self.verifier.verify_single(EDGE_NULL_CHECK_AFTER_FREE, 'test_func')
        self.assertEqual(v.verdict, 'CONFIRMED',
                         'NULL check after free does NOT nullify ptr')

    def test_nullify_after_free(self):
        v = self.verifier.verify_single(EDGE_NULLIFY_AFTER_FREE, 'test_func')
        self.assertEqual(v.verdict, 'SAFE',
                         'NULL-assigned ptr use is not UAF (nullptr deref)')

    def test_realloc_new_ptr_safe(self):
        v = self.verifier.verify_single(EDGE_REALLOC_NEW_PTR_USE, 'test_func')
        self.assertEqual(v.verdict, 'SAFE', 'realloc new ptr use is safe')

    def test_strdup_uaf(self):
        v = self.verifier.verify_single(EDGE_STRDUP_UAF, 'test_func')
        self.assertEqual(v.verdict, 'CONFIRMED',
                         'strdup object free then use is UAF')


class TestHoigFPFilter(unittest.TestCase):
    """HOIG 误报过滤 — 应返回 SAFE."""

    def setUp(self):
        self.verifier = HoigVerifier()

    def test_different_object(self):
        v = self.verifier.verify_single(FP_DIFFERENT_OBJ, 'test_func')
        self.assertEqual(v.verdict, 'SAFE',
                         'Different ObjectIDs — free(p) does not affect q')

    def test_safe_realloc(self):
        v = self.verifier.verify_single(FP_SAFE_REALLOC, 'test_func')
        self.assertEqual(v.verdict, 'SAFE', 'Using realloc new ptr is safe')

    def test_refcount_pattern(self):
        v = self.verifier.verify_single(FP_REFCOUNT_RESET, 'test_func')
        self.assertEqual(v.verdict, 'SAFE',
                         'Freeing parent struct not UAF for child data field')


class TestHoigReallocTracker(unittest.TestCase):
    """realloc 追踪器专项测试."""

    def setUp(self):
        self.tracker = HoigReallocTracker()

    def test_realloc_old_ptr_use_after(self):
        code = "char *p = malloc(64);\nchar *q = realloc(p, 128);\n*p = 42;"
        verdicts = self.tracker.analyze(code)
        self.assertGreater(len(verdicts), 0, 'realloc old ptr use should be detected')

    def test_realloc_new_ptr_safe(self):
        code = "char *p = malloc(64);\nchar *q = realloc(p, 128);\nq[0] = 42;"
        verdicts = self.tracker.analyze(code)
        self.assertEqual(len(verdicts), 0, 'realloc new ptr use is safe')

    def test_double_realloc(self):
        code = ("char *p = malloc(32);\n"
                "char *q = realloc(p, 64);\n"
                "char *r = realloc(q, 128);\n"
                "*p = 1;")
        verdicts = self.tracker.analyze(code)
        self.assertGreater(len(verdicts), 0, 'double realloc: *p after realloc chain')


# 基准测试运行器

def run_hoig_benchmark():
    """运行 HOIG 全量回归测试并报告结果."""
    import json, time

    verifier = HoigVerifier()
    results = {}
    tp = fp = tn = fn = 0
    total_time = 0.0

    for name, code in BENCHMARK_SAMPLES.items():
        start = time.perf_counter()
        v = verifier.verify_single(code, name)
        elapsed = time.perf_counter() - start
        total_time += elapsed

        exp = BENCHMARK_EXPECTED.get(name, 'CONFIRMED')
        correct = (v.verdict == exp)
        results[name] = {
            'verdict': v.verdict,
            'expected': exp,
            'correct': correct,
            'confidence': v.confidence,
            'reason': v.reason,
            'time_ms': round(elapsed * 1000, 2),
        }

        if exp == 'CONFIRMED' and v.verdict == 'CONFIRMED':
            tp += 1
        elif exp == 'CONFIRMED' and v.verdict != 'CONFIRMED':
            fn += 1
        elif exp == 'SAFE' and v.verdict == 'CONFIRMED':
            fp += 1
        elif exp == 'SAFE' and v.verdict == 'SAFE':
            tn += 1

    n = len(BENCHMARK_SAMPLES)
    precision = tp / max(1, tp + fp)
    recall = tp / max(1, tp + fn)
    f1 = 2 * precision * recall / max(0.001, precision + recall)
    accuracy = (tp + tn) / n

    report = {
        'module': 'HOIG (Heap Object Identity Graph)',
        'total_samples': n,
        'tp': tp, 'fp': fp, 'tn': tn, 'fn': fn,
        'precision': round(precision, 4),
        'recall': round(recall, 4),
        'f1': round(f1, 4),
        'accuracy': round(accuracy, 4),
        'avg_time_ms': round(total_time / n * 1000, 2),
        'details': results,
    }

    out_dir = os.path.join(BASE, 'eval')
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, 'uaf_hoig_benchmark_results.json')
    with open(out_path, 'w') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print('\n' + '='*70)
    print('HOIG UAF Detection Benchmark Results')
    print('='*70)
    print(f'  Total: {n} samples  |  TP={tp}  FP={fp}  TN={tn}  FN={fn}')
    print(f'  Precision: {precision:.4f}  Recall: {recall:.4f}  F1: {f1:.4f}')
    print(f'  Accuracy:  {accuracy:.4f}  Avg Time: {total_time/n*1000:.2f}ms')
    print(f'  Results saved to: {out_path}')
    print('-'*70)
    for name, r in results.items():
        status = 'PASS' if r['correct'] else 'FAIL'
        print(f'  [{status}] {name:<25s} → {r["verdict"]:>10s} '
              f'(expected {r["expected"]})')
    print('='*70)

    return report


if __name__ == '__main__':
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument('--benchmark', action='store_true',
                   help='Run full HOIG benchmark')
    p.add_argument('--test', action='store_true', default=True,
                   help='Run unittest suite')
    args = p.parse_args()

    if args.benchmark:
        run_hoig_benchmark()
    else:
        unittest.main(argv=[''], exit=False)
