"""
格式说明符类型 回归测试 — 格式说明符语义感知污点传播.

测试结构 (≥15 samples):
  - CONST (3):   常量字符串 — 安全
  - USER_INPUT (4): 用户输入 — CWE-134
  - SANITIZED (4): 清理后 — 过滤FP
  - EDGE (4):    边界情况 — 复杂赋值/snprintf链接/嵌套
"""

from __future__ import annotations

import importlib.util, os, sys, unittest

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

# 直接加载模块
_fstp_path = os.path.join(BASE, 'analysis', 'fmt_semantic_taint.py')

# 确保真实 analysis 包被导入, 而非被空白占位覆盖
import analysis as _analysis_pkg  # noqa: F401

_fstp_spec = importlib.util.spec_from_file_location(
    'analysis.fmt_semantic_taint', _fstp_path)
_fstp_mod = importlib.util.module_from_spec(_fstp_spec)
sys.modules['analysis.fmt_semantic_taint'] = _fstp_mod
_fstp_spec.loader.exec_module(_fstp_mod)

SemClass = _fstp_mod.SemClass
FstpVerdict = _fstp_mod.FstpVerdict
FmtSemanticTaintPropagator = _fstp_mod.FmtSemanticTaintPropagator

from tests.test_fstp_regression_samples import (
    CONST_FMT, CONST_PURE, CONST_FORMATTED,
    USER_INPUT_SCANF, USER_INPUT_FGETS, USER_INPUT_RECV, USER_INPUT_ARGV,
    SANITIZED_STRREPLACE, SANITIZED_SANITIZE,
    SANITIZED_G_STRDUP_PRINTF, SANITIZED_ESCAPE_FORMAT,
    EDGE_SNPRINTF_CHAIN, EDGE_ASSIGN_CHAIN,
    EDGE_NO_FORMAT_INPUT, EDGE_WRAPPER_PATTERN,
    FMT_SPEC_WRITE_CAPABLE, FMT_SPEC_READ_ONLY,
    BENCHMARK_SAMPLES, EXPECTED_CWE,
)


class TestFstpConstants(unittest.TestCase):
    """常量字符串 — 应判定为 SAFE."""

    def setUp(self):
        self.fstp = FmtSemanticTaintPropagator()

    def assert_sem(self, code, expected_class, msg=""):
        vs, st = self.fstp.analyze(code)
        self.assertGreater(len(vs), 0, f'No calls found. {msg}')
        self.assertEqual(vs[0].sem_class, expected_class,
                         f'Expected {expected_class}, got {vs[0].sem_class}: '
                         f'{vs[0].reason}. {msg}')

    def test_const_fmt(self):
        """常量格式字符串: "Hello %s" → SEM_CONST_FMT"""
        self.assert_sem(CONST_FMT, SemClass.SEM_CONST_FMT)

    def test_const_pure(self):
        """常量纯字符串: "System ready." → SEM_CLEAN"""
        self.assert_sem(CONST_PURE, SemClass.SEM_CLEAN)

    def test_const_formatted(self):
        """常量格式字符串: "[%s:%d]" → SEM_CONST_FMT"""
        self.assert_sem(CONST_FORMATTED, SemClass.SEM_CONST_FMT)


class TestFstpUserInput(unittest.TestCase):
    """用户输入 — 应判定为 CWE-134."""

    def setUp(self):
        self.fstp = FmtSemanticTaintPropagator()

    def test_scanf_input(self):
        """scanf → printf → CWE-134"""
        vs, st = self.fstp.analyze(USER_INPUT_SCANF)
        self.assertTrue(vs[0].is_cwe134, 'scanf→printf should be CWE-134')

    def test_fgets_input(self):
        """fgets → printf → CWE-134"""
        vs, st = self.fstp.analyze(USER_INPUT_FGETS)
        self.assertTrue(vs[0].is_cwe134, 'fgets→printf should be CWE-134')

    def test_recv_input(self):
        """recv → fprintf → CWE-134"""
        vs, st = self.fstp.analyze(USER_INPUT_RECV)
        self.assertTrue(vs[0].is_cwe134, 'recv→fprintf should be CWE-134')

    def test_argv_input(self):
        """argv[1] → printf → CWE-134"""
        vs, st = self.fstp.analyze(USER_INPUT_ARGV)
        self.assertTrue(vs[0].is_cwe134, 'argv→printf should be CWE-134')


class TestFstpSanitized(unittest.TestCase):
    """清理后 — 应过滤FP (判定 SAFE)."""

    def setUp(self):
        self.fstp = FmtSemanticTaintPropagator()

    def test_strreplace_sanitized(self):
        """strreplace(buf, "%", "%%") → SEM_USER_SAFE"""
        vs, st = self.fstp.analyze(SANITIZED_STRREPLACE)
        self.assertEqual(vs[0].sem_class, SemClass.SEM_USER_SAFE,
                         'strreplace should sanitize to USER_SAFE')
        self.assertFalse(vs[0].is_cwe134)

    def test_sanitize_func(self):
        """sanitize(input) → SEM_USER_SAFE"""
        vs, st = self.fstp.analyze(SANITIZED_SANITIZE)
        self.assertEqual(vs[0].sem_class, SemClass.SEM_USER_SAFE)

    def test_g_strdup_printf(self):
        """g_strdup_printf("%s", name) → SEM_USER_SAFE"""
        vs, st = self.fstp.analyze(SANITIZED_G_STRDUP_PRINTF)
        self.assertEqual(vs[0].sem_class, SemClass.SEM_USER_SAFE)

    def test_escape_format(self):
        """escape_format(user) → SEM_USER_SAFE"""
        vs, st = self.fstp.analyze(SANITIZED_ESCAPE_FORMAT)
        self.assertEqual(vs[0].sem_class, SemClass.SEM_USER_SAFE)


class TestFstpEdgeCases(unittest.TestCase):
    """边界情况."""

    def setUp(self):
        self.fstp = FmtSemanticTaintPropagator()

    def test_snprintf_chain(self):
        """snprintf链传播污点"""
        vs, st = self.fstp.analyze(EDGE_SNPRINTF_CHAIN)
        self.assertTrue(vs[0].is_cwe134,
                        'snprintf chain should propagate taint')

    def test_assign_chain(self):
        """赋值链传播: user → fmt → printf"""
        vs, st = self.fstp.analyze(EDGE_ASSIGN_CHAIN)
        self.assertTrue(vs[0].is_cwe134,
                        'assign chain should propagate taint')

    def test_no_format_string(self):
        """无格式字符串的变量 → SAFE"""
        vs, st = self.fstp.analyze(EDGE_NO_FORMAT_INPUT)
        self.assertFalse(vs[0].is_cwe134,
                         'non-user-input should not be CWE-134')

    def test_sem_class_distinction(self):
        """语义分类: recv → SEM_USER_WRITE vs fgets → SEM_USER_READ"""
        vs1, _ = self.fstp.analyze(FMT_SPEC_WRITE_CAPABLE)
        vs2, _ = self.fstp.analyze(FMT_SPEC_READ_ONLY)
        self.assertEqual(vs1[0].sem_class, SemClass.SEM_USER_WRITE)
        self.assertEqual(vs2[0].sem_class, SemClass.SEM_USER_READ)


# 基准测试

def run_fstp_benchmark():
    """运行 格式说明符类型 全量基准测试."""
    import json, time

    fstp = FmtSemanticTaintPropagator()
    results = {}
    tp = fp = tn = fn = 0
    total_time = 0.0

    for name, code in BENCHMARK_SAMPLES.items():
        fstp.clear()
        start = time.perf_counter()
        vs, st = fstp.analyze(code)
        elapsed = time.perf_counter() - start
        total_time += elapsed

        exp = EXPECTED_CWE.get(name, True)
        got = vs[0].is_cwe134 if vs else False
        correct = (got == exp)
        results[name] = {
            'is_cwe134': got,
            'expected_cwe134': exp,
            'correct': correct,
            'sem_class': vs[0].sem_class.name if vs else 'NONE',
            'confidence': vs[0].confidence if vs else 0,
            'time_ms': round(elapsed * 1000, 3),
        }

        if exp and got:       tp += 1
        elif exp and not got:  fn += 1
        elif not exp and got:  fp += 1
        elif not exp and not got: tn += 1

    n = len(BENCHMARK_SAMPLES)
    precision = tp / max(1, tp + fp)
    recall = tp / max(1, tp + fn)
    f1 = 2 * precision * recall / max(0.001, precision + recall)

    report = {
        'module': '格式说明符类型 (Format Semantic Taint Propagation)',
        'total_samples': n,
        'tp': tp, 'fp': fp, 'tn': tn, 'fn': fn,
        'precision': round(precision, 4),
        'recall': round(recall, 4),
        'f1': round(f1, 4),
        'avg_time_ms': round(total_time / n * 1000, 3),
        'details': results,
    }

    out_dir = os.path.join(BASE, 'eval')
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, 'fmt_spec_type_benchmark_results.json')
    with open(out_path, 'w') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print('\n' + '='*70)
    print('格式说明符类型 Format String Detection Benchmark Results')
    print('='*70)
    print(f'  Total: {n}  |  TP={tp}  FP={fp}  TN={tn}  FN={fn}')
    print(f'  Precision: {precision:.4f}  Recall: {recall:.4f}  F1: {f1:.4f}')
    print(f'  Avg Time: {total_time/n*1000:.3f}ms')
    print(f'  Saved: {out_path}')
    print('-'*70)
    for name, r in results.items():
        status = 'PASS' if r['correct'] else 'FAIL'
        print(f'  [{status}] {name:<28s} CWE-134={r["is_cwe134"]} '
              f'(exp={r["expected_cwe134"]}) sem={r["sem_class"]}')
    print('='*70)

    return report


if __name__ == '__main__':
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument('--benchmark', action='store_true')
    p.add_argument('--test', action='store_true', default=True)
    args = p.parse_args()

    if args.benchmark:
        run_fstp_benchmark()
    else:
        unittest.main(argv=[''], exit=False)
