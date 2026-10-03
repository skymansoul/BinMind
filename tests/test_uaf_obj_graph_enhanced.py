"""
UAF 对象身份图增强回归测试 — 调用图+路径敏感.

测试新增模块:
  1. uaf_obj_graph_callgraph: 自动调用图构建与参数绑定
  2. uaf_obj_graph_path_sensitive: 条件分支路径可行性分析

跨过程/CVE 测试见 test_uaf_obj_graph_enhanced_interproc.py.
"""

from __future__ import annotations

import importlib.util, os, sys, unittest

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

import analysis as _analysis_pkg  # noqa: F401

from tests.test_uaf_obj_graph_enhanced_samples import (
    PATH_FREE_IN_BRANCH_USE_OUTSIDE,
    PATH_FREE_USE_SAME_PATH,
    PATH_FREE_IN_BOTH_BRANCHES,
    PATH_REASSIGN_AFTER_FREE,
    CG_MAIN_SRC,
    CG_CALLER_SRC,
)


def _load_module(name, path):
    if 'analysis' not in sys.modules:
        import analysis
        sys.modules['analysis'] = analysis
    deps = [
        ('analysis.uaf_obj_graph_types', 'uaf_obj_graph_types.py'),
        ('analysis.uaf_obj_graph_builder', 'uaf_obj_graph_builder.py'),
        ('analysis.uaf_obj_graph_callgraph', 'uaf_obj_graph_callgraph.py'),
        ('analysis.uaf_obj_graph_propagator', 'uaf_obj_graph_propagator.py'),
        ('analysis.uaf_obj_graph_cross_func', 'uaf_obj_graph_cross_func.py'),
        ('analysis.uaf_obj_graph_verifier', 'uaf_obj_graph_verifier.py'),
        ('analysis.uaf_obj_graph_path_sensitive', 'uaf_obj_graph_path_sensitive.py'),
    ]
    for mod_name, fname in deps:
        if mod_name not in sys.modules:
            fpath = os.path.join(BASE, 'analysis', fname)
            spec = importlib.util.spec_from_file_location(mod_name, fpath)
            mod = importlib.util.module_from_spec(spec)
            sys.modules[mod_name] = mod
            spec.loader.exec_module(mod)
            setattr(sys.modules['analysis'],
                    mod_name.split('.')[-1], mod)
            for attr in getattr(mod, '__all__', []):
                setattr(sys.modules['analysis'], attr, getattr(mod, attr))
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


_cg = _load_module('analysis.uaf_obj_graph_callgraph',
                   os.path.join(BASE, 'analysis', 'uaf_obj_graph_callgraph.py'))
_ps = _load_module('analysis.uaf_obj_graph_path_sensitive',
                   os.path.join(BASE, 'analysis',
                                'uaf_obj_graph_path_sensitive.py'))

HoigCallGraph = _cg.HoigCallGraph
PathSensitiveHOIG = _ps.PathSensitiveHOIG


# 测试类

class TestHoigCallGraph(unittest.TestCase):
    """调用图构建测试."""

    def test_extract_params(self):
        """从函数签名提取参数名."""
        cg = HoigCallGraph()
        cg.register('foo', 'void foo(int x, char *buf, int len) {\n}')
        params = cg.get_params('foo')
        self.assertEqual(params, ['x', 'buf', 'len'])

    def test_extract_call_sites(self):
        """提取调用点: 赋值调用 + 裸调用."""
        cg = HoigCallGraph()
        cg.register('main', CG_MAIN_SRC)
        sites = cg.get_call_sites('main')
        callees = [s.callee for s in sites]
        self.assertIn('make_obj', callees)
        self.assertIn('destroy', callees)

    def test_call_lines(self):
        """查找调用点行号."""
        cg = HoigCallGraph()
        cg.register('caller', CG_CALLER_SRC)
        lines = cg.find_call_lines('caller', 'helper')
        self.assertEqual(len(lines), 1)

    def test_param_binding(self):
        """参数绑定: 实参→形参名映射."""
        cg = HoigCallGraph()
        cg.register('sink', 'void sink(char *p) {\n free(p);\n}')
        bindings = cg.bind_params('sink', ['buf'])
        self.assertEqual(bindings, {'p': 'buf'})


class TestPathSensitivity(unittest.TestCase):
    """路径敏感分析测试."""

    def setUp(self):
        self.ps = PathSensitiveHOIG()

    def test_free_in_branch_use_outside(self):
        """free 在 if 分支, use 在分支外 → 存在 safe path."""
        results = self.ps.analyze(PATH_FREE_IN_BRANCH_USE_OUTSIDE)
        use_results = [r for r in results if r.var == 'p' and r.is_uaf]
        self.assertEqual(len(use_results), 0,
                         'free in branch, use outside → safe path exists')

    def test_free_use_same_path(self):
        """free 和 use 在同一分支 → UAF."""
        results = self.ps.analyze(PATH_FREE_USE_SAME_PATH)
        use_results = [r for r in results if r.var == 'p' and r.is_uaf]
        self.assertGreater(len(use_results), 0,
                           'free and use on same path → UAF')

    def test_reassign_after_free(self):
        """free 后重新 malloc → 安全."""
        results = self.ps.analyze(PATH_REASSIGN_AFTER_FREE)
        use_results = [r for r in results if r.var == 'p' and r.is_uaf]
        self.assertEqual(len(use_results), 0,
                         'reassign after free → safe')

    def test_free_in_both_branches(self):
        """两个分支都 free → 所有路径 UAF."""
        results = self.ps.analyze(PATH_FREE_IN_BOTH_BRANCHES)
        use_results = [r for r in results if r.var == 'p' and r.is_uaf]
        self.assertGreater(len(use_results), 0,
                           'free on all paths → UAF confirmed')


# 基准测试

def run_enhanced_benchmark():
    """运行增强 UAF 对象身份图基准测试."""
    import json, time

    samples = {
        'path_branch_free': PATH_FREE_IN_BRANCH_USE_OUTSIDE,
        'path_same_path': PATH_FREE_USE_SAME_PATH,
        'path_both_branches': PATH_FREE_IN_BOTH_BRANCHES,
        'path_reassign': PATH_REASSIGN_AFTER_FREE,
    }
    expected = {
        'path_branch_free': 'SAFE',
        'path_same_path': 'CONFIRMED',
        'path_both_branches': 'CONFIRMED',
        'path_reassign': 'SAFE',
    }

    ps = PathSensitiveHOIG()
    tp = fp = tn = fn = 0
    results = {}

    for name, code in samples.items():
        res_list = ps.analyze(code)
        has_uaf = any(r.is_uaf for r in res_list)
        verdict = 'CONFIRMED' if has_uaf else 'SAFE'
        exp = expected[name]
        correct = (verdict == exp)
        results[name] = {'verdict': verdict, 'expected': exp,
                         'correct': correct}
        if exp == 'CONFIRMED' and verdict == 'CONFIRMED': tp += 1
        elif exp == 'CONFIRMED' and verdict != 'CONFIRMED': fn += 1
        elif exp == 'SAFE' and verdict == 'CONFIRMED': fp += 1
        elif exp == 'SAFE' and verdict == 'SAFE': tn += 1

    n = len(samples)
    p = tp / max(1, tp + fp)
    r = tp / max(1, tp + fn)
    f1 = 2*p*r / max(0.001, p+r)

    print('\n' + '='*60)
    print('UAF 对象身份图 Enhanced (Path Sensitivity) Benchmark')
    print('='*60)
    print(f'  TP={tp} FP={fp} TN={tn} FN={fn}')
    print(f'  P={p:.4f} R={r:.4f} F1={f1:.4f}')
    for name, r in results.items():
        st = 'PASS' if r['correct'] else 'FAIL'
        print(f'  [{st}] {name:<30s} → {r["verdict"]:>10s}')
    print('='*60)
    return results


if __name__ == '__main__':
    unittest.main(argv=[''], exit=False)
