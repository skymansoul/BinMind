"""
HOIG 增强回归测试 — 跨过程传播+CVE模拟.

测试模块:
  - HoigPropagator 跨函数参数释放检测
  - HoigCrossFuncVerifier 回调/链式释放检测
"""

from __future__ import annotations

import os, sys, unittest

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

# 确保分析模块已加载 (由主测试文件或自身引导)
import analysis as _analysis_pkg  # noqa: F401


def _ensure_dep(name, fname):
    """惰性加载分析子模块."""
    if name not in sys.modules:
        import importlib.util
        fpath = os.path.join(BASE, 'analysis', fname)
        spec = importlib.util.spec_from_file_location(name, fpath)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod
        spec.loader.exec_module(mod)
        setattr(sys.modules['analysis'],
                name.split('.')[-1], mod)
        for attr in getattr(mod, '__all__', []):
            setattr(sys.modules['analysis'], attr, getattr(mod, attr))


def _bootstrap_deps():
    """引导所有 HOIG 依赖模块."""
    deps = [
        ('analysis.uaf_hoig_types', 'uaf_hoig_types.py'),
        ('analysis.uaf_hoig_builder', 'uaf_hoig_builder.py'),
        ('analysis.uaf_hoig_callgraph', 'uaf_hoig_callgraph.py'),
        ('analysis.uaf_hoig_propagator', 'uaf_hoig_propagator.py'),
        ('analysis.uaf_hoig_cross_func', 'uaf_hoig_cross_func.py'),
        ('analysis.uaf_hoig_verifier', 'uaf_hoig_verifier.py'),
        ('analysis.uaf_hoig_path_sensitive', 'uaf_hoig_path_sensitive.py'),
    ]
    for mod_name, fname in deps:
        _ensure_dep(mod_name, fname)


_bootstrap_deps()

from analysis.uaf_hoig_propagator import HoigPropagator  # noqa: E402
from analysis.uaf_hoig_cross_func import HoigCrossFuncVerifier  # noqa: E402


class TestInterprocPropagator(unittest.TestCase):
    """跨过程传播器测试."""

    def test_callee_frees_param(self):
        """被调用者释放参数 → 调用者 UAF."""
        prop = HoigPropagator()
        prop.register_function('destroy', (
            'void destroy(char *obj) {\n free(obj);\n}'
        ))
        prop.register_function('process', (
            'void process() {\n'
            '    char *buf = malloc(64);\n'
            '    destroy(buf);\n'
            "    buf[0] = 'A';\n"
            '}\n'
        ))
        verdicts = prop.analyze_all()
        cross = [v for v in verdicts if v.is_cross_func]
        self.assertGreater(len(cross), 0,
                           'Should detect cross-function UAF: '
                           'destroy frees param, process uses after')

    def test_deep_chain(self):
        """三层调用链: top→mid→leaf(free) → top use."""
        prop = HoigPropagator()
        prop.register_function('leaf_free', (
            'void leaf_free(char *data) {\n free(data);\n}'
        ))
        prop.register_function('mid_process', (
            'void mid_process(char *item) {\n leaf_free(item);\n}'
        ))
        prop.register_function('top_handler', (
            'void top_handler() {\n'
            '    char *obj = malloc(256);\n'
            '    mid_process(obj);\n'
            '    obj->field = 0;\n'
            '}\n'
        ))
        verdicts = prop.analyze_all()
        cross = [v for v in verdicts if v.is_cross_func]
        self.assertGreater(len(cross), 0,
                           'Should detect deep chain UAF: '
                           'top→mid→leaf_free, top uses after')

    def test_return_live_is_safe(self):
        """函数返回 live 对象 → 调用者使用安全."""
        prop = HoigPropagator()
        prop.register_function('make_obj', (
            'char *make_obj() {\n'
            '    char *p = malloc(64);\n'
            '    return p;\n'
            '}\n'
        ))
        prop.register_function('use_obj', (
            'void use_obj() {\n'
            '    char *q = make_obj();\n'
            "    q[0] = 'x';\n"
            '}\n'
        ))
        verdicts = prop.analyze_all()
        confirmed = [v for v in verdicts if v.verdict == 'CONFIRMED']
        cross_to_use = [v for v in confirmed
                        if 'use_obj' in v.reason]
        self.assertEqual(len(cross_to_use), 0,
                         'Returning live object and using it is safe')

    def test_reuse_after_free_safe(self):
        """free 后重新 malloc → 安全."""
        prop = HoigPropagator()
        prop.register_function('clear', (
            'void clear(char *ptr) {\n free(ptr);\n}'
        ))
        prop.register_function('work', (
            'void work() {\n'
            '    char *buf = malloc(64);\n'
            '    clear(buf);\n'
            '    buf = malloc(128);\n'
            '    buf[0] = 1;\n'
            '}\n'
        ))
        verdicts = prop.analyze_all()
        cross_work = [v for v in verdicts
                      if v.is_cross_func and 'work' in v.reason
                      and v.verdict == 'CONFIRMED']
        late_uses = [v for v in cross_work if v.use_line >= 4]
        self.assertEqual(len(late_uses), 0,
                         'After reassign post-free, use should not be UAF')


class TestCVESimulation(unittest.TestCase):
    """CVE 模拟样本测试."""

    def test_obj_cache_reuse(self):
        """对象缓存复用 UAF: free(e->data) → e->data[0]"""
        prop = HoigPropagator()
        prop.register_function('cache_flush', (
            'void cache_flush(struct cache_entry *e) {\n'
            '    free(e->data);\n'
            '}\n'
        ))
        prop.register_function('use_cache', (
            'void use_cache() {\n'
            '    struct cache_entry *e = malloc(sizeof(struct cache_entry));\n'
            '    e->data = malloc(256);\n'
            '    cache_flush(e);\n'
            "    e->data[0] = 'x';\n"
            '}\n'
        ))
        verdicts = prop.analyze_all()
        confirmed = [v for v in verdicts if v.verdict == 'CONFIRMED']
        self.assertGreater(len(confirmed), 0,
                           'Should detect cache reuse UAF')

    def test_callback_uaf(self):
        """回调 UAF: release(buf) → buf[0]"""
        cv = HoigCrossFuncVerifier()
        cv.register('release', 'void release(void *p) { free(p); }')
        cv.register('trigger', (
            'void trigger() {\n'
            '    char *buf = malloc(128);\n'
            '    release(buf);\n'
            '    buf[0] = 1;\n'
            '}\n'
        ))
        cv.register_call('trigger', 'release')
        verdicts = cv.verify_all()
        confirmed = [v for v in verdicts if v.verdict == 'CONFIRMED']
        self.assertGreater(len(confirmed), 0,
                           'Should detect callback UAF')

    def test_chained_free(self):
        """链式释放: caller→delete_list→free_node → caller uses h."""
        cv = HoigCrossFuncVerifier()
        cv.register('free_node', 'void free_node(struct node *n) { free(n); }')
        cv.register('delete_list', (
            'void delete_list(struct node *head) { free_node(head); }'
        ))
        cv.register('caller', (
            'void caller() {\n'
            '    struct node *h = malloc(sizeof(struct node));\n'
            '    delete_list(h);\n'
            '    h->next = NULL;\n'
            '}\n'
        ))
        cv.register_call('caller', 'delete_list')
        cv.register_call('delete_list', 'free_node')
        verdicts = cv.verify_all()
        confirmed = [v for v in verdicts if v.verdict == 'CONFIRMED']
        self.assertGreater(len(confirmed), 0,
                           'Should detect chained free UAF')


if __name__ == '__main__':
    unittest.main(argv=[''], exit=False)
