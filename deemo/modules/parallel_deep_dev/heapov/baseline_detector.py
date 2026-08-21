"""朴素基线检测器 — 模拟经典静态堆溢出检测。

与 CACBV 同解析/提取, 但验证仅做常量偏移比较:
  常量范围 > 分配大小 → 报;
  动态范围 → 一律告警(不耦合、不查守卫、不做对齐)。
这是"高召回高误报"的参照系, 用于量化 CACBV 的误报削减。
"""


from typing import List

from . import cparser as cp
from .dataflow import build_env
from .alloc_extract import extract_allocs
from .write_extract import extract_writes
from .interval import Interval, eval_expr
from .expr_ast import expr_str, Const


class BaselineDetector:
    """朴素基线。"""

    def __init__(self):
        self.stats = {}

    def analyze(self, source: str) -> List[dict]:
        funcs, _ = cp.parse_source_full(source)
        report: List[dict] = []
        for func in funcs:
            env = build_env(func)
            allocs = extract_allocs(func)
            writes = extract_writes(func, env)
            allocs_by_var = {a.var: a for a in allocs}
            for w in writes:
                alloc = allocs_by_var.get(w.alias_base) or \
                    allocs_by_var.get(w.dst_var)
                if alloc is None:
                    continue
                extent = w.extent_expr
                if extent is None:
                    # 动态拷贝 → 无条件告警
                    report.append(self._mk(func.name, alloc, w,
                                            'OVERFLOW', 0.5,
                                            'dynamic-extent'))
                    continue
                ext_iv = eval_expr(extent, env.intervals, env.tainted)
                size_iv = eval_expr(alloc.size_expr, env.intervals, env.tainted)
                if ext_iv.lo is not None and ext_iv.hi == ext_iv.lo:
                    # 常量范围
                    if ext_iv.lo > (size_iv.hi or 0):
                        report.append(self._mk(func.name, alloc, w,
                                               'OVERFLOW', 0.85,
                                               'const-offset'))
                    continue
                # 动态范围: 忽略对齐/守卫/耦合, 一律告警
                report.append(self._mk(func.name, alloc, w,
                                       'OVERFLOW', 0.55,
                                       'dynamic-extent'))
        report.sort(key=lambda r: -r['confidence'])
        self.stats = {'total': len(report)}
        return report

    def _mk(self, func, alloc, w, verdict, conf, reason):
        return {
            'func': func,
            'alloc_var': alloc.var,
            'alloc_size': expr_str(alloc.size_expr),
            'write': w.desc,
            'extent': expr_str(w.extent_expr) if w.extent_expr else '?',
            'verdict': verdict,
            'confidence': conf,
            'fp_reasons': [reason],
            'overflow_bytes': 0,
        }


def analyze_baseline(source: str) -> List[dict]:
    return BaselineDetector().analyze(source)
