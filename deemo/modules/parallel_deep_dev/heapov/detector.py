"""容量感知耦合边界验证 主检测器 — 端到端编排。

流程: 解析 → 每函数建环境 → 提取分配/写点 → 收集守卫 →
逐对耦合验证 → 误报收敛。输出报告列表与各级统计。
"""


from typing import Dict, List

from . import cparser as cp
from .dataflow import build_env, iter_statements
from .alloc_extract import extract_allocs
from .write_extract import extract_writes
from .guard_collector import collect_guards
from .coupling_check import verify_pair
from .fp_filter import finalize
from .expr_ast import expr_str, Var, Const, Binary, Sizeof, Index
from . import verdict as V
from .model import Finding


class CACBVDetector:
    """容量感知耦合边界验证检测器。"""

    def __init__(self, report_threshold: float = V.CONF_REPORT_MIN):
        self._threshold = report_threshold
        self.stats: Dict = {}

    def analyze(self, source: str) -> List[dict]:
        """分析 C 源码, 返回报告条目列表。"""
        funcs, str_lits = cp.parse_source_full(source)
        if not funcs:
            return []
        findings: List[Finding] = []
        per_func: Dict[str, dict] = {}

        for func in funcs:
            env = build_env(func)
            allocs = extract_allocs(func)
            writes = extract_writes(func, env)
            guards = collect_guards(func)
            array_sizes = _collect_array_sizes(func, str_lits)
            f_findings = self._pair_verify(
                func, env, allocs, writes, guards, str_lits, array_sizes)
            findings.extend(f_findings)
            f_report, f_stats = finalize(f_findings, self._threshold)
            per_func[func.name] = {
                'allocs': len(allocs), 'writes': len(writes),
                'raw': len(f_findings), 'reported': len(f_report),
                'stats': f_stats,
            }

        report, g_stats = finalize(findings, self._threshold)
        self.stats = {
            'functions': len(funcs),
            'per_func': per_func,
            'total_raw': len(findings),
            'reported': len(report),
            'filtered': g_stats['filtered'],
            'by_reason': g_stats['by_reason'],
            'per_verdict': g_stats['per_verdict'],
        }
        return [self._to_dict(f) for f in report]

    def _pair_verify(self, func, env, allocs, writes, guards, str_lits,
                     array_sizes=None):
        out: List[Finding] = []
        seen = set()
        for alloc in allocs:
            for w in writes:
                if w.alias_base != alloc.var and w.dst_var != alloc.var:
                    continue
                key = (alloc.var, id(w.stmt))
                if key in seen:
                    continue
                seen.add(key)
                g = guards.get(id(w.stmt), []) if w.stmt is not None else []
                verdict, conf, reasons, ov = verify_pair(
                    alloc, w, env, g, str_lits, array_sizes)
                out.append(Finding(
                    func=func.name, alloc_var=alloc.var,
                    alloc_expr=expr_str(alloc.size_expr),
                    alloc_site=alloc, write=w,
                    size_expr_str=expr_str(alloc.size_expr),
                    extent_expr_str=expr_str(w.extent_expr)
                    if w.extent_expr else '?',
                    verdict=verdict, confidence=conf,
                    fp_reasons=reasons, overflow_bytes=ov,
                    description=w.desc, pos=w.pos))
        return out

    def _to_dict(self, f: Finding) -> dict:
        return {
            'func': f.func,
            'alloc_var': f.alloc_var,
            'alloc_size': f.alloc_expr,
            'write': f.description,
            'extent': f.extent_expr_str,
            'verdict': f.verdict,
            'confidence': round(f.confidence, 3),
            'fp_reasons': f.fp_reasons,
            'overflow_bytes': f.overflow_bytes,
        }


def _collect_array_sizes(func, str_lits: dict) -> dict:
    """sizeof(数组变量) 的尺寸表: 声明数组长度或字面量初始化长度。"""
    sizes = {}
    base_sz = {'char': 1, 'int': 4, 'short': 2, 'long': 8, 'float': 4,
               'double': 8, 'size_t': 8}
    for it in iter_statements(func):
        if not isinstance(it, cp.Decl):
            continue
        base = it.base_type.strip().split(' ')[-1]
        elem = base_sz.get(base, 1)
        if it.init is not None and isinstance(it.init, Var) \
                and it.init.name.startswith('__str__'):
            lit = str_lits.get(it.init.name)
            if lit is not None:
                sizes[it.name] = len(lit) + 1
                continue
        if it.array_size is not None:
            sizes[it.name] = it.array_size * elem
    return sizes


def analyze_source(source: str, threshold: float = V.CONF_REPORT_MIN):
    """便捷入口。返回 (report, stats)。"""
    det = CACBVDetector(threshold)
    report = det.analyze(source)
    return report, det.stats
