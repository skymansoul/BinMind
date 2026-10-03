"""UAF 主检测器 — 生命周期耦合验证编排。

流程: 解析 → 每函数抽取事件(分配/释放/使用/重绑定) → 逐对验证
→ 误报收敛(仅 UAF/DOUBLE_FREE 且置信度达标者进入报告)。
"""

from __future__ import annotations

from typing import List

from ..heapov.cparser import parse_source_full

from . import verdict as V
from .model import Finding
from .lcv import verify_func


def _to_dict(f: Finding) -> dict:
    return {
        'func': f.func,
        'base_var': f.base_var,
        'verdict': f.verdict,
        'confidence': round(f.confidence, 3),
        'reasons': f.reasons,
        'description': f.description,
        'kind': f.kind,
        'free_pos': f.free_pos,
        'use_pos': f.use_pos,
    }


def analyze_source(src: str, threshold: float = V.REPORT_MIN):
    """分析 C 源码, 返回 (report, stats)。"""
    funcs, _ = parse_source_full(src)
    findings: List[Finding] = []
    for func in funcs:
        findings.extend(verify_func(func))
    reportable = [f for f in findings
                  if f.verdict in V.REPORT_SET and f.confidence >= threshold]
    stats = {
        'functions': len(funcs),
        'raw': len(findings),
        'reported': len(reportable),
        'per_verdict': {v: sum(1 for f in findings if f.verdict == v)
                        for v in (V.UAF, V.DOUBLE_FREE, V.SAFE)},
    }
    return [_to_dict(f) for f in reportable], stats
