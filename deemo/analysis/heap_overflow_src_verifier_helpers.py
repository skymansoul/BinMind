"""
heap_overflow_src_verifier 辅助函数 — 构造判定结果.

三种判定结果的工厂函数, 保持主验证器精简.
"""

from analysis.heap_overflow_types import HoVerdict, HoResult


def vuln(a, w, ac, ws, detail, conf=0.85) -> HoResult:
    """构造 VULN 判定结果."""
    return HoResult(
        verdict=HoVerdict.VULN, alloc_line=a.line, write_line=w.line,
        var_name=a.var, alloc_size=ac, write_size=ws,
        confidence=conf if detail.startswith('unbounded') else 0.70,
        reason=f"'{a.var}': malloc({ac})@L{a.line} + {detail}@L{w.line}"
               if detail.startswith('unbounded') else
        f"'{a.var}': malloc({ac})@L{a.line} + {detail}@L{w.line}"
        f" — unbounded copy into fixed buffer")


def safe(a, w, ac, ws, detail, conf=0.90) -> HoResult:
    """构造 SAFE 判定结果."""
    return HoResult(
        verdict=HoVerdict.SAFE, alloc_line=a.line, write_line=w.line,
        var_name=a.var, alloc_size=ac, write_size=ws, confidence=conf,
        reason=f"'{a.var}': malloc({ac}) + {detail} — safe")


def uncertain(a, w, ac, detail, conf=0.50) -> HoResult:
    """构造 UNCERTAIN 判定结果."""
    return HoResult(
        verdict=HoVerdict.UNCERTAIN, alloc_line=a.line, write_line=w.line,
        var_name=a.var, alloc_size=ac, write_size=-1, confidence=conf,
        reason=f"'{a.var}': {detail}@L{w.line} — needs further analysis")


__all__ = ['vuln', 'safe', 'uncertain']
