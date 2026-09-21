"""
UAF Realloc 集成适配器 — 时序-别名-可达-路径验证 (Type-State Alias Reachability Verification) 集成 + 便捷函数 + 报告生成.
"""


from typing import Dict, List, Optional, Set, Tuple

from analysis.uaf_realloc_tracker import ReallocPathTracker
from analysis.uaf_realloc_types import DanglingAlias, ReallocSite, ReallocVerdict


def enhance_tarps_alias_with_realloc(
    pseudocode: str,
    existing_aliases: Optional[Dict[str, str]] = None,
) -> Tuple[List[DanglingAlias], Dict[str, Set[str]]]:
    """时序-别名-可达-路径验证 (Type-State Alias Reachability Verification) Stage A 增强: 将 realloc 感知的别名分析注入现有别名映射."""
    tracker = ReallocPathTracker()
    danglings = tracker.analyze(pseudocode)
    enriched = dict(tracker._ptr_aliases)
    if existing_aliases:
        for dst, src in existing_aliases.items():
            if dst not in enriched:
                enriched[dst] = set()
            enriched[dst].add(src)
    return danglings, enriched


def check_realloc_uaf(pseudocode: str) -> List[Dict]:
    """便捷函数: 检查伪代码中的 realloc UAF.

    返回 [{line, var, realloc_line, reason, risk}, ...].
    """
    tracker = ReallocPathTracker()
    danglings = tracker.analyze(pseudocode)
    return [
        {
            'line': d.use_line, 'var': d.alias_var,
            'realloc_line': d.realloc_line,
            'reason': (f"'{d.alias_var}' aliases pointer freed by "
                      f"realloc at line {d.realloc_line}, "
                      f"used at line {d.use_line}"),
            'risk': d.risk,
        }
        for d in danglings
    ]


def generate_realloc_report(sites: List[ReallocSite],
                            danglings: List[DanglingAlias]) -> str:
    """生成 realloc UAF 分析报告 (markdown格式).

    原方法保留为薄包装器以维持API兼容.
    """
    if not sites and not danglings:
        return "## Realloc UAF Analysis\n\nNo realloc sites found.\n"

    lines = ["## Realloc UAF Analysis", ""]
    lines.append("### Summary")
    lines.append(f"- Realloc sites: {len(sites)}")
    lines.append(f"- Dangling aliases: {len(danglings)}")
    lines.append(f"- Double free risks: "
                f"{sum(1 for s in sites if s.verdict == ReallocVerdict.DOUBLE_FREE)}")
    lines.append(f"- Realloc(ptr, 0) free equivalents: "
                f"{sum(1 for s in sites if s.verdict == ReallocVerdict.REALLOC_ZERO)}")
    lines.append("")

    if danglings:
        lines.append("### Dangling Alias Details")
        lines.append("| Alias | Realloc Line | Use Line | Target | Risk |")
        lines.append("|-------|-------------|----------|--------|------|")
        for d in danglings:
            lines.append(
                f"| `{d.alias_var}` | {d.realloc_line} | {d.use_line} "
                f"| `{d.realloc_target}` | {d.risk} |")
        lines.append("")

    if sites:
        lines.append("### Realloc Sites")
        lines.append("| Line | Target | Arg | New Size | Zero? | Self? | Verdict | Aliases |")
        lines.append("|------|--------|-----|----------|-------|-------|---------|---------|")
        for s in sites:
            lines.append(
                f"| {s.line_no} | `{s.target_var}` | `{s.arg_var}` "
                f"| `{s.new_size}` | {s.is_zero_size} | {s.is_self_assign} "
                f"| {s.verdict.value} | {s.old_aliases} |")
        lines.append("")

    return '\n'.join(lines)


__all__ = ['enhance_tarps_alias_with_realloc', 'check_realloc_uaf',
           'generate_realloc_report']
