"""
约束联结误报过滤器 — 仿射关系边界验证-约束求解 核心过滤模块: 将约束联结求解器作为 pipeline 的过滤阶段, 对每个候选构建约束系统并联合求解, 替代逐维度独立判定。
集成策略: 仅对非累积候选 (基础检测器输出) 应用约束求解过滤, [CUMUL] 标记的累积候选跳过; 约束求解证明 SAFE → 滤除, 证明 OVERFLOW → 提升置信度, 无法判定 → 保留 (零召回损失)。
作为阶段 7 插入, 位于增强过滤器之后、最终阈值之前; 不替代任何已有阶段。
"""

from typing import Any

from core.constraint_solver import solve_candidate, solve_candidate_path_sensitive
from core.constraint_constraint_types import SolverVerdict


def filter_by_constraint_join(
    candidates: list[Any],
    ir_lines: list[str],
    decompiled_text: str = "",
    platform: str = "x86_64",
    use_path_sensitive: bool = False,
) -> tuple[list[Any], dict]:
    """对候选列表执行约束联结过滤.

    use_path_sensitive=True时启用路径敏感约束求解,
    在每条CFG路径上独立判定, 保守融合.
    返回 (filtered_candidates, stats).
    """
    stats = {
        'input': len(candidates),
        'proven_safe': 0,
        'proven_overflow': 0,
        'inconclusive': 0,
        'skipped_cumulative': 0,
        'output': 0,
        'ps_cj_used': 0,
        'ps_cj_fallback': 0,
    }

    kept = []
    for c in candidates:
        desc = getattr(c, 'description', '')
        if desc.startswith('[CUMUL]'):
            kept.append(c)
            stats['skipped_cumulative'] += 1
            continue

        if use_path_sensitive and decompiled_text:
            psj_result, _ = solve_candidate_path_sensitive(
                c, ir_lines, decompiled_text, platform)
            stats['ps_cj_used'] += 1
            if psj_result.fallback_global_cj:
                stats['ps_cj_fallback'] += 1

            if psj_result.verdict == SolverVerdict.PROVEN_SAFE:
                stats['proven_safe'] += 1
                continue

            if psj_result.verdict == SolverVerdict.PROVEN_OVERFLOW:
                stats['proven_overflow'] += 1
                if hasattr(c, 'confidence'):
                    c.confidence = min(0.98,
                        c.confidence + psj_result.confidence_delta)
                if hasattr(c, 'description'):
                    c.description += (
                        f' [PS-CJ confirmed: {psj_result.reason}]')
                kept.append(c)
                continue

            stats['inconclusive'] += 1
            if hasattr(c, 'confidence') and psj_result.confidence_delta != 0:
                c.confidence = max(0.10,
                    min(0.95, c.confidence + psj_result.confidence_delta))
            kept.append(c)
            continue

        result, constraint_sys = solve_candidate(
            c, ir_lines, decompiled_text, platform)

        if result.verdict == SolverVerdict.PROVEN_SAFE:
            stats['proven_safe'] += 1
            continue

        if result.verdict == SolverVerdict.PROVEN_OVERFLOW:
            stats['proven_overflow'] += 1
            if hasattr(c, 'confidence'):
                c.confidence = min(0.98,
                    c.confidence + result.confidence_delta)
            if hasattr(c, 'description'):
                c.description += f' [CJ-confirmed: {result.reason}]'
            kept.append(c)
            continue

        stats['inconclusive'] += 1
        if hasattr(c, 'confidence') and result.confidence_delta != 0:
            c.confidence = max(0.10,
                min(0.95, c.confidence + result.confidence_delta))
        kept.append(c)

    stats['output'] = len(kept)
    return kept, stats


def cj_filter_stats_summary(stats: dict) -> str:
    """生成约束求解过滤器的统计摘要文本."""
    inp = stats.get('input', 0)
    safe = stats.get('proven_safe', 0)
    ovf = stats.get('proven_overflow', 0)
    inc = stats.get('inconclusive', 0)
    skip = stats.get('skipped_cumulative', 0)
    out = stats.get('output', 0)
    ps_used = stats.get('ps_cj_used', 0)
    ps_fb = stats.get('ps_cj_fallback', 0)
    reduction = ((inp - skip - out) / max(inp - skip, 1)) * 100
    ps_info = f", ps_cj={ps_used}(fb={ps_fb})" if ps_used > 0 else ""
    return (
        f"CJ-Filter: input={inp}, "
        f"proven_safe={safe}, overflow_confirmed={ovf}, "
        f"inconclusive={inc}, cumulative_skipped={skip}, "
        f"output={out}, FP_reduction={reduction:.1f}%{ps_info}"
    )


__all__ = [
    'filter_by_constraint_join',
    'cj_filter_stats_summary',
]
