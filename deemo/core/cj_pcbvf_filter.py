"""
PC-BVF 管线级过滤器: 在 BVF INCONCLUSIVE 时触发路径约束感知判定; 集成到 heap_overflow_pipeline 的 BVF 阶段之后 (阶段 7.5 DD-BVF 反向值流过滤, 阶段 7.6 PC-BVF 对 BVF 无法判定的候选提取路径约束收紧值域后重新判定)。
保守策略: PC-BVF 无法判定时保留候选, 不影响召回率。
"""
from typing import Any, Dict, List, Tuple

from core.heap_overflow_detector import HeapOverflowCandidate
from core.cj_constraint_types import SolverVerdict


def filter_by_pcbvf(
    candidates: List[Any],
    ir_lines: List[str],
    decompiled_text: str = "",
    platform: str = "x86_64",
) -> Tuple[List[Any], Dict]:
    """对BVF INCONCLUSIVE候选执行PC-BVF约束感知过滤.

    返回 (filtered_candidates, stats).
    """
    stats = {
        'input': len(candidates),
        'pcbvf_triggered': 0,
        'pcbvf_safe': 0,
        'pcbvf_overflow': 0,
        'pcbvf_inconclusive': 0,
        'output': 0,
    }

    from core.cj_pcbvf_bridge import try_pcbvf_proof

    kept = []

    for c in candidates:
        desc = getattr(c, 'description', '')
        if desc.startswith('[CUMUL]'):
            kept.append(c)
            continue

        if not _should_trigger_pcbvf(c, ir_lines):
            kept.append(c)
            continue

        stats['pcbvf_triggered'] += 1
        result = try_pcbvf_proof(c, ir_lines, platform)

        if result is None:
            stats['pcbvf_inconclusive'] += 1
            kept.append(c)
            continue

        if result.verdict == SolverVerdict.PROVEN_SAFE:
            stats['pcbvf_safe'] += 1
            continue

        if result.verdict == SolverVerdict.PROVEN_OVERFLOW:
            stats['pcbvf_overflow'] += 1
            if hasattr(c, 'confidence'):
                c.confidence = min(0.98, c.confidence + 0.15)
            if hasattr(c, 'description'):
                c.description += f' [PC-BVF-confirmed: {result.reason}]'
            kept.append(c)
            continue

        stats['pcbvf_inconclusive'] += 1
        kept.append(c)

    stats['output'] = len(kept)
    return kept, stats


def _should_trigger_pcbvf(
    candidate: HeapOverflowCandidate,
    ir_lines: List[str],
) -> bool:
    """判断候选是否值得触发PC-BVF.

    触发条件:
      - 分配大小或写入大小含变量(动态)
      - 候选描述不含[PC-BVF-confirmed]标记(避免重复触发)
    """
    alloc = candidate.alloc_site
    store = candidate.overflow_store
    desc = getattr(candidate, 'description', '')

    if '[PC-BVF-confirmed]' in desc:
        return False

    if alloc.size_is_dynamic:
        return True

    if store.mnemonic in ('memcpy', 'strncpy', 'memset', 'strncat',
                          'memmove'):
        return True

    if store.offset_is_dynamic:
        return True

    return False


def pcbvf_filter_stats_summary(stats: Dict) -> str:
    """生成PC-BVF过滤器的统计摘要."""
    inp = stats.get('input', 0)
    trig = stats.get('pcbvf_triggered', 0)
    safe = stats.get('pcbvf_safe', 0)
    ovf = stats.get('pcbvf_overflow', 0)
    inc = stats.get('pcbvf_inconclusive', 0)
    out = stats.get('output', 0)
    reduction = ((inp - out) / max(inp, 1)) * 100
    return (
        f"PC-BVF-Filter: input={inp}, triggered={trig}, "
        f"proven_safe={safe}, overflow_confirmed={ovf}, "
        f"inconclusive={inc}, output={out}, "
        f"FP_reduction={reduction:.1f}%"
    )


__all__ = [
    'filter_by_pcbvf', 'pcbvf_filter_stats_summary',
]
