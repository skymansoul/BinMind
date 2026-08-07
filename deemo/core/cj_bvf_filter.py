"""
DD-BVF误报过滤器 — 在CJ返回INCONCLUSIVE时触发反向值流安全证明.

集成策略:
  CJ求解器四步均返回INCONCLUSIVE时, 不保守保留, 而是:
    1. 触发BackwardValueFlow追踪alloc_size和write_size的符号表达式
    2. 用correlate()判定alloc-write的符号相关性
    3. 共享变量 + 子集关系 → PROVEN_SAFE (过滤)
    4. 共享变量 + 系数溢出 → PROVEN_OVERFLOW (确认)
    5. 无法判定 → 保留(零召回损失, 回退到保守策略)

  与CJ的关系:
    - CJ在前, BVF在后: CJ能判定的不触发BVF
    - BVF是CJ的精确化: 利用CJ无法获取的跨跳赋值链信息
    - BVF不重复CJ的工作: 只在CJ无法判定时启动

  分配器对齐余量:
    BVF判定SAFE时, 将分配器对齐余量(chunk_slack)纳入考虑:
      write_end <= alloc_size + chunk_slack → SAFE
    避免因对齐余量导致的边界case误判.
"""

from typing import Any, Dict, List, Optional, Tuple

from core.cj_bvf_tracer import (
    BackwardValueFlow, CorrelationResult, SymbolicExpr,
)
from core.cj_constraint_types import SolverVerdict, SolverResult
from core.heap_overflow_detector import HeapOverflowCandidate


def filter_by_bvf(
    candidates: List[Any],
    ir_lines: List[str],
    decompiled_text: str = "",
    platform: str = "x86_64",
) -> Tuple[List[Any], Dict]:
    """对CJ INCONCLUSIVE候选执行DD-BVF过滤.

    返回 (filtered_candidates, stats).
    """
    stats = {
        'input': len(candidates),
        'bvf_triggered': 0,
        'bvf_safe': 0,
        'bvf_overflow': 0,
        'bvf_inconclusive': 0,
        'output': 0,
    }

    bvf = BackwardValueFlow()
    kept = []

    for c in candidates:
        desc = getattr(c, 'description', '')
        if desc.startswith('[CUMUL]'):
            kept.append(c)
            continue

        if not _should_trigger_bvf(c, ir_lines):
            kept.append(c)
            continue

        stats['bvf_triggered'] += 1
        result = _run_bvf_on_candidate(c, ir_lines, bvf, platform)

        if result.proven_safe:
            stats['bvf_safe'] += 1
            continue

        if result.proven_overflow:
            stats['bvf_overflow'] += 1
            if hasattr(c, 'confidence'):
                c.confidence = min(0.98, c.confidence + 0.20)
            if hasattr(c, 'description'):
                c.description += f' [BVF-confirmed: {result.reason}]'
            kept.append(c)
            continue

        stats['bvf_inconclusive'] += 1
        kept.append(c)

    stats['output'] = len(kept)
    return kept, stats


def _should_trigger_bvf(
    candidate: HeapOverflowCandidate,
    ir_lines: List[str],
) -> bool:
    """判断候选是否值得触发BVF.

    触发条件:
      - 分配大小或写入大小含变量(动态)
      - 候选不是显式常量溢出(已在CJ中判定)
    """
    alloc = candidate.alloc_site
    store = candidate.overflow_store

    if alloc.size_is_dynamic:
        return True

    if store.mnemonic in ('memcpy', 'strncpy', 'memset', 'strncat',
                          'memmove') and store.store_size <= 0:
        return True

    if store.offset_is_dynamic:
        return True

    return False


def _run_bvf_on_candidate(
    candidate: HeapOverflowCandidate,
    ir_lines: List[str],
    bvf: BackwardValueFlow,
    platform: str,
) -> CorrelationResult:
    """对单个候选执行DD-BVF分析."""
    alloc = candidate.alloc_site
    store = candidate.overflow_store

    alloc_expr = bvf.trace_alloc_size(
        ir_lines, alloc.alloc_func,
        alloc.size_expr if alloc.size_is_dynamic else str(alloc.size_arg),
        alloc.pc)

    if alloc.size_arg > 0 and not alloc.size_is_dynamic:
        alloc_expr = SymbolicExpr(
            const=float(alloc.size_arg),
            origin=f"const_alloc:{alloc.size_arg}")

    write_expr = _trace_write_expr(bvf, candidate, ir_lines)

    offset_expr = _trace_offset_expr(bvf, candidate, ir_lines)

    chunk_slack = _compute_chunk_slack(alloc.size_arg, platform)

    result = bvf.correlate(alloc_expr, write_expr, offset_expr)

    if result.proven_safe and chunk_slack > 0:
        _adjust_for_slack(result, alloc_expr, write_expr,
                          offset_expr, chunk_slack)

    return result


def _trace_write_expr(
    bvf: BackwardValueFlow,
    candidate: HeapOverflowCandidate,
    ir_lines: List[str],
) -> SymbolicExpr:
    """追踪写入大小的符号表达式."""
    store = candidate.overflow_store

    if store.mnemonic in ('strcpy', 'strcat'):
        return SymbolicExpr(tainted=True, origin="unbounded_copy")

    if store.store_size > 0:
        return SymbolicExpr(
            const=float(store.store_size),
            origin=f"store_size:{store.store_size}")

    if store.mnemonic in ('memcpy', 'memmove', 'strncpy', 'memset',
                           'strncat'):
        return bvf.trace_write_size(
            ir_lines, store.pc, store.mnemonic, store.store_size)

    return SymbolicExpr(
        const=float(store.store_size if store.store_size > 0 else 4),
        origin="default_store_size")


def _trace_offset_expr(
    bvf: BackwardValueFlow,
    candidate: HeapOverflowCandidate,
    ir_lines: List[str],
) -> SymbolicExpr:
    """追踪写入偏移的符号表达式."""
    store = candidate.overflow_store

    if not store.offset_is_dynamic and store.offset >= 0:
        return SymbolicExpr(
            const=float(store.offset),
            origin=f"const_offset:{store.offset}")

    if store.offset_is_dynamic:
        line = ir_lines[store.pc] if store.pc < len(ir_lines) else ""
        import re
        m = re.search(r'\[(\w+)\s*\+\s*(\w+)\]', line)
        if m:
            return bvf.trace_var(ir_lines, m.group(2), store.pc)
        return bvf.trace_var(
            ir_lines, "offset", store.pc)

    return SymbolicExpr(const=0.0, origin="zero_offset")


def _compute_chunk_slack(alloc_size: int, platform: str) -> int:
    """计算分配器对齐余量."""
    if alloc_size <= 0:
        return 0
    try:
        from analysis.allocator_chunk_model import compute_effective_boundary
        usable = compute_effective_boundary(alloc_size, "malloc")
        return max(0, usable - alloc_size)
    except ImportError:
        if platform == "x86_64":
            return (16 - (alloc_size % 16)) % 16
        return 0


def _adjust_for_slack(
    result: CorrelationResult,
    alloc_expr: SymbolicExpr,
    write_expr: SymbolicExpr,
    offset_expr: Optional[SymbolicExpr],
    chunk_slack: int,
) -> None:
    """将分配器对齐余量纳入alloc_expr的const分量.
    write_end <= alloc_size + chunk_slack时, 安全阈值放宽chunk_slack字节.
    对已判定proven_safe的结果无影响; 对边界case(差值在slack范围内)重新评估.
    """
    if not result or chunk_slack <= 0:
        return
    write_const = getattr(write_expr, 'const', 0.0) or 0.0
    offset_const = getattr(offset_expr, 'const', 0.0) or 0.0 if offset_expr else 0.0
    alloc_const = getattr(alloc_expr, 'const', 0.0) or 0.0
    diff = (write_const + offset_const) - alloc_const
    if 0 < diff <= chunk_slack:
        result.proven_safe = True
        result.proven_overflow = False
        result.reason = f'slack_absorbed: diff={diff:.0f} <= slack={chunk_slack}'


def bvf_filter_stats_summary(stats: Dict) -> str:
    """生成BVF过滤器的统计摘要."""
    inp = stats.get('input', 0)
    trig = stats.get('bvf_triggered', 0)
    safe = stats.get('bvf_safe', 0)
    ovf = stats.get('bvf_overflow', 0)
    inc = stats.get('bvf_inconclusive', 0)
    out = stats.get('output', 0)
    reduction = ((inp - out) / max(inp, 1)) * 100
    return (
        f"BVF-Filter: input={inp}, triggered={trig}, "
        f"proven_safe={safe}, overflow_confirmed={ovf}, "
        f"inconclusive={inc}, output={out}, "
        f"FP_reduction={reduction:.1f}%"
    )


__all__ = [
    'filter_by_bvf', 'bvf_filter_stats_summary',
]
