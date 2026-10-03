"""
仿射关系桥接器 — 将路径敏感仿射分析集成到约束求解器: 仿射关系域跟踪变量间线性等式 x = k*y + c, 在共享基变量时通过系数比较判定安全性, 无需具体区间。
集成策略: 在常量代换之后、FM 消元之前插入仿射证明步骤, 匹配候选的 alloc/write 到对应仿射 site, 查询 can_prove_safe / can_prove_overflow; 仿射无法判定时回退到 FM 流程 (零召回损失)。
"""

import re
from typing import Optional, Tuple

from core.constraint_constraint_types import (
    SolverVerdict, SolverResult,
)
from core.affine_analyzer import AffineAnalyzer
from core.heap_overflow_detector import HeapOverflowCandidate


def try_affine_proof(
    candidate: HeapOverflowCandidate,
    ir_lines: list[str],
    platform: str = "x86_64",
) -> Optional[SolverResult]:
    """对候选尝试仿射关系证明.

    返回SolverResult(仿射证明成功时)或None(仿射无法判定).

    流程:
      1. 运行AffineAnalyzer获取全程序仿射状态
      2. 匹配候选的alloc_site到malloc_site, store到memcpy_site
      3. 计算分配器对齐余量(chunk_slack)
      4. 调用can_prove_safe / can_prove_overflow
    """
    analyzer = AffineAnalyzer()
    malloc_sites, memcpy_sites, _ = analyzer.analyze(ir_lines)

    alloc_var, write_var = _match_affine_sites(
        candidate, malloc_sites, memcpy_sites)

    if not alloc_var:
        return None

    chunk_slack = _compute_chunk_slack(candidate, platform)

    result = SolverResult()
    result.constraints_collected = 0
    result.constraints_used = 0

    malloc_site = _find_matching_malloc_site(
        candidate, malloc_sites)
    if malloc_site is None:
        return None

    affine_state = malloc_site.get('affine_state')
    if affine_state is None:
        return None

    if not write_var:
        copy_ops = ('memcpy', 'memmove', 'strncpy', 'memset', 'strncat')
        if candidate.overflow_store.mnemonic in copy_ops:
            return None
        if _try_store_affine_safety(
                candidate, affine_state, chunk_slack, result):
            return result
        return None

    proven, reason = affine_state.can_prove_safe(
        write_var, alloc_var, chunk_slack)
    if proven:
        result.verdict = SolverVerdict.PROVEN_SAFE
        result.reason = f"affine: {reason}"
        result.confidence_delta = -0.50
        result.proof_chain = [
            f"Step 1: affine analysis tracks alloc={alloc_var}, write={write_var}",
            f"Step 2: can_prove_safe → {reason}",
            f"Step 3: chunk_slack={chunk_slack}",
            "Conclusion: write_size <= alloc_size + slack → SAFE (affine proven)",
        ]
        return result

    proven, reason = affine_state.can_prove_overflow(
        write_var, alloc_var)
    if proven:
        result.verdict = SolverVerdict.PROVEN_OVERFLOW
        result.reason = f"affine: {reason}"
        result.confidence_delta = +0.20
        result.proof_chain = [
            f"Step 1: affine analysis tracks alloc={alloc_var}, write={write_var}",
            f"Step 2: can_prove_overflow → {reason}",
            "Conclusion: write_size > alloc_size → OVERFLOW (affine proven)",
        ]
        return result

    return None


def _match_affine_sites(
    candidate: HeapOverflowCandidate,
    malloc_sites: list[dict],
    memcpy_sites: list[dict],
) -> Tuple[Optional[str], Optional[str]]:
    """匹配候选的alloc_var和write_var到仿射site.

    返回 (alloc_size_var, write_size_var).
    若无法匹配返回 (None, None).
    """
    alloc = candidate.alloc_site
    store = candidate.overflow_store

    alloc_var = None
    if alloc.size_is_dynamic and alloc.size_expr:
        alloc_var = _extract_base_var(alloc.size_expr)
    elif not alloc.size_is_dynamic and alloc.size_expr:
        alloc_var = alloc.size_expr

    if not alloc_var:
        for ms in malloc_sites:
            if ms.get('var') == alloc.result_var:
                alloc_var = ms.get('size_var')
                break

    write_var = None
    copy_ops = ('memcpy', 'memmove', 'strncpy', 'memset', 'strncat')
    if store.mnemonic in copy_ops and store.store_size == -1:
        for ms in memcpy_sites:
            if ms.get('dst_var') == store.base_var:
                write_var = ms.get('size_var')
                break

    return alloc_var, write_var


def _find_matching_malloc_site(
    candidate: HeapOverflowCandidate,
    malloc_sites: list[dict],
) -> Optional[dict]:
    """找到与候选alloc_site匹配的仿射malloc_site."""
    alloc = candidate.alloc_site
    result_var = alloc.result_var

    for ms in malloc_sites:
        if ms.get('var') == result_var:
            return ms

    if malloc_sites:
        pc = alloc.pc
        best = None
        best_dist = float('inf')
        for ms in malloc_sites:
            dist = abs(ms.get('line', 0) - pc)
            if dist < best_dist:
                best_dist = dist
                best = ms
        if best is not None and best_dist < 5:
            return best

    return None


def _try_store_affine_safety(
    candidate: HeapOverflowCandidate,
    affine_state,
    chunk_slack: int,
    result: SolverResult,
) -> bool:
    """对store操作(非copy族)尝试仿射安全证明.

    store操作: write_end = offset + store_size.
    若offset有仿射表达式且可用alloc_size约束, 可证明安全.
    """
    store = candidate.overflow_store
    alloc = candidate.alloc_site

    if store.offset_is_dynamic and store.offset >= 0:
        return False

    if alloc.size_is_dynamic:
        alloc_var = _extract_base_var(alloc.size_expr) if alloc.size_expr else None
        if alloc_var and affine_state and alloc_var in affine_state:
            eval_val = affine_state.evaluate(alloc_var)
            if eval_val is not None and eval_val > 0:
                from analysis.allocator_chunk_model import compute_effective_boundary
                usable = compute_effective_boundary(eval_val, "malloc")
                write_end = store.offset + max(store.store_size, 1)
                if write_end <= usable:
                    result.verdict = SolverVerdict.PROVEN_SAFE
                    result.reason = (
                        f"affine-store: alloc={alloc_var}={eval_val}, "
                        f"usable={usable}, write_end={write_end}")
                    result.confidence_delta = -0.45
                    result.proof_chain = [
                        f"Step 1: affine evaluates alloc_var {alloc_var} = {eval_val}",
                        f"Step 2: usable_size = {usable}",
                        f"Step 3: write_end = offset({store.offset}) + store({max(store.store_size,1)}) = {write_end}",
                        f"Step 4: {write_end} <= {usable} → SAFE",
                    ]
                    return True
    return False


def _compute_chunk_slack(
    candidate: HeapOverflowCandidate,
    platform: str,
) -> int:
    """计算分配器对齐余量.

    glibc malloc: request N → usable = align_up(N, 16) - 16 (metadata) + alignment_reuse
    简化: usable >= request_size (通常多8-16字节)
    """
    from analysis.allocator_chunk_model import compute_effective_boundary

    alloc_size = candidate.alloc_site.size_arg
    if alloc_size <= 0:
        return 0

    usable = compute_effective_boundary(alloc_size, "malloc")
    return max(0, usable - alloc_size)


def _extract_base_var(expr: str) -> Optional[str]:
    """从表达式中提取基变量名.

    'n' → 'n', 'n*4' → 'n', 'n+8' → 'n', 'size+1' → 'size'
    '2*n+8' → 'n'
    """
    if not expr:
        return None

    m = re.match(r'^(\d+)\s*[\*\+]', expr)
    if m:
        rest = expr[m.end():]
        var_m = re.match(r'(\w+)', rest)
        if var_m:
            return var_m.group(1)

    m = re.match(r'^(\w+)', expr)
    if m:
        return m.group(1)

    return None


__all__ = ['try_affine_proof']
