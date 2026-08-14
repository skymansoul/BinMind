"""
堆溢出值流验证管道 — 用约束安全证明过滤堆溢出误报, 而非仅靠启发式模式匹配。
阶段: VFG构建→约束累加→循环边界推断→安全证明→路径可行性, 各阶段独立可降级。
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
import re
import time


@dataclass
class VFlowVerifyResult:
    """值流验证结果 — 对单个候选的判定。"""
    candidate_index: int
    verdict: str = ''       # 'safe' | 'unsafe' | 'uncertain'
    proof_detail: str = ''  # 证明过程描述
    confidence_delta: float = 0.0  # 置信度调整


@dataclass
class PipelineStats:
    """管道统计 — 各阶段的过滤效果。"""
    candidates_in: int = 0
    candidates_out: int = 0
    vfg_nodes: int = 0
    vfg_edges: int = 0
    constraints_extracted: int = 0
    loops_inferred: int = 0
    safe_proved: int = 0     # 可证明安全 (滤除的FP)
    unsafe_proved: int = 0   # 可证明不安全 (确认的真阳性)
    uncertain: int = 0       # 无法确定 (保留)
    path_infeasible: int = 0 # 路径不可行
    time_ms: float = 0.0


def verify_heap_candidates(
    candidates: list,
    ir_lines: List[str],
    decompiled_text: str = '',
    verbose: bool = False,
) -> Tuple[list, PipelineStats]:
    """主入口: 对堆溢出候选列表执行值流验证。

    参数:
      candidates: heap_overflow_detector 或 pipeline 输出的候选列表
      ir_lines: 标准化IR行列表
      decompiled_text: 原始解压缩文本 (备用)
      verbose: 输出调试信息

    返回:
      (filtered_candidates, stats): 过滤后的候选列表和统计信息
    """
    t0 = time.perf_counter()
    stats = PipelineStats(candidates_in=len(candidates))

    if not candidates:
        stats.time_ms = (time.perf_counter() - t0) * 1000
        return candidates, stats

    # 阶段1: VFG构建
    try:
        from core.vfg_builder import build_vfg
        vfg = build_vfg(ir_lines)
        stats.vfg_nodes = len(vfg.nodes)
        stats.vfg_edges = len(vfg.edges)
    except Exception:
        stats.time_ms = (time.perf_counter() - t0) * 1000
        return candidates, stats

    # 阶段2: 约束累加
    try:
        from core.constraint_accumulator import ConstraintAccumulator
        acc = ConstraintAccumulator()
        acc.accumulate(vfg)
        stats.constraints_extracted = sum(
            len(v) for v in acc._constraints.values())
    except Exception:
        acc = None

    # 阶段3: 循环边界推断
    loops = []
    try:
        from core.loop_bound_inferrer import infer_loop_bounds
        loops = infer_loop_bounds(ir_lines)
        stats.loops_inferred = len(loops)
    except Exception:
        pass

    # 阶段4: 对每个候选执行安全证明
    verified = []
    for idx, c in enumerate(candidates):
        result = _verify_single_candidate(c, ir_lines, vfg, acc, loops)
        verified.append(result)

    # 应用判定
    kept = []
    for idx, (c, vr) in enumerate(zip(candidates, verified)):
        if vr.verdict == 'safe':
            stats.safe_proved += 1
            # 可证明安全: 这是FP, 滤除
            continue
        elif vr.verdict == 'unsafe':
            stats.unsafe_proved += 1
            # 可证明不安全: 真阳性, 提升置信度
            if hasattr(c, 'confidence'):
                c.confidence = min(0.98, c.confidence + 0.15)
        else:
            stats.uncertain += 1

        kept.append(c)

    # 阶段5: 路径可行性
    try:
        from core.path_feasibility_check import PathFeasibilityChecker
        pfc = PathFeasibilityChecker()
        before_path = len(kept)
        kept = pfc.filter_candidates(kept, ir_lines)
        stats.path_infeasible = before_path - len(kept)
    except Exception:
        pass

    stats.candidates_out = len(kept)
    stats.time_ms = round((time.perf_counter() - t0) * 1000, 1)
    return kept, stats


def _verify_single_candidate(
    c,
    ir_lines: List[str],
    vfg,
    acc,
    loops: list,
) -> VFlowVerifyResult:
    """对单个候选执行验证 — 尝试证明写入安全或确认溢出。"""
    # 提取候选信息
    if hasattr(c, 'alloc_site'):
        alloc_size = c.alloc_site.size_arg
        alloc_var = c.alloc_site.result_var
        store_offset = c.overflow_store.offset
        store_var = c.overflow_store.base_var
    else:
        # dict形式
        alloc_size = c.get('alloc_size', 0)
        alloc_var = c.get('alloc_var', '')
        store_offset = c.get('store_offset', 0)
        store_var = c.get('base_var', '')

    idx = 0
    proof_parts = []

    # 检查1: 循环边界安全性
    if loops and store_var:
        for loop in loops:
            if loop.base_pointer == store_var and loop.is_valid:
                max_off = loop.max_offset
                if max_off > 0 and max_off < alloc_size:
                    proof_parts.append(
                        f'loop bound: max_offset={max_off} < alloc={alloc_size}')
                    return VFlowVerifyResult(
                        candidate_index=idx,
                        verdict='safe',
                        proof_detail='; '.join(proof_parts),
                        confidence_delta=-0.40,
                    )

    # 检查2: 约束推理 — alloc_size vs store_offset
    if acc is not None and alloc_var:
        alloc_val = acc.get_value(alloc_var)
        if alloc_val is not None and isinstance(store_offset, int) and store_offset >= 0:
            if store_offset < alloc_val:
                proof_parts.append(
                    f'constraint: offset={store_offset} < alloc={alloc_val}')
                return VFlowVerifyResult(
                    candidate_index=idx,
                    verdict='safe',
                    proof_detail='; '.join(proof_parts),
                    confidence_delta=-0.30,
                )

    # 检查3: 分配大小约束传播
    if acc is not None and alloc_var:
        # 查找 alloc_var_size 是否有约束
        size_var = alloc_var + '_size'
        size_val = acc.get_value(size_var)
        if size_val is not None and store_offset >= 0:
            if store_offset < size_val:
                proof_parts.append(
                    f'propagated alloc size: {size_val}, offset: {store_offset}')
                return VFlowVerifyResult(
                    candidate_index=idx,
                    verdict='safe',
                    proof_detail='; '.join(proof_parts),
                    confidence_delta=-0.25,
                )

    # 检查4: 确认溢出 (可证明不安全)
    if alloc_size > 0 and isinstance(store_offset, int) and store_offset > 0:
        if store_offset > alloc_size + 32:
            # 偏移远超过分配大小 → 明显溢出
            return VFlowVerifyResult(
                candidate_index=idx,
                verdict='unsafe',
                proof_detail=f'offset {store_offset} >> alloc {alloc_size}',
                confidence_delta=+0.15,
            )

    # 无法确定
    return VFlowVerifyResult(
        candidate_index=idx,
        verdict='uncertain',
        proof_detail='; '.join(proof_parts) if proof_parts else 'insufficient constraints',
        confidence_delta=0.0,
    )


def vflow_filter(candidates: list, ir_lines: List[str],
                 decompiled_text: str = '') -> Tuple[list, dict]:
    """便捷过滤函数 — 兼容现有 pipeline 接口。

    返回 (filtered_candidates, stats_dict)。"""
    filtered, stats = verify_heap_candidates(candidates, ir_lines, decompiled_text)
    return filtered, {
        'vfg_stage': {
            'in': stats.candidates_in,
            'out': stats.candidates_out,
            'safe_proved': stats.safe_proved,
            'unsafe_proved': stats.unsafe_proved,
            'uncertain': stats.uncertain,
            'path_infeasible': stats.path_infeasible,
            'time_ms': stats.time_ms,
        }
    }
