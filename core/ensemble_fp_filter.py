"""集成 FP 过滤器: 3 引擎 (值流切片+守卫关联+污点) 抑制堆溢出假阳性.
加权委员会投票: 全票一致直接采纳; 2:1+REVIEW多数决; 三向分裂判REVIEW.
参考: Dietterich MCS 2000; Sridharan et al. OOPSLA 2011."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
import json, time

from core.value_flow_slicer import ValueFlowSlicer, SlicedWrite
from core.guard_correlator import GuardCorrelator, GuardCorrelationResult
from core.taint_propagator import TaintPropagator
try:
    from core.taint_propagator import HeapWriteTaint
except ImportError:
    # HeapWriteTaint 已移除; 污点投票引擎降级, 调用点按 None 守卫跳过
    HeapWriteTaint = None


# 判定域 ──────────────────────────────────────────────────────────────

VERDICT = {'SUPPRESS', 'REVIEW', 'KEEP'}  # KEEP = 疑似真实溢出

@dataclass
class EngineVote:
    """单个引擎对堆写入候选的投票."""
    engine: str           # 'vfs' | 'guard' | 'taint'
    verdict: str          # SUPPRESS | REVIEW | KEEP
    confidence: float     # 0-1
    reason: str = ''
    detail: Dict[str, Any] = field(default_factory=dict)

@dataclass
class EnsembleDecision:
    """单个堆写入的 FP 过滤聚合决策."""
    write_line: int; write_text: str
    alloc_var: str = ''; alloc_size: int = 0; size_var: str = ''
    votes: List[EngineVote] = field(default_factory=list)
    verdict: str = 'REVIEW'
    ensemble_score: float = 0.50   # 0=overflow, 1=FP
    vfs_result: Optional[SlicedWrite] = None
    guard_result: Optional[GuardCorrelationResult] = None
    taint_result: Optional[HeapWriteTaint] = None

    def is_suppressed(self) -> bool:
        return self.verdict == 'SUPPRESS'

    def summary(self) -> str:
        return (f'[{self.verdict}] L{self.write_line} {self.write_text[:60]} '
                f'score={self.ensemble_score:.3f} '
                f'votes={"/".join(v.engine[0]+":"+v.verdict[0] for v in self.votes)}')


# 集成引擎 ────────────────────────────────────────────────────────────

class EnsembleFpFilter:
    """堆溢出候选的三引擎 FP 过滤器.

    用法: filter(ir_lines, candidates) → decisions, 逐条给出 SUPPRESS/REVIEW/KEEP.
    """

    def __init__(self):
        self._vfs = ValueFlowSlicer(max_hops=8)
        self._guard = GuardCorrelator(max_lookback=50)
        self._taint = TaintPropagator()
        self.stats: Dict[str, Any] = {}

    # 公开 API ────────────────────────────────────────────────────────

    def filter(
        self, ir_lines: List[str],
        candidates: List[Dict[str, Any]],
    ) -> List[EnsembleDecision]:
        """对每个候选运行三引擎, 返回集成决策列表.

        candidates: [{'line', 'alloc_var', 'alloc_size', 'size_var', 'write_func'}, ...]
        """
        t0 = time.time()
        decisions: List[EnsembleDecision] = []

        # 预计算污点分析 (跨全部行)
        taint_map = self._taint.analyze(ir_lines)

        for cand in candidates:
            wl = cand.get('line', -1)
            alloc_var = cand.get('alloc_var', 'buf')
            alloc_size = cand.get('alloc_size', 0)
            size_var = cand.get('size_var', 'len')

            if wl < 0 or wl >= len(ir_lines):
                continue

            dec = EnsembleDecision(
                write_line=wl,
                write_text=ir_lines[wl].strip(),
                alloc_var=alloc_var, alloc_size=alloc_size,
                size_var=size_var,
            )

            # 引擎 A: 值流切片
            vfs_r = self._vfs.slice_write(ir_lines, wl, alloc_var)
            dec.vfs_result = vfs_r
            dec.votes.append(self._vfs_vote(vfs_r, alloc_size))

            # 引擎 B: 守卫关联
            guard_r = self._guard.correlate(
                ir_lines, wl, size_var, alloc_var, alloc_size)
            dec.guard_result = guard_r
            dec.votes.append(self._guard_vote(guard_r))

            # 引擎 C: 污点传播
            taint_r = self._taint.check_write(
                ir_lines, wl, alloc_var, size_var)
            dec.taint_result = taint_r
            dec.votes.append(self._taint_vote(taint_r))

            # 集成聚合
            dec.verdict, dec.ensemble_score = self._aggregate(dec.votes)
            decisions.append(dec)

        self.stats = {
            'total': len(decisions),
            'suppressed': sum(1 for d in decisions if d.verdict == 'SUPPRESS'),
            'review': sum(1 for d in decisions if d.verdict == 'REVIEW'),
            'kept': sum(1 for d in decisions if d.verdict == 'KEEP'),
            'elapsed_ms': round((time.time() - t0) * 1000, 2),
        }
        return decisions

    # 逐引擎投票 ─────────────────────────────────────────────────────

    @staticmethod
    def _vfs_vote(vfs: SlicedWrite, alloc_size: int) -> EngineVote:
        """值流切片器投票."""
        reasons = []
        fp_score = vfs.fp_likelihood  # 高 → 疑似 FP

        if vfs.size_slice:
            ss = vfs.size_slice
            if ss.origin_type == 'constant':
                if ss.resolved_const >= 0:
                    if ss.resolved_const <= alloc_size:
                        reasons.append(f'write_size({ss.resolved_const}) <= alloc({alloc_size})')
                        fp_score = max(fp_score, 0.80)
                    else:
                        reasons.append(f'write_size({ss.resolved_const}) > alloc({alloc_size})')
                        fp_score = min(fp_score, 0.30)
            elif ss.origin_type == 'user_input':
                reasons.append(f'size from user_input: {ss.definition_expr}')
                fp_score = min(fp_score, 0.15)

        if vfs.is_user_controlled and not vfs.guards:
            reasons.append('user_controlled, no guards')
            fp_score = 0.10

        dom_guards = [g for g in vfs.guards if g.dominates]
        if dom_guards:
            reasons.append(f'{len(dom_guards)} dominating guards')
            fp_score = max(fp_score, 0.70)

        verdict = EnsembleFpFilter._threshold(fp_score)
        return EngineVote(
            engine='vfs', verdict=verdict, confidence=abs(fp_score - 0.5) * 2,
            reason='; '.join(reasons) if reasons else f'fp_likelihood={fp_score:.2f}',
            detail={'fp_likelihood': fp_score, 'origin': vfs.size_slice.origin_type if vfs.size_slice else 'none'},
        )

    @staticmethod
    def _guard_vote(gr: GuardCorrelationResult) -> EngineVote:
        """守卫关联器投票."""
        reasons = []
        score = gr.safe_confidence  # 高 → 疑似安全 (FP)

        if gr.dominant_guard:
            dg = gr.dominant_guard
            reasons.append(
                f'dominant: if({dg.guard_var}{dg.op}{dg.bound_value}) '
                f'strength={dg.strength:.2f} scope={dg.scope_match}')
        elif gr.guards:
            reasons.append(f'{len(gr.guards)} guards, none dominant')

        if score >= 0.70:
            reasons.append('strong guard protection')
        elif score >= 0.30:
            reasons.append('moderate guard presence')

        verdict = EnsembleFpFilter._threshold(score)
        return EngineVote(
            engine='guard', verdict=verdict, confidence=score,
            reason='; '.join(reasons) if reasons else 'no guards found',
            detail={
                'safe_confidence': score,
                'guard_count': len(gr.guards),
                'dominant_strength': gr.dominant_guard.strength if gr.dominant_guard else 0,
            },
        )

    @staticmethod
    def _taint_vote(ht: HeapWriteTaint) -> EngineVote:
        """污点传播器投票."""
        reasons = []
        # 分数: 0=干净(安全/FP), 1=被污染(真实溢出)
        # 反转: 高 taint_score → 低 FP 分数
        taint_score = ht.taint_score if ht else 0.0
        fp_score = 1.0 - taint_score

        if ht:
            if ht.alloc_tainted:
                reasons.append('alloc size tainted')
                fp_score = min(fp_score, 0.25)
            if ht.write_tainted:
                reasons.append('write size tainted')
                fp_score = min(fp_score, 0.15)
            if ht.guard_count > 0:
                reasons.append(f'{ht.guard_count} guards on tainted path')
                fp_score = max(fp_score, 0.55 + 0.10 * min(ht.guard_count, 2))
            reasons.append(f'taint={taint_score:.2f} → fp={fp_score:.2f}')

        verdict = EnsembleFpFilter._threshold(fp_score)
        return EngineVote(
            engine='taint', verdict=verdict, confidence=abs(fp_score - 0.5) * 2,
            reason='; '.join(reasons) if reasons else 'clean (likely FP)',
            detail={'taint_score': taint_score, 'fp_score': fp_score,
                    'alloc_tainted': ht.alloc_tainted if ht else False,
                    'write_tainted': ht.write_tainted if ht else False},
        )

    @staticmethod
    def _threshold(score: float) -> str:
        """将 0-1 分数映射为判定. 分数趋向1 = FP (抑制), 分数趋向0 = 真实 (保留)."""
        if score >= 0.65:
            return 'SUPPRESS'
        elif score <= 0.35:
            return 'KEEP'
        return 'REVIEW'

    # 聚合 ────────────────────────────────────────────────────────────

    @staticmethod
    def _aggregate(votes: List[EngineVote]) -> Tuple[str, float]:
        """加权委员会: 3 引擎 → 判定 + 集成分数.

        决策矩阵:
          三引擎全一致 → 直接采纳该判定
          2 票一致, 1 票分歧 → 按置信度加权多数决
          三向分裂或 1-1-1 → REVIEW
        """
        counts = {'SUPPRESS': 0, 'REVIEW': 0, 'KEEP': 0}
        conf_sum = {'SUPPRESS': 0.0, 'REVIEW': 0.0, 'KEEP': 0.0}
        for v in votes:
            counts[v.verdict] += 1
            conf_sum[v.verdict] += v.confidence

        # 全票一致
        for vk in ['SUPPRESS', 'KEEP', 'REVIEW']:
            if counts[vk] == 3:
                return vk, conf_sum[vk] / 3

        # 多数决 (2 vs 1) 或 (2 vs REVIEW)
        for vk in ['SUPPRESS', 'KEEP']:
            if counts[vk] == 2:
                # 2:1 vs REVIEW → majority wins directly
                if counts['REVIEW'] == 1:
                    return vk, conf_sum[vk] / 3
                # 2:1 vs the other substantive vote → weighted
                other = next((v for v in votes
                    if v.verdict not in (vk, 'REVIEW')), None)
                if other and conf_sum[vk] >= other.confidence:
                    return vk, conf_sum[vk] / 3
                return 'REVIEW', 0.50

        # 三向分裂 → REVIEW
        return 'REVIEW', 0.50


# 便捷接口 ─────────────────────────────────────────────────────────────

def filter_heap_candidates(
    ir_lines: List[str],
    candidates: List[Dict[str, Any]],
) -> Tuple[List[EnsembleDecision], Dict[str, Any]]:
    """便捷函数: 对堆溢出候选执行集成过滤."""
    ef = EnsembleFpFilter()
    decisions = ef.filter(ir_lines, candidates)
    return decisions, ef.stats


__all__ = [
    'EngineVote', 'EnsembleDecision', 'EnsembleFpFilter',
    'filter_heap_candidates', 'VERDICT',
]
