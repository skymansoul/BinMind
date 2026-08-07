"""
HOIG Pipeline Integration — 将 HOIG 接入 BinMind UAF 管线.

作为 UAF 管线的独立验证维度, 与 PTASM + Temporal 并行:
  PTASM: 状态机快速筛选 → 高召回
  Temporal: 路径敏感验证 → 削减FP
  HOIG: 对象身份追踪 → 消除别名FP + 补充跨函数FN
  PCOL: 路径条件对象生命周期 → 过滤路径不可达的UAF (CONFIRMED→SAFE)

融合策略 (保守):
  1. HOIG SAFE → 过滤 PTASM/Temporal CONFIRMED (消除别名FP)
  2. HOIG CONFIRMED → 补充 PTASM/Temporal UNCERTAIN (减少FN)
  3. 冲突时保持原判定 (不引入新FN)
  4. PCOL 仅过滤 HOIG CONFIRMED 中路径不可达的误报 (不升级SAFE)
"""


from typing import Any, Dict, List, Optional, Tuple

from .uaf_hoig_types import ObjState, ObjectID, UafHoigVerdict
from .uaf_hoig_builder import HoigBuilder
from .uaf_hoig_cross_func import HoigCrossFuncVerifier
from .uaf_hoig_verifier import HoigVerifier, HoigReallocTracker
from .uaf_pcol_verifier import filter_uaf_by_pcol


class UafHoigPipeline:
    """HOIG UAF 检测管线.

    集成 HOIG 的四个核心能力:
      1. 单函数内 ObjectID 追踪
      2. realloc 对象身份延续
      3. 跨函数 freed_vars 传递性传播
      4. 与 PTASM/Temporal 的精化融合
    """

    def __init__(self):
        self.hoig_verifier = HoigVerifier()
        self.cross_verifier = HoigCrossFuncVerifier()
        self.realloc_tracker = HoigReallocTracker()
        self.results: List[UafHoigVerdict] = []

    def analyze(self, pseudocode: str, func_name: str = "",
                func_bodies: Optional[Dict[str, str]] = None,
                calls: Optional[List[Tuple[str, str]]] = None,
                ) -> Dict[str, Any]:
        """运行完整的 HOIG UAF 分析.

        Args:
            pseudocode: 主函数伪代码
            func_name: 主函数名
            func_bodies: 所有相关函数体 (用于跨函数分析)
            calls: 调用关系 [(caller, callee), ...]

        Returns:
            {
                'verdict': overall verdict,
                'intra_func': intra-function findings,
                'cross_func': cross-function findings,
                'realloc': realloc findings,
                'stats': performance stats,
            }
        """
        import time
        start = time.perf_counter()
        all_verdicts: List[UafHoigVerdict] = []

        # Phase 1: 单函数内分析
        intra_v = self.hoig_verifier.verify_single(pseudocode, func_name)
        if intra_v.verdict == 'CONFIRMED':
            all_verdicts.append(intra_v)

        # Phase 2: realloc 追踪
        realloc_vs = self.realloc_tracker.analyze(pseudocode)
        all_verdicts.extend(realloc_vs)

        # Phase 3: 跨函数分析
        cross_vs: List[UafHoigVerdict] = []
        if func_bodies and calls:
            for fname, body in func_bodies.items():
                self.cross_verifier.register(fname, body)
            for caller, callee in calls:
                self.cross_verifier.register_call(caller, callee)
            cross_vs = self.cross_verifier.verify_all()
            all_verdicts.extend(cross_vs)

        # Phase 4: PCOL路径条件感知过滤
        confirmed = [v for v in all_verdicts if v.verdict == 'CONFIRMED']
        pcol_stats = {'pcol_triggered': 0, 'pcol_filtered': 0,
                      'pcol_kept': 0}
        if confirmed:
            filtered_all, pcol_stats = filter_uaf_by_pcol(
                pseudocode, all_verdicts)
            all_verdicts = filtered_all

        elapsed = time.perf_counter() - start

        # 确定最终判定
        confirmed = [v for v in all_verdicts if v.verdict == 'CONFIRMED']
        uncertain = [v for v in all_verdicts if v.verdict == 'UNCERTAIN']
        safe = [v for v in all_verdicts if v.verdict == 'SAFE']

        if confirmed:
            overall = 'CONFIRMED'
            max_conf = max(v.confidence for v in confirmed)
        elif uncertain:
            overall = 'UNCERTAIN'
            max_conf = max(v.confidence for v in uncertain)
        else:
            overall = 'SAFE'
            max_conf = 0.80

        return {
            'verdict': overall,
            'confidence': max_conf,
            'total_findings': len(all_verdicts),
            'confirmed': len(confirmed),
            'uncertain': len(uncertain),
            'safe': len(safe),
            'intra_func_findings': [v for v in all_verdicts
                                    if not v.is_cross_func],
            'cross_func_findings': [v for v in all_verdicts
                                    if v.is_cross_func],
            'realloc_findings': realloc_vs,
            'stats': {
                'time_ms': round(elapsed * 1000, 2),
                'intra_func_verdict': intra_v.verdict,
                'cross_func_count': len(cross_vs),
                'realloc_count': len(realloc_vs),
                'pcol_triggered': pcol_stats.get('pcol_triggered', 0),
                'pcol_filtered': pcol_stats.get('pcol_filtered', 0),
            },
        }

    def refine_existing(self, existing_verdict: str,
                        hoig_result: Dict[str, Any]
                        ) -> Tuple[str, float, str]:
        """用 HOIG 结果精化已有管线判定.

        Args:
            existing_verdict: PTASM/Temporal 的判定
            hoig_result: HOIG 管线的分析结果

        Returns:
            (final_verdict, confidence, reason)
        """
        hoig_v = hoig_result.get('verdict', 'UNCERTAIN')
        hoig_c = hoig_result.get('confidence', 0.0)

        # HOIG SAFE → 过滤已有确认
        if hoig_v == 'SAFE' and existing_verdict in ('CONFIRMED', 'LIKELY'):
            return ('SAFE', hoig_c,
                    'HOIG: object identity tracking proves no UAF '
                    '(different ObjectIDs or safe realloc)')

        # HOIG CONFIRMED → 补充已有遗漏
        if hoig_v == 'CONFIRMED' and existing_verdict in ('SAFE', 'UNCERTAIN'):
            return ('CONFIRMED', hoig_c,
                    f'HOIG: cross-function object tracking reveals UAF '
                    f'(confirmed findings: {hoig_result.get("confirmed", 0)})')

        # 一致或 HOIG UNCERTAIN → 保持原有
        return (existing_verdict, hoig_c,
                'HOIG: no refinement needed (consistent with existing)')

    def batch_verify(self, samples: Dict[str, str],
                     func_bodies: Optional[Dict[str, str]] = None,
                     calls: Optional[List[Tuple[str, str]]] = None,
                     ) -> List[Dict[str, Any]]:
        """批量 UAF 验证."""
        results = []
        for name, code in samples.items():
            r = self.analyze(code, name, func_bodies, calls)
            r['sample'] = name
            results.append(r)
        return results


__all__ = ['UafHoigPipeline']
