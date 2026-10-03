"""
带集成误报过滤的堆溢出检测器 — 包装 仿射边界验证 (Affine Bound Verification) 5阶段管线, 将候选经
3引擎集成过滤 (VFS + 守卫关联 + 污点传播) 后处理; ≥2引擎判 SUPPRESS
的候选从 CONFIRMED/UNCERTAIN 重分类为 FILTERED。
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from core.heap_overflow_enhanced import (
    EnhancedHeapOverflowDetector, EnhancedHeapCandidate,
    detect_heap_overflow_enhanced,
)
from core.ensemble_fp_filter import (
    EnsembleFpFilter, EnsembleDecision,
)


# helpers ──────────────────────────────────────────────────────────────

import re as _re
_WRITE_ARGS = _re.compile(
    r'(?:memcpy|memmove|strncpy|strcpy|sprintf)\s*\(\s*[^,]+,\s*[^,]+,\s*(\w[\w.]*)')

def _extract_size_var(ir: list, wl: int) -> str:
    """从堆写入IR行提取大小参数变量。"""
    if wl < len(ir):
        m = _WRITE_ARGS.search(ir[wl])
        if m:
            return m.group(1)
    return 'len'

def _best_alloc_size(c) -> int:
    """尽力获取分配大小: effective > refined > raw。"""
    if c.effective_alloc > 0:
        return c.effective_alloc
    lo = c.refined_alloc_iv.lo
    return lo if lo > 0 and lo < 2**60 else 0


# integrated detector ──────────────────────────────────────────────────

class HeapEnsembleDetector:
    """仿射边界验证 (Affine Bound Verification) 5阶段管线 + 3引擎集成误报过滤。"""

    def __init__(self, platform: str = 'x86_64',
                 enable_ensemble: bool = True):
        self._pipeline = EnhancedHeapOverflowDetector(platform=platform)
        self._ensemble = EnsembleFpFilter() if enable_ensemble else None
        self.stats: Dict[str, Any] = {}

    def detect(
        self, ir_lines: List[str],
        binary_path: str = '', arch_bits: int = 64,
    ) -> Tuple[List[EnhancedHeapCandidate], List[EnsembleDecision], Dict]:
        """运行检测管线与可选的集成过滤, 返回 (候选, 集成判定, 统计)。"""
        # 阶段1-5: 既有仿射边界验证 (Affine Bound Verification) 管线
        candidates = self._pipeline.detect(ir_lines, binary_path, arch_bits)
        pipeline_stats = dict(self._pipeline.stats)
        ensemble_decisions: List[EnsembleDecision] = []

        if not self._ensemble or not candidates:
            self.stats = {**pipeline_stats,
                'ensemble_enabled': self._ensemble is not None,
                'ensemble_suppressed': 0}
            return candidates, ensemble_decisions, self.stats

        # 将候选转换为集成输入格式
        cand_dicts = []
        for c in candidates:
            size_var = _extract_size_var(ir_lines, c.write_site.loc)
            cand_dicts.append({
                'line': c.write_site.loc,
                'alloc_var': c.alloc_site.var_name,
                'alloc_size': _best_alloc_size(c),
                'size_var': size_var,
                'write_func': 'memcpy',
            })

        # 阶段6: 集成误报过滤
        decisions = self._ensemble.filter(ir_lines, cand_dicts)
        ensemble_decisions = decisions

        # 依据集成判定重分类候选
        for i, dec in enumerate(decisions):
            if i >= len(candidates):
                break
            if dec.verdict == 'SUPPRESS':
                cand = candidates[i]
                # 仅抑制非确定性溢出
                if cand.verdict in ('UNCERTAIN',):
                    cand.verdict = 'FILTERED'
                    cand.fp_likelihood = max(cand.fp_likelihood, 0.85)
                elif cand.verdict == 'CONFIRMED' and cand.confidence < 0.85:
                    # 临界情形: 降级为 UNCERTAIN
                    cand.verdict = 'UNCERTAIN'
                    cand.confidence = max(cand.confidence - 0.15, 0.30)
                    cand.fp_likelihood = min(cand.fp_likelihood + 0.30, 0.95)

        suppressed = sum(1 for d in decisions if d.verdict == 'SUPPRESS')
        self.stats = {
            **pipeline_stats,
            'ensemble_enabled': True,
            'ensemble_total': len(decisions),
            'ensemble_suppressed': suppressed,
            'ensemble_review': sum(1 for d in decisions if d.verdict == 'REVIEW'),
            'ensemble_kept': sum(1 for d in decisions if d.verdict == 'KEEP'),
            'ensemble_elapsed_ms': self._ensemble.stats.get('elapsed_ms', 0),
        }
        return candidates, ensemble_decisions, self.stats

    def print_ensemble_report(
        self, candidates: List[EnhancedHeapCandidate],
        decisions: List[EnsembleDecision],
    ) -> str:
        """生成可读的集成报告文本。"""
        lines = ['Ensemble FP Filter Report',
                 f"{'='*70}",
                 f"{'Line':5s} {'Write':35s} {'Pipeline':12s} "
                 f"{'Ensemble':12s} {'Score':7s}"]
        lines.append('-' * 70)
        for i, (c, d) in enumerate(zip(candidates, decisions)):
            if i >= len(decisions):
                break
            lines.append(
                f"{d.write_line:<5d} {d.write_text[:34]:35s} "
                f"{c.verdict:12s} {d.verdict:12s} {d.ensemble_score:.3f}")
        lines.append('-' * 70)
        lines.append(f"Total: {len(candidates)} candidates, "
                     f"{self.stats.get('ensemble_suppressed', 0)} suppressed")
        return '\n'.join(lines)


def detect_with_ensemble(
    ir_lines: List[str], binary_path: str = '', arch_bits: int = 64,
) -> Tuple[List[EnhancedHeapCandidate], List[EnsembleDecision], Dict]:
    """便捷接口: 带集成误报过滤的堆溢出检测。"""
    det = HeapEnsembleDetector()
    return det.detect(ir_lines, binary_path, arch_bits)


__all__ = ['HeapEnsembleDetector', 'detect_with_ensemble']
