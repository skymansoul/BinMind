"""
TARPS五阶段增强UAF检测: A-NULL置零, B-立即复用, C-别名分析,
D-路径可行性, E-置信度评分。事件提取移至 core/uaf_event_extractor.py。
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from core.uaf_event_extractor import extract_uaf_events, PtrEvent


# data types ────────────────────────────────────────────────────────

@dataclass
class UafCandidate:
    """UAF候选 — 含完整分析溯源"""
    ptr_name: str
    alloc_event: Optional[PtrEvent] = None
    free_event: Optional[PtrEvent] = None
    uaf_events: List[PtrEvent] = field(default_factory=list)
    verdict: str = 'UNCERTAIN'  # CONFIRMED | FILTERED | UNCERTAIN
    confidence: float = 0.0
    fp_likelihood: float = 0.5
    null_guarded: bool = False
    reassigned_after_free: bool = False
    has_alias: bool = False
    path_mutually_exclusive: bool = False
    stage_results: Dict[str, Any] = field(default_factory=dict)

    def summary(self) -> str:
        return (
            f'[{self.verdict}] ptr={self.ptr_name} '
            f'alloc@{self.alloc_event.line_idx if self.alloc_event else "?"} '
            f'free@{self.free_event.line_idx if self.free_event else "?"} '
            f'uaf_sites={len(self.uaf_events)} '
            f'conf={self.confidence:.2f} fp={self.fp_likelihood:.2f}'
        )


# TARPS 增强检测器 ──────────────────────────────────────────────────

class EnhancedUafDetector:
    """五阶段增强UAF检测器。

    用法:
      detector = EnhancedUafDetector()
      candidates = detector.detect(ir_lines)
    """

    def __init__(self):
        self.stats: Dict[str, Any] = {}

    def detect(self, ir_lines: List[str]) -> List[UafCandidate]:
        """运行五阶段TARPS检测, 返回排序后的候选列表。"""
        t0 = time.time()
        self.stats = {
            'stageA_null_guards': 0, 'stageB_reassign': 0,
            'stageC_aliases': 0, 'stageD_paths': 0,
            'stageE_candidates': 0,
        }

        events, alias_map = extract_uaf_events(ir_lines)

        # 按指针分组事件
        ptr_events: Dict[str, List[PtrEvent]] = {}
        for ev in events:
            ptr_events.setdefault(ev.ptr_name, []).append(ev)

        # 构建别名反向映射: alias → original
        alias_to_orig: Dict[str, str] = {}
        for alias, target in alias_map.items():
            orig = target
            visited = {alias}
            while orig in alias_map and orig not in visited:
                visited.add(orig)
                orig = alias_map[orig]
            alias_to_orig[alias] = orig

        # 识别 (alloc, free, use_after_free) 三元组
        candidates: List[UafCandidate] = []
        for ptr_name, ev_list in ptr_events.items():
            alloc_ev = None; free_ev = None
            uaf_events: List[PtrEvent] = []
            null_guarded = False; reassigned = False
            aliases: Set[str] = set()

            resolved_alloc = None; resolved_free = None
            if ptr_name in alias_to_orig:
                orig = alias_to_orig[ptr_name]
                orig_events = ptr_events.get(orig, [])
                for oev in orig_events:
                    if oev.event_type == 'ALLOC':
                        resolved_alloc = oev
                    elif oev.event_type == 'FREE':
                        resolved_free = oev
                aliases.add(orig)
                if orig in alias_to_orig:
                    aliases.add(alias_to_orig[orig])

            for ev in sorted(ev_list, key=lambda e: e.line_idx):
                if ev.event_type == 'ALLOC':
                    if free_ev and ev.line_idx > free_ev.line_idx:
                        reassigned = True
                        alloc_ev = ev
                    elif alloc_ev is None:
                        alloc_ev = ev
                elif ev.event_type == 'FREE':
                    # Double-free (CWE-415): 第二次free=USE
                    if free_ev and (alloc_ev or resolved_alloc) \
                       and not reassigned and not null_guarded:
                        if not uaf_events:
                            uaf_events.append(PtrEvent(
                                ev.line_idx, ptr_name, 'USE',
                                f'double-free CWE-415: 2nd free of {ptr_name}'))
                    if free_ev and uaf_events and (alloc_ev or resolved_alloc):
                        prev_cand = self._evaluate(
                            ptr_name, alloc_ev or resolved_alloc,
                            free_ev, uaf_events,
                            null_guarded, reassigned, aliases, ir_lines)
                        candidates.append(prev_cand)
                    free_ev = ev
                    uaf_events = []
                    null_guarded = False
                    reassigned = False
                elif ev.event_type == 'NULLIFY':
                    if free_ev and ev.line_idx > free_ev.line_idx:
                        null_guarded = True
                elif ev.event_type == 'REASSIGN':
                    if free_ev and ev.line_idx > free_ev.line_idx:
                        reassigned = True
                elif ev.event_type == 'USE':
                    effective_free = free_ev or resolved_free
                    if effective_free and ev.line_idx > effective_free.line_idx:
                        uaf_events.append(ev)
                elif ev.event_type == 'ALIAS':
                    aliases.add(ev.detail)

            if alloc_ev is None:
                alloc_ev = resolved_alloc
            if free_ev is None:
                free_ev = resolved_free

            # Stage B 前置检查
            if alloc_ev and free_ev and alloc_ev.line_idx > free_ev.line_idx:
                reassigned = True
                if uaf_events:
                    cand = self._evaluate(
                        ptr_name, alloc_ev, free_ev, uaf_events,
                        False, True, aliases, ir_lines)
                    candidates.append(cand)
                continue

            if free_ev and uaf_events:
                use_alloc = alloc_ev or resolved_alloc
                cand = self._evaluate(
                    ptr_name, use_alloc, free_ev, uaf_events,
                    null_guarded, reassigned, aliases, ir_lines)
                if not use_alloc:
                    cand.confidence = min(cand.confidence, 0.65)
                    cand.stage_results['cross_function'] = True
                candidates.append(cand)

        candidates.sort(key=lambda c: (-c.confidence, -len(c.uaf_events)))

        self.stats['stageE_candidates'] = len(candidates)
        self.stats['confirmed'] = sum(1 for c in candidates if c.verdict == 'CONFIRMED')
        self.stats['filtered'] = sum(1 for c in candidates if c.verdict == 'FILTERED')
        self.stats['uncertain'] = sum(1 for c in candidates if c.verdict == 'UNCERTAIN')
        self.stats['elapsed'] = round(time.time() - t0, 4)
        return candidates

    def _evaluate(
        self,
        ptr_name: str,
        alloc_ev: Optional[PtrEvent],
        free_ev: PtrEvent,
        uaf_events: List[PtrEvent],
        null_guarded: bool,
        reassigned: bool,
        aliases: Set[str],
        ir_lines: List[str],
    ) -> UafCandidate:
        """综合评估UAF候选 — 应用TARPS五阶段过滤。"""
        cand = UafCandidate(
            ptr_name=ptr_name,
            alloc_event=alloc_ev,
            free_event=free_ev,
            uaf_events=uaf_events,
            null_guarded=null_guarded,
            reassigned_after_free=reassigned,
            has_alias=len(aliases) > 0,
        )

        # Stage A: NULL置零过滤
        if null_guarded:
            cand.stage_results['A_null_guard'] = True
            cand.verdict = 'FILTERED'
            cand.confidence = 0.05
            cand.fp_likelihood = 0.98
            self.stats['stageA_null_guards'] += 1
            return cand

        # Stage B: 立即复用过滤
        if reassigned:
            cand.stage_results['B_reassign'] = True
            cand.verdict = 'FILTERED'
            cand.confidence = 0.10
            cand.fp_likelihood = 0.95
            self.stats['stageB_reassign'] += 1
            return cand

        # Stage C: 别名分析
        if aliases:
            cand.stage_results['C_aliases'] = list(aliases)
            self.stats['stageC_aliases'] += 1
            cand.confidence = 0.65
        else:
            cand.confidence = 0.80

        # Stage D: 路径可行性
        path_feasible = self._check_path_feasibility(
            free_ev.line_idx, uaf_events[0].line_idx, ir_lines)
        cand.path_mutually_exclusive = not path_feasible
        if not path_feasible:
            cand.stage_results['D_path_mutex'] = True
            cand.verdict = 'FILTERED'
            cand.confidence = 0.15
            cand.fp_likelihood = 0.90
            self.stats['stageD_paths'] += 1
            return cand

        # Stage E: 置信度评分
        n_uaf = len(uaf_events)
        distance = uaf_events[0].line_idx - free_ev.line_idx

        confidence = cand.confidence
        confidence += 0.05 * min(n_uaf - 1, 3)
        if distance <= 2:
            confidence += 0.05
        if aliases:
            confidence -= 0.10

        confidence = max(0.05, min(0.95, confidence))
        cand.confidence = confidence
        cand.fp_likelihood = 1.0 - confidence

        if confidence >= 0.60:
            cand.verdict = 'CONFIRMED'
        elif confidence >= 0.30:
            cand.verdict = 'UNCERTAIN'
        else:
            cand.verdict = 'FILTERED'

        return cand

    @staticmethod
    def _check_path_feasibility(
        free_line: int, use_line: int, ir_lines: List[str],
    ) -> bool:
        """检查free和use之间是否有条件跳转导致路径不可达。"""
        if free_line >= use_line:
            return False
        between = ir_lines[free_line:use_line + 1]
        has_jump = any(
            re.search(r'\b(?:return|goto|break|exit)\b', l)
            for l in between[1:-1])
        return not has_jump

    def summary_table(self, candidates: List[UafCandidate]) -> str:
        """生成候选摘要表。"""
        hdr = (f"{'Verdict':12s} {'Ptr':15s} {'Alloc@':8s} "
               f"{'Free@':8s} {'UAFs':6s} {'Conf':6s} {'FP%':6s}")
        rows = ["EnhancedUafDetector TARPS Results", hdr, "-" * 70]
        for c in candidates:
            rows.append(
                f"{c.verdict:12s} {c.ptr_name:15s} "
                f"{c.alloc_event.line_idx if c.alloc_event else '?':8s} "
                f"{c.free_event.line_idx if c.free_event else '?':8s} "
                f"{len(c.uaf_events):6d} {c.confidence:.2f}  {c.fp_likelihood:.2f}")
        return '\n'.join(rows)


def detect_uaf_enhanced(
    ir_lines: List[str],
) -> Tuple[List[UafCandidate], Dict[str, Any]]:
    """便捷函数: 对IR行运行增强UAF检测, 返回 (candidates, stats)。"""
    detector = EnhancedUafDetector()
    candidates = detector.detect(ir_lines)
    return candidates, detector.stats

__all__ = ['UafCandidate', 'PtrEvent', 'EnhancedUafDetector',
           'detect_uaf_enhanced']
