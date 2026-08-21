# coding: utf-8
"""
UAF realloc 链追踪 + PTLV 批量验证入口.

realloc(ptr, size) 可能分配新块并返回新指针, 旧 ptr 变为悬空.
对旧 ptr 的后续访问即为 use-after-realloc (UAF 子类).
"""

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from .uaf_temporal_path import (
    TemporalPathVerifier, PathSensitiveCfg, TemporalVerdict)


@dataclass
class ReallocRecord:
    old_ptr: str; new_ptr: str; new_size: int; addr: int; ts: int


class ReallocChainTracker:
    """realloc 链追踪器 — 检测 realloc 后的悬空旧指针使用."""

    def __init__(self):
        self._records: List[ReallocRecord] = []
        self._dangling: Dict[str, ReallocRecord] = {}

    def record_realloc(self, old_ptr: str, new_ptr: str,
                       new_size: int, addr: int, ts: int):
        rec = ReallocRecord(old_ptr, new_ptr, new_size, addr, ts)
        self._records.append(rec)
        if old_ptr != new_ptr:
            self._dangling[old_ptr] = rec

    def is_dangling(self, ptr: str, at_ts: int) -> Tuple[bool, str]:
        if ptr not in self._dangling: return False, ''
        rec = self._dangling[ptr]
        if at_ts > rec.ts:
            return True, (f'realloc@{rec.addr:x} (ts={rec.ts}) '
                         f'{rec.old_ptr}->{rec.new_ptr}, '
                         f'访问 {ptr}@ts={at_ts} (> {rec.ts})')
        return False, ''


def verify_uaf_candidates(
    candidates: List[Dict],
    instructions: List[Dict],
    callee_names: Dict[int, str],
) -> Tuple[List[Dict], Dict]:
    """PTLV 批量验证 UAF 候选 — 路径互斥 + realloc 链 + 支配关系."""
    verifier = TemporalPathVerifier()
    realloc_tracker = ReallocChainTracker()
    ptr_cfgs: Dict[str, PathSensitiveCfg] = {}

    for ptr in set(c.get('ptr_name', '') for c in candidates):
        if ptr:
            ptr_cfgs[ptr] = verifier.build_from_instructions(
                instructions, callee_names, ptr)

    stats = {'total': len(candidates), 'confirmed_uaf': 0,
             'filtered_safe': 0, 'realloc_dangling': 0,
             'guards_contradict': 0, 'dominated_free': 0, 'retained': 0}

    verified = []
    for c in candidates:
        ptr = c.get('ptr_name', '')
        free_site = c.get('free_site', 0)
        use_site = c.get('use_site', 0)

        is_dangling, dang_reason = realloc_tracker.is_dangling(
            ptr, c.get('use_ts', use_site))
        if is_dangling:
            c['confidence'] = max(c.get('confidence', 0.5), 0.90)
            c['_ptlv_reason'] = dang_reason
            c['_ptlv_type'] = 'realloc_dangling'
            stats['realloc_dangling'] += 1
            stats['confirmed_uaf'] += 1
            verified.append(c)
            continue

        cfg = ptr_cfgs.get(ptr)
        if cfg:
            verifier._cfg = cfg
            verdict = verifier.verify(free_site, use_site, ptr)
            if not verdict.is_uaf:
                c['_filtered_by'] = 'PTLV'
                c['_ptlv_reason'] = verdict.reason
                if verdict.guards_contradict: stats['guards_contradict'] += 1
                stats['filtered_safe'] += 1
                continue
            c['confidence'] = verdict.confidence
            c['_ptlv_confidence'] = verdict.confidence
            if verdict.dominated:
                stats['dominated_free'] += 1
                c['_ptlv_type'] = 'dominated_free'

        stats['retained'] += 1
        verified.append(c)

    return verified, stats
