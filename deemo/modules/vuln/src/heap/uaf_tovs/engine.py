"""TOVS 判定引擎 — 时序验证 + 身份验证 → 最终判定.

创建: 2026-04-17
设计决策:
  - 判定顺序: 时序不成立(证据充分) → SAFE; 时序成立且身份一致 →
    CONFIRMED; 其余 → POSSIBLE (保守保留, 保召回).
  - 时序成立但身份被杀 → SAFE (重新赋值的合法模式).
  - 时序无法判定 → 降级身份验证: 身份被杀仍可 SAFE, 否则 POSSIBLE.
"""
from typing import List

from .types import (TovsVerdict, TovsRule, Evidence, FreeUsePair,
                    PairVerdict)
from .order_verify import OrderVerifier
from .redef_verify import RedefVerifier


class TovsEngine:
    """单函数 TOVS 判定引擎."""

    def __init__(self, insns: list, tracer):
        self._order = OrderVerifier(insns)
        self._redef = RedefVerifier(insns)
        self._tracer = tracer
        self._stats = {'total': 0, 'confirmed': 0, 'possible': 0,
                       'filtered': 0}

    def evaluate(self, pair: FreeUsePair,
                 sample_id: str = '') -> PairVerdict:
        self._stats['total'] += 1
        pv = PairVerdict(sample_id=sample_id, pair=pair)

        order_ok, order_evs = self._order.verify(pair)
        pv.evidences.extend(order_evs)

        if order_ok is False:
            pv.verdict = TovsVerdict.SAFE_FILTERED
            pv.fp_probability = 0.9
            self._stats['filtered'] += 1
            return pv

        killed, redef_evs = self._redef.verify(pair, self._tracer)
        pv.evidences.extend(redef_evs)

        if killed is True:
            pv.verdict = TovsVerdict.SAFE_FILTERED
            pv.fp_probability = 0.92
            self._stats['filtered'] += 1
            return pv

        if order_ok is True:
            pv.verdict = TovsVerdict.CONFIRMED
            pv.fp_probability = 0.05
            self._stats['confirmed'] += 1
            return pv

        pv.verdict = TovsVerdict.POSSIBLE
        pv.fp_probability = 0.35
        self._stats['possible'] += 1
        return pv

    def stats(self) -> dict:
        return dict(self._stats)
