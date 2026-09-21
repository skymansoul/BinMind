"""分配容量溯源判定引擎 — 汇总容量/溯源/守卫证据, 输出最终误报裁定.

用途: 将 equivalence.classify_pair 的关系映射为可审计的判定:
      SAFE(滤除) / VULN_CONFIRMED / VULN_LIKELY / UNCERTAIN。
      同时结合反例守卫(写出仅在 size>cap 时可达)提升 CONFIRMED 精度。

保守性原则:
  - 只有具备明确安全证据(EQUIV/CONST_LE/ARITH_LE/GUARDED)才滤除。
  - ARITH_SLACK 因落在分配器 slack 区可能被误滤真溢出, 因此归入
    UNCERTAIN 保留, 只降低排序优先级, 不滤除。
  - UNRELATED 一律保留为 VULN_LIKELY, 保证召回不受损。
"""

from dataclasses import dataclass
from enum import Enum
from typing import List, Optional

from modules.vuln.detection.heap_analysis.acpe.capacity_model import (
    CapExpr, usable_size)
from modules.vuln.detection.heap_analysis.acpe.guard_dominance import (
    GuardEvidence)
from modules.vuln.detection.heap_analysis.acpe.equivalence import (
    classify_pair)


class Verdict(Enum):
    SAFE = 'safe'
    VULN_CONFIRMED = 'vuln_confirmed'
    VULN_LIKELY = 'vuln_likely'
    UNCERTAIN = 'uncertain'


@dataclass
class AcpeVerdict:
    """一次写入的分配容量溯源最终判定."""
    func_name: str
    write_addr: int
    write_func: str
    alloc_expr: CapExpr
    write_expr: CapExpr
    relation: str
    verdict: Verdict
    reasoning: str
    confidence: float = 0.5
    fp_probability: float = 0.5


# 关系 → 判定 映射表
_SAFE_RELATIONS = {'EQUIV', 'CONST_LE', 'ARITH_LE', 'GUARDED'}
_CONFIRMED_RELATIONS = {'CONST_GT', 'ARITH_GT'}
_SLACK_RELATIONS = {'ARITH_SLACK'}


def evaluate(alloc_expr: CapExpr, write_expr: CapExpr,
             write_unbounded: bool,
             guard_ev: Optional[GuardEvidence],
             insns=None,
             func_name: str = '',
             write_addr: int = 0,
             write_func: str = 'memcpy',
             write_offset: int = 0,
             offset_unknown: bool = False) -> AcpeVerdict:
    """对单次写入执行完整分配容量溯源判定.

    write_offset: 目标缓冲区内已知常量偏移 (memcpy(box+200, ...)=200)。
                  容量判定须以 size + offset ≤ usable 为准。
    offset_unknown: 偏移符号化 (box+msg_len) → 终点不可判, 不得放行。
    """
    eq = classify_pair(alloc_expr, write_expr, write_unbounded,
                       guard_ev, insns)

    # 反例守卫优先: 写出仅在 size > bound 时可达 → 更精确的 CONFIRMED
    if eq.relation == 'UNRELATED' and guard_ev is not None \
            and guard_ev.overflow_hint is not None:
        cu = alloc_expr.upper_bound()
        if cu is not None and guard_ev.overflow_hint >= usable_size(cu):
            return AcpeVerdict(
                func_name=func_name, write_addr=write_addr,
                write_func=write_func, alloc_expr=alloc_expr,
                write_expr=write_expr, relation='REVERSE_GUARD',
                verdict=Verdict.VULN_CONFIRMED,
                reasoning=(f'write reachable only when size > '
                           f'{guard_ev.overflow_hint} >= usable '
                           f'{usable_size(cu)}B'),
                confidence=0.9, fp_probability=0.05)
        return AcpeVerdict(
            func_name=func_name, write_addr=write_addr,
            write_func=write_func, alloc_expr=alloc_expr,
            write_expr=write_expr, relation='REVERSE_GUARD',
            verdict=Verdict.VULN_LIKELY,
            reasoning=(f'write reachable when size > '
                       f'{guard_ev.overflow_hint} (possible overflow)'),
            confidence=0.6, fp_probability=0.25)

    if eq.relation in _CONFIRMED_RELATIONS:
        return AcpeVerdict(
            func_name=func_name, write_addr=write_addr,
            write_func=write_func, alloc_expr=alloc_expr,
            write_expr=write_expr, relation=eq.relation,
            verdict=Verdict.VULN_CONFIRMED, reasoning=eq.reasoning,
            confidence=0.85, fp_probability=0.10)

    if eq.relation in _SLACK_RELATIONS:
        return AcpeVerdict(
            func_name=func_name, write_addr=write_addr,
            write_func=write_func, alloc_expr=alloc_expr,
            write_expr=write_expr, relation=eq.relation,
            verdict=Verdict.UNCERTAIN, reasoning=eq.reasoning,
            confidence=0.5, fp_probability=0.5)

    # 目标偏移并入容量: 安全类关系若带正偏移, 必须重判终点
    if offset_unknown:
        return AcpeVerdict(
            func_name=func_name, write_addr=write_addr,
            write_func=write_func, alloc_expr=alloc_expr,
            write_expr=write_expr, relation=eq.relation,
            verdict=Verdict.UNCERTAIN,
            reasoning=(f'{eq.reasoning}; dst offset symbolic — '
                       f'endpoint cannot be proven safe'),
            confidence=0.5, fp_probability=0.5)

    if write_offset > 0 and eq.relation in _SAFE_RELATIONS:
        cu = alloc_expr.upper_bound()
        wu = write_expr.upper_bound()
        if cu is not None and wu is not None:
            end = wu + write_offset
            if end <= usable_size(cu):
                return AcpeVerdict(
                    func_name=func_name, write_addr=write_addr,
                    write_func=write_func, alloc_expr=alloc_expr,
                    write_expr=write_expr, relation=eq.relation,
                    verdict=Verdict.SAFE,
                    reasoning=(f'{eq.reasoning}; size+offset {end}B '
                               f'<= usable {usable_size(cu)}B'),
                    confidence=0.9, fp_probability=0.90)
            return AcpeVerdict(
                func_name=func_name, write_addr=write_addr,
                write_func=write_func, alloc_expr=alloc_expr,
                write_expr=write_expr, relation='OFFSET_GT',
                verdict=Verdict.VULN_CONFIRMED,
                reasoning=(f'size+offset {end}B exceeds usable '
                           f'{usable_size(cu)}B (dst offset '
                           f'+{write_offset}B)'),
                confidence=0.85, fp_probability=0.10)
        # 容量或大小非常数 → 保守保留
        return AcpeVerdict(
            func_name=func_name, write_addr=write_addr,
            write_func=write_func, alloc_expr=alloc_expr,
            write_expr=write_expr, relation=eq.relation,
            verdict=Verdict.VULN_LIKELY,
            reasoning=(f'{eq.reasoning}; dst offset +{write_offset}B '
                       f'with non-constant capacity — keep'),
            confidence=0.55, fp_probability=0.30)

    if eq.relation in _SAFE_RELATIONS:
        return AcpeVerdict(
            func_name=func_name, write_addr=write_addr,
            write_func=write_func, alloc_expr=alloc_expr,
            write_expr=write_expr, relation=eq.relation,
            verdict=Verdict.SAFE, reasoning=eq.reasoning,
            confidence=0.9, fp_probability=0.90)

    # UNRELATED 兜底: 保守保留为 LIKELY, 不滤除
    return AcpeVerdict(
        func_name=func_name, write_addr=write_addr,
        write_func=write_func, alloc_expr=alloc_expr,
        write_expr=write_expr, relation=eq.relation,
        verdict=Verdict.VULN_LIKELY, reasoning=eq.reasoning,
        confidence=0.55, fp_probability=0.30)


def summarize(verdicts: List[AcpeVerdict]) -> dict:
    """判定汇总统计."""
    counts = {v: 0 for v in Verdict}
    for vd in verdicts:
        counts[vd.verdict] += 1
    total = len(verdicts)
    safe = counts[Verdict.SAFE]
    kept = total - safe
    return {
        'total': total,
        'safe_filtered': safe,
        'kept': kept,
        'confirmed': counts[Verdict.VULN_CONFIRMED],
        'likely': counts[Verdict.VULN_LIKELY],
        'uncertain': counts[Verdict.UNCERTAIN],
        'fp_reduction_pct': round(safe / total * 100, 1) if total else 0.0,
    }


# 自检
def _check():
    # EQUIV → SAFE
    v = evaluate(CapExpr.sym('A:1'), CapExpr.sym('A:1'), False, None)
    assert v.verdict == Verdict.SAFE, v
    # CONST_GT → CONFIRMED
    v2 = evaluate(CapExpr.const(64), CapExpr.const(128), False, None)
    assert v2.verdict == Verdict.VULN_CONFIRMED, v2
    # UNRELATED → LIKELY (保留)
    v3 = evaluate(CapExpr.sym('A:1'), CapExpr.sym('A:2'), False, None)
    assert v3.verdict == Verdict.VULN_LIKELY, v3
    s = summarize([v, v2, v3])
    assert s['safe_filtered'] == 1 and s['kept'] == 2, s
    print('[OK] verdict passed')


if __name__ == '__main__':
    _check()
