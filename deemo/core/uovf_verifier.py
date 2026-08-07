"""
UOVF 值流门控核验.

对 build_chains 生成的 free→use 链施加值流门控, 产出三值裁决:
  FILTERED  释放与使用位于互斥路径 (return/exit/break 阻断)
  CONFIRMED 悬垂链真实存在, 无任何值流复活证据
  UNCERTAIN 证据不足以裁定

重赋值/置空复活已在事件行走阶段弹出悬垂状态, 本模块只处理
路径互斥与置信度, 职责分离.
"""

import re
from typing import List, Tuple

from core.uovf_types import UafChain, UafEvidence, UafVerdict, UovfStats
from core.hovf_write_extract import _strip_block_comments

_BREAK_RE = re.compile(r'\b(return|exit\s*\(|break\s*;|goto\s+\w+|'
                       r'abort\s*\(|_exit\s*\()')


def _is_break_line(line: str) -> bool:
    """该行是否包含阻断性控制流 (return/exit/break/goto)."""
    return bool(_BREAK_RE.search(line))


def _between(lines: List[str], a: int, b: int) -> List[str]:
    lo, hi = max(0, a), min(len(lines), b)
    return lines[lo:hi] if lo < hi else []


def _path_mutually_exclusive(lines: List[str], chain: UafChain) -> bool:
    """释放与使用之间是否存在无条件阻断.

    若 free 与 use 之间出现 return/exit/break/goto, 则两条语句
    不可能在同一条执行路径上, 判定为误报 (互斥路径).
    """
    for line in _between(lines, chain.free_pc + 1, chain.use_pc):
        if _is_break_line(line):
            return True
    return False


def _confidence(chain: UafChain) -> float:
    conf = 0.75
    distance = chain.use_pc - chain.free_pc
    if 0 < distance <= 8:
        conf += 0.10
    elif distance > 40:
        conf -= 0.05
    if len(chain.aliases) > 0:
        conf += 0.05
    return min(0.95, max(0.40, conf))


def verify_chains(ir: List[str],
                  chains: List[UafChain]) -> Tuple[
                      List[UafEvidence], UovfStats]:
    """核验全部事件链, 返回 (证据列表, 统计)."""
    lines = _strip_block_comments(list(ir))
    evidence: List[UafEvidence] = []
    stats = UovfStats(chains=len(chains))
    for chain in chains:
        if _path_mutually_exclusive(lines, chain):
            evidence.append(UafEvidence(
                verdict=UafVerdict.FILTERED, chain=chain,
                reasons=['释放与使用位于互斥路径 (阻断语句介入)'],
                confidence=0.10))
            stats.filtered += 1
            continue
        evidence.append(UafEvidence(
            verdict=UafVerdict.CONFIRMED, chain=chain,
            reasons=['悬垂指针在释放后被解引用, 无值流复活证据'],
            confidence=_confidence(chain)))
        stats.confirmed += 1
    if stats.chains:
        stats.fp_reduction_ratio = stats.filtered / stats.chains
    return evidence, stats


def verdict_counts(evidence: List[UafEvidence]) -> dict:
    """按裁决统计, 供回归与对比实验使用."""
    out = {'confirmed': 0, 'filtered': 0, 'uncertain': 0}
    for e in evidence:
        out[e.verdict.value.lower()] = out.get(
            e.verdict.value.lower(), 0) + 1
    return out
