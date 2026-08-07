"""
PCOL管线集成 — 将路径条件感知过滤接入HOIG UAF检测管线.

集成位置: HOIG verify_single之后, 对CONFIRMED判定执行PCOL过滤.
集成策略:
  1. HoigBuilder.build → 获取CONFIRMED verdicts
  2. PCOL提取free-use路径条件 → 过滤互斥路径上的误报
  3. 返回过滤后的verdicts

PCOL是HOIG的正交补充:
  HOIG回答: "被释放的对象是否在后续被使用?" (对象身份)
  PCOL回答: "free和use是否在同一执行路径上可达?" (路径可达性)
"""
from typing import Any, Dict, List, Optional, Tuple

from analysis.uaf_hoig_types import UafHoigVerdict
from analysis.uaf_pcol_verifier import filter_uaf_by_pcol


def verify_with_pcol(
    pseudocode: str,
    func_name: str = "",
) -> UafHoigVerdict:
    """HOIG + PCOL联合UAF验证.

    先用HOIG判定, 再用PCOL过滤路径不可达的UAF.
    """
    from analysis.uaf_hoig_builder import HoigBuilder

    builder = HoigBuilder()
    _, _, verdicts = builder.build(pseudocode, func_name)

    confirmed = [v for v in verdicts if v.verdict == 'CONFIRMED']
    if not confirmed:
        from analysis.uaf_hoig_verifier import HoigVerifier
        return UafHoigVerdict(
            verdict='SAFE', confidence=0.80,
            reason='No UAF detected by HOIG',
        )

    filtered, stats = filter_uaf_by_pcol(pseudocode, confirmed)

    still_confirmed = [
        v for v in filtered if v.verdict == 'CONFIRMED']
    if still_confirmed:
        return max(still_confirmed, key=lambda v: v.confidence)

    safe_verdicts = [v for v in filtered if v.verdict == 'SAFE']
    if safe_verdicts:
        return max(safe_verdicts, key=lambda v: v.confidence)

    return UafHoigVerdict(
        verdict='UNCERTAIN', confidence=0.50,
        reason='PCOL filtered all CONFIRMED but no SAFE verdict',
    )


def batch_verify_with_pcol(
    samples: Dict[str, str],
) -> List[Dict[str, Any]]:
    """批量HOIG+PCOL验证."""
    results = []
    for name, code in samples.items():
        v = verify_with_pcol(code, name)
        results.append({
            'sample': name,
            'verdict': v.verdict,
            'confidence': v.confidence,
            'reason': v.reason,
        })
    return results


__all__ = ['verify_with_pcol', 'batch_verify_with_pcol']
