"""
路径条件对象生命周期管线集成 — 将路径条件感知过滤接入 UAF 对象身份图 UAF检测管线.

集成位置: UAF 对象身份图 verify_single之后, 对CONFIRMED判定执行路径条件对象生命周期过滤.
集成策略:
  1. 构建器.build → 获取CONFIRMED verdicts
  2. 路径条件对象生命周期提取free-use路径条件 → 过滤互斥路径上的误报
  3. 返回过滤后的verdicts

路径条件对象生命周期是 UAF 对象身份图的正交补充:
  UAF 对象身份图回答: "被释放的对象是否在后续被使用?" (对象身份)
  路径条件对象生命周期回答: "free和use是否在同一执行路径上可达?" (路径可达性)
"""
from typing import Any, Dict, List, Optional, Tuple

from analysis.uaf_obj_graph_types import UafHoigVerdict
from analysis.uaf_path_lifecycle_verifier import filter_uaf_by_pcol


def verify_with_pcol(
    pseudocode: str,
    func_name: str = "",
) -> UafHoigVerdict:
    """UAF 对象身份图 + 路径条件对象生命周期联合UAF验证.

    先用 UAF 对象身份图判定, 再用路径条件对象生命周期过滤路径不可达的UAF.
    """
    from analysis.uaf_obj_graph_builder import HoigBuilder

    builder = HoigBuilder()
    _, _, verdicts = builder.build(pseudocode, func_name)

    confirmed = [v for v in verdicts if v.verdict == 'CONFIRMED']
    if not confirmed:
        from analysis.uaf_obj_graph_verifier import HoigVerifier
        return UafHoigVerdict(
            verdict='SAFE', confidence=0.80,
            reason='No UAF detected by UAF 对象身份图',
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
        reason='路径条件对象生命周期 filtered all CONFIRMED but no SAFE verdict',
    )


def batch_verify_with_pcol(
    samples: Dict[str, str],
) -> List[Dict[str, Any]]:
    """批量 UAF 对象身份图 + 路径条件对象生命周期验证."""
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
