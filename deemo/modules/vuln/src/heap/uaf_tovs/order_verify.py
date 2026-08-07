"""时序验证 — use 是否在 free 的后支配路径上.

创建: 2026-06-27
设计决策:
  - 时序成立的充分条件: use 可达 且 所有通往 use 的路径必经 free
    (free 后支配 use). 线性地址序是必要不充分条件, 分支互斥与提前
    返回会使地址序误判.
  - 判定规则:
    POST_DOMINANCE: free ∈ dom(use) 且 use 经 free 的 fallthrough 可达
      → 时序成立 (CONFIRMED 候选).
    EXCLUSIVE_BRANCH: use 可达, 但存在不经过 free 的路径
      (free 不在 dom(use)) → 时序不成立 (SAFE).
    EARLY_RETURN: 不经过 free 的路径以 ret/jmp-out 终止 → 同样 SAFE.
  - 复用 pcfv.cfg.IntraCFG: 支配者集合 + 前向可达性均已实现.
"""
from typing import List, Optional, Tuple

from .types import Evidence, TovsRule, FreeUsePair


class OrderVerifier:
    """分支敏感时序验证器."""

    def __init__(self, insns: list):
        from pcfv.cfg import IntraCFG
        self._insns = insns
        self._cfg = IntraCFG(insns)
        self._addr_set = {i.addr for i in insns}

    def verify(self, pair: FreeUsePair) -> Tuple[Optional[bool], List[Evidence]]:
        """返回 (时序是否成立, 证据). None=无法判定."""
        evs: List[Evidence] = []
        free_a = pair.free_addr
        use_a = pair.use_addr
        if free_a not in self._addr_set or use_a not in self._addr_set:
            return None, evs
        if use_a == free_a:
            return None, evs

        # use 是否可达 (函数入口可达性由 cfg 隐式保证)
        if not self._cfg.reachable(self._cfg._entry, use_a):
            return None, evs

        doms = self._cfg.dominators(use_a)
        if free_a in doms:
            evs.append(Evidence(
                rule=TovsRule.POST_DOMINANCE,
                detail='free %#x post-dominates use %#x' % (free_a, use_a),
                confidence=0.92,
                extra={'free': free_a, 'use': use_a}))
            return True, evs

        # free 不支配 use: 检查 use 是否经 free 可达 (存在经过 free 的路径)
        via_free = self._cfg.reachable(free_a, use_a)
        if not via_free:
            evs.append(Evidence(
                rule=TovsRule.EXCLUSIVE_BRANCH,
                detail='use %#x unreachable from free %#x (exclusive '
                       'branches or use-before-free)' % (use_a, free_a),
                confidence=0.85,
                extra={'free': free_a, 'use': use_a}))
            return False, evs

        # use 经 free 可达但不被支配 → 条件释放后的部分路径 UAF:
        # free 路径上成立, 绕过路径上安全 → 不能过滤, 保守保留
        evs.append(Evidence(
            rule=TovsRule.UNRESOLVED,
            detail='use %#x reachable via free %#x but not dominated: '
                   'partial-path UAF, conservative keep' % (use_a, free_a),
            confidence=0.6,
            extra={'free': free_a, 'use': use_a}))
        return None, evs
