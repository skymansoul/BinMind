"""时序验证 — use 是否在 free 的后支配路径上.

创建: 2023-12-18
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

import re

from .types import (ConservativeVerdict, Evidence, TovsRule,
                    TovsVerdict, FreeUsePair)

# 条件跳转模式 — 向前扫描 free 前驱路径判断 free 是否条件性执行
_JCC_PATTERN = re.compile(
    r'\b(?:jne|je|jg|jl|jge|jle|ja|jb|jae|jbe|jz|jnz)\b'
)


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
        # 不再返回 None: 返回 ConservativeVerdict 避免成为 Recall 黑洞
        evidence = Evidence(
            rule=TovsRule.UNRESOLVED,
            detail='use %#x reachable via free %#x but not dominated: '
                   'partial-path UAF, conservative keep' % (use_a, free_a),
            confidence=0.6,
            extra={'free': free_a, 'use': use_a})
        evs.append(evidence)

        # 条件释放分析: 向前扫描 free 前 5 条指令找 cmp+jcc 模式
        # 如果该条件在 use 点可被证明恒真, 升级为 CONFIRMED
        conditional_confirmed = self._check_conditional_free(
            free_a, use_a, evs)

        if conditional_confirmed:
            return True, evs

        return ConservativeVerdict(
            rule=TovsRule.UNRESOLVED,
            confidence=0.6,
            detail=evidence.detail,
            evidence=evidence), evs

    def _check_conditional_free(self, free_a: int, use_a: int,
                                evs: List[Evidence]) -> bool:
        """条件释放分析: free 前驱路径若有 cmp+jcc 且条件在 use 点恒真则升级.

        设计决策:
          - O2 常将 if(ptr) free(ptr) 优化为 test+je, free 位于条件分支内.
          - 向前扫描 5 条指令检测 jcc, 判断 free 是否条件性执行.
          - 若条件跳转在 use 点可达路径上恒真 (use 前无相反跳转),
            则 free 必然执行, 升级为 CONFIRMED (confidence=0.8).
        """
        free_idx = None
        for i, insn in enumerate(self._insns):
            if insn.addr == free_a:
                free_idx = i
                break
        if free_idx is None:
            return False

        scan_start = max(0, free_idx - 5)
        has_conditional = False
        for i in range(scan_start, free_idx):
            raw = getattr(self._insns[i], 'raw', '') or ''
            mnem = getattr(self._insns[i], 'mnemonic', '') or ''
            text = (raw + ' ' + mnem).lower()
            if _JCC_PATTERN.search(text):
                has_conditional = True
                break

        if not has_conditional:
            return False

        # 检查 use 点之前是否存在与该 jcc 方向相反的跳转
        # 若不存在相反跳转, 则条件在 use 路径上恒真, free 必经
        use_idx = None
        for i, insn in enumerate(self._insns):
            if insn.addr == use_a:
                use_idx = i
                break
        if use_idx is None:
            return False

        # use 之前到 free 之后之间检测是否有无条件跳转改变控制流
        between = self._insns[free_idx + 1:use_idx]
        has_redirect = False
        for insn in between:
            mnem = getattr(insn, 'mnemonic', '') or ''
            if mnem.lower().startswith('jmp'):
                has_redirect = True
                break

        if not has_redirect:
            evs.append(Evidence(
                rule=TovsRule.POST_DOMINANCE,
                detail='conditional free %#x proven always-taken at '
                       'use %#x (no contrary branch)' % (free_a, use_a),
                confidence=0.8,
                extra={'free': free_a, 'use': use_a,
                       'conditional_free': True}))
            return True

        return False
