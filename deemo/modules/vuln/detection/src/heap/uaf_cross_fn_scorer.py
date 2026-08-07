"""跨函数UAF评分增强器 — 过程间指针逃逸 + 堆块重用概率.

创建: 2026-07-30 15:31
用途: 扩展 uaf_candidate_scorer.py 的函数内三因素评分到跨函数场景,
      使用 PointerAliasTracker 的别名分析结果做过程间指针追踪。

设计决策:
  - 不替代 uaf_candidate_scorer.py: 保留其三因素 (指针逃逸/生命期间距/重分配),
    本模块在它之上增加跨函数维度的评估, 融合为综合评分。
  - 启发式跨函数连接: 不构建完整调用图, 而是通过函数参数传递和返回值做启发式连接。
    在 strip 二进制中, 调用的目标函数名可能不可用, 此时保守假设所有 call 指令
    都可能产生指针逃逸。
"""

import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from .pointer_alias_tracker import PointerAliasTracker, AliasResult


@dataclass
class UAFCrossFnResult:
    """跨函数 UAF 综合评分结果."""
    function_name: str
    ptr_name: str
    intra_fn_score: float       # 函数内评分 (来自 uaf_candidate_scorer)
    cross_fn_score: float       # 跨函数评分 (本模块)
    combined_score: float       # 综合评分 (0.6*cross + 0.4*intra)
    alias_count: int            # 别名数量
    escaped: bool               # 是否逃逸到全局/返回值
    uaf_evidence: List[str]     # UAF 证据描述


class CrossFunctionUAFScorer:
    """跨函数 UAF 评分增强器.

    处理三种跨函数 UAF 模式:
      1. 函数 A 中 malloc(p) → 传递给函数 B → B 中 free(p) → A 中继续使用 p
      2. malloc 的指针存储到全局变量 → 多个函数通过全局变量使用 → 某处 free
      3. 指针作为返回值返回 → 调用方 free → 被调用方仍持有副本

    使用方式:
      scorer = CrossFunctionUAFScorer()
      scorer.set_intra_fn_score('fn_A', 'p_rax', 0.65)
      tracker = PointerAliasTracker()
      # ... 填充 tracker ...
      scorer.set_alias_tracker(tracker)
      results = scorer.analyze_all()
    """

    def __init__(self):
        # 函数内评分: (fn_name, ptr_name) → score
        self._intra_scores: Dict[Tuple[str, str], float] = {}
        # 指针别名追踪器
        self._alias_tracker: Optional[PointerAliasTracker] = None
        # 函数间参数传递记录
        self._param_passing: List[Tuple[str, str, str]] = []
        # (caller_fn, callee_fn, ptr_name)

    def set_intra_fn_score(self, func_name: str, ptr_name: str,
                           score: float) -> None:
        """设置函数内评分 (来自 uaf_candidate_scorer)."""
        self._intra_scores[(func_name, ptr_name)] = max(0.0, min(1.0, score))

    def set_alias_tracker(self, tracker: PointerAliasTracker) -> None:
        self._alias_tracker = tracker

    def record_param_passing(self, caller: str, callee: str,
                              ptr_name: str) -> None:
        """记录函数间参数传递."""
        self._param_passing.append((caller, callee, ptr_name))

    # //// 分析 ////
    def analyze_all(self) -> List[UAFCrossFnResult]:
        """分析所有已注册的指针."""
        results = []
        if self._alias_tracker is None:
            return results

        for (fn_name, ptr_name), intra_score in self._intra_scores.items():
            alias_result = self._alias_tracker.analyze(ptr_name)

            # 跨函数评分
            cross_score = self._compute_cross_fn_score(
                fn_name, ptr_name, alias_result)

            # 综合: 跨函数权重 0.6 (新信息), 函数内权重 0.4 (已有)
            combined = 0.6 * cross_score + 0.4 * intra_score

            # 收集证据
            evidence = []
            if alias_result.escaped_to:
                evidence.append(
                    f'escaped to: {", ".join(alias_result.escaped_to)}')
            if alias_result.used_after_free:
                evidence.append(
                    f'used after free at: {alias_result.used_after_free}')
            if len(alias_result.aliases) > 3:
                evidence.append(
                    f'high alias count: {len(alias_result.aliases)}')

            results.append(UAFCrossFnResult(
                function_name=fn_name, ptr_name=ptr_name,
                intra_fn_score=intra_score, cross_fn_score=cross_score,
                combined_score=combined, alias_count=len(alias_result.aliases),
                escaped=len(alias_result.escaped_to) > 0,
                uaf_evidence=evidence))

        results.sort(key=lambda r: r.combined_score, reverse=True)
        return results

    def _compute_cross_fn_score(self, fn_name: str, ptr_name: str,
                                 alias: AliasResult) -> float:
        """计算跨函数 UAF 风险评分."""
        score = 0.0

        # 因素1: 别名复杂度 (越多别名→越难追踪→越高UAF风险)
        if alias.aliases:
            score += 0.20 * min(1.0, (len(alias.aliases) - 1) * 0.25)

        # 因素2: 指针逃逸 (全局变量/返回值)
        if alias.escaped_to:
            score += 0.35 * min(1.0, len(alias.escaped_to) * 0.5)

        # 因素3: 直接 UAF 证据
        if alias.used_after_free:
            score += 0.30 * min(1.0, len(alias.used_after_free) * 0.2)

        # 因素4: 跨函数传递
        cross_fn_count = sum(
            1 for c, _, p in self._param_passing
            if p == ptr_name and c != fn_name)
        score += 0.15 * min(1.0, cross_fn_count * 0.25)

        return min(1.0, score)

    def stats(self) -> dict:
        results = self.analyze_all()
        high_risk = sum(1 for r in results if r.combined_score > 0.6)
        return {
            'n_pointers_analyzed': len(results),
            'n_high_risk': high_risk,
            'mean_combined_score': (
                sum(r.combined_score for r in results) / max(1, len(results))
                if results else 0),
            'mean_alias_count': (
                sum(r.alias_count for r in results) / max(1, len(results))
                if results else 0),
        }

    def clear(self) -> None:
        self._intra_scores.clear()
        self._alias_tracker = None
        self._param_passing.clear()
