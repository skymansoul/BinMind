"""语义级误报过滤器 — 替代 regex 模式匹配的算法级 FP 削减.

不依赖模式库做表面文本匹配, 而是利用程序语义特征
(值流约束、控制流守卫、调用上下文) 做多维评分, 对每个 heap overflow
finding 给出结构化置信度.

与 false_positive_filter.py 的关系:
  false_positive_filter: regex 先验 → 0~1 连续分值 → 阈值截断
  本模块: 语义特征 + 值流约束 → 结构化评分 → 排序/过滤

两者级联: regex 粗筛 (高效) → 语义精筛 (精确)

设计参考:
  - MECA: multi-dimensional evidence combination for static
    analysis warnings — 但 MECA 面向通用警告, 本模块特化于堆语义
  - CRYPTOSS: 污点+守卫条件的联合评分 — 借鉴其控制流敏感理念
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from collections import Counter

from .malloc_size_inferrer import MallocSite, SInterval, AllocatorModel


# 语义特征定义

@dataclass
class SemanticFeatures:
    """一次堆访问的语义特征向量."""
    # 值流特征
    alloc_size_exact: bool = False       # malloc 参数是否精确已知
    alloc_size_min: int = 0
    alloc_size_max: int = 0xFFFFFFFF
    size_is_known: bool = False          # size 是否非 TOP (影响特征可信度)
    # 对齐特征
    offset_aligned: bool = False
    size_aligned: bool = False
    within_alignment_padding: bool = False  # 溢出量 <= 对齐填充量
    # 控制流特征
    guarded_by_bounds_check: bool = False  # 访问前有边界检查
    has_size_guard: bool = False           # malloc 前有 size→常量 cmp+jcc (约束证据)
    in_loop_body: bool = False
    in_error_cleanup: bool = False
    # 偏移特征 (size未知时的主要判别信号)
    offset_is_small_const: bool = False    # 偏移是 ≤256 的小常量 → 正常堆访问
    offset_is_large: bool = False          # 偏移 >2048 → 高概率溢出
    # 调用上下文
    caller_is_trusted: bool = False
    alloc_site_in_same_fn: bool = True
    # 操作特征
    is_write: bool = True
    is_memcpy_like: bool = False
    multi_byte_access: bool = False
    # 计数器
    n_features_valid: int = 0


class SemanticFalsePositiveFilter:
    """基于语义特征的堆溢出误报过滤器.

    评分公式: score = Σ(w_i * f_i) / Σ(w_i)
    其中 f_i 是归一化特征值, w_i 是特征权重.

    关键决策:
      - within_alignment_padding 权重最高 (0.30): 对齐填充内写入是最大的 FP 来源
      - guarded_by_bounds_check 权重次高 (0.25): 显式守卫通常说明安全
      - 值流置信度权重 0.20: 精确知道 alloc 大小增加检出可信度
    """

    # 特征权重 — 分两种情况:
    #   size_known:  值流特征可靠, 对齐判别精确
    #   size_unknown: 依赖控制流+偏移特征做粗糙判别
    _WEIGHTS_KNOWN = {
        'within_alignment_padding': -0.30,
        'guarded_by_bounds_check': -0.25,
        'has_size_guard': -0.20,
        'in_error_cleanup': -0.15,
        'caller_is_trusted': -0.10,
        'alloc_size_exact': +0.20,
        'in_loop_body': +0.15,
        'offset_aligned': +0.10,
        'is_write': +0.10,
        'offset_is_large': +0.10,
        'is_memcpy_like': +0.05,
        'alloc_site_in_same_fn': +0.00,
        'size_aligned': +0.05,
        'multi_byte_access': +0.05,
    }
    _WEIGHTS_UNKNOWN = {
        # size未知: 对齐特征不可靠 → 降权/禁用
        'within_alignment_padding': -0.00,   # 无法判断 → 禁用
        'alloc_size_exact': +0.00,            # 恒为 False → 禁用
        'offset_aligned': +0.00,              # 无 size 时无意义
        'size_aligned': +0.00,                # 同上
        # 控制流特征 → 升权 (它们是唯一的强信号)
        'guarded_by_bounds_check': -0.35,
        'has_size_guard': -0.25,
        'in_error_cleanup': -0.20,
        'caller_is_trusted': -0.15,
        # 偏移特征 → 升权 (替代对齐判别)
        'offset_is_large': +0.20,             # 大偏移=高风险
        'offset_is_small_const': +0.10,       # 小偏移=正常缓冲区内访问
        'in_loop_body': +0.15,
        'is_write': +0.10,
        'is_memcpy_like': +0.10,
        'alloc_site_in_same_fn': +0.00,
        'multi_byte_access': +0.05,
    }

    def __init__(self, fp_threshold: float = 0.35):
        """threshold: 低于此分的 finding 标记为 likely_false_positive."""
        self._threshold = fp_threshold
        self._stats: Dict[str, int] = Counter()
        self._all_scores: List[float] = []

    def extract_features(self,
                         alloc_site: MallocSite,
                         offset: int,
                         access_size: int,
                         ctx: dict) -> SemanticFeatures:
        """从 malloc site 和访问上下文提取语义特征.

        size已知 vs 未知的判别差异:
        - size已知: 精确计算 within_alignment_padding + overflow
        - size未知: 依赖控制流特征 (bounds check, size guard)
          和偏移启发式 (offset_is_small_const, offset_is_large)
        """
        f = SemanticFeatures()
        f.is_write = ctx.get('is_write', True)
        n = 0

        # 1. 值流特征 + 偏移启发式
        if alloc_site.size_interval.is_top:
            f.alloc_size_exact = False
            f.alloc_size_min = 0
            f.alloc_size_max = 0xFFFFFFFF
            f.size_is_known = False
            # size未知: 用偏移值做启发式判别
            # 小常量偏移 (<256) → 通常是正常的结构体字段访问
            # 大偏移 → 高概率是缓冲区越界
            f.offset_is_small_const = (0 < offset <= 256)
            f.offset_is_large = (offset > 2048)
        else:
            f.alloc_size_exact = (alloc_site.size_interval.lo == alloc_site.size_interval.hi)
            f.alloc_size_min = alloc_site.size_interval.min_possible()
            f.alloc_size_max = alloc_site.size_interval.max_possible()
            f.size_is_known = True
            f.offset_is_small_const = False
            f.offset_is_large = False
        n += 1

        # 2. 对齐特征 (仅在 size 已知时有意义)
        alignment = ctx.get('allocator_alignment', 16)
        f.offset_aligned = (offset % alignment == 0)
        f.size_aligned = (access_size % alignment == 0)
        if f.size_is_known and f.alloc_size_min > 0:
            overflow = (offset + access_size) - f.alloc_size_min
            f.within_alignment_padding = (0 < overflow <= alignment)
        else:
            f.within_alignment_padding = False
        n += 3

        # 3. 控制流特征
        f.in_loop_body = ctx.get('in_loop_body', False)
        f.in_error_cleanup = ctx.get('in_error_cleanup', False)
        f.guarded_by_bounds_check = ctx.get('guarded_by_bounds_check', False)
        f.has_size_guard = ctx.get('has_size_guard', False)
        n += 4

        # 4. 偏移特征 (size未知时的主要信号)
        # offset_is_small_const / offset_is_large 已在值流阶段设置
        # 此处不做二次覆盖

        # 5. 调用上下文
        f.caller_is_trusted = ctx.get('caller_is_trusted', False)
        f.alloc_site_in_same_fn = ctx.get('alloc_site_in_same_fn', True)
        n += 2

        # 6. 操作特征
        f.is_memcpy_like = ctx.get('is_memcpy_like', False)
        f.multi_byte_access = (access_size > 1)
        n += 2

        f.n_features_valid = n
        return f

    def score(self, features: SemanticFeatures) -> float:
        """计算语义评分 [0, 1] — 高分为真阳性.

        size已知时用 _WEIGHTS_KNOWN (对齐+溢出精确),
        size未知时用 _WEIGHTS_UNKNOWN (控制流+偏移启发式).
        """
        weights = (self._WEIGHTS_KNOWN if features.size_is_known
                   else self._WEIGHTS_UNKNOWN)

        total_w = 0.0
        score = 0.0

        def _add(key, val):
            nonlocal total_w, score
            w = weights.get(key, 0.0)
            total_w += abs(w)
            score += w * (1.0 if val else 0.0)

        _add('within_alignment_padding', features.within_alignment_padding)
        _add('guarded_by_bounds_check', features.guarded_by_bounds_check)
        _add('has_size_guard', features.has_size_guard)
        _add('in_error_cleanup', features.in_error_cleanup)
        _add('caller_is_trusted', features.caller_is_trusted)
        _add('alloc_size_exact', features.alloc_size_exact)
        _add('in_loop_body', features.in_loop_body)
        _add('offset_aligned', features.offset_aligned)
        _add('is_write', features.is_write)
        _add('offset_is_large', features.offset_is_large)
        _add('offset_is_small_const', features.offset_is_small_const)
        _add('is_memcpy_like', features.is_memcpy_like)
        _add('alloc_site_in_same_fn', features.alloc_site_in_same_fn)
        _add('size_aligned', features.size_aligned)
        _add('multi_byte_access', features.multi_byte_access)

        if total_w == 0:
            return 0.5
        # 归一化到 [0, 1]
        normalized = (score + total_w) / (2 * total_w)
        return max(0.0, min(1.0, normalized))

    def is_likely_fp(self, features: SemanticFeatures) -> bool:
        """基于语义特征判断是否为误报."""
        s = self.score(features)
        self._all_scores.append(s)
        verdict = s < self._threshold
        if verdict:
            self._stats['filtered_fp'] += 1
        else:
            self._stats['passed'] += 1
        self._stats['total'] += 1
        return verdict

    def rank_findings(self,
                      findings: List[Tuple[dict, SemanticFeatures]]
                      ) -> List[Tuple[dict, SemanticFeatures, float]]:
        """对 findings 按语义评分排序 — 高分优先审查."""
        scored = [(f, feats, self.score(feats)) for f, feats in findings]
        scored.sort(key=lambda x: -x[2])
        return scored

    def _explain(self, feats: SemanticFeatures, score: float) -> str:
        reasons = []
        if feats.within_alignment_padding:
            reasons.append('align_pad')
        if feats.guarded_by_bounds_check:
            reasons.append('bounds_check')
        if feats.has_size_guard:
            reasons.append('size_guard')
        if feats.in_error_cleanup:
            reasons.append('cleanup')
        if feats.caller_is_trusted:
            reasons.append('trusted')
        if not feats.size_is_known:
            reasons.append('size_unknown')
        return '+'.join(reasons) if reasons else 'low_confidence'

    @property
    def fp_rate(self) -> float:
        d = max(1, self._stats.get('total', 1))
        return self._stats.get('filtered_fp', 0) / d

    @property
    def stats(self) -> dict:
        d = dict(self._stats)
        d['fp_rate'] = round(self.fp_rate, 3)
        if self._all_scores:
            d['mean_score'] = round(sum(self._all_scores) / len(self._all_scores), 3)
        return d

    def clear(self) -> None:
        self._stats.clear()
        self._all_scores.clear()
