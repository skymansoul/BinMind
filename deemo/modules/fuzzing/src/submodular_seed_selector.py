"""次模种子选择器 — 贪心 (1-1/e) 近似保证 + lazy greedy + 随机贪心 + 多目标鲁棒. 参考: Nemhauser et al. (1978), Minoux (1978), Mirzasoleiman et al. (2015). 次模优化在 fuzzing 种子选择中无先例. 覆盖并集函数是单调次模的, 贪心算法提供可证明的最优性下界."""

import heapq
import math
import random
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Set, Tuple


# ---- S4G 参数 ----
_DEFAULT_QUEUE_SIZE = 200     # 种子队列最大大小 k
_RANDOM_GREEDY_M = 50         # 随机贪心每轮的候选数


@dataclass
class SeedCandidate:
    """候选种子及其次模选择元数据."""
    seed_id: str
    coverage: FrozenSet[int]
    marginal_gain: float = 0.0          # 最近一次计算的边际收益
    marginal_gain_ub: float = float('inf')  # lazy greedy 上界
    selected: bool = False


class SubmodularSeedSelector:
    """次模种子选择器 — 贪心最大化覆盖率并集.

    形式化: max_{S⊆V, |S|≤k} f(S) = |∪_{s∈S} coverage(s)|

    贪心算法:
      初始化 S = ∅, covered = ∅
      重复 k 次:
        s* = argmax_{s not in S} |coverage(s) - covered|
        S ← S ∪ {s*}, covered ← covered ∪ coverage(s*)
      返回 S

    近似保证: f(S_greedy) ≥ (1 - 1/e) · OPT

    使用方式:
      sss = SubmodularSeedSelector(queue_size=200)
      for seed in candidates:
          sss.add_candidate(seed.id, seed.coverage)
      selected = sss.select_greedy()
    """

    def __init__(self, queue_size: int = _DEFAULT_QUEUE_SIZE):
        self.queue_size = queue_size
        self._candidates: Dict[str, SeedCandidate] = {}
        self._selected: List[str] = []
        self._covered_union: Set[int] = set()
        self._total_coverage: int = 0
        self._dirty: bool = True

    # //// 候选管理 ////
    def add_candidate(self, seed_id: str, coverage: Set[int]) -> None:
        fp = frozenset(coverage)
        existing = self._candidates.get(seed_id)
        if existing is not None and existing.coverage == fp:
            return
        self._candidates[seed_id] = SeedCandidate(
            seed_id=seed_id, coverage=fp,
            marginal_gain_ub=float(len(fp)))
        self._dirty = True

    def remove_candidate(self, seed_id: str) -> bool:
        if seed_id in self._candidates:
            del self._candidates[seed_id]
            self._dirty = True
            return True
        return False

    # //// 贪心选择 (精确) ////
    def select_greedy(self) -> List[str]:
        """标准贪心: O(kn) 次覆盖计算.

        每轮对所有未选候选重新计算边际收益。
        对于 n ≤ 500 的种子池, 这是可接受的。
        """
        n = len(self._candidates)
        k = min(self.queue_size, n)
        if k == 0:
            return []

        selected = []
        covered = set()
        # 重置状态
        for c in self._candidates.values():
            c.selected = False

        for _ in range(k):
            best_id = None
            best_gain = -1
            for sid, cand in self._candidates.items():
                if cand.selected:
                    continue
                gain = len(cand.coverage - covered)
                cand.marginal_gain = gain
                if gain > best_gain:
                    best_gain = gain
                    best_id = sid
            if best_id is None or best_gain == 0:
                break
            self._candidates[best_id].selected = True
            covered.update(self._candidates[best_id].coverage)
            selected.append(best_id)

        self._selected = selected
        self._covered_union = covered
        self._total_coverage = len(covered)
        self._dirty = False
        return selected

    # //// Lazy Greedy ////
    def select_lazy_greedy(self) -> List[str]:
        """Lazy greedy: O(kn log n) 摊销.

        利用边际收益的递减性: 若候选 s 的当前上界小于已评估的
        最佳候选, 则无需重新计算 s 的边际收益 (因为上界只会下降)。
        """
        n = len(self._candidates)
        k = min(self.queue_size, n)
        if k == 0:
            return []

        for c in self._candidates.values():
            c.selected = False
            c.marginal_gain_ub = float(len(c.coverage))

        selected = []
        covered = set()

        for _ in range(k):
            # 按上界降序排列候选
            heap = [(-c.marginal_gain_ub, i, sid)
                    for i, (sid, c) in enumerate(self._candidates.items())
                    if not c.selected]
            heapq.heapify(heap)
            found = False

            while heap:
                neg_ub, _, sid = heapq.heappop(heap)
                cand = self._candidates[sid]
                gain = len(cand.coverage - covered)
                cand.marginal_gain = gain
                cand.marginal_gain_ub = gain
                # 若这是堆中最好的, 或 gain == ub (精确上界也最优)
                if not heap or gain >= -heap[0][0]:
                    if gain > 0:
                        cand.selected = True
                        covered.update(cand.coverage)
                        selected.append(sid)
                    found = True
                    break
                else:
                    # 重新入堆 (上界已降低但仍可能最优)
                    heapq.heappush(heap, (-gain, _, sid))

            if not found:
                break

        self._selected = selected
        self._covered_union = covered
        self._total_coverage = len(covered)
        self._dirty = False
        return selected

    # //// 随机贪心 ////
    def select_stochastic_greedy(self, m: int = _RANDOM_GREEDY_M
                                  ) -> List[str]:
        """随机贪心: O(k·m).

        每轮随机采样 m 个未选候选, 仅从中选最佳。
        高概率保证 (1-1/e-ε) 近似, 其中 ε ≈ O(1/√m)。
        """
        n = len(self._candidates)
        k = min(self.queue_size, n)
        if k == 0:
            return []

        for c in self._candidates.values():
            c.selected = False

        selected = []
        covered = set()
        rng = random.Random(42)
        all_ids = list(self._candidates.keys())

        for _ in range(k):
            # 获取未选候选
            unselected = [sid for sid in all_ids
                         if not self._candidates[sid].selected]
            if not unselected:
                break
            # 随机采样 m 个
            sample = rng.sample(unselected, min(m, len(unselected)))
            # 从采样中选择最佳
            best_id = None
            best_gain = -1
            for sid in sample:
                gain = len(self._candidates[sid].coverage - covered)
                if gain > best_gain:
                    best_gain = gain
                    best_id = sid
            if best_id is None or best_gain == 0:
                break
            self._candidates[best_id].selected = True
            covered.update(self._candidates[best_id].coverage)
            selected.append(best_id)

        self._selected = selected
        self._covered_union = covered
        self._total_coverage = len(covered)
        self._dirty = False
        return selected

    # //// 多目标鲁棒次模 ////
    def select_robust(self, diversity_weight: float = 0.3
                       ) -> List[str]:
        """多目标鲁棒: max min(f_cover, f_diversity).

        f_cover = |∪ coverage|
        f_diversity = Σ (1 - max_jaccard_with_selected)
        取两者的 min → 最大化被短板约束的目标。
        """
        n = len(self._candidates)
        k = min(self.queue_size, n)
        if k == 0:
            return []

        for c in self._candidates.values():
            c.selected = False

        selected = []
        covered = set()

        for _ in range(k):
            best_id = None
            best_worst = -1.0
            for sid, cand in self._candidates.items():
                if cand.selected:
                    continue
                # 覆盖增益 (归一化)
                cov_gain = len(cand.coverage - covered)
                cov_norm = cov_gain / max(1, len(cand.coverage))
                # 多样性增益: 1 - max_jaccard_with_existing
                max_jac = 0.0
                for sel_id in selected:
                    sel_cov = self._candidates[sel_id].coverage
                    inter = len(cand.coverage & sel_cov)
                    union = len(cand.coverage | sel_cov)
                    jac = inter / union if union > 0 else 0.0
                    if jac > max_jac:
                        max_jac = jac
                div_gain = 1.0 - max_jac
                # 综合评分
                combined = min(cov_norm, div_gain) + (
                    diversity_weight * div_gain + (1 - diversity_weight) * cov_norm)
                if combined > best_worst:
                    best_worst = combined
                    best_id = sid
            if best_id is None:
                break
            self._candidates[best_id].selected = True
            covered.update(self._candidates[best_id].coverage)
            selected.append(best_id)

        self._selected = selected
        self._covered_union = covered
        self._total_coverage = len(covered)
        self._dirty = False
        return selected

    # //// 查询 ////
    def approximation_ratio_lower_bound(self) -> float:
        """贪心选择的 (1-1/e) 下界."""
        return 1.0 - 1.0 / math.e

    def marginal_gains(self) -> Dict[str, float]:
        """返回所有已选种子的边际收益."""
        return {sid: self._candidates[sid].marginal_gain
                for sid in self._selected}

    # //// 统计 ////
    def stats(self) -> dict:
        n_candidates = len(self._candidates)
        n_selected = len(self._selected)
        avg_cov = (sum(len(c.coverage) for c in self._candidates.values())
                   / max(1, n_candidates))
        return {
            "candidates": n_candidates,
            "selected": n_selected,
            "total_coverage_achieved": self._total_coverage,
            "avg_coverage_per_seed": round(avg_cov, 1),
            "approximation_guarantee": round(
                self.approximation_ratio_lower_bound(), 4),
            "queue_size_limit": self.queue_size,
            "redundancy_ratio": round(
                1.0 - self._total_coverage / max(1, int(avg_cov * n_selected)), 4),
        }

    def clear(self) -> None:
        self._candidates.clear(); self._selected.clear()
        self._covered_union.clear()
        self._total_coverage = 0; self._dirty = True
