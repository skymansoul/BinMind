# Shapley-Taylor交互指数
# 交互指数 — 多源CVE情报融合的合作博弈归因
#
# 问题: 现有DS融合 (cve_ds_fusion) 使用Dempster-Shafer理论组合多源证据,
# 但DS理论不回答"每个源贡献了多少"或"两个源之间是否存在协同效应".
# Shapley值 (2025年Waffo Kemgne et al.用于攻击图) 可分解边际贡献,
# 但标准Shapley假设特征独立性 — 在CVE情报源之间, 这一假设不成立:
#   NVD+KEV联合使用时的增益 > NVD单独+KEV单独的增益之和.
#   这是源间交互效应 (synergy/ redundancy).
#
# 解决方案: Shapley-Taylor交互指数.
# 将模型输出分解为:
#   f(x) = Σ_i φ_i + Σ_{i<j} φ_{ij} + Σ_{i<j<k} φ_{ijk} + ...
# 其中:
#   φ_i: 源i的主效应 (一阶Shapley值)
#   φ_{ij}: 源i和j的交互效应 (二阶). φ_{ij}>0 → 协同, φ_{ij}<0 → 冗余.
#   φ_{ijk}: 三阶交互 (实际中截断到二阶, 计算复杂度O(2^n)→O(n²)).
#
# 应用到CVE多源融合:
#   源集合 = {NVD, GHSA, OSV, ExploitDB, KEV, EPSS}.
#   效用函数 v(S) = 融合源集合S后的预测准确率.
#   φ_i = 源i的平均边际贡献.
#   φ_{ij} = 源i和j的交互 — 正=协同 (1+1>2), 负=冗余 (GHSA+OSV重叠).
#
# 交互指数的两个关键用途:
#   1. 源选择: 如果φ_{ij}强负 → 源i和j冗余, 可移除其一节省计算.
#   2. 权重校准: 将φ_i用作DS融合中源权重的贝叶斯先验,
#      替代cve_ds_fusion中的静态 _SOURCE_PRIOR_ACCURACY.
#
# 与现有模块的关系:
# cve_ds_fusion: DS理论融合 (证据组合).
# cve_info_theory: 信息论特征归因 (MI/SU/CMI).
# 本模块: 合作博弈归因 (Shapley+交互), 补充前两者.
#
# 设计说明:
#   1. 截断二阶交互 (O(2^n)→O(n²)), 使计算在6源时可行.
#   2. 交互符号解释: φ_{ij}>0 → 源互补 (协同增益),
#      φ_{ij}<0 → 源重叠 (冗余信息). 直接指导情报源采购决策.
#
#
# Shapley-Taylor Interaction Index (ICML)
# Shapley for Vulnerability Ranking (JDG)
# Beyond Shapley: Weber & Harsanyi Sets (IJCAI XAI)

import math
import itertools
from typing import Callable, Dict, List, Optional, Set, Tuple, Any


def _powerset(iterable, max_size: int = None):
    """生成幂集. max_size限制最大子集大小."""
    s = list(iterable)
    if max_size is None:
        max_size = len(s)
    return itertools.chain.from_iterable(
        itertools.combinations(s, r) for r in range(min(max_size, len(s)) + 1)
    )


def _shapley_weight(s: int, n: int) -> float:
    """Shapley权重: |S|!(n-|S|-1)!/n!."""
    return (math.factorial(s) * math.factorial(n - s - 1) /
            math.factorial(n))


def _interaction_weight(s: int, n: int, k: int) -> float:
    """Shapley-Taylor k阶交互权重.

    对于大小为|S|的子集 (不包含i,j), i和j的交互权重为:
      Σ_{t=0}^{k-1} (|S|+t)!(n-|S|-t-1)!/n! × (-1)^{k-1-t} / (t!(k-1-t)!)
    简化到二阶 (k=2):
      (|S|)! (n-|S|-2)!/n! × (n - 2|S| - 1)
    当n-2|S|-1 > 0时为正, 否则为负.
    """
    # 返回二阶交互的权重因子
    denom = math.factorial(n)
    num = math.factorial(s) * math.factorial(n - s - 2)
    weight = num / denom * (n - 2 * s - 1)
    return weight


class InteractionIndex:
    """Shapley-Taylor交互指数计算器.

    对效用函数v(S)计算一阶(Shapley值)和二阶(交互项).
    截断到二阶以控制计算复杂度.
    """

    def __init__(self, utility_fn: Callable[[Set[str]], float],
                 source_names: List[str]):
        """
        utility_fn: v(S) → float, 输入源子集, 返回效用 (如F1/准确率).
        source_names: 所有源的标识符列表.
        """
        self._v = utility_fn
        self._sources = list(source_names)
        self._n = len(self._sources)
        self._shapley_values: Dict[str, float] = {}
        self._interactions: Dict[Tuple[str, str], float] = {}
        self._computed = False

    def compute(self):
        """计算一阶和二阶指数."""
        if self._n < 2:
            return

        # 预计算所有子集的效用 (至多2^n个, n≤10时可行)
        n = self._n
        utility_cache: Dict[frozenset, float] = {}

        # 仅需大小≤n-1的子集 (全集的效用不用于边际计算)
        for r in range(n):
            for subset in itertools.combinations(self._sources, r):
                subset_set = frozenset(subset)
                utility_cache[subset_set] = self._v(set(subset))

        # 一阶Shapley值
        self._shapley_values.clear()
        for i, src_i in enumerate(self._sources):
            phi_i = 0.0
            for r in range(n):
                for subset in itertools.combinations(
                    [s for s in self._sources if s != src_i], r):
                    S = frozenset(subset)
                    v_with = utility_cache.get(frozenset(set(subset) | {src_i}),
                                                utility_cache.get(S, 0.0))
                    v_without = utility_cache.get(S, 0.0)
                    weight = _shapley_weight(r, n)
                    phi_i += weight * (v_with - v_without)
            self._shapley_values[src_i] = round(phi_i, 6)

        # 二阶交互 (Shapley-Taylor)
        self._interactions.clear()
        for i, src_i in enumerate(self._sources):
            for j, src_j in enumerate(self._sources):
                if j <= i:
                    continue
                phi_ij = 0.0
                for r in range(n - 1):  # 至多n-2个其他源
                    others = [s for s in self._sources if s not in (src_i, src_j)]
                    for subset in itertools.combinations(others, r):
                        S = frozenset(subset)
                        v_S = utility_cache.get(S, 0.0)
                        v_S_i = utility_cache.get(
                            frozenset(set(subset) | {src_i}), v_S)
                        v_S_j = utility_cache.get(
                            frozenset(set(subset) | {src_j}), v_S)
                        v_S_ij = utility_cache.get(
                            frozenset(set(subset) | {src_i, src_j}), v_S)
                        # 交互 = v(S∪{i,j}) - v(S∪{i}) - v(S∪{j}) + v(S)
                        interaction = v_S_ij - v_S_i - v_S_j + v_S
                        weight = _interaction_weight(r, n, 2)
                        phi_ij += weight * interaction
                self._interactions[(src_i, src_j)] = round(phi_ij, 6)

        self._computed = True

    def get_attribution(self) -> Dict[str, Dict[str, Any]]:
        """返回完整归因报告."""
        if not self._computed:
            return {}

        result = {}
        for src in self._sources:
            result[src] = {
                "shapley_value": self._shapley_values.get(src, 0.0),
                "interactions": {},
                "net_contribution": self._shapley_values.get(src, 0.0),
            }

        for (si, sj), phi_ij in self._interactions.items():
            result[si]["interactions"][sj] = phi_ij
            result[sj]["interactions"][si] = phi_ij
            # 交互值均分给双方
            result[si]["net_contribution"] += phi_ij * 0.5
            result[sj]["net_contribution"] += phi_ij * 0.5

        for src in self._sources:
            result[src]["net_contribution"] = round(
                result[src]["net_contribution"], 6)

        return result

    def find_synergies(self, threshold: float = 0.01) -> List[Dict]:
        """找出强协同源对."""
        synergies = []
        for (si, sj), phi in self._interactions.items():
            if phi > threshold:
                synergies.append({"sources": [si, sj],
                                  "interaction": round(phi, 4),
                                  "type": "synergy"})
        return sorted(synergies, key=lambda x: x["interaction"], reverse=True)

    def find_redundancies(self, threshold: float = -0.01) -> List[Dict]:
        """找出冗余源对."""
        reds = []
        for (si, sj), phi in self._interactions.items():
            if phi < threshold:
                reds.append({"sources": [si, sj],
                             "interaction": round(phi, 4),
                             "type": "redundancy"})
        return sorted(reds, key=lambda x: x["interaction"])

    def recommend_optimal_subset(self, budget: int = 3) -> List[str]:
        """推荐给定预算下的最优源子集.

        贪心选择: 每步选取对当前集合边际贡献最大的源.
        Shapley值高且与已选源互补 (φ_{ij}>0) 的源优先.
        """
        if not self._computed:
            return self._sources[:budget]

        remaining = set(self._sources)
        selected: List[str] = []

        for _ in range(min(budget, len(self._sources))):
            best_src = None
            best_score = float('-inf')
            for src in remaining:
                # 基础分 = Shapley值
                score = self._shapley_values.get(src, 0.0)
                # 加分: 与已选源的交互
                for sel in selected:
                    key = (min(src, sel), max(src, sel))
                    if key in self._interactions:
                        score += self._interactions[key] * 0.3  # 协同加权
                if score > best_score:
                    best_score = score
                    best_src = src
            if best_src:
                selected.append(best_src)
                remaining.discard(best_src)

        return selected

    @property
    def shapley_values(self) -> Dict[str, float]:
        return dict(self._shapley_values)

    @property
    def interactions(self) -> Dict[Tuple[str, str], float]:
        return dict(self._interactions)

    @property
    def is_computed(self) -> bool:
        return self._computed


# CVE适配

def build_cve_source_utility(scores_per_source: Dict[str, List[Tuple[float, bool]]]
                             ) -> Callable[[Set[str]], float]:
    """从各源的 (预测分数, 真实标签) 对构建效用函数.

    utility_fn(S) = 融合源集S的预测的加权F1分数.
    模拟: 对S中每个源的分数取平均, 计算F1.

    scores_per_source: {source_name: [(score, label), ...]}.
    """
    def utility(subset: Set[str]) -> float:
        n_samples = 0
        tp = fp = fn = 0.0
        # 取S中所有源的样本, 分数取平均
        samples: Dict[int, List[float]] = {}
        sample_labels: Dict[int, bool] = {}
        for src in subset:
            if src not in scores_per_source:
                continue
            for idx, (score, label) in enumerate(scores_per_source[src]):
                if idx not in samples:
                    samples[idx] = []
                    sample_labels[idx] = label
                samples[idx].append(score)
        for idx, scores in samples.items():
            if not scores:
                continue
            avg_score = sum(scores) / len(scores)
            pred = avg_score >= 0.5
            if pred and sample_labels[idx]:
                tp += 1
            elif pred and not sample_labels[idx]:
                fp += 1
            elif not pred and sample_labels[idx]:
                fn += 1
            n_samples += 1
        if n_samples == 0:
            return 0.0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall / (precision + recall)
              if (precision + recall) > 0 else 0.0)
        return f1

    return utility


def analyze_source_interactions(
    scores_per_source: Dict[str, List[Tuple[float, bool]]]
) -> Dict[str, Any]:
    """一站式源交互分析."""
    sources = list(scores_per_source.keys())
    utility_fn = build_cve_source_utility(scores_per_source)
    index = InteractionIndex(utility_fn, sources)
    index.compute()

    return {
        "n_sources": len(sources),
        "shapley_values": index.shapley_values,
        "interactions": {
            f"{si}-{sj}": round(v, 4)
            for (si, sj), v in index.interactions.items()
        },
        "synergies": index.find_synergies(),
        "redundancies": index.find_redundancies(),
        "optimal_subset_budget_3": index.recommend_optimal_subset(3),
        "attribution": index.get_attribution(),
    }
