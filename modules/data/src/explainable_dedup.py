# 可解释去重决策 (Explainable Dedup Decisions)
#
# 去重流水线判定两个二进制相似时, 输出仅包含相似度分值,
# 不解释哪些特征维度驱动了该判定. 安全分析师无法区分:
#   a) 真正相同的文件 (不同路径, 相同内容)
#   b) 同一家族变种 (函数重排, 编译器差异)
#   c) 误判 (偶然的哈希碰撞或低阈值)
#
# 创新点:
#   1. 特征消融归因: 对每个特征维度单独移除后重新计算相似度,
#      该维度的贡献 = (完整相似度 - 移除后相似度) / 完整相似度.
#      正值=正向贡献, 负值=抑制相似度.
#   2. 分组归因: 将特征按语义分组 (结构组/熵组/元数据组),
#      报告组级别和维度级别的双层归因.
#   3. 判定置信度: 基于归因分布的熵计算判定确定性 ——
#      若单个维度贡献 > 80%, 判定高度集中 (可能是 hash 碰撞).
#      若贡献分散在多个维度, 判定更可信.
#   4. 对策建议: 基于归因模式推荐分析师应采取的行动
#      (如"对比源码"、"检查编译选项"、"标记为误判").
#
# 与现有工作:
# SHAP/LIME: 需要模型训练, 面向分类任务. 本方案直接操作相似度函数.
#   - RealExp: 面向 Shapley 值的相关解耦. 本方案面向去重场景.
# 适用场景: 安全审计中对自动去重结果的复核.

import math
from typing import Callable, Dict, List, Optional, Tuple


class FeatureAttribution:
    """单维度归因结果."""
    __slots__ = ("name","group","contribution","full_score","ablated_score","direction")
    def __init__(self, name: str, group: str, contribution: float,
                 full_score: float, ablated_score: float):
        self.name = name; self.group = group
        self.contribution = contribution
        self.full_score = full_score; self.ablated_score = ablated_score
        self.direction = "positive" if contribution >= 0 else "negative"


class DedupExplanation:
    """完整的去重解释."""
    __slots__ = ("full_similarity","attributions","group_contributions",
                 "confidence","entropy","recommendation","n_features")
    def __init__(self, full_sim: float, attributions: List[FeatureAttribution]):
        self.full_similarity = full_sim
        self.attributions = sorted(attributions, key=lambda a: abs(a.contribution), reverse=True)
        self.n_features = len(attributions)
        self.group_contributions = self._group_agg()
        self.entropy = self._contribution_entropy()
        self.confidence = self._confidence()
        self.recommendation = self._recommend()

    def _group_agg(self) -> Dict[str, float]:
        groups = {}
        for a in self.attributions:
            groups[a.group] = groups.get(a.group, 0.0) + a.contribution
        return {g: round(v, 4) for g, v in sorted(groups.items(), key=lambda x: abs(x[1]), reverse=True)}

    def _contribution_entropy(self) -> float:
        abs_sum = sum(abs(a.contribution) for a in self.attributions)
        if abs_sum < 1e-9: return 0.0
        e = 0.0
        for a in self.attributions:
            p = abs(a.contribution) / abs_sum
            if p > 0: e -= p * math.log2(p)
        return e / max(math.log2(self.n_features), 1e-9)

    def _confidence(self) -> str:
        if self.entropy < 0.3: return "high"
        elif self.entropy < 0.6: return "medium"
        return "low"

    def _recommend(self) -> str:
        if self.full_similarity < 0.5: return "likely_different"
        if self.confidence == "high" and self.entropy < 0.2:
            top = self.attributions[0]
            if top.contribution > 0.8 * self.full_similarity:
                return "possible_hash_collision_or_exact_duplicate"
        if self.confidence == "low":
            return "review_manually_dispersed_contribution"
        struct_contrib = self.group_contributions.get("structure", 0)
        entropy_contrib = self.group_contributions.get("entropy", 0)
        if struct_contrib > 0.4:
            return "same_family_variant_inspect_cfg"
        if entropy_contrib > 0.4:
            return "similar_compilation_check_build_flags"
        return "likely_duplicate"

    def to_dict(self) -> dict:
        return {
            "similarity": round(self.full_similarity, 6),
            "confidence": self.confidence,
            "entropy": round(self.entropy, 4),
            "recommendation": self.recommendation,
            "top_features": [
                {"name": a.name, "contribution": round(a.contribution, 4),
                 "direction": a.direction}
                for a in self.attributions[:6]
            ],
            "groups": self.group_contributions,
        }


class ExplainableDedup:
    """可解释去重: 特征消融 + 分组归因 + 对策建议.

    特征维度定义 (15 维, 4 组):
      structure (6): file_size, section_count, import_count, symbol_count,
                     has_debug, is_stripped
      entropy (5):   byte_entropy, zero_ratio, compression_ratio,
                     code_entropy, data_entropy
      metadata (2):  stage_match, tag_jaccard
      graph (2):     graphlet_similarity, wl_similarity

    用法:
      ed = ExplainableDedup()
      result = ed.explain(features_a, features_b, sim_func)
    其中 sim_func(feats_a, feats_b) -> float 是任意相似度函数.
    """

    FEATURE_GROUPS = {
        "structure":  ["file_size","section_count","import_count","symbol_count","has_debug","is_stripped"],
        "entropy":    ["byte_entropy","zero_ratio","compression_ratio","code_entropy","data_entropy"],
        "metadata":   ["stage_match","tag_jaccard"],
        "graph":      ["graphlet_sim","wl_sim"],
    }

    def __init__(self, ablation_value: float = 0.0):
        self._ablate_val = ablation_value

    def explain(self, feats_a: List[float], feats_b: List[float],
                sim_func: Callable[[List[float], List[float]], float],
                dim_names: List[str] = None) -> DedupExplanation:
        """计算完整归因解释.

        dim_names 未提供时使用默认维度名 (dim_0..dim_N-1),
        分组信息从 FEATURE_GROUPS 反查.
        """
        n = min(len(feats_a), len(feats_b))
        if dim_names is None:
            dim_names = [f"dim_{i}" for i in range(n)]

        # 完整相似度
        full_sim = sim_func(feats_a, feats_b)

        # 特征消融: 逐维度置零后重算
        attributions = []
        for i in range(n):
            fa_mod = list(feats_a)
            fb_mod = list(feats_b)
            fa_mod[i] = self._ablate_val
            fb_mod[i] = self._ablate_val
            ablated_sim = sim_func(fa_mod, fb_mod)
            contribution = full_sim - ablated_sim
            group = self._find_group(dim_names[i])

            attributions.append(FeatureAttribution(
                name=dim_names[i], group=group,
                contribution=contribution,
                full_score=full_sim, ablated_score=ablated_sim,
            ))

        return DedupExplanation(full_sim, attributions)

    def quick_explain(self, feats_a: List[float], feats_b: List[float],
                       sim_func: Callable, top_k: int = 5
                       ) -> List[FeatureAttribution]:
        """快速归因: 仅返回 Top-K 贡献维度, 跳过完整解释构造."""
        exp = self.explain(feats_a, feats_b, sim_func)
        return exp.attributions[:top_k]

    def _find_group(self, dim_name: str) -> str:
        for group, members in self.FEATURE_GROUPS.items():
            if dim_name in members:
                return group
        return "other"


# 预置相似度函数 (用于消融测试)

def cosine_similarity(a: List[float], b: List[float]) -> float:
    """余弦相似度 —— 最常用的向量相似度度量."""
    n = min(len(a), len(b))
    dot = sum(a[i]*b[i] for i in range(n))
    na = math.sqrt(sum(x*x for x in a[:n]))
    nb = math.sqrt(sum(x*x for x in b[:n]))
    denom = na * nb
    return dot / denom if denom > 1e-9 else 0.0


def weighted_l1_similarity(a: List[float], b: List[float],
                            weights: List[float] = None) -> float:
    """加权 L1 相似度: 1/(1 + Σ w_i|a_i - b_i|)."""
    n = min(len(a), len(b))
    if weights is None:
        weights = [1.0/n] * n
    dist = sum(weights[i]*abs(a[i]-b[i]) for i in range(n))
    return 1.0 / (1.0 + dist)


def jaccard_binary_similarity(a: List[float], b: List[float],
                               threshold: float = 0.5) -> float:
    """二值化 Jaccard: 将 >threshold 的值视为 1, 否则 0."""
    n = min(len(a), len(b))
    a_bin = {i for i in range(n) if a[i] > threshold}
    b_bin = {i for i in range(n) if b[i] > threshold}
    inter = len(a_bin & b_bin)
    union = len(a_bin | b_bin)
    return inter / max(union, 1)


__all__ = [
    "ExplainableDedup",
    "DedupExplanation",
    "FeatureAttribution",
    "cosine_similarity",
    "weighted_l1_similarity",
    "jaccard_binary_similarity",
]
