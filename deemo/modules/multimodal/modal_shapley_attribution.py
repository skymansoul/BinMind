"""
模态 Shapley 归因 (Modal Shapley Attribution, MSA)
---------------------------------------------------
用 Shapley 值量化各模态对融合预测的边际贡献,
区分 "真正有用的模态" 与 "搭便车的噪声模态".

设计依据:
  多模态融合的常见失败模式: 某一模态 (如 decompile) 提供噪声,
  但因注意力机制的过自信而归因到高贡献.
  标准注意力权重反映的是"模型关注哪里", 而非"该模态实际贡献了多少".

  Shapley 值从合作博弈角度回答: 移除该模态后预测质量下降多少?
  边际贡献 = E[f(S ∪ {i})] - E[f(S)], 对所有子集 S 求期望.
  模态数 ≤ 5 时可以精确计算 (2^5 = 32 个子集).

  与现有方案的差异:
  - SHAP: 特征级, 需要背景数据集, 计算昂贵
  - 本方案: 模态级, 仅 2^K 次前向传播 (K≤5, 至多 32 次), 无需背景集
"""
import math
import itertools
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple


@dataclass
class ModalContribution:
    """单模态的 Shapley 贡献."""
    modality: str
    shapley_value: float       # 边际贡献 (可正可负——负值=噪声)
    relative_contribution: float  # 归一化后占比 (0-1)
    rank: int
    is_noise: bool = False     # Shapley < 0 → 该模态降低整体性能


@dataclass(frozen=True)
class FusionPrediction:
    """融合预测结果 — 用于 Shapley 计算."""
    score: float               # 预测质量指标 (越大越好)
    label: str = ""


class ModalShapleyAttributor:
    """模态级 Shapley 值归因器.

    用法:
      msa = ModalShapleyAttributor(fusion_fn, eval_fn)
      # fusion_fn: 接受模态子集 → 融合预测
      # eval_fn: FusionPrediction → float (质量分)
      contributions = msa.attribute(['disasm','decompile','dynamic','symexec'])
    """

    def __init__(self,
                 fusion_fn: Callable[[Set[str]], FusionPrediction],
                 eval_fn: Callable[[FusionPrediction], float] = None):
        self._fusion = fusion_fn
        self._eval = eval_fn or (lambda fp: fp.score)

    def attribute(self, modalities: List[str]) -> List[ModalContribution]:
        """计算所有模态的 Shapley 值."""
        K = len(modalities)
        if K == 0:
            return []
        if K > 6:
            # 超过 6 个模态用蒙特卡洛采样近似
            return self._approximate(modalities)

        # 精确计算: 2^K 个子集
        shapley = {m: 0.0 for m in modalities}
        all_subsets = list(_powerset(modalities))

        for m in modalities:
            for subset in all_subsets:
                if m in subset:
                    continue
                s = set(subset)
                s_with = s | {m}
                # 边际贡献 = f(S ∪ {m}) - f(S)
                score_with = self._eval(self._fusion(s_with))
                score_without = self._eval(self._fusion(s))
                marginal = score_with - score_without
                # Shapley 权重: |S|! * (K-|S|-1)! / K!
                weight = _shapley_weight(len(s), K)
                shapley[m] += weight * marginal

        # 归一化为相对贡献
        total_pos = sum(max(0, v) for v in shapley.values())
        contributions = []
        for rank, (mod, val) in enumerate(
            sorted(shapley.items(), key=lambda x: x[1], reverse=True), 1
        ):
            contributions.append(ModalContribution(
                modality=mod,
                shapley_value=round(val, 6),
                relative_contribution=round(
                    max(0, val) / total_pos if total_pos > 0 else 1.0 / K, 4
                ),
                rank=rank,
                is_noise=val < -0.01,
            ))
        return contributions

    def _approximate(self, modalities: List[str],
                     n_samples: int = 100) -> List[ModalContribution]:
        """蒙特卡洛采样近似 — 对大模态数."""
        K = len(modalities)
        shapley = {m: 0.0 for m in modalities}
        for _ in range(n_samples):
            # 随机排列
            perm = list(modalities)
            import random
            random.shuffle(perm)
            prev_set: Set[str] = set()
            prev_score = self._eval(self._fusion(prev_set))
            for m in perm:
                cur_set = prev_set | {m}
                cur_score = self._eval(self._fusion(cur_set))
                shapley[m] += (cur_score - prev_score) / n_samples
                prev_set = cur_set
                prev_score = cur_score

        total_pos = sum(max(0, v) for v in shapley.values())
        contributions = []
        for rank, (mod, val) in enumerate(
            sorted(shapley.items(), key=lambda x: x[1], reverse=True), 1
        ):
            contributions.append(ModalContribution(
                modality=mod,
                shapley_value=round(val, 6),
                relative_contribution=round(
                    max(0, val) / total_pos if total_pos > 0 else 1.0 / K, 4
                ),
                rank=rank,
                is_noise=val < -0.01,
            ))
        return contributions

    def prune_noise_modalities(self, contributions: List[ModalContribution]
                               ) -> List[str]:
        """返回应被剪枝的噪声模态列表."""
        return [c.modality for c in contributions if c.is_noise]

    def dominant_modality(self, contributions: List[ModalContribution]
                          ) -> Optional[str]:
        """返回贡献最高的模态, 若最高贡献 < 0.3 则返回 None."""
        if not contributions:
            return None
        top = contributions[0]
        return top.modality if top.relative_contribution >= 0.3 else None


def _powerset(items: List[str]) -> List[List[str]]:
    return [list(combo)
            for r in range(len(items) + 1)
            for combo in itertools.combinations(items, r)]


def _shapley_weight(s_size: int, K: int) -> float:
    """Shapley 权重: |S|!(K-|S|-1)!/K!."""
    import math
    return (math.factorial(s_size) * math.factorial(K - s_size - 1)
            / math.factorial(K))


def make_fusion_eval_from_dict(
    cache: Dict[str, float],
) -> Callable[[Set[str]], FusionPrediction]:
    """从预计算缓存创建融合评估函数 — 用于测试."""
    def fusion(subset: Set[str]) -> FusionPrediction:
        key = ','.join(sorted(subset)) if subset else 'empty'
        return FusionPrediction(score=cache.get(key, 0.0))
    return fusion
