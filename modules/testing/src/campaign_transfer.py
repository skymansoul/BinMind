# 跨活动策略迁移 — 基于二进制指纹的变异操作符知识复用
#
# 核心问题:
#   每次对新二进制启动fuzzing活动时, 变异策略从零开始学习。
#   adaptive_mutator.py 和 interaction_bandit.py 的EWMA/LinUCB状态
#   在活动结束后被丢弃——之前学到"对加密库, arith_8更有效;
#   对解析器, dict_insert更有效"的知识全部丢失。
#
#   现有方案 (BandFuzz, autofz) 均从零开始, 无跨活动知识复用机制。
#
# 本模块的方法 — 二进制指纹匹配 + 策略迁移:
#   1. 活动结束时, 记录 CampaignFingerprint:
#      a) 二进制特征: CFG熵、导入函数画像、节区数、二进制大小
#      b) 最佳操作符: 按EWMA奖励排序的Top-K操作符
#   2. 新活动启动时, 提取新二进制的特征向量
#   3. 在历史活动指纹库中做cosine nearest-neighbor搜索
#   4. 将最近邻活动的操作符权重作为新活动的初始先验
#   5. 先验权重与默认权重的混合: w_init = λ*w_transfer + (1-λ)*w_default
#
# 为什么指纹匹配有效:
# 同一领域的二进制有相似的导入函数画像 (如加密库都用AES/md5 API)
# CFG结构熵反映代码复杂度类别 (简单解析器 vs 复杂编译器)
# 这些特征与"哪种变异策略有效"有因果关系

from __future__ import annotations

import hashlib
import math
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

# 桥接 interaction_bandit.py + adaptive_mutator.py:
# build_fingerprint() 的 operator_rewards 参数格式为 {op_name: ewma_reward},
# 可直接从 InteractionBanditScheduler._arms[op].ewma_reward 或
# adaptive_mutator.OperatorStats.ewma_reward 提取后传入。
# blended_weights 输出格式与两者的权重字典兼容。


@dataclass
class BinaryFeatures:
    """二进制静态特征向量——用于相似度匹配"""
    # CFG 统计 (来自 cfg_entropy_fingerprint 或 cfg_info)
    cfg_entropy: float = 0.0
    avg_block_size: float = 0.0
    branch_density: float = 0.0
    # 导入表画像
    import_profile_hash: int = 0    # 导入函数集合的哈希
    import_count: int = 0
    io_import_count: int = 0        # 输入/输出类导入数
    crypto_import_count: int = 0    # 加密类导入数
    mem_import_count: int = 0       # 内存操作类导入数
    # 结构特征
    section_count: int = 0
    binary_size_log2: float = 0.0   # log2(binary_size_bytes)
    # 向量形式 (用于余弦相似度)
    _cached_vector: Optional[List[float]] = None

    def to_vector(self) -> List[float]:
        if self._cached_vector is None:
            self._cached_vector = [
                self.cfg_entropy,
                self.avg_block_size / 20.0,
                self.branch_density,
                min(1.0, self.import_count / 500.0),
                min(1.0, self.io_import_count / 50.0),
                min(1.0, self.crypto_import_count / 20.0),
                min(1.0, self.mem_import_count / 30.0),
                min(1.0, self.section_count / 20.0),
                self.binary_size_log2 / 32.0,
            ]
        return self._cached_vector


@dataclass
class OperatorEffectiveness:
    """单个操作符在某一活动中的效果记录"""
    operator_name: str
    ewma_reward: float = 0.5
    trials: int = 0
    # 归一化到 [0,1] 的有效性分
    normalized_score: float = 0.5


@dataclass
class CampaignFingerprint:
    """单个fuzzing活动的完整指纹"""
    campaign_id: str
    binary_name: str = ""
    binary_features: BinaryFeatures = field(default_factory=BinaryFeatures)
    # Top-K 最有效的操作符
    top_operators: List[OperatorEffectiveness] = field(default_factory=list)
    # 元数据
    total_execs: int = 0
    total_crashes: int = 0
    duration_s: float = 0.0
    created_at: float = 0.0


@dataclass
class TransferResult:
    """策略迁移结果"""
    source_campaign: Optional[CampaignFingerprint] = None
    similarity: float = 0.0
    transferred_weights: Dict[str, float] = field(default_factory=dict)
    # 混合权重 (transfer × λ + default × (1-λ))
    blended_weights: Dict[str, float] = field(default_factory=dict)
    rationale: str = ""


class CampaignTransferEngine:
    """跨活动策略迁移引擎。

    典型用法:
        engine = CampaignTransferEngine()
        # 活动结束时:
        fp = engine.build_fingerprint(campaign_id, binary_features,
                                       operator_ewma_rewards)
        engine.archive(fp)
        # 新活动开始时:
        result = engine.transfer(new_binary_features, blend_ratio=0.4)
        # 用 result.blended_weights 初始化 adaptive_mutator
    """

    def __init__(self, blend_ratio: float = 0.4,
                 min_similarity: float = 0.3):
        """
        blend_ratio: 迁移权重的初始混合比
        min_similarity: 低于此相似度的历史活动不被考虑
        """
        self._blend_ratio = blend_ratio
        self._min_similarity = min_similarity
        self._archive: List[CampaignFingerprint] = []
        # 在线贝叶斯适应: Beta(α, β) 后验追踪迁移有效性
        # α = 迁移后有效的证据, β = 迁移后无效的证据
        self._adapt_alpha: float = 1.0
        self._adapt_beta: float = 1.0

    def build_fingerprint(self,
                           campaign_id: str,
                           binary_features: BinaryFeatures,
                           operator_rewards: Dict[str, float],
                           operator_trials: Optional[Dict[str, int]] = None,
                           binary_name: str = "",
                           total_execs: int = 0,
                           total_crashes: int = 0,
                           duration_s: float = 0.0,
                           ) -> CampaignFingerprint:
        """从活动结果构造指纹"""
        # 归一化操作符奖励到 [0, 1]
        if operator_rewards:
            max_r = max(operator_rewards.values())
            min_r = min(operator_rewards.values())
            rng = max(max_r - min_r, 0.01)
            top_ops = [
                OperatorEffectiveness(
                    operator_name=name,
                    ewma_reward=reward,
                    trials=operator_trials.get(name, 0) if operator_trials else 0,
                    normalized_score=(reward - min_r) / rng,
                )
                for name, reward in sorted(
                    operator_rewards.items(), key=lambda x: -x[1])[:10]
            ]
        else:
            top_ops = []

        return CampaignFingerprint(
            campaign_id=campaign_id,
            binary_name=binary_name,
            binary_features=binary_features,
            top_operators=top_ops,
            total_execs=total_execs,
            total_crashes=total_crashes,
            duration_s=duration_s,
            created_at=time.time(),
        )

    def archive(self, fp: CampaignFingerprint) -> None:
        """存档一个活动的指纹"""
        self._archive.append(fp)
        # 限制存档大小
        if len(self._archive) > 128:
            self._archive = self._archive[-128:]

    def transfer(self, target_features: BinaryFeatures,
                  operator_names: Optional[List[str]] = None,
                  blend_ratio: Optional[float] = None,
                  ) -> TransferResult:
        """为新活动迁移策略——找最近邻历史活动, 混合其操作符权重"""
        ratio = blend_ratio if blend_ratio is not None else self._blend_ratio

        if not self._archive:
            return TransferResult(
                rationale="无历史活动, 使用默认权重")

        target_vec = target_features.to_vector()

        # 找最相似的历史活动
        best_fp, best_sim = self._find_nearest(target_vec)
        if best_fp is None or best_sim < self._min_similarity:
            return TransferResult(
                similarity=best_sim,
                rationale=f"最相似活动相似度{best_sim:.2f} < {self._min_similarity}, 不使用迁移")

        # 提取迁移权重
        transferred: Dict[str, float] = {}
        for op in best_fp.top_operators:
            transferred[op.operator_name] = op.normalized_score

        # 自适应混合: 贝叶斯后验均值缩放静态blend_ratio
        default_weight = 0.5
        blended: Dict[str, float] = {}
        all_ops = set(transferred.keys())
        if operator_names:
            all_ops |= set(operator_names)

        adaptive_ratio = self._current_adaptive_ratio()
        effective_ratio = ratio * adaptive_ratio

        for op_name in all_ops:
            t_weight = transferred.get(op_name, default_weight)
            blended[op_name] = effective_ratio * t_weight + (1.0 - effective_ratio) * default_weight

        return TransferResult(
            source_campaign=best_fp,
            similarity=best_sim,
            transferred_weights=transferred,
            blended_weights=blended,
            rationale=(
                f"从 {best_fp.campaign_id} ({best_fp.binary_name}) "
                f"迁移, 相似度={best_sim:.3f}, 自适应混合比={effective_ratio:.3f}"),
        )

    def adapt_blend_ratio(self, was_effective: bool) -> None:
        """在线贝叶斯更新: 根据迁移效果调整混合比。

        was_effective: 迁移的权重是否在新活动中表现优于默认权重。
        若True → α+=1 (增加对迁移的信任)
        若False → β+=1 (减少对迁移的信任)
        后验均值 α/(α+β) 作为自适应混合比的缩放因子。
        """
        if was_effective:
            self._adapt_alpha += 1.0
        else:
            self._adapt_beta += 1.0

    def _current_adaptive_ratio(self) -> float:
        """当前贝叶斯后验均值——迁移有效性的估计"""
        return self._adapt_alpha / (self._adapt_alpha + self._adapt_beta)

    def _find_nearest(self, target_vec: List[float]
                       ) -> Tuple[Optional[CampaignFingerprint], float]:
        best_fp = None
        best_sim = -1.0
        for fp in self._archive:
            sim = self._cosine_similarity(
                target_vec, fp.binary_features.to_vector())
            if sim > best_sim:
                best_sim = sim
                best_fp = fp
        return best_fp, best_sim

    @staticmethod
    def _cosine_similarity(a: List[float], b: List[float]) -> float:
        dot = sum(x * y for x, y in zip(a, b))
        na = math.sqrt(sum(x * x for x in a))
        nb = math.sqrt(sum(y * y for y in b))
        if na < 1e-12 or nb < 1e-12:
            return 0.0
        return max(-1.0, min(1.0, dot / (na * nb)))

    # 诊断

    def stats(self) -> Dict[str, Any]:
        return {
            "archived_campaigns": len(self._archive),
            "recent_campaigns": [
                {"id": fp.campaign_id, "binary": fp.binary_name,
                 "crashes": fp.total_crashes}
                for fp in self._archive[-5:]
            ],
        }

    def reset(self) -> None:
        self._archive.clear()


def quick_transfer(operator_rewards_by_campaign: Dict[str, Dict[str, float]],
                    target_features: BinaryFeatures,
                    ) -> TransferResult:
    """便捷入口: 给定多活动的操作符奖励历史, 快速迁移到新目标"""
    engine = CampaignTransferEngine()
    for camp_id, rewards in operator_rewards_by_campaign.items():
        fp = engine.build_fingerprint(
            camp_id, BinaryFeatures(), rewards,
            binary_name=camp_id)
        engine.archive(fp)
    return engine.transfer(target_features)
