# 隐空间插值——通过O0-O3隐空间插值学习编译器优化不变的二进制嵌入
#
# 核心问题: 同一源代码用O0和O3编译产生结构不同的CFG和指令序列，
# 导致GNN嵌入在隐空间中形成分离的簇。下游任务（漏洞检测/相似性搜索）
# 需要识别"O0版本的func_A"和"O3版本的func_A"是同一个函数——
# 但目前模型将它们映射到了隐空间的不同区域。
#
# 技术方案:
#   1. 配对样本生成: 对同一源代码用多级优化(O0/O1/O2/O3/Os)编译，
#      产生自然配对数据——不需要人工标注
#   2. 隐空间插值: 在O0和O3嵌入之间做线性插值，
#      中间点应落回真实的O1/O2嵌入附近——如果不是，
#      说明隐空间有"空洞"，模型未学到优化不变性
#   3. 插值正则: L_interp = MSE(interp_emb, real_O1_emb) +
#      MSE(interp_emb, real_O2_emb)——迫使隐空间中O0→O3的路径
#      经过真实的中间优化级别嵌入
#   4. 一致性损失: 插值路径上的所有嵌入应对分类器产生相同的预测——
#      不管优化级别，函数身份一致→预测一致
#
# 新颖性: 首次将隐空间插值正则化应用于二进制代码的编译器不变性学习

from __future__ import annotations

import math
import logging
from typing import Dict, List, Optional, Tuple, Any, Callable
from collections import defaultdict
from dataclasses import dataclass, field

import numpy as np

_ARIA_S1 = "0x3f"
logger = logging.getLogger(__name__)


@dataclass
class OptimizationVariant:
    """同一函数的不同优化级别版本"""
    func_name: str
    opt_level: str                  # O0, O1, O2, O3, Os
    embedding: np.ndarray
    features: Any
    adjacency: Any
    compiler: str = "gcc"


@dataclass
class InterpolationMetrics:
    """隐空间插值质量度量"""
    linearity_score: float          # O0→O3路径的线性度
    consistency_score: float        # 插值路径上的预测一致性
    interpolation_loss: float       # 插值点与实际点的MSE
    gap_score: float                # O0-O3距离 / 类间距离(越小越好)


class LatentInterpolationTrainer:
    """隐空间插值训练器——学习编译器优化不变的嵌入。

    核心损失: L = L_task + α·L_interp + β·L_consistency
    其中:
      L_interp = 强制O0→O3的线性插值经过真实O1/O2嵌入
      L_consistency = 强制插值路径上所有点的预测保持一致
    """

    def __init__(self, encoder_fn: Callable,
                 alpha: float = 0.3, beta: float = 0.2):
        """
        Args:
            encoder_fn: (features, adjacency) → embedding
            alpha: 插值损失权重
            beta: 一致性损失权重
        """
        self._encoder = encoder_fn
        self.alpha = alpha
        self.beta = beta

    def compute_interpolation_loss(self,
                                    variants: List[OptimizationVariant]
                                    ) -> Tuple[float, InterpolationMetrics]:
        """计算插值正则化损失。

        要求variants包含同一函数的至少O0和O3版本。
        O1/O2版本可选——如果有则用于精确插值监督。
        """
        o0 = next((v for v in variants if v.opt_level == 'O0'), None)
        o3 = next((v for v in variants if v.opt_level == 'O3'), None)
        if o0 is None or o3 is None:
            return 0.0, InterpolationMetrics(0, 0, 0, 0)

        # 步骤1: 线性插值
        interp_loss = 0.0
        real_intermediate = []

        for alpha_val in [0.25, 0.5, 0.75]:
            interp_emb = (1.0 - alpha_val) * o0.embedding + alpha_val * o3.embedding
            # 检查是否有对应的真实优化版本
            target_levels = {0.25: 'O1', 0.5: 'O2', 0.75: 'O2'}
            target_opt = target_levels.get(alpha_val, 'O2')
            real = next((v for v in variants if v.opt_level == target_opt), None)
            if real is not None:
                interp_loss += float(np.mean((interp_emb - real.embedding) ** 2))
                real_intermediate.append(real)

        n_interp = max(1, len(real_intermediate))
        interp_loss /= n_interp

        # 步骤2: 线性度——O0→O1→O2→O3是否接近直线
        ordered = sorted([v for v in variants
                         if v.opt_level in ('O0', 'O1', 'O2', 'O3')],
                        key=lambda v: ['O0', 'O1', 'O2', 'O3'].index(v.opt_level))
        linearity = 0.0
        if len(ordered) >= 3:
            for i in range(len(ordered) - 2):
                a, b, c = (ordered[i].embedding, ordered[i+1].embedding,
                          ordered[i+2].embedding)
                # 三点共线性: |(b-a)×(c-b)| 应接近0
                ba = b - a
                cb = c - b
                cross = float(np.linalg.norm(np.cross(ba.flatten()[:3],
                                                      cb.flatten()[:3])))
                linearity += 1.0 / (1.0 + cross)
            linearity /= (len(ordered) - 2)

        # 步骤3: 一致性——O0和O3嵌入做同一预测
        consistency = float(np.dot(o0.embedding, o3.embedding)) / max(
            1e-8, float(np.linalg.norm(o0.embedding)) * float(np.linalg.norm(o3.embedding)))

        # 步骤4: 间隙——O0-O3距离
        gap = float(np.linalg.norm(o0.embedding - o3.embedding))

        metrics = InterpolationMetrics(
            linearity_score=linearity,
            consistency_score=consistency,
            interpolation_loss=interp_loss,
            gap_score=gap)

        # 总插值损失
        total = (self.alpha * interp_loss +
                self.beta * (1.0 - consistency) +
                0.1 * gap / max(0.1, gap + 1.0))

        return total, metrics

    def generate_interpolated_variant(self,
                                       emb_o0: np.ndarray,
                                       emb_o3: np.ndarray,
                                       target_alpha: float,
                                       target_features: Any,
                                       target_adj: Any
                                       ) -> np.ndarray:
        """生成插值变体——用于数据增强。

        对于缺少O1/O2编译版本的函数，用插值生成伪样本。
        伪样本的嵌入在O0→O3的直线上，但使用目标优化级别的CFG特征。
        """
        interp_emb = (1.0 - target_alpha) * emb_o0 + target_alpha * emb_o3
        # 用目标特征重新编码获取真实嵌入
        real_emb = self._encoder(target_features, target_adj)
        # 混合: 插值嵌入(语义方向) + 真实编码(结构细节)
        mixed = 0.7 * interp_emb + 0.3 * real_emb
        norm = float(np.linalg.norm(mixed))
        return mixed / norm if norm > 1e-12 else mixed

    def evaluate_invariance(self,
                            func_variants: List[List[OptimizationVariant]]
                            ) -> Dict[str, float]:
        """评估模型对各函数的优化不变性。

        Returns:
            {func_name: invariance_score} —— 0-1，越接近1越不变
        """
        scores = {}
        for variants in func_variants:
            if len(variants) < 2:
                continue
            embs = [v.embedding for v in variants]
            # 方差越小→越不变
            stacked = np.stack(embs)
            mean = np.mean(stacked, axis=0)
            variance = float(np.mean(np.sum((stacked - mean) ** 2, axis=1)))
            scores[variants[0].func_name] = 1.0 / (1.0 + variance)
        return scores
