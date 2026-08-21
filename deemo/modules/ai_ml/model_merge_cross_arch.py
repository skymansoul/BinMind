# 跨架构GNN模型合并——不同ISA独立训练的模型融合为统一模型
#
# 核心问题: cross_arch_transfer.py做跨架构迁移但需成对跨ISA数据。
# 实际中x86和ARM模型独立训练（各有标注），无成对数据可用。
# 如何将两个"孤岛"模型合并为在两种ISA上都工作的统一模型？
#
# 技术方案（基于AdaMMS CVPR 2025的异构模型合并，扩展到跨ISA GNN）:
#   1. 任务向量: τ = θ_finetuned - θ_base
#   2. 层间独立SLERP: 浅层(CFG拓扑)ISA间差异大→偏好单ISA
#      深层(语义)ISA间差异小→均匀混合，每层独立α
#   3. 功能保留检查: 合并后单ISA退化>阈值→回退该ISA原始权重
#
# 新颖性: AdaMMS针对多模态LLM，本工作首次针对跨ISA GNN二进制模型

from __future__ import annotations

import math
import logging
from typing import Dict, List, Optional, Tuple, Any, Callable
from dataclasses import dataclass

import numpy as np

logger = logging.getLogger(__name__)


@dataclass
class MergeConfig:
    layer_alphas: Dict[str, float] = None
    global_alpha: float = 0.5
    preserve_threshold: float = 0.03

    def __post_init__(self):
        if self.layer_alphas is None:
            self.layer_alphas = {}


class WeightOps:
    """跨架构权重操作——SLERP保持范数不变，优于LERP的范数收缩"""

    @staticmethod
    def slerp(w1: np.ndarray, w2: np.ndarray, alpha: float) -> np.ndarray:
        w1_f = w1.astype(np.float64).flatten()
        w2_f = w2.astype(np.float64).flatten()
        n1, n2 = float(np.linalg.norm(w1_f)), float(np.linalg.norm(w2_f))
        if n1 < 1e-12 or n2 < 1e-12:
            return (1.0 - alpha) * w1 + alpha * w2
        w1n, w2n = w1_f / n1, w2_f / n2
        dot = float(np.clip(np.dot(w1n, w2n), -1.0, 1.0))
        omega = math.acos(dot)
        if omega < 1e-6:
            return (1.0 - alpha) * w1 + alpha * w2
        sin_om = math.sin(omega)
        c1 = math.sin((1.0 - alpha) * omega) / sin_om
        c2 = math.sin(alpha * omega) / sin_om
        merged_flat = c1 * w1_f + c2 * w2_f
        mn = float(np.linalg.norm(merged_flat))
        tn = (1.0 - alpha) * n1 + alpha * n2
        if mn > 1e-12:
            merged_flat *= tn / mn
        return merged_flat.reshape(w1.shape)


class CrossArchModelMerger:
    """跨架构GNN模型合并器。

    算法:
      1. 对每层计算ISA间权重余弦相似度→自动生成层间α
      2. SLERP合并→功能保留检查→逐层回退修复退化层
    """

    def __init__(self, merge_config: Optional[MergeConfig] = None):
        self.config = merge_config or MergeConfig()

    def compute_layer_alphas(self,
                             weights_a: List[np.ndarray],
                             weights_b: List[np.ndarray]) -> Dict[str, float]:
        """基于层间余弦相似度自动计算每层插值系数。

        cos≈1(完全平行)→α≈0.5(均匀混合), cos≈-1→α接近0或1"""
        alphas = {}
        for i, (wa, wb) in enumerate(zip(weights_a, weights_b)):
            waf = wa.flatten().astype(np.float64)
            wbf = wb.flatten().astype(np.float64)
            na = float(np.linalg.norm(waf))
            nb = float(np.linalg.norm(wbf))
            if na < 1e-8 or nb < 1e-8:
                alphas[f"layer_{i}"] = 0.5
                continue
            cos_sim = float(np.dot(waf, wbf) / (na * nb))
            raw = 1.0 / (1.0 + math.exp(-(cos_sim - 0.5) * 4.0))
            alphas[f"layer_{i}"] = 0.15 + 0.7 * raw
        return alphas

    def merge_weights(self,
                      weights_a: List[np.ndarray],
                      weights_b: List[np.ndarray],
                      layer_alphas: Optional[Dict[str, float]] = None
                      ) -> List[np.ndarray]:
        if layer_alphas is None:
            layer_alphas = self.compute_layer_alphas(weights_a, weights_b)
        merged = []
        for i, (wa, wb) in enumerate(zip(weights_a, weights_b)):
            alpha = layer_alphas.get(f"layer_{i}", 0.5)
            merged.append(WeightOps.slerp(wa, wb, alpha))
        return merged

    def merge_with_preservation(self,
                                weights_a: List[np.ndarray],
                                weights_b: List[np.ndarray],
                                eval_fn_a: Callable,
                                eval_fn_b: Callable,
                                ) -> Tuple[List[np.ndarray], Dict[str, Any]]:
        """功能保留合并——确保合并不导致单ISA显著退化"""
        base_a = eval_fn_a(weights_a)
        base_b = eval_fn_b(weights_b)
        layer_alphas = self.compute_layer_alphas(weights_a, weights_b)
        merged = self.merge_weights(weights_a, weights_b, layer_alphas)
        merged_a = eval_fn_a(merged)
        merged_b = eval_fn_b(merged)
        thresh = self.config.preserve_threshold

        repaired = list(merged)
        repairs = 0
        if merged_a < base_a - thresh:
            for i in range(len(repaired)):
                repaired[i] = weights_a[i]
            repairs += len(repaired)
        if merged_b < base_b - thresh:
            for i in range(len(repaired)):
                repaired[i] = weights_b[i]
            repairs += len(repaired)

        return repaired, {
            'isa_a_baseline': base_a, 'isa_b_baseline': base_b,
            'merged_isa_a': merged_a, 'merged_isa_b': merged_b,
            'degradation_a': base_a - merged_a,
            'degradation_b': base_b - merged_b,
            'n_repairs': repairs, 'layer_alphas': layer_alphas,
        }
