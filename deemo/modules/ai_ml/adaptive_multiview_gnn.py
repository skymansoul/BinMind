# 自适应多视图GNN-基于预测熵的动态视图权重融合
#
# 核心问题: multi_view_gnn.py使用固定权重融合多个GNN视图（CFG/DFG/调用图），
# 但不同样本在不同视图上的可靠性不同。循环密集函数的CFG视图信息丰富，
# 线性函数的DFG视图更可靠。固定权重无法利用这种样本级差异。
#
# 技术方案:
#   1. 每视图独立GNN: 对CFG/DFG/CallGraph视图分别运行GNN编码
#   2. 视图不确定性: 每个视图输出预测分布→计算熵作为不确定性
#   3. 动态融合权重: w_i = softmax(-entropy_i / temperature)——
#      低熵(高确定性)的视图获得更高权重
#   4. 视图一致性正则: 除了任务损失，加入视图间预测一致性损失——
#      防止某个视图的预测与其他视图完全脱节
#   5. 自适应温度: temperature = τ_0/(1+log(1+epoch))——训练早期均匀融合，
#      后期sharp融合（高度确定性视图主导）
#
# 与multi_view_gnn.py的固定权重不同, 本模块采用预测熵驱动的动态视图权重融合,
# 权重随样本的视图不确定性自适应调整

from __future__ import annotations

import math
import logging
from typing import Dict, List, Optional, Set, Tuple, Any, Callable
from collections import defaultdict
from dataclasses import dataclass, field

import numpy as np

logger = logging.getLogger(__name__)


class ViewKind:
    CFG = 'cfg'
    DFG = 'dfg'
    CALL_GRAPH = 'call_graph'


@dataclass
class ViewOutput:
    # 单个视图的GNN输出
    view_name: str
    logits: np.ndarray             # (n_nodes, n_classes)
    probabilities: np.ndarray      # softmax(logits)
    entropy: float                 # 预测熵-不确定性度量
    embedding: np.ndarray          # (n_nodes, hidden_dim)
    weight: float = 0.0            # 动态融合权重


@dataclass
class MultiViewFusion:
    # 自适应多视图融合结果
    fused_logits: np.ndarray
    fused_probs: np.ndarray
    view_weights: Dict[str, float]
    view_outputs: Dict[str, ViewOutput]
    consistency_loss: float
    prediction_confidence: float


class AdaptiveMultiViewGNN:
    # 自适应多视图GNN-熵驱动的动态视图权重.
    # 融合: w_i = softmax(-entropy_i / T), 低熵视图获更高权重.
    # 温度调度: T(t) = T_0/(1+log(1+t)), 早期均匀探索后期sharp融合.

    def __init__(self,
                 n_classes: int = 2,
                 temperature_initial: float = 1.0,
                 consistency_weight: float = 0.1):
        self.n_classes = n_classes
        self.T_initial = temperature_initial
        self._consistency_weight = consistency_weight
        self._epoch = 0

    def _current_temperature(self) -> float:
        return self.T_initial / (1.0 + math.log(1 + self._epoch))

    def forward(self,
                view_fns: Dict[str, Callable],
                view_data: Dict[str, Tuple[Any, Any]]
                ) -> MultiViewFusion:
        view_outputs = {}
        T = self._current_temperature()
        entropies = []

        for view_name, gnn_fn in view_fns.items():
            if view_name not in view_data:
                continue
            feats, adj = view_data[view_name]
            try:
                logits = gnn_fn(feats, adj)
                logits_arr = np.asarray(logits)
                if logits_arr.ndim == 1:
                    logits_arr = np.column_stack([1 - logits_arr, logits_arr])
            except Exception:
                logits_arr = np.zeros((1, self.n_classes))

            # softmax
            logits_shifted = logits_arr - logits_arr.max(axis=-1, keepdims=True)
            probs = np.exp(logits_shifted) / (
                np.exp(logits_shifted).sum(axis=-1, keepdims=True) + 1e-12)

            # 预测熵: -sum(p * log(p))
            eps = 1e-12
            entropy = -float(np.mean(
                np.sum(probs * np.log(probs + eps), axis=-1)))
            entropies.append(entropy)

            view_outputs[view_name] = ViewOutput(
                view_name=view_name,
                logits=logits_arr, probabilities=probs,
                entropy=entropy,
                embedding=logits_arr.flatten()[:64])

        if not view_outputs:
            empty = np.zeros((1, self.n_classes))
            return MultiViewFusion(
                fused_logits=empty, fused_probs=empty,
                view_weights={}, view_outputs={},
                consistency_loss=0.0, prediction_confidence=0.0)

        # 动态权重: softmax(-entropy / T)
        ent_arr = np.array(entropies)
        neg_ent = -ent_arr / max(T, 0.01)
        neg_ent -= neg_ent.max()
        weights = np.exp(neg_ent) / np.exp(neg_ent).sum()

        # 加权融合
        fused_logits = np.zeros_like(list(view_outputs.values())[0].logits)
        for i, (name, out) in enumerate(view_outputs.items()):
            out.weight = float(weights[i])
            fused_logits += weights[i] * out.logits

        fused_shifted = fused_logits - fused_logits.max(axis=-1, keepdims=True)
        fused_probs = np.exp(fused_shifted) / (
            np.exp(fused_shifted).sum(axis=-1, keepdims=True) + 1e-12)

        # 视图一致性损失: 成对预测的KL散度均值
        cons_loss = self._compute_consistency_loss(view_outputs)

        # 置信度: 1 - 加权熵
        weighted_entropy = sum(
            out.weight * out.entropy for out in view_outputs.values())
        confidence = 1.0 - min(1.0, weighted_entropy / math.log(self.n_classes))

        weights_dict = {name: float(out.weight)
                       for name, out in view_outputs.items()}

        return MultiViewFusion(
            fused_logits=fused_logits, fused_probs=fused_probs,
            view_weights=weights_dict, view_outputs=view_outputs,
            consistency_loss=cons_loss,
            prediction_confidence=confidence)

    def _compute_consistency_loss(self,
                                   view_outputs: Dict[str, ViewOutput]
                                   ) -> float:
        # 视图间预测一致性-KL散度均值; 低一致性应降低融合置信度.
        names = list(view_outputs.keys())
        if len(names) < 2:
            return 0.0

        total_kl = 0.0
        pair_count = 0
        for i in range(len(names)):
            for j in range(i + 1, len(names)):
                p = view_outputs[names[i]].probabilities.flatten()
                q = view_outputs[names[j]].probabilities.flatten()
                eps = 1e-12
                kl_ij = float(np.sum(p * np.log((p + eps) / (q + eps))))
                kl_ji = float(np.sum(q * np.log((q + eps) / (p + eps))))
                total_kl += (kl_ij + kl_ji) / 2.0
                pair_count += 1
        return total_kl / max(1, pair_count)

    def compute_total_loss(self,
                           fusion: MultiViewFusion,
                           labels: np.ndarray) -> float:
        # 总损失 = 交叉熵 + 一致性正则
        eps = 1e-8
        probs_flat = fusion.fused_probs.flatten()
        if len(probs_flat) >= 2 and len(labels) > 0:
            ce = -float(np.mean(
                labels * np.log(probs_flat[1] if len(probs_flat) > 1 else probs_flat[0] + eps) +
                (1 - labels) * np.log(probs_flat[0] if len(probs_flat) > 1 else (1 - probs_flat[0]) + eps)))
        else:
            ce = 0.0
        return ce + self._consistency_weight * fusion.consistency_loss

    def step_epoch(self):
        self._epoch += 1

    def get_dominant_view(self, fusion: MultiViewFusion) -> str:
        if not fusion.view_weights:
            return "none"
        return max(fusion.view_weights, key=fusion.view_weights.get)
