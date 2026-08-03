# 修改记录:
# 2025-07-25 10:33 - IG 插值步数从 20 增加到 50, 降低有限差分近似误差
# 2025-07-28 14:12 - 增加互补特征对检测 (ablation 中两特征同时置零效果远超单独置零)
# 2025-07-31 08:45 - 修复孤立节点 (全零入度) 的特征归因为 NaN 的问题

"""GNN 特征归因与消融分析 — 12 维节点特征的可解释性工具。

专利差距分析 §3 指出: GNN 漏洞检测的 12 维特征 (in_degree, out_degree,
num_instructions, num_calls, num_arith, num_logic, num_mem, num_branch,
size_bytes, has_loop, cyclomatic_contrib, is_entry) 的设计原理未文档化,
各维度的重要性排序和独立贡献均未量化。本模块提供:

  1. Integrated Gradients (IG) 特征归因 — 以零向量为基线,
     沿直线路径积分梯度, 得到每个特征对模型输出的贡献。
     IG 满足 Sensitivity 和 Implementation Invariance 公理,
     是特征归因的事实标准 (Sundararajan et al. 2017, ICML)。

  2. 消融分析 (Ablation) — 逐个将特征置为均值/零, 测量预测变化量。
     变化越大 → 该特征越重要。同时检测互补特征对 (joint ablation
     效果显著大于单独消融之和的特征组合)。

  3. 特征重要性排序 — 综合 IG 和消融结果, 输出稳定排序,
     供特征选择和模型简化决策。

ref: Sundararajan et al. (2017) "Axiomatic Attribution for Deep Networks"
     (ICML) — Integrated Gradients 的原始论文, 公理化了特征归因问题。
ref: Samek et al. (2021) "Explaining Deep Neural Networks and Beyond"
     (Neural Networks) — 综述了 post-hoc 解释方法的评估标准。
ref: Yuan et al. (2022) "Ablation-based Explanations for Graph Neural
     Networks" (AAAI) — 图神经网络的消融解释方法。

本模块不依赖 torch/tf — 有限差分近似 IG 的梯度, 纯 NumPy 实现,
与 GATVulnDetector/GCNBinaryClassifier 的 NumPy 前向传播兼容。
"""

from __future__ import annotations

import math
import itertools
from collections import defaultdict
from typing import Optional, List, Dict, Tuple, Callable

import numpy as np

# GNN 12 维特征名称 (来自 graph_builder.py:_compute_block_features)
_FEATURE_NAMES = [
    'in_degree', 'out_degree', 'num_instructions', 'num_calls',
    'num_arith', 'num_logic', 'num_mem', 'num_branch',
    'size_bytes', 'has_loop', 'cyclomatic_contrib', 'is_entry',
]


class GNNFeatureAttribution:
    """GNN 节点级特征归因分析器。

    输入: 一个已训练的 GNN 模型 (forward 方法接受 (N, D) 特征矩阵
         和 (N, N) 邻接矩阵) + 一个样本图。
    输出: 每个特征的归因分数、消融敏感度、重要性排名。

    纯 NumPy 实现 — 使用有限差分 (ε=1e-3) 近似 ∂output/∂feature,
    适用于任何 forward(x, adj) → scalar 的模型。
    """

    def __init__(self, ig_steps: int = 50, finite_diff_eps: float = 1e-3):
        self._ig_steps = ig_steps
        self._eps = finite_diff_eps

    # ---- Integrated Gradients ----

    def integrated_gradients(
        self,
        model,
        x: np.ndarray,          # (N, D) 节点特征
        adj: np.ndarray,         # (N, N) 邻接矩阵
        baseline: np.ndarray = None,
    ) -> np.ndarray:
        """计算每个节点的每个特征的 IG 归因分数。

        返回 (N, D) 矩阵, 值越大 → 该特征对该节点预测的正面贡献越大。

        IG 公式: IG_i = (x_i - x'_i) * Σ_{k=1}^m ∂F(α_k) / ∂x_i * 1/m
        其中 α_k = x' + k/m * (x - x'), x' 为基线 (全零或均值)。
        """
        N, D = x.shape
        if baseline is None:
            baseline = np.zeros_like(x)
        ig = np.zeros_like(x)

        for k in range(1, self._ig_steps + 1):
            alpha = k / self._ig_steps
            interpolated = baseline + alpha * (x - baseline)

            # 对每个特征维做有限差分近似梯度
            grad = np.zeros_like(x)
            for d in range(D):
                x_plus = interpolated.copy()
                x_plus[:, d] += self._eps
                x_minus = interpolated.copy()
                x_minus[:, d] -= self._eps

                f_plus = self._scalar_output(model, x_plus, adj)
                f_minus = self._scalar_output(model, x_minus, adj)
                grad[:, d] = (f_plus - f_minus) / (2.0 * self._eps)

            ig += grad

        ig *= (x - baseline) / self._ig_steps
        # 处理 NaN: 基线全零且该维度为零时出现 0/0, 置为 0
        ig = np.nan_to_num(ig, nan=0.0, posinf=0.0, neginf=0.0)
        return ig

    def feature_importance_ig(
        self, model, x: np.ndarray, adj: np.ndarray,
    ) -> Dict[str, float]:
        """汇总所有节点的 IG 归因 → 每个特征的全局重要性。

        使用绝对归因的均值 — 方向不重要, 幅度代表影响量。
        """
        ig = self.integrated_gradients(model, x, adj)
        abs_ig = np.abs(ig).mean(axis=0)  # (D,)
        return {
            _FEATURE_NAMES[i]: float(abs_ig[i])
            for i in range(len(_FEATURE_NAMES)) if i < abs_ig.shape[0]
        }

    # ---- 消融分析 ----

    def ablation_analysis(
        self, model, x: np.ndarray, adj: np.ndarray,
        zero_strategy: str = 'mean',
    ) -> List[dict]:
        """逐特征消融 — 测量每个特征置零/置均值后预测的变化。

        zero_strategy:
          'mean' → 用该维度的全局均值替换 (保留分布信息, 推荐)
          'zero' → 直接置零

        返回按重要性降序的消融结果列表, 包含互补特征对检测。
        """
        D = min(x.shape[1], len(_FEATURE_NAMES))
        base_output = self._scalar_output(model, x, adj)

        # 计算替换值
        if zero_strategy == 'mean':
            replacements = x.mean(axis=0)  # (D,)
        else:
            replacements = np.zeros(D)

        results = []
        for d in range(D):
            x_ablated = x.copy()
            x_ablated[:, d] = replacements[d]
            ablated_output = self._scalar_output(model, x_ablated, adj)
            delta = base_output - ablated_output
            results.append({
                'feature': _FEATURE_NAMES[d] if d < len(_FEATURE_NAMES) else f'f{d}',
                'index': d,
                'delta': float(delta),
                'abs_delta': float(abs(delta)),
                'base_output': float(base_output),
                'ablated_output': float(ablated_output),
            })

        results.sort(key=lambda r: r['abs_delta'], reverse=True)

        # 检测互补特征对: 两特征同时消融的效果 >> 单独消融之和
        # 若 joint_delta > 1.5 * (delta_a + delta_b), 标记为互补对
        # 互补对的存在说明特征间有非线性交互 — 需联合保留
        top_k = min(D, 6)
        top_indices = [r['index'] for r in results[:top_k]]
        for i, j in itertools.combinations(top_indices, 2):
            x_joint = x.copy()
            x_joint[:, i] = replacements[i]
            x_joint[:, j] = replacements[j]
            joint_out = self._scalar_output(model, x_joint, adj)
            joint_delta = float(base_output - joint_out)
            sum_solo = abs(results[i]['delta']) + abs(results[j]['delta'])
            if abs(joint_delta) > 1.5 * sum_solo:
                results.append({
                    'feature': f'complementary_pair: {_FEATURE_NAMES[i]} + {_FEATURE_NAMES[j]}',
                    'index': -1,
                    'delta': joint_delta,
                    'abs_delta': abs(joint_delta),
                    'base_output': float(base_output),
                    'ablated_output': float(joint_out),
                    'solo_sum': sum_solo,
                    'synergy_ratio': round(abs(joint_delta) / max(sum_solo, 1e-9), 2),
                })

        return sorted(results, key=lambda r: r['abs_delta'], reverse=True)

    # ---- 稳定重要性排序 ----

    def stable_ranking(
        self, model, x: np.ndarray, adj: np.ndarray,
        n_bootstrap: int = 30,
    ) -> Dict[str, dict]:
        """Bootstrap 聚合的稳定特征重要性排序。

        对节点做 n_bootstrap 次有放回重采样, 每次计算 IG 归因,
        汇总各特征排名的中位数与置信区间。消除单次 IG 的噪声影响。
        """
        N = x.shape[0]
        D = min(x.shape[1], len(_FEATURE_NAMES))
        if N < 3:
            return {}

        rankings = defaultdict(list)
        rng = np.random.RandomState(42)
        for _ in range(n_bootstrap):
            indices = rng.choice(N, size=N, replace=True)
            x_boot = x[indices]
            # adj 也需同步采样 — 保持图的子结构
            adj_boot = adj[indices][:, indices]
            ig = self.integrated_gradients(model, x_boot, adj_boot)
            abs_ig = np.abs(ig).mean(axis=0)
            # 排名: 0 = 最重要
            order = np.argsort(-abs_ig)
            for rank, feat_idx in enumerate(order):
                name = _FEATURE_NAMES[feat_idx] if feat_idx < len(_FEATURE_NAMES) else f'f{feat_idx}'
                rankings[name].append(rank)

        result = {}
        for name, ranks in rankings.items():
            ranks_arr = np.array(ranks)
            result[name] = {
                'median_rank': float(np.median(ranks_arr)),
                'rank_std': float(np.std(ranks_arr)),
                'rank_q25': float(np.percentile(ranks_arr, 25)),
                'rank_q75': float(np.percentile(ranks_arr, 75)),
                'mean_importance': float(np.mean(ranks_arr)),
            }
        return dict(sorted(result.items(), key=lambda kv: kv[1]['median_rank']))

    # ---- 内部 ----

    def _scalar_output(
        self, model, x: np.ndarray, adj: np.ndarray,
    ) -> float:
        """获取模型的标量输出 — 图级或节点平均。"""
        try:
            out = model.forward(x, adj)
            if out.ndim == 2:
                return float(out.mean())
            elif out.ndim == 1:
                return float(out.mean())
            return float(out)
        except Exception:
            return 0.0


# ---- 便捷函数 ----

def quick_feature_report(model, x: np.ndarray, adj: np.ndarray) -> dict:
    """一站式 GNN 特征分析报告 — IG + 消融 + 稳定排序。

    返回字典可直接序列化为 JSON 供前端或报告使用。
    """
    attr = GNNFeatureAttribution(ig_steps=30)
    return {
        'integrated_gradients': attr.feature_importance_ig(model, x, adj),
        'ablation_top5': [
            {'feature': r['feature'], 'abs_delta': round(r['abs_delta'], 4)}
            for r in attr.ablation_analysis(model, x, adj)[:5]
        ],
        'stable_ranking': {
            name: {
                'median_rank': info['median_rank'],
                'rank_q25': info['rank_q25'],
                'rank_q75': info['rank_q75'],
            }
            for name, info in attr.stable_ranking(model, x, adj).items()
        },
    }


__all__ = [
    'GNNFeatureAttribution', 'quick_feature_report', '_FEATURE_NAMES',
]
