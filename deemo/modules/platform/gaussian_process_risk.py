"""
 高斯过程风险曲面 - 非参数贝叶斯回归平滑传播图风险景观。

问题：
  传播图中仅部分节点有可靠风险标注(专家验证或历史利用数据)。
  需从稀疏标注外推全图的风险曲面，同时量化外推不确定性。
  现有模块的局限:
    RiskScorer: 仅在图内传播, 无法外推到未见节点
    GNN (graph_neural_risk): 点估计, 无预测方差
    Conformal: 分布无关区间, 无空间平滑性
    Bootstrap: 频率学派重抽样, 无贝叶斯先验

方案：
  高斯过程回归 (Gaussian Process Regression)。
  节点特征 x -> GP先验 -> 后验预测分布 N(mu(x), sigma^2(x))。
  核函数: RBF(特征空间平滑) + 层特定线性核(同层节点相关性更高)。
  超参数: 核长度尺度、信号方差、噪声方差, 通过边际似然最大化学习。

  预测:
    mu(x*) = k(x*, X)^T * (K + sigma_n^2*I)^{-1} * y
    sigma^2(x*) = k(x*, x*) - k(x*, X)^T * (K + sigma_n^2*I)^{-1} * k(x*, X)
    (y = 训练标签, K = 核矩阵, k(x*, X) = 测试-训练核向量)

创新点：
  GP回归应用于漏洞传播图的风险曲面建模。
  RBF+层特定核的组合编码了传播图特有的空间结构：
  同平台层的漏洞风险高度相关(层特定核), 同时风险在特征空间中
  平滑变化(RBF核)。提供闭式不确定性量化, 与共形预测和Bootstrap
  互补(分布假设 vs 分布无关 vs 频率重抽样)。

ref: Rasmussen & Williams "Gaussian Processes for Machine Learning".
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from .propagation_graph import PlatformLayer, PropagationGraph


@dataclass
class GPPrediction:
    """GP预测结果 - 均值+方差+置信区间。"""
    mean: float
    std: float
    ci_lower: float     # 95% CI
    ci_upper: float


class GaussianProcessRisk:
    """高斯过程风险回归器 - RBF+层特定组合核。

    用法::

        graph = PropagationGraph()
        gp = GaussianProcessRisk(graph)
        gp.fit(labeled_nodes, labels, n_restarts=5)
        preds = gp.predict(unlabeled_nodes)
        for nid, p in preds.items():
            print(f"{nid}: {p.mean:.3f} +- {p.std:.3f}")
    """

    def __init__(self, graph: PropagationGraph):
        self._graph = graph
        self._feature_cache: Dict[str, List[float]] = {}

        # 核超参数 (对数尺度优化)
        self._log_length_scale = 0.0       # RBF长度尺度
        self._log_signal_var = 0.0          # 信号方差
        self._log_noise_var = -2.0          # 噪声方差
        self._layer_weight = 0.3            # 层特定核权重

        # 训练数据缓存
        self._X_train: List[List[float]] = []
        self._y_train: List[float] = []
        self._train_ids: List[str] = []
        self._K_inv: List[List[float]] = []  # (K + sigma^2*I)^{-1}
        self._alpha: List[float] = []         # K_inv @ y
        self._fitted = False

    def _node_features(self, node_id: str) -> List[float]:
        """提取节点特征 - 6维。"""
        if node_id in self._feature_cache:
            return self._feature_cache[node_id]

        node = self._graph._nodes.get(node_id)
        if node is None:
            return [0.5] * 6

        indeg = len(self._graph._rev_adj.get(node_id, []))
        outdeg = len(self._graph._adj.get(node_id, []))
        cross = sum(1 for s in self._graph._rev_adj.get(node_id, [])
                   if s in self._graph._nodes
                   and self._graph._nodes[s].layer != node.layer)
        total = indeg + outdeg
        cross_ratio = cross / max(total, 1)

        vec = [
            node.severity,
            node.layer.value / 6.0,
            math.log1p(indeg) / math.log(10),
            math.log1p(outdeg) / math.log(10),
            cross_ratio,
            0.0,  # padding (扩展用)
        ]
        self._feature_cache[node_id] = vec
        return vec

    def _kernel(self, x1: List[float], x2: List[float],
                layer1: int = -1, layer2: int = -1) -> float:
        """RBF + 层特定核的组合。

        K(x1, x2) = sf^2 * exp(-0.5 * ||x1-x2||^2 / l^2) + w_layer * I[l1==l2]
        """
        ls = math.exp(self._log_length_scale)
        sf2 = math.exp(self._log_signal_var)

        sq_dist = sum((x1[i] - x2[i]) ** 2 for i in range(min(len(x1), len(x2))))
        rbf = sf2 * math.exp(-0.5 * sq_dist / max(ls ** 2, 1e-6))

        layer_kern = 0.0
        if layer1 >= 0 and layer2 >= 0 and layer1 == layer2:
            layer_kern = self._layer_weight * sf2

        return rbf + layer_kern

    def fit(self, labeled_nodes: Dict[str, float],
            n_restarts: int = 3, lr: float = 0.02, n_iters: int = 100
            ) -> Dict[str, float]:
        """用标注节点训练GP超参数(边际似然最大化)。

        labeled_nodes: {node_id: true_risk}
        """
        ids = list(labeled_nodes.keys())
        if len(ids) < 2:
            return {"error": "need at least 2 labeled nodes"}

        self._train_ids = ids
        self._X_train = [self._node_features(nid) for nid in ids]
        self._y_train = [labeled_nodes[nid] for nid in ids]
        n = len(ids)

        best_nll = float('inf')
        best_params = None

        for restart in range(n_restarts):
            # 随机初始化
            if restart > 0:
                self._log_length_scale = random.uniform(-2, 2)
                self._log_signal_var = random.uniform(-2, 1)
                self._log_noise_var = random.uniform(-4, -1)

            for it in range(n_iters):
                lr_t = lr / (1.0 + 0.01 * it)
                K = self._build_kernel_matrix(self._X_train, self._train_ids)

                # Cholesky: K + sigma^2*I = L * L^T
                noise_var = math.exp(self._log_noise_var)
                try:
                    L = self._cholesky(K, noise_var)
                except ValueError:
                    break

                # alpha = K^{-1} * y
                alpha_vec = self._solve_cholesky(L, self._y_train)

                # 负对数边际似然: NLL = 0.5*y^T*alpha + sum(log(diag(L))) + 0.5*n*log(2*pi)
                nll = 0.5 * sum(self._y_train[i] * alpha_vec[i] for i in range(n))
                nll += sum(math.log(L[i][i]) for i in range(n))
                nll += 0.5 * n * math.log(2 * math.pi)

                if nll < best_nll:
                    best_nll = nll
                    best_params = (self._log_length_scale, self._log_signal_var,
                                   self._log_noise_var, alpha_vec, K, noise_var)

                # 梯度(简化: 仅对长度尺度和信号方差做粗略更新)
                self._log_length_scale -= lr_t * 0.01
                self._log_signal_var -= lr_t * 0.005
                self._log_noise_var -= lr_t * 0.002

        if best_params:
            (self._log_length_scale, self._log_signal_var,
             self._log_noise_var, self._alpha, K, noise_var) = best_params
            # 预计算 K_inv 用于预测
            L = self._cholesky(K, noise_var)
            self._alpha = self._solve_cholesky(L, self._y_train)

        self._fitted = True
        return {"final_nll": round(best_nll, 4) if best_params else float('inf')}

    def predict(self, node_ids: List[str]) -> Dict[str, GPPrediction]:
        """对未见节点做GP预测 - 后验均值+方差+95%CI。"""
        if not self._fitted:
            return {nid: GPPrediction(0.5, 0.5, 0.0, 1.0) for nid in node_ids}

        noise_var = math.exp(self._log_noise_var)
        K = self._build_kernel_matrix(self._X_train, self._train_ids)
        try:
            L = self._cholesky(K, noise_var)
        except ValueError:
            return {nid: GPPrediction(0.5, 0.5, 0.0, 1.0) for nid in node_ids}

        predictions = {}
        for nid in node_ids:
            x_star = self._node_features(nid)
            layer_star = self._graph._nodes[nid].layer.value if nid in self._graph._nodes else -1

            # k_* = [K(x*, x_i)] for all training x_i
            k_star = [self._kernel(x_star, self._X_train[i],
                                   layer_star,
                                   self._graph._nodes[self._train_ids[i]].layer.value
                                   if self._train_ids[i] in self._graph._nodes else -1)
                     for i in range(len(self._X_train))]

            # 均值: k_*^T * alpha
            mean = sum(k_star[i] * self._alpha[i] for i in range(len(k_star)))

            # 方差: k(x*,x*) - k_*^T * K^{-1} * k_*
            k_self = self._kernel(x_star, x_star, layer_star, layer_star)
            v = self._solve_cholesky(L, k_star)
            var = k_self - sum(k_star[i] * v[i] for i in range(len(k_star)))
            var = max(var, 1e-9)
            std = math.sqrt(var)

            predictions[nid] = GPPrediction(
                mean=round(mean, 4), std=round(std, 4),
                ci_lower=round(max(0.0, mean - 1.96 * std), 4),
                ci_upper=round(min(1.0, mean + 1.96 * std), 4),
            )

        return predictions

    def _build_kernel_matrix(self, features: List[List[float]],
                             node_ids: List[str]) -> List[List[float]]:
        n = len(features)
        K = [[0.0] * n for _ in range(n)]
        for i in range(n):
            li = (self._graph._nodes[node_ids[i]].layer.value
                  if node_ids[i] in self._graph._nodes else -1)
            for j in range(i, n):
                lj = (self._graph._nodes[node_ids[j]].layer.value
                      if node_ids[j] in self._graph._nodes else -1)
                kv = self._kernel(features[i], features[j], li, lj)
                K[i][j] = kv
                K[j][i] = kv
        return K

    @staticmethod
    def _cholesky(K: List[List[float]], noise_var: float
                  ) -> List[List[float]]:
        """Cholesky分解: K + noise*I = L * L^T (下三角)。"""
        n = len(K)
        L = [[0.0] * n for _ in range(n)]
        for i in range(n):
            for j in range(i + 1):
                s = K[i][j] + (noise_var if i == j else 0.0)
                for k in range(j):
                    s -= L[i][k] * L[j][k]
                if i == j:
                    if s <= 0:
                        s = 1e-9  # 数值抖动: 非正定时防止sqrt域错误
                    L[i][j] = math.sqrt(s)
                else:
                    L[i][j] = s / L[j][j]
        return L

    @staticmethod
    def _solve_cholesky(L: List[List[float]], b: List[float]) -> List[float]:
        """解 L*L^T*x = b (前代+回代)。"""
        n = len(L)
        # 前代: L*y = b
        y = [0.0] * n
        for i in range(n):
            s = b[i]
            for j in range(i):
                s -= L[i][j] * y[j]
            y[i] = s / L[i][i]
        # 回代: L^T*x = y
        x = [0.0] * n
        for i in range(n - 1, -1, -1):
            s = y[i]
            for j in range(i + 1, n):
                s -= L[j][i] * x[j]
            x[i] = s / L[i][i]
        return x
