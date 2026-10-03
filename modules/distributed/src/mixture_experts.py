# 混合专家调度策略选择 — 轻量门控网络的多策略自适应融合
#
# adversarial_bandits.py 的 EXP3-IX 每次选单一臂 (hard selection)。
# 混合专家 (Mixture of Experts, MoE) 产生 soft combination——
# 对 K 个专家策略的输出加权平均，权重由门控网络学习。
#
# 本模块的简化 MoE:
#   专家 = {HEFT贪心, GRL-RL调度, 模拟退火, 批处理优先}
#   门控 = 对工作负载特征的 softmax 加权
#   训练 = 每轮观测 makespan → 更新门控参数 (在线梯度)
#
# 与对抗老虎机的互补:
#   EXP3-IX: 适合非平稳/对抗环境，hard selection, 遗憾界 O(√T)
#   MoE:     适合平稳多模态环境，soft blend, 可线性加权组合策略
#   调度器在外层用 CUSUM 检测漂移 → 平稳期用 MoE, 非平稳期切 EXP3-IX

from __future__ import annotations

import math
import random
import threading
from typing import Optional, List, Dict, Tuple


class MoEGatingNetwork:
    """线性门控网络 — softmax(w·x) 输出各专家的权重。

    特征 x = [平均任务执行时间, 任务数, 图密度, 关键路径长度/任务数]
    参数 w 每轮通过在线梯度下降更新。
    """

    def __init__(self, n_experts: int = 4, n_features: int = 4,
                 lr: float = 0.05, seed: Optional[int] = None):
        self._K = n_experts
        self._D = n_features
        self._lr = lr
        self._rng = random.Random(seed)
        # Xavier 初始化
        scale = math.sqrt(2.0 / (n_features + n_experts))
        self._W = [[self._rng.gauss(0, scale) for _ in range(n_features)]
                    for _ in range(n_experts)]

    def forward(self, features: List[float]) -> List[float]:
        """softmax(W·x) → 专家权重。"""
        logits = [sum(self._W[k][j] * features[j]
                      for j in range(min(self._D, len(features))))
                  for k in range(self._K)]
        max_logit = max(logits)
        exps = [math.exp(l - max_logit) for l in logits]
        total = sum(exps)
        return [e / total for e in exps]

    def update(self, features: List[float], expert_losses: List[float]):
        """在线梯度更新 — 最小化 Σ w_k · loss_k。

        ∂(Σ w_k·loss_k)/∂W_{k,j} = w_k·(loss_k - Σ w_i·loss_i)·x_j
        这是 softmax 交叉熵梯度的变体。
        """
        weights = self.forward(features)
        avg_loss = sum(weights[i] * expert_losses[i] for i in range(self._K))

        for k in range(self._K):
            # 若该专家的损失低于均值 → 增加其权重
            grad_factor = weights[k] * (expert_losses[k] - avg_loss)
            for j in range(min(self._D, len(features))):
                self._W[k][j] -= self._lr * grad_factor * features[j]

    def best_expert(self, features: List[float]) -> int:
        """返回当前最高权重的专家索引。"""
        w = self.forward(features)
        return max(range(self._K), key=lambda i: w[i])


class MixtureOfExpertsScheduler:
    """混合专家调度器 — 门控融合多策略。

    4 个专家:
      E0: HEFT 贪心 (makespan 导向)
      E1: GRL RL (学习型, 需训练)
      E2: 模拟退火 (全局搜索)
      E3: 负载均衡优先 (min-max 机器负载)

    每轮:
      1. 提取工作负载特征
      2. 门控网络输出各专家权重
      3. 按权重采样 (或加权) → 选择调度策略
      4. 执行调度，观测 makespan
      5. 更新门控参数
    """

    def __init__(self, n_experts: int = 4, seed: Optional[int] = None):
        self._gate = MoEGatingNetwork(n_experts=n_experts, seed=seed)
        self._expert_names = ["heft", "grl", "sa", "load_balance"]
        self._n_experts = n_experts
        self._last_weights: List[float] = [0.25] * n_experts
        self._lock = threading.Lock()

    def select_expert(self, features: List[float]) -> int:
        with self._lock:
            self._last_weights = self._gate.forward(features)
            # 概率采样 (非 hard max, 保持探索)
            r = random.random()
            cum = 0.0
            for i, w in enumerate(self._last_weights):
                cum += w
                if r <= cum:
                    return i
            return self._n_experts - 1

    def observe(self, features: List[float], expert_losses: List[float]):
        with self._lock:
            self._gate.update(features, expert_losses)

    @property
    def expert_weights(self) -> Dict[str, float]:
        return {
            name: round(w, 4)
            for name, w in zip(self._expert_names, self._last_weights)
        }

    @staticmethod
    def extract_features(dag) -> List[float]:
        """从 DAG 提取工作负载特征向量。

        返回 [avg_exec_time, n_nodes/100, edge_density, critical_path_ratio]
        均为归一化到 [0,1] 的值。
        """
        ids = dag.node_ids
        n = len(ids)
        if n == 0:
            return [0.0, 0.0, 0.0, 0.0]

        exec_times = [dag.node(x).exec_time for x in ids if dag.node(x)]
        avg_exec = sum(exec_times) / n if exec_times else 1.0

        edge_count = sum(len(dag._out.get(x, [])) for x in ids)
        max_edges = n * (n - 1)
        density = edge_count / max(max_edges, 1)

        cp = dag.critical_path()
        cp_ratio = cp / max(sum(exec_times), 0.01)

        return [
            min(1.0, avg_exec / 10.0),
            min(1.0, n / 100.0),
            density,
            min(1.0, cp_ratio),
        ]

    def stats(self) -> dict:
        return {
            "n_experts": self._n_experts,
            "expert_names": self._expert_names,
            "current_weights": self.expert_weights,
        }
