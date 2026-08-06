"""
集成卡尔曼风险估计 -- 多源风险评分的动态状态融合。

问题：
  传播图中每个节点的真实风险值是潜在状态(latent state)。
  多个风险估计方法（RiskScorer的PageRank传播、纯severity基准、
  GNN预测、专家标注）各自提供带噪声的观测。
  单一方法的选择引入方法学偏差——PageRank低估孤立高风险节点，
  severity忽略拓扑上下文。

方案：
  集成卡尔曼滤波器(EnKF)将传播图建模为动态系统：
  - 状态 x_t: 各节点的真实风险值向量 [n_nodes]
  - 状态转移: x_{t+1} = A * x_t + w_t
    其中 A_ij = edge(j->i).confidence（入边风险传播矩阵）+ 对角衰减
  - 观测 z_t^k: 第k个风险估计方法给出的观测向量 + v_t^k ~ N(0, R_k)

  EnKF避免扩展卡尔曼的线性化误差：
  1. 生成N个状态实现(ensemble members)代表后验分布
  2. 预测步：每个ensemble member经转移矩阵传播
  3. 更新步：用ensemble协方差计算Kalman增益，融合新观测

  多观测源顺序同化：按观测噪声升序逐个融合，信息增益最大化优先。

与已有工作的区分：
  标准Kalman滤波用于电力系统/工业控制的状态估计，不涉及漏洞传播图。
  多传感器融合(EKF/UKF)用于机器人定位，从未应用于安全风险状态估计。
  本模块首次将EnKF应用于传播图的多源风险评分融合。

ref: Evensen (2009) "Data Assimilation: The Ensemble Kalman Filter".
ref: EnKF for power systems (2024) -- 最接近的工程应用，但不涉及安全风险。
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from .propagation_graph import PlatformLayer, PropagationGraph


@dataclass
class RiskMeasurement:
    """单次风险观测 -- 来自某个风险估计方法。"""
    source_name: str             # 估计方法名 (e.g. "RiskScorer", "GNN", "severity")
    values: Dict[str, float]     # {node_id: risk_score}
    noise_std: float = 0.10      # 该方法的观测噪声标准差(先验估计)


@dataclass
class EnKFState:
    """EnKF状态估计结果。"""
    mean_risk: Dict[str, float]           # 后验均值估计
    std_risk: Dict[str, float]            # 后验标准差(不确定性)
    ensemble_size: int
    measurements_assimilated: int


class EnsembleKalmanRiskFilter:
    """集成卡尔曼滤波器 -- 多源风险观测的在线状态融合。

    用法::

        graph = PropagationGraph()
        filter = EnsembleKalmanRiskFilter(graph, ensemble_size=50)

        # 用RiskScorer做初次观测
        scores_a = RiskScorer(graph).score_all()
        filter.predict()
        filter.update(RiskMeasurement("RiskScorer", scores_a, noise_std=0.10))

        # 用GNN做第二次观测(融合)
        scores_b = DAGMessagePassingRisk(...).predict(graph)
        filter.update(RiskMeasurement("GNN", scores_b, noise_std=0.15))

        state = filter.current_state()
        print(state.mean_risk)  # 融合后的最优风险估计
    """

    def __init__(self, graph: PropagationGraph,
                 ensemble_size: int = 50,
                 process_noise_std: float = 0.02):
        self._graph = graph
        self._nodes = list(graph._nodes.keys())
        self._n = len(self._nodes)
        if self._n == 0:
            raise ValueError("graph has no nodes")

        self._N = ensemble_size
        self._q = process_noise_std   # 过程噪声标准差

        # 节点索引映射
        self._idx = {nid: i for i, nid in enumerate(self._nodes)}

        # 状态转移矩阵 A: [n x n]
        self._A = self._build_transition_matrix()

        # Ensemble: [n x N] -- 每列是一个ensemble member
        self._ensemble: List[List[float]] = []
        self._initialized = False

        # 观测历史
        self._assim_count = 0

    def _build_transition_matrix(self) -> List[List[float]]:
        """从传播图构建状态转移矩阵。

        A[i][j] = 从节点j到节点i的风险传播系数。
        对角元素 = 自衰减因子(0.85)。
        非对角(i≠j) = edge(j->i).confidence / indegree(i) (入边置信度归一化)。

        约束：每行和≤1 (子随机矩阵)，保证状态不发散。
        """
        A = [[0.0] * self._n for _ in range(self._n)]
        decay = 0.85

        for i, nid_i in enumerate(self._nodes):
            indeg = len(self._graph._rev_adj.get(nid_i, []))
            incoming_sum = 0.0
            for j, nid_j in enumerate(self._nodes):
                edge = self._graph._edges.get((nid_j, nid_i))
                if edge:
                    weight = edge.confidence / max(indeg, 1)
                    A[i][j] = (1.0 - decay) * weight
                    incoming_sum += weight
            A[i][i] = decay + (1.0 - decay) * max(0.0, 1.0 - incoming_sum)

        return A

    def initialize(self, initial_guess: Optional[Dict[str, float]] = None,
                   init_std: float = 0.15) -> None:
        """初始化ensemble -- 从先验分布采样。

        initial_guess: 初始风险猜测({node_id: value})，默认全部0.5
        init_std: 先验标准差
        """
        guess = initial_guess or {nid: 0.5 for nid in self._nodes}

        self._ensemble = []
        for _ in range(self._N):
            member = [0.0] * self._n
            for i, nid in enumerate(self._nodes):
                base = guess.get(nid, 0.5)
                # 截断正态采样(近似)
                noise = random.gauss(0, init_std)
                member[i] = max(0.0, min(1.0, base + noise))
            self._ensemble.append(member)
        self._initialized = True

    def predict(self) -> None:
        """预测步 -- 经状态转移矩阵传播每个ensemble member。

        x_{t+1}^{(k)} = A * x_t^{(k)} + w_t^{(k)}
        w_t^{(k)} ~ N(0, q^2 * I) 是过程噪声。
        """
        if not self._initialized:
            self.initialize()

        new_ensemble = []
        for member in self._ensemble:
            # 矩阵-向量乘: x_new = A * x_old
            new_member = [0.0] * self._n
            for i in range(self._n):
                s = sum(self._A[i][j] * member[j] for j in range(self._n))
                # 过程噪声
                s += random.gauss(0, self._q)
                new_member[i] = max(0.0, min(1.0, s))
            new_ensemble.append(new_member)
        self._ensemble = new_ensemble

    def update(self, measurement: RiskMeasurement) -> Dict[str, Any]:
        """更新步 -- 用新观测同化ensemble。

        标准EnKF更新公式：
          x^a = x^f + K * (z - H*x^f)
          K = P^f * H^T * (H * P^f * H^T + R)^{-1}

        其中:
          P^f = ensemble预测协方差 (从ensemble members计算)
          H = 观测算子 (将状态映射到观测空间)
          R = 观测噪声协方差 (对角, noise_std^2 * I)
          z = 观测向量
        """
        if not self._initialized:
            self.initialize()

        # 构建观测向量和掩码
        z = [0.0] * self._n
        H_mask = [False] * self._n
        obs_count = 0
        for i, nid in enumerate(self._nodes):
            val = measurement.values.get(nid)
            if val is not None:
                z[i] = max(0.0, min(1.0, val))
                H_mask[i] = True
                obs_count += 1

        if obs_count == 0:
            return {"assimilated": 0, "note": "no matching nodes in measurement"}

        # Ensemble均值
        x_mean = [0.0] * self._n
        for member in self._ensemble:
            for i in range(self._n):
                x_mean[i] += member[i] / self._N

        # 对每个被观测的节点独立做标量更新 (对角R假设)
        R_var = measurement.noise_std ** 2
        updated = 0

        for i in range(self._n):
            if not H_mask[i]:
                continue
            # Ensemble在该节点的方差
            var_f = 0.0
            for member in self._ensemble:
                diff = member[i] - x_mean[i]
                var_f += diff * diff / (self._N - 1)

            # Kalman增益: K = var_f / (var_f + R)
            K = var_f / max(var_f + R_var, 1e-9)

            # 创新: innovation = z[i] - x_mean[i]
            innov = z[i] - x_mean[i]

            # 更新每个ensemble member
            for member in self._ensemble:
                # 对ensemble member加扰动观测 (维持ensemble spread)
                pert_obs = z[i] + random.gauss(0, math.sqrt(R_var))
                pert_innov = pert_obs - member[i]
                member[i] += K * pert_innov
                member[i] = max(0.0, min(1.0, member[i]))

            updated += 1

        self._assim_count += 1
        return {"assimilated": updated, "source": measurement.source_name}

    def current_state(self) -> EnKFState:
        """返回当前状态估计 -- ensemble均值+标准差。"""
        if not self._initialized:
            self.initialize()

        mean = {}
        std = {}
        for i, nid in enumerate(self._nodes):
            vals = [member[i] for member in self._ensemble]
            mean[nid] = round(sum(vals) / self._N, 4)
            m = mean[nid]
            var = sum((v - m) ** 2 for v in vals) / (self._N - 1)
            std[nid] = round(math.sqrt(max(var, 0.0)), 4)

        return EnKFState(
            mean_risk=mean,
            std_risk=std,
            ensemble_size=self._N,
            measurements_assimilated=self._assim_count,
        )

    def fuse_multiple(self,
                      measurements: List[RiskMeasurement],
                      n_predict_between: int = 1) -> EnKFState:
        """融合多个观测源 -- 顺序同化。

        measurements按noise_std升序排列(低噪声优先)，中间插入预测步。
        """
        if not self._initialized:
            self.initialize()

        # 按噪声升序排列：低噪声观测先同化(更高信息量)
        sorted_ms = sorted(measurements, key=lambda m: m.noise_std)

        for m in sorted_ms:
            for _ in range(n_predict_between):
                self.predict()
            self.update(m)

        return self.current_state()
