# 基于迭代邻居均值传播的图异常检测
# 依据: DDGAD 的轨迹动力学扩散异常检测
# "Trajectory Dynamics for Diffusion-Based Graph Anomaly Detection"
# 核心思路: 正常节点在迭代传播过程中表示稳定, 异常节点表现出不稳定/冲突的轨迹动态
# 实现: 线性意见动力学 x_{t+1}=(1-α)x_t + α·mean(neighbors) + noise,
#       不采用完整的扩散 PDE / 拉普拉斯谱分解
# 三个异常信号: 邻居不一致性 / 可靠性权重 / 动态冲突能量
# 注: 方法本身基于线性意见动力学
# 的扩散模拟是独立的实现，不依赖该论文的具体结果。

from __future__ import annotations
import math
import random
import logging
from typing import Dict, List, Optional, Tuple, Any, Set
from collections import defaultdict
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


# 纯Python矩阵运算

def _da_vec_zeros(n: int) -> List[float]:
    return [0.0] * n

def _da_vec_mean(vecs: List[List[float]]) -> List[float]:
    if not vecs:
        return []
    d = len(vecs[0])
    avg = _da_vec_zeros(d)
    for v in vecs:
        for j in range(d):
            avg[j] += v[j]
    n = len(vecs)
    return [x / n for x in avg]

def _da_l2_dist(a: List[float], b: List[float]) -> float:
    return math.sqrt(sum((a[i] - b[i]) ** 2 for i in range(len(a))))

def _da_cosine(a: List[float], b: List[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na < 1e-12 or nb < 1e-12:
        return 0.0
    return max(-1.0, min(1.0, dot / (na * nb)))


# 扩散模拟

class DiffusionSimulator:
    """图上的扩散过程模拟

    DDGAD的核心: 在图上运行离散扩散过程, 观察每个节点表示如何演变。
    正常节点: 平滑收敛到稳态。
    异常节点: 轨迹震荡或偏离邻域共识。
    """

    def __init__(self, diffusion_steps: int = 20,
                 diffusion_rate: float = 0.1,
                 noise_scale: float = 0.01):
        self.n_steps = diffusion_steps
        self.diff_rate = diffusion_rate
        self.noise_scale = noise_scale

    def simulate(self, features: List[List[float]],
                 adjacency: List[List[int]]) -> List[List[List[float]]]:
        """运行扩散过程, 返回每一步的节点表示轨迹"""
        N = len(features)
        if N == 0:
            return []

        D = len(features[0])
        trajectories = []

        # 初始状态
        current = [f[:] for f in features]
        trajectories.append([f[:] for f in current])

        rng = random.Random(42)

        for step in range(self.n_steps):
            next_state = []
            for i in range(N):
                neighbors = adjacency[i] if i < len(adjacency) else []

                if not neighbors:
                    next_state.append(current[i][:])
                    continue

                # 邻居均值
                nb_mean = _da_vec_zeros(D)
                for nb in neighbors:
                    if nb < N:
                        for d in range(D):
                            nb_mean[d] += current[nb][d]
                for d in range(D):
                    nb_mean[d] /= len(neighbors)

                # 扩散更新: x_{t+1} = (1-α)*x_t + α*mean(N(x_t)) + ε
                new_h = _da_vec_zeros(D)
                for d in range(D):
                    diff_term = current[i][d] + self.diff_rate * (nb_mean[d] - current[i][d])
                    noise = rng.gauss(0, self.noise_scale)
                    new_h[d] = diff_term + noise

                next_state.append(new_h)

            current = next_state
            trajectories.append([f[:] for f in current])

        return trajectories


# 异常检测器

@dataclass
class DiffusionAnomalyScore:
    node_index: int
    # DDGAD的三个异常信号
    neighbor_inconsistency: float   # 与邻居轨迹的偏差
    reliability_weight: float       # 轨迹可靠性 (低=异常)
    dynamical_conflict: float       # 动态冲突能量
    # 综合
    anomaly_score: float
    is_anomalous: bool
    # 细节
    trajectory_variance: float = 0.0
    final_deviation: float = 0.0


class DiffusionAnomalyDetector:
    """基于扩散过程的图异常节点检测器

    DDGAD [2026]: 异常节点在扩散过程中表现出不稳定的表示动态。
    正常节点收敛到邻域共识; 异常节点要么剧烈震荡, 要么偏离邻域方向。
    """

    def __init__(self, diffusion_steps: int = 20,
                 diffusion_rate: float = 0.1,
                 anomaly_percentile: float = 95.0,
                 n_simulations: int = 3):
        self.sim = DiffusionSimulator(
            diffusion_steps=diffusion_steps,
            diffusion_rate=diffusion_rate,
        )
        self.percentile = anomaly_percentile
        self.n_sims = n_simulations

    def detect(self, features: List[List[float]],
               adjacency: List[List[int]]) -> List[DiffusionAnomalyScore]:
        """检测图中的异常节点"""
        N = len(features)
        if N == 0:
            return []

        # 运行多次扩散以获得更稳健的信号
        all_signals = []
        for sim_i in range(self.n_sims):
            trajectories = self.sim.simulate(features, adjacency)
            signals = self._extract_signals(trajectories, features, adjacency)
            all_signals.append(signals)

        # 聚合多次模拟的信号
        results = []
        for i in range(N):
            ni_mean = sum(all_signals[sim][i][0] for sim in range(self.n_sims)) / self.n_sims
            rw_mean = sum(all_signals[sim][i][1] for sim in range(self.n_sims)) / self.n_sims
            dc_mean = sum(all_signals[sim][i][2] for sim in range(self.n_sims)) / self.n_sims
            tv_mean = sum(all_signals[sim][i][3] for sim in range(self.n_sims)) / self.n_sims
            fd_mean = sum(all_signals[sim][i][4] for sim in range(self.n_sims)) / self.n_sims

            # 综合异常分数: 加权组合
            anomaly_score = (
                ni_mean * 0.35 +        # 邻居不一致性
                (1.0 - rw_mean) * 0.25 + # 不可靠性
                dc_mean * 0.25 +         # 动态冲突
                tv_mean * 0.10 +         # 轨迹方差
                fd_mean * 0.05           # 最终偏离
            )

            results.append(DiffusionAnomalyScore(
                node_index=i,
                neighbor_inconsistency=ni_mean,
                reliability_weight=rw_mean,
                dynamical_conflict=dc_mean,
                anomaly_score=anomaly_score,
                is_anomalous=False,  # 稍后根据百分位确定
                trajectory_variance=tv_mean,
                final_deviation=fd_mean,
            ))

        # 基于百分位阈值确定异常
        scores = sorted([r.anomaly_score for r in results])
        threshold_idx = int(len(scores) * self.percentile / 100.0)
        threshold = scores[min(threshold_idx, len(scores) - 1)]

        for r in results:
            r.is_anomalous = r.anomaly_score >= threshold

        return results

    def _extract_signals(self, trajectories, init_features, adjacency):
        """从扩散轨迹提取DDGAD三个异常信号"""
        N = len(init_features)
        T = len(trajectories)

        signals = []
        for i in range(N):
            # 1. 邻居不一致性: |x_i(T) - mean(N(x_i(T)))|
            final_state = trajectories[-1][i]
            neighbors = adjacency[i] if i < len(adjacency) else []

            if neighbors:
                nb_final_mean = _da_vec_zeros(len(final_state))
                for nb in neighbors:
                    if nb < N:
                        nb_state = trajectories[-1][nb]
                        for d in range(len(final_state)):
                            nb_final_mean[d] += nb_state[d]
                for d in range(len(final_state)):
                    nb_final_mean[d] /= len(neighbors)
                ni = _da_l2_dist(final_state, nb_final_mean)
                # 归一化
                ni_norm = math.tanh(ni)
                neighbor_inconsistency = ni_norm
            else:
                neighbor_inconsistency = 0.5

            # 2. 可靠性权重: 轨迹平滑度的倒数
            # 平滑轨迹 -> 可靠; 震荡轨迹 -> 不可靠
            total_shift = 0.0
            for t in range(1, T):
                total_shift += _da_l2_dist(trajectories[t][i], trajectories[t - 1][i])
            avg_shift = total_shift / max(T - 1, 1)
            # 可靠性 = exp(-avg_shift) 的形式, 震荡大则可靠性低
            reliability = math.exp(-avg_shift * 2.0)

            # 3. 动态冲突能量: 轨迹方向与邻域方向的余弦距离
            if T >= 3 and neighbors:
                # 节点i的轨迹方向
                own_direction = [
                    trajectories[-1][i][d] - trajectories[0][i][d]
                    for d in range(len(final_state))
                ]
                # 邻域的平均轨迹方向
                nb_direction = _da_vec_zeros(len(final_state))
                nb_count = 0
                for nb in neighbors:
                    if nb < N:
                        for d in range(len(final_state)):
                            nb_direction[d] += (trajectories[-1][nb][d] -
                                               trajectories[0][nb][d])
                        nb_count += 1
                if nb_count > 0:
                    for d in range(len(final_state)):
                        nb_direction[d] /= nb_count

                conflict = 1.0 - max(0.0, _da_cosine(own_direction, nb_direction))
            else:
                conflict = 0.5

            dynamical_conflict = conflict

            # 4. 轨迹方差 (辅助信号)
            all_positions = [[trajectories[t][i][d] for t in range(T)]
                            for d in range(len(final_state))]
            dim_variances = []
            for dim_pos in all_positions:
                mu = sum(dim_pos) / T
                var = sum((p - mu) ** 2 for p in dim_pos) / T
                dim_variances.append(var)
            trajectory_variance = math.tanh(sum(dim_variances) / max(len(dim_variances), 1))

            # 5. 最终状态偏离初始状态
            final_deviation = math.tanh(
                _da_l2_dist(trajectories[-1][i], init_features[i]))

            signals.append((
                neighbor_inconsistency,
                reliability,
                dynamical_conflict,
                trajectory_variance,
                final_deviation,
            ))

        return signals

    def detect_batch(self, graphs: List[Tuple[List[List[float]], List[List[int]]]]):
        return [self.detect(features, adj) for features, adj in graphs]


# 工厂

def create_diffusion_anomaly_detector(diffusion_steps: int = 20,
                                       anomaly_percentile: float = 95.0):
    return DiffusionAnomalyDetector(
        diffusion_steps=diffusion_steps,
        anomaly_percentile=anomaly_percentile,
    )


def detect_graph_anomalies(features, adjacency, top_k=10):
    """检测并返回前K个异常节点"""
    det = create_diffusion_anomaly_detector()
    results = det.detect(features, adjacency)
    results.sort(key=lambda r: r.anomaly_score, reverse=True)
    return results[:top_k]
