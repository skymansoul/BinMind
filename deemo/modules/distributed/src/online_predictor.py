# 自适应遗忘因子的 RLS 在线执行时间预测
#
# GRL-Sched 与 SpeculativeExecutor 依赖任务执行时间估计 (DAG 节点 exec_time)。
# 现状: 使用静态标注值或简单 EMA，无法跟踪非平稳变化 (如二进制类型切换导致
# 执行时间分布漂移)。
#
# RLS (递归最小二乘) 以指数衰减加权历史观测，在平稳环境中收敛到 Wiener 最优。
# 但固定遗忘因子 λ 在非平稳环境中进退两难:
#   λ 大 → 收敛慢，跟踪变化能力弱
#   λ 小 → 噪声敏感，估计方差大
#
# 本模块: 自适应遗忘因子 (Adaptive Forgetting Factor RLS)。
#   遗忘因子 λ_t 根据预测误差的 CUSUM 统计量自动调节:
# 预测误差持续偏大 → 检测到分布漂移 → λ ↓ (加速遗忘旧数据)
# 预测误差在正常范围 → 环境平稳 → λ ↑ (利用更多历史，降低方差)
#   这使得 RLS 在平稳期有低方差，在漂移时有快速适应能力。
#
# 与现有方案的差异:
# 普通 EMA: 无自适应，无法区分噪声和漂移
#   - Fortescue et al. 的自适应 λ: 基于恒定信息准则，不检测漂移方向
# 本方案: 用 CUSUM 的符号检测漂移方向 (向上/向下)，λ 调节是非对称的
#     (执行时间突然增加 → 快速响应；突然减少 → 较慢响应，避免欠估计)

from __future__ import annotations

import math
import threading
from collections import deque
from typing import Optional, Dict, Tuple


class AdaptiveRLS:
    """自适应遗忘因子的递归最小二乘预测器。

    单变量版本 — 对每个任务独立维护一个实例。
    预测: ŷ_t = θ_t · x_t  (特征 x_t = [1, recent_load, time_of_day, ...])
    更新: θ_{t+1} = θ_t + K_t · (y_t - ŷ_t)
          K_t = P_t · x_t / (λ_t + x_t^T · P_t · x_t)
          P_{t+1} = (I - K_t · x_t^T) · P_t / λ_t

    自适应 λ: 基于标准化预测误差的 CUSUM。
      S_t^+ = max(0, S_{t-1}^+ + e_t - κ)   (上偏 CUSUM)
      S_t^- = max(0, S_{t-1}^- - e_t - κ)   (下偏 CUSUM)
      若 S^+ > H → 检测到上偏漂移 → λ = λ_base - Δ_up
      若 S^- > H → 检测到下偏漂移 → λ = λ_base - Δ_down (幅度较小)
      否则 → λ = λ_base
    """

    def __init__(
        self,
        feature_dim: int = 3,
        lambda_base: float = 0.95,
        delta_lambda_up: float = 0.20,
        delta_lambda_down: float = 0.10,
        kappa: float = 0.8,         # CUSUM 参考值 (标准化残差单位)
        h_threshold: float = 4.0,   # CUSUM 决策阈值
        delta_init: float = 100.0,  # 初始协方差对角值
    ):
        self._dim = feature_dim
        self._lambda_base = lambda_base
        self._delta_up = delta_lambda_up
        self._delta_down = delta_lambda_down
        self._kappa = kappa
        self._H = h_threshold

        # RLS 状态
        self._theta = [0.0] * feature_dim  # 参数向量
        self._P = [[delta_init if i == j else 0.0
                    for j in range(feature_dim)]
                   for i in range(feature_dim)]  # 协方差矩阵
        self._lambda = lambda_base

        # CUSUM 状态
        self._S_up: float = 0.0
        self._S_down: float = 0.0
        self._residual_ema: float = 0.0
        self._residual_std: float = 0.02  # 避免除零

        # 统计
        self._n_updates: int = 0
        self._lock = threading.Lock()

    def predict(self, features: list) -> float:
        """基于当前参数和特征预测执行时间。≥ 0.01 保底。"""
        with self._lock:
            pred = sum(self._theta[i] * features[i] for i in range(self._dim))
        return max(0.01, pred)

    def update(self, features: list, observed: float):
        """用新观测更新参数 + 自适应 λ。

        特征向量特征:
          features[0] = 1.0 (截距 — 基准执行时间)
          features[1] = 机器负载 (0~1)
          features[2] = 一天中的时段特征 (0~1, e.g. hour/24)
        """
        with self._lock:
            pred = sum(self._theta[i] * features[i] for i in range(self._dim))
            error = observed - pred

            # 标准化残差
            self._residual_ema = 0.9 * self._residual_ema + 0.1 * abs(error)
            self._residual_std = 0.9 * self._residual_std + 0.1 * abs(
                abs(error) - self._residual_ema
            )
            norm_error = error / max(self._residual_std, 0.001)

            # CUSUM 更新
            self._S_up = max(0.0, self._S_up + norm_error - self._kappa)
            self._S_down = max(0.0, self._S_down - norm_error - self._kappa)

            # 自适应 λ
            if self._S_up > self._H:
                self._lambda = max(0.60, self._lambda_base - self._delta_up)
            elif self._S_down > self._H:
                self._lambda = max(0.70, self._lambda_base - self._delta_down)
            else:
                self._lambda += 0.01 * (self._lambda_base - self._lambda)
                self._lambda = min(0.99, max(0.60, self._lambda))

            # RLS 更新 (标准公式)
            # K = P·x / (λ + x^T·P·x)
            Px = [0.0] * self._dim
            for i in range(self._dim):
                for j in range(self._dim):
                    Px[i] += self._P[i][j] * features[j]

            denom = self._lambda
            for i in range(self._dim):
                denom += Px[i] * features[i]

            K = [px / max(denom, 0.001) for px in Px]

            # θ_new = θ + K·error
            for i in range(self._dim):
                self._theta[i] += K[i] * error

            # P_new = (I - K·x^T)·P / λ
            P_new = [[0.0] * self._dim for _ in range(self._dim)]
            for i in range(self._dim):
                for j in range(self._dim):
                    ik_term = (1.0 - K[i] * features[i]) if i == j else (
                        -K[i] * features[j]
                    )
                    P_new[i][j] = ik_term * self._P[i][j] / self._lambda

            # 协方差正则化: 每步微量加回对角线，防止 P 坍缩
            for i in range(self._dim):
                P_new[i][i] += 1e-6

            self._P = P_new
            self._n_updates += 1

            # 漂移检测触发后重置 CUSUM (避免同一漂移反复触发)
            if self._S_up > self._H:
                self._S_up = self._H * 0.5
            if self._S_down > self._H:
                self._S_down = self._H * 0.5

    @property
    def lambda_current(self) -> float:
        return self._lambda

    @property
    def theta(self) -> list:
        return list(self._theta)

    def is_drift_detected(self) -> Tuple[bool, str]:
        """当前是否检测到分布漂移及方向。"""
        if self._S_up > self._H:
            return True, "upward"
        if self._S_down > self._H:
            return True, "downward"
        return False, "stable"


class TaskTimePredictor:
    """多任务在线执行时间预测器。

    为每个任务维护独立的 AdaptiveRLS 实例。
    与 DAG 节点执行时间标注集成: 替代静态 exec_time 作为调度权重。
    """

    def __init__(self, feature_dim: int = 3, lambda_base: float = 0.95):
        self._dim = feature_dim
        self._lambda_base = lambda_base
        self._predictors: Dict[str, AdaptiveRLS] = {}
        self._lock = threading.Lock()

    def predict(self, task_id: str, machine_load: float = 0.5,
                time_of_day: float = 0.5) -> float:
        features = [1.0, machine_load, time_of_day]
        with self._lock:
            if task_id not in self._predictors:
                self._predictors[task_id] = AdaptiveRLS(
                    feature_dim=self._dim, lambda_base=self._lambda_base
                )
            return self._predictors[task_id].predict(features)

    def observe(self, task_id: str, actual: float,
                machine_load: float = 0.5, time_of_day: float = 0.5):
        features = [1.0, machine_load, time_of_day]
        with self._lock:
            if task_id not in self._predictors:
                self._predictors[task_id] = AdaptiveRLS(
                    feature_dim=self._dim, lambda_base=self._lambda_base
                )
            self._predictors[task_id].update(features, actual)

    def predict_all(self, dag, machine_load: float = 0.5) -> Dict[str, float]:
        """为 DAG 所有节点预测执行时间。"""
        import time as _time
        hour = _time.localtime().tm_hour
        tod = hour / 24.0
        result = {}
        for nid in dag.node_ids:
            result[nid] = self.predict(nid, machine_load, tod)
        return result

    def get_drifted_tasks(self) -> Dict[str, str]:
        """返回当前检测到分布漂移的任务及方向。"""
        with self._lock:
            return {
                tid: direction
                for tid, p in self._predictors.items()
                for detected, direction in [p.is_drift_detected()]
                if detected
            }

    def stats(self) -> dict:
        with self._lock:
            drift_count = sum(
                1 for p in self._predictors.values()
                if p.is_drift_detected()[0]
            )
            lambdas = [p.lambda_current for p in self._predictors.values()]
            avg_lambda = sum(lambdas) / len(lambdas) if lambdas else 0.0
            return {
                "tracked_tasks": len(self._predictors),
                "drift_detected": drift_count,
                "avg_lambda": round(avg_lambda, 4),
            }
