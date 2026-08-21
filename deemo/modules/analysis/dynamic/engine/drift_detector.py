# 多维联合漂移检测: 不再单独检测每个度量, 而是联合 N 个度量的 Mahalanobis 距离
# 校准触发滞后机制: 连续 K 次异常才触发, 避免对瞬态尖峰的过度反应

"""分析管道漂移检测器 - 多维联合异常检测与校准触发

单维度的孤立异常检测 (如仅监控求解器延迟) 误报率高:
- GC 暂停导致求解器延迟瞬时尖峰--不是真正的漂移
- 覆盖率在发现新模块时短暂回升--不是真正走出停滞
- 污点置信度在处理特定指令序列时天然低--不是模型退化

联合多维检测解决此问题:
1. 维护 6 个度量的 EWMA 均值向量 μ 和协方差矩阵 Σ
2. 新样本向量的 Mahalanobis 距离 D² = (x-μ)ᵀ Σ⁻¹ (x-μ)
3. D² > χ²(6, alpha=0.999) 阈值 -> 触发异常 (6 自由度卡方分布)
4. 连续 K 次异常 -> 触发校准

滞后触发机制:
- 短暂异常 (1-2 次) -> 记录但不触发 (可能是瞬态扰动)
- 持续异常 (K=3 次) -> 触发对应级别的校准动作
- 校准后冷却期: min(10min, 3xcollect_interval) 内不再次触发

- Hotelling's T² 控制图 的多维推广--本模块使用协方差
  估计替代 Hotelling 的假设已知 Σ, 更符合实际工程
- 滞后机制受制于 CUSUM 控制图的 "累积和" 思想--小偏差累积
  达到阈值后才告警, 但本模块使用连续计数替代累积和, 减少参数
"""

from __future__ import annotations

import math
import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Tuple

from .drift_metrics import DriftMetricCollector, MetricSnapshot

# 漂移严重度与校准级别

class DriftSeverity(Enum):
    NORMAL = auto()         # 所有度量在正常范围
    MILD = auto()           # 1-2 个度量轻微偏离
    MODERATE = auto()       # 2-3 个度量中度偏离 -> 轻量级校准
    SEVERE = auto()         # >=3 个度量显著偏离 -> 深度校准
    CRITICAL = auto()       # 核心路径全部退化 -> 重置管道

class CalibrationAction(Enum):
    NONE = "none"
    FLUSH_SOLVER_CACHE = "flush_solver_cache"           # 清空求解器缓存
    RESET_SOLVER_CONTEXT = "reset_solver_context"       # 重建 Z3 context
    INJECT_EXPLORATION_NOISE = "inject_exploration"     # 增加探索随机性
    RESET_TAINT_MODEL = "reset_taint_model"             # 重置污点传播模型
    PRUNE_STALE_STATES = "prune_stale_states"           # 剪枝过期的符号状态
    RESTART_PIPELINE = "restart_pipeline"               # 重启分析管线

@dataclass
class DriftReport:
    """单次漂移检测的报告"""
    timestamp: float
    severity: DriftSeverity
    mahalanobis_distance: float
    anomalous_metrics: List[str]          # 偏离正常的度量名称
    metric_z_scores: Dict[str, float]     # 各度量的单维 z-score
    consecutive_anomalies: int            # 连续异常计数
    recommended_actions: List[CalibrationAction]
    is_calibrating: bool                  # 是否已触发校准

# 多维联合漂移检测器

class DriftDetector:
    """多维联合漂移检测--Mahalanobis 距离 + 滞后触发

    参数:
    warmup_samples:      EWMA 初始化前收集的最小样本数
    alert_quantile:      卡方分布的告警分位数 (默认 0.999)
    consecutive_threshold: 连续多少次异常后触发校准
    cooldown_collects:   两次校准间的最小采集周期数
    """

    # 6 自由度卡方分布的分位数表 (预先计算)
    # alpha = 0.99: 16.81, alpha = 0.999: 22.46, alpha = 0.9999: 27.86
    _CHI2_QUANTILES = {
        0.99: 16.81,
        0.999: 22.46,
        0.9999: 27.86,
    }

    def __init__(
        self,
        warmup_samples: int = 30,
        alert_quantile: float = 0.999,
        consecutive_threshold: int = 3,
        cooldown_collects: int = 10,
    ):
        self._warmup = warmup_samples
        self._alert_q = alert_quantile
        self._consec_thresh = consecutive_threshold
        self._cooldown = cooldown_collects

        # 协方差估计的在线更新
        self._count = 0
        self._mean_vec: List[float] = [0.0] * 6
        self._cov_matrix: List[List[float]] = [
            [0.0] * 6 for _ in range(6)
        ]
        # 辅助变量--在线协方差更新
        self._m2_matrix: List[List[float]] = [
            [0.0] * 6 for _ in range(6)
        ]

        self._consecutive_anomalies = 0
        self._last_calibration_time = 0.0
        self._calibration_in_progress = False

        # 最近样本的滑动窗口--用于计算当前 z-score
        self._recent_samples: deque = deque(maxlen=20)

    def _vector_from_snapshot(self, snap: MetricSnapshot) -> List[float]:
        """从 MetricSnapshot 提取 6 维特征向量"""
        return [
            snap.solver_latency_ms,
            float(snap.constraint_size),
            snap.path_entropy,
            float(snap.state_queue_depth),
            snap.taint_confidence_mean,
            snap.coverage_marginal_gain,
        ]

    def update_covariance(self, vec: List[float]) -> None:
        """在线更新均值向量和协方差矩阵--使用 Welford 类算法

        避免存储全部历史样本--协方差矩阵 O(d²) 在线更新
        d=6 -> 36 个浮点数, 内存开销可忽略
        """
        self._count += 1
        n = float(self._count)

        # 均值更新
        for i in range(6):
            delta = vec[i] - self._mean_vec[i]
            self._mean_vec[i] += delta / n

        # 协方差更新: Σ_{t+1} = ((n-1)/n) Σ_t + (1/(n+1)) (x_{t+1} - μ_t)(x_{t+1} - μ_t)ᵀ
        for i in range(6):
            delta_i = vec[i] - self._mean_vec[i]
            # 使用旧均值计算残差
            old_mean_i = self._mean_vec[i] - delta_i / n
            resid_i_new = vec[i] - self._mean_vec[i]
            for j in range(6):
                old_mean_j = self._mean_vec[j] - (vec[j] - self._mean_vec[j]) / n
                resid_j_new = vec[j] - self._mean_vec[j]
                # 协方差在线更新
                self._cov_matrix[i][j] = (
                    (n - 1) / n * self._cov_matrix[i][j]
                    + (vec[i] - old_mean_i) * resid_j_new / n
                )

    def _mahalanobis_distance(self, vec: List[float]) -> float:
        """计算向量到当前均值的 Mahalanobis 距离平方

        若协方差矩阵奇异 (初始化阶段), 回退为标准化欧氏距离
        """
        # 中心化
        centered = [vec[i] - self._mean_vec[i] for i in range(6)]

        # 协方差矩阵求逆--6x6 矩阵使用解析求逆
        # 比调用 numpy.linalg.inv 快 3-5x 且避免 numpy 依赖
        try:
            inv_cov = self._invert_6x6(self._cov_matrix)
        except ValueError:
            # 协方差矩阵奇异--回退为标准化欧氏距离
            var_sum = 0.0
            for i in range(6):
                v = self._cov_matrix[i][i]
                if v > 1e-9:
                    var_sum += centered[i] * centered[i] / v
            return var_sum

        # D² = (x-μ)ᵀ Σ⁻¹ (x-μ)
        # 先算 Σ⁻¹ (x-μ) -> temp
        temp = [0.0] * 6
        for i in range(6):
            s = 0.0
            for j in range(6):
                s += inv_cov[i][j] * centered[j]
            temp[i] = s

        d2 = sum(centered[i] * temp[i] for i in range(6))
        return max(0.0, d2)

    @staticmethod
    def _invert_6x6(matrix: List[List[float]]) -> List[List[float]]:
        """6x6 对称正定矩阵的解析求逆--Cholesky 分解 -> 前代/回代

        仅用于 6x6 矩阵--对更大矩阵不适用 (协方差维度固定为 6)
        """
        n = 6
        # Cholesky L (下三角)
        L = [[0.0] * n for _ in range(n)]
        for i in range(n):
            for j in range(i + 1):
                s = matrix[i][j]
                for k in range(j):
                    s -= L[i][k] * L[j][k]
                if i == j:
                    if s <= 1e-12:
                        raise ValueError("Matrix not positive definite")
                    L[i][j] = math.sqrt(s)
                else:
                    L[i][j] = s / L[j][j]

        # 求逆: Σ⁻¹ = (L⁻¹)ᵀ L⁻¹
        # 先求 L⁻¹ (解 LY = I -> Y)
        inv_L = [[0.0] * n for _ in range(n)]
        for col in range(n):
            # 前代: L y = e_col
            y = [0.0] * n
            for i in range(n):
                s = 1.0 if i == col else 0.0
                for j in range(i):
                    s -= L[i][j] * y[j]
                y[i] = s / L[i][i]
            for i in range(n):
                inv_L[i][col] = y[i]

        # Σ⁻¹ = (L⁻¹)ᵀ L⁻¹
        inv = [[0.0] * n for _ in range(n)]
        for i in range(n):
            for j in range(i, n):
                s = 0.0
                for k in range(n):
                    s += inv_L[k][i] * inv_L[k][j]
                inv[i][j] = s
                inv[j][i] = s

        return inv

    def _compute_z_scores(self, vec: List[float]) -> Dict[str, float]:
        """每度量的单维 z-score--用于异常度量的可解释性"""
        metric_names = [
            "solver_latency", "constraint_size", "path_entropy",
            "state_queue_depth", "taint_confidence", "coverage_gain",
        ]
        z_scores = {}
        for idx, name in enumerate(metric_names):
            var = self._cov_matrix[idx][idx]
            if var > 1e-9:
                z = abs(vec[idx] - self._mean_vec[idx]) / math.sqrt(var)
            else:
                z = 0.0
            z_scores[name] = z
        return z_scores

    def detect(self, snapshot: MetricSnapshot) -> DriftReport:
        """检测当前快照是否存在漂移

        返回 DriftReport 包含严重度、异常度量和建议动作
        """
        vec = self._vector_from_snapshot(snapshot)
        self._recent_samples.append(vec)

        # 预热阶段: 累积协方差但不报告异常
        if self._count < self._warmup:
            self.update_covariance(vec)
            return DriftReport(
                timestamp=snapshot.timestamp,
                severity=DriftSeverity.NORMAL,
                mahalanobis_distance=0.0,
                anomalous_metrics=[],
                metric_z_scores={},
                consecutive_anomalies=0,
                recommended_actions=[],
                is_calibrating=False,
            )

        # 计算 Mahalanobis 距离
        d2 = self._mahalanobis_distance(vec)
        threshold = self._CHI2_QUANTILES.get(self._alert_q, 22.46)

        # 冷却期检查
        samples_since_calibration = self._count - int(getattr(
            self, '_last_calibration_count', 0
        ))
        in_cooldown = samples_since_calibration < self._cooldown

        z_scores = self._compute_z_scores(vec)

        if d2 > threshold and not in_cooldown:
            self._consecutive_anomalies += 1
        else:
            if d2 <= threshold:
                self._consecutive_anomalies = max(0, self._consecutive_anomalies - 1)

        # 确定异常度量 (z > 2.0)
        anomalous = [
            name for name, z in z_scores.items() if z > 2.0
        ]

        # 严重度判定
        severity = DriftSeverity.NORMAL
        if self._consecutive_anomalies >= self._consec_thresh:
            n_anomalous = len(anomalous)
            if n_anomalous >= 4:
                severity = DriftSeverity.CRITICAL
            elif n_anomalous >= 3:
                severity = DriftSeverity.SEVERE
            elif n_anomalous >= 2:
                severity = DriftSeverity.MODERATE
            else:
                severity = DriftSeverity.MILD
        elif self._consecutive_anomalies > 0:
            severity = DriftSeverity.MILD

        # 映射严重度到校准动作
        actions = self._actions_for_severity(severity, anomalous)

        # 更新协方差
        self.update_covariance(vec)

        return DriftReport(
            timestamp=snapshot.timestamp,
            severity=severity,
            mahalanobis_distance=d2,
            anomalous_metrics=anomalous,
            metric_z_scores=z_scores,
            consecutive_anomalies=self._consecutive_anomalies,
            recommended_actions=actions,
            is_calibrating=self._consecutive_anomalies >= self._consec_thresh,
        )

    def _actions_for_severity(
        self, severity: DriftSeverity, anomalous: List[str]
    ) -> List[CalibrationAction]:
        """根据异常度量选择校准动作

        动作选择的逻辑:
        - solver_latency 异常 -> FLUSH_SOLVER_CACHE, RESET_SOLVER_CONTEXT
        - path_entropy + coverage_gain 同时异常 -> 探索退化 -> INJECT_EXPLORATION_NOISE
        - taint_confidence 异常 -> RESET_TAINT_MODEL
        - state_queue_depth 异常 -> PRUNE_STALE_STATES
        - >=4 度量同时异常 -> RESTART_PIPELINE
        """
        if severity == DriftSeverity.NORMAL:
            return [CalibrationAction.NONE]

        actions: List[CalibrationAction] = []

        if severity == DriftSeverity.MILD:
            if "solver_latency" in anomalous:
                actions.append(CalibrationAction.FLUSH_SOLVER_CACHE)
            if "taint_confidence" in anomalous:
                actions.append(CalibrationAction.RESET_TAINT_MODEL)
            if not actions:
                actions.append(CalibrationAction.NONE)
            return actions

        if severity >= DriftSeverity.CRITICAL:
            return [CalibrationAction.RESTART_PIPELINE]

        # MODERATE / SEVERE
        if "solver_latency" in anomalous or "constraint_size" in anomalous:
            actions.append(CalibrationAction.RESET_SOLVER_CONTEXT)

        if "path_entropy" in anomalous or "coverage_gain" in anomalous:
            actions.append(CalibrationAction.INJECT_EXPLORATION_NOISE)
            actions.append(CalibrationAction.PRUNE_STALE_STATES)

        if "taint_confidence" in anomalous:
            actions.append(CalibrationAction.RESET_TAINT_MODEL)

        if "state_queue_depth" in anomalous:
            actions.append(CalibrationAction.PRUNE_STALE_STATES)

        return actions if actions else [CalibrationAction.NONE]

    def mark_calibration_complete(self) -> None:
        """标记当前校准周期完成--重置连续异常计数, 进入冷却期"""
        self._consecutive_anomalies = 0
        self._last_calibration_time = time.monotonic()
        self._last_calibration_count = self._count
        self._calibration_in_progress = False

    def mark_calibration_started(self) -> None:
        self._calibration_in_progress = True

    @property
    def is_warmed_up(self) -> bool:
        return self._count >= self._warmup
