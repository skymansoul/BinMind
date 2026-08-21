# 自适应校准器+分布偏移检测
# 自适应校准器 - 分布偏移检测与校准集动态维护
#
# 问题: 标准共形预测假设校准集与测试集同分布 (exchangeability).
# 但在CVE场景中, NVD发布策略变更 (2026年4月后停止全量富化)、
# 新漏洞类型出现 (如AI/ML供应链)、利用模式漂移等, 均违反此假设.
#
# 解决方案: 自适应校准器.
# 1. 维护滑动窗口校准集 (最近N条, 覆盖时间窗口W天).
# 2. 持续监测KS统计量 (校准集 vs 测试集分数分布).
# 3. 当分布偏移检测触发时, 自动扩大预测区间宽度 (保守化)
#    或触发校准集更新 (增量学习).
#
# KS检验的在线近似:
#   D_n = sup_x |F_calibration(x) - F_recent(x)|
#   其中F_calibration为校准集经验CDF, F_recent为最近M条预测的经验CDF.
#   若 D_n > threshold * sqrt((n+m)/(n*m)), 触发漂移告警.
#
# 保守化策略:
#   漂移检测后, 将共形分位数 q_hat 临时提升为:
#   q_hat' = min(1.0, q_hat + drift_magnitude * (1 - q_hat))
#   这使预测区间变宽, 在分布不确定时保持覆盖率.
#
# 时间复杂度: O(N_cal · log N_cal) 在校准集更新时; KS检验 O(N · log N).

import math
from collections import deque
from typing import Deque, Dict, List, Optional, Tuple


class CalibrationWindow:
    """带时间衰减的滑动窗口校准集.

    存储 (nonconformity_score, timestamp) 对.
    支持按时间的指数衰减权重: w_i = exp(-λ·(T_now - t_i)).
    衰减因子使近期样本对分位数估计的影响更大.
    """

    def __init__(self, max_size: int = 500, decay_lambda: float = 0.001):
        self._scores: Deque[Tuple[float, float]] = deque()  # (score, timestamp)
        self._max_size = max_size
        self._decay_lambda = decay_lambda
        self._sorted_cache: Optional[List[float]] = None
        self._dirty = True

    def add(self, score: float, timestamp: float):
        """添加一个nonconformity分数."""
        self._scores.append((score, timestamp))
        if len(self._scores) > self._max_size:
            self._scores.popleft()
        self._dirty = True

    def add_batch(self, scores: List[float], timestamps: List[float]):
        """批量添加分数."""
        for s, t in zip(scores, timestamps):
            self._scores.append((s, t))
        while len(self._scores) > self._max_size:
            self._scores.popleft()
        self._dirty = True

    def get_quantile(self, q: float, current_time: float) -> float:
        """计算衰减加权的分位数.

        q ∈ [0, 1], 例如 q=0.9 返回第90百分位数.
        加权分位数: 找到最小x使得 Σ_{s_i≤x} w_i ≥ q · Σ w_i.
        """
        if not self._scores:
            return float('inf')

        weights = [math.exp(-self._decay_lambda * max(current_time - t, 0))
                   for _, t in self._scores]
        total_w = sum(weights)
        if total_w < 1e-10:
            return float('inf')

        # 按分数排序
        indexed = sorted(enumerate(self._scores), key=lambda x: x[1][0])
        cumulative = 0.0
        for idx, (score, _) in indexed:
            cumulative += weights[idx]
            if cumulative >= q * total_w:
                return score

        return indexed[-1][1][0]

    def get_unweighted_quantile(self, q: float) -> float:
        """等权分位数 - 用于KS检验."""
        if not self._scores:
            return float('inf')
        scores = sorted(s[0] for s in self._scores)
        idx = int(math.ceil(q * len(scores))) - 1
        return scores[max(0, min(idx, len(scores) - 1))]

    def all_scores(self) -> List[float]:
        return [s for s, _ in self._scores]

    def size(self) -> int:
        return len(self._scores)


class DriftDetector:
    """基于双样本KS检验的分布偏移检测器.

    维护两个缓冲区: 长期 (校准窗口) 和近期 (最近M次预测结果).
    当D_n超过自适应阈值时发出漂移信号.
    """

    def __init__(self, window_size: int = 50, significance: float = 0.01):
        self._recent_scores: Deque[float] = deque(maxlen=window_size)
        self._significance = significance
        self._drift_count = 0
        self._last_drift_magnitude = 0.0

    def observe(self, score: float):
        self._recent_scores.append(score)

    def check_drift(self, calibration: CalibrationWindow) -> Tuple[bool, float]:
        """执行KS检验, 返回 (drifted, magnitude).

        magnitude ∈ [0, 1]: 经验分布间的最大垂直距离.
        阈值 = c(α)·√((n+m)/(n·m)), c(0.01)≈1.628.
        """
        n = calibration.size()
        m = len(self._recent_scores)
        if n < 20 or m < 10:
            return False, 0.0

        cal_scores = sorted(calibration.all_scores())
        recent_sorted = sorted(self._recent_scores)

        # 双样本KS统计量
        d_max = 0.0
        i, j = 0, 0
        while i < n and j < m:
            if cal_scores[i] < recent_sorted[j]:
                i += 1
            elif cal_scores[i] > recent_sorted[j]:
                j += 1
            else:
                i += 1
                j += 1
            f_cal = i / n
            f_rec = j / m
            d_max = max(d_max, abs(f_cal - f_rec))

        # 阈值
        critical = 1.628 * math.sqrt((n + m) / (n * m))
        drifted = d_max > critical

        if drifted:
            self._drift_count += 1
            self._last_drift_magnitude = d_max
        else:
            self._last_drift_magnitude = max(0.0, self._last_drift_magnitude - 0.01)

        return drifted, d_max

    @property
    def drift_count(self) -> int:
        return self._drift_count

    @property
    def current_magnitude(self) -> float:
        return self._last_drift_magnitude


class AdaptiveCalibrator:
    """自适应共形校准器 - 组合校准窗口与偏移检测.

    核心逻辑:
    1. 从校准窗口获取基准分位数 q_hat.
    2. 检测分布偏移: 若漂移, q_hat ← boosted_q(q_hat, magnitude).
    3. 对新nonconformity分数更新窗口和检测器.
    4. 周期性触发校准窗口修剪 (移除过旧样本, 维持统计效力).
    """

    def __init__(self, window_size: int = 500,
                 drift_window: int = 50,
                 decay_lambda: float = 0.001,
                 boost_factor: float = 0.3,
                 min_coverage: float = 0.80,
                 target_coverage: float = 0.90):
        self._window = CalibrationWindow(window_size, decay_lambda)
        self._detector = DriftDetector(drift_window)
        self._boost_factor = boost_factor
        self._min_coverage = min_coverage
        self._target_coverage = target_coverage
        self._current_alpha = 1.0 - target_coverage  # 显著性水平
        self._empirical_coverage: Deque[float] = deque(maxlen=200)
        self._total_predictions = 0
        self._covered_predictions = 0

    def calibrate(self, nonconformity_scores: List[float],
                  timestamps: Optional[List[float]] = None):
        """初始化校准集."""
        if timestamps is None:
            import time
            now = time.time()
            timestamps = [now] * len(nonconformity_scores)
        self._window.add_batch(nonconformity_scores, timestamps)

    def predict_interval(self, prediction: float,
                         timestamp: Optional[float] = None) -> Tuple[float, float, float]:
        """返回预测区间 [lower, upper] 和调整后的分位数.

        prediction: 点预测值 (如利用概率的点估计).
        返回 (lower_bound, upper_bound, q_hat_used).
        """
        if timestamp is None:
            import time
            timestamp = time.time()

        # 基准分位数
        base_q = self._window.get_quantile(1.0 - self._current_alpha, timestamp)

        # 漂移检测
        drifted, magnitude = self._detector.check_drift(self._window)
        if drifted:
            # 保守化: 提升分位数补偿分布偏移
            boost = self._boost_factor * magnitude
            q_hat = min(1.0, base_q * (1.0 + boost) + boost * (1.0 - base_q))
        else:
            q_hat = base_q

        if q_hat >= float('inf') or q_hat <= 0:
            q_hat = max(prediction, 1.0 - prediction, 0.5)

        lower = max(0.0, prediction - q_hat)
        upper = min(1.0, prediction + q_hat)

        return lower, upper, q_hat

    def update(self, nonconformity_score: float, actual_in_interval: bool,
               timestamp: Optional[float] = None):
        """用新的(nonconformity分数, 实际覆盖结果)更新校准器.

        nonconformity_score: 新预测的nonconformity分数.
        actual_in_interval: 实际值是否落入预测区间.
        """
        if timestamp is None:
            import time
            timestamp = time.time()

        self._window.add(nonconformity_score, timestamp)
        self._detector.observe(nonconformity_score)
        self._empirical_coverage.append(1.0 if actual_in_interval else 0.0)
        self._total_predictions += 1
        if actual_in_interval:
            self._covered_predictions += 1

        # 自适应调整α: 经验覆盖率低于目标时收紧
        if len(self._empirical_coverage) >= 20:
            emp_cov = sum(self._empirical_coverage) / len(self._empirical_coverage)
            if emp_cov < self._target_coverage - 0.05:
                self._current_alpha = max(0.01, self._current_alpha * 0.9)
            elif emp_cov > self._target_coverage + 0.05:
                self._current_alpha = min(0.50, self._current_alpha * 1.05)

    def get_stats(self) -> Dict[str, float]:
        """校准器统计信息."""
        emp_cov = (sum(self._empirical_coverage) / len(self._empirical_coverage)
                   if self._empirical_coverage else 0.0)
        return {
            "window_size": self._window.size(),
            "current_alpha": round(self._current_alpha, 4),
            "empirical_coverage": round(emp_cov, 4),
            "target_coverage": self._target_coverage,
            "drift_count": self._detector.drift_count,
            "drift_magnitude": round(self._detector.current_magnitude, 4),
            "total_predictions": self._total_predictions,
            "covered_fraction": round(
                self._covered_predictions / max(self._total_predictions, 1), 4),
        }
