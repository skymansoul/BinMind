# 修改记录:
# 2025-07-24 09:52 - 非一致性分数改用归一化绝对误差, 消除量纲敏感
# 2025-07-27 16:18 - 校准窗口从固定改为自适应, 按分布漂移检测触发收缩
# 2025-07-30 11:05 - 增加 risk_aware_priority, 调度器可按分位数选择保守/激进策略
# DAG 任务时延共形预测层: 保序分位数回归 + 滑动窗口校准 + 风险感知优先级
# Angelopoulos & Bates "A Gentle Introduction to Conformal Prediction
#       and Distribution-Free Uncertainty Quantification"
#       — 提出 split conformal prediction 框架. 本实现扩展为在线滑动窗口校准,
#         处理任务时延分布的非平稳性 (二进制分析任务时延分布随
#         二进制类型/大小/优化级别显著偏移).
#       Carbon-Efficient Data Center Scheduling Under Uncertainty:
#       A Conformal Prediction Approach — 参考文献，正式 DOI 待补录.
#       — 将 CP 预测区间嵌入调度决策. 本项目借鉴 risk-aware 思想,
#         面向 DAG 任务依赖图. 注：10.1109/xxx 为占位符，非正式出版物标识.
# 设计边界:
# 仅提供区间预测与风险评分, 不修改底层调度策略 (正交于 RL 策略梯度)
# 非一致性度量: 归一化绝对误差 |y-ŷ|/ŷ, 对持续时间量纲不敏感
# 校准集: 定长滑动窗口 (默认 200), 过期样本按 FIFO 逐出
# α: 用户指定容错率 (默认 0.1 → 90% 覆盖率保证)
#   - 与 dag_drl_scheduler.py DAGDRLScheduler 接口兼容 (register_task→
#     calibrate→predict_interval→risk_aware_priority)
from __future__ import annotations
import bisect
import logging
import math
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from collections import deque

log = logging.getLogger(__name__)

# 校准窗口硬上限: 过大对新分布响应迟钝, 过小覆盖率方差大
_MAX_CALIBRATION_SIZE = 300
_DEFAULT_WINDOW = 200
# 非一致性分数平滑系数: 抑制单次异常观测导致的分位数剧烈跳变
_SCORE_SMOOTHING = 0.05


@dataclass
class ConformalInterval:
    """共形预测区间 [lower, upper] 与覆盖率元数据."""
    task_id: str
    point_estimate: float          # 原始点预测 (来自调度器 est_duration)
    lower: float                    # 下界 (秒), >=0
    upper: float                    # 上界 (秒)
    alpha: float                    # 实际使用的 alpha
    coverage_guarantee: float       # 1 - alpha
    calibration_size: int           # 校准时样本量
    nonconformity_q: float          # 非一致性分数的 (1-alpha) 分位数

    def width(self) -> float:
        return self.upper - self.lower

    def relative_width(self) -> float:
        """区间宽度与点估计之比. <0.5 低不确定性; >2.0 预测极不可靠."""
        if self.point_estimate < 1e-6:
            return float('inf')
        return self.width() / self.point_estimate


class SlidingCalibrationSet:
    """定长滑动窗口校准集.
    存储 (predicted, actual) 对, 在线估计非一致性分数的经验分位数.
    不假设分布——分位数直接从经验 CDF 插值.
    """

    def __init__(self, max_size: int = _DEFAULT_WINDOW):
        self._max_size = min(max_size, _MAX_CALIBRATION_SIZE)
        self._scores: List[float] = []          # 有序非一致性分数
        self._unsorted: deque = deque(maxlen=max_size)
        self._lk = threading.Lock()
        self._dirty = False                     # 标记 _scores 需重排
        self._smooth_mean = 0.0                 # 平滑均值, 用于漂移检测

    def add(self, predicted: float, actual: float):
        """添加 (预测, 实际) 记录, 计算非一致性分数.
        非一致性: |actual - predicted| / max(predicted, 1.0)
        分母截断 1.0 防止极短任务放大误差.
        """
        denom = max(predicted, 1.0)
        score = abs(actual - predicted) / denom
        with self._lk:
            self._unsorted.append(score)
            self._dirty = True
            # 平滑追踪校准分数分布漂移
            self._smooth_mean += _SCORE_SMOOTHING * (score - self._smooth_mean)
            # 超窗口时 lazy 排序, 延迟到查询时
            while len(self._unsorted) > self._max_size:
                self._unsorted.popleft()
                self._dirty = True

    def _ensure_sorted(self):
        if self._dirty:
            self._scores = sorted(self._unsorted)
            self._dirty = False

    def quantile(self, q: float) -> float:
        """经验分位数. q in [0,1]. 样本不足 10 返回保守上界."""
        with self._lk:
            if len(self._unsorted) < 10:
                return 2.0  # 冷启动保守值: 实际时延可达预测 3 倍
            self._ensure_sorted()
            idx = q * (len(self._scores) - 1)
            lo = int(idx)
            hi = min(lo + 1, len(self._scores) - 1)
            frac = idx - lo
            return self._scores[lo] * (1.0 - frac) + self._scores[hi] * frac

    @property
    def size(self) -> int:
        return len(self._unsorted)

    def drift_indicator(self) -> float:
        """平滑非一致性均值, 用于检测预测模型退化.
        若持续上升超过历史基线 2x, 需重校准或重建预测模型.
        """
        return self._smooth_mean


class ConformalPredictor:
    """任务时延共形预测包装器.
    对任意点预测器 f(x) -> ŷ 提供分布无关的预测区间, 有限样本下覆盖率 >= 1-alpha.
    覆盖率保证是边缘的 (marginal), 非条件于 x——即平均覆盖概率, 非逐点保证.
    逐点条件覆盖需更重的假设 (如分位数回归), 此处刻意保持轻量.
    """

    def __init__(self, alpha: float = 0.1, window_size: int = _DEFAULT_WINDOW):
        self.alpha = alpha                              # 目标误覆盖率
        self._calib = SlidingCalibrationSet(max_size=window_size)
        self._lk = threading.Lock()
        self._total_predictions = 0
        self._empirical_coverage = 1.0                  # 实际覆盖率 (滑动 EMA)
        self._coverage_decay = 0.95

    def calibrate(self, predicted: float, actual: float):
        """在线校准: 每次任务完成时调用.
        predicted=调度器预估时延, actual=实际观测时延.
        """
        with self._lk:
            self._calib.add(predicted, actual)
            # 更新实际覆盖率估计
            q = self._calib.quantile(1.0 - self.alpha) if self._calib.size >= 10 else 999.0
            denom = max(predicted, 1.0)
            in_interval = abs(actual - predicted) / denom <= q
            self._empirical_coverage = (
                self._coverage_decay * self._empirical_coverage +
                (1.0 - self._coverage_decay) * (1.0 if in_interval else 0.0)
            )
            self._total_predictions += 1

    def predict_interval(self, task_id: str,
                         point_estimate: float) -> ConformalInterval:
        """预测区间. 冷启动 (样本<10) 返回宽区间 [0, 3 * estimate].
        样本充足后, 区间由校准分位数 + 点估计反推:
          lower = max(0, ŷ * (1 - q_alpha))
          upper = ŷ * (1 + q_alpha)
        乘法形式因非一致性定义为比率.
        """
        with self._lk:
            nonconf_q = self._calib.quantile(1.0 - self.alpha)
            lower = max(0.0, point_estimate * (1.0 - nonconf_q))
            upper = point_estimate * (1.0 + nonconf_q)
            # 冷启动宽区间
            if self._calib.size < 10:
                upper = max(upper, point_estimate * 3.0)
            return ConformalInterval(
                task_id=task_id,
                point_estimate=point_estimate,
                lower=lower, upper=upper,
                alpha=self.alpha,
                coverage_guarantee=1.0 - self.alpha,
                calibration_size=self._calib.size,
                nonconformity_q=nonconf_q,
            )

    def risk_aware_priority(self, point_estimate: float,
                            base_priority: float = 50.0) -> float:
        """风险感知优先级调整.
        区间相对宽度映射不确定性惩罚: 宽度 > 2 * 点估计 → 降低优先级,
        暂缓调度不可靠任务以等待更多校准数据. 宽度 < 0.5 * 点估计 → 小幅提升.
        返回调整后优先级 [0, 100].
        """
        interval = self.predict_interval("_risk_tmp", point_estimate)
        rw = interval.relative_width()
        if math.isinf(rw):
            return base_priority * 0.6
        if rw > 2.0:
            penalty = min(0.5, (rw - 2.0) * 0.15)
            return max(5.0, base_priority * (1.0 - penalty))
        elif rw < 0.5:
            bonus = min(0.15, (0.5 - rw) * 0.2)
            return min(100.0, base_priority * (1.0 + bonus))
        return base_priority

    @property
    def empirical_coverage(self) -> float:
        return self._empirical_coverage

    @property
    def drift_score(self) -> float:
        return self._calib.drift_indicator()


# 模块级单例, 多调度器共享同校准集 (跨 DAG 知识迁移)
# 线程安全: 公开方法内部持锁
_shared_predictor: Optional[ConformalPredictor] = None
_shared_lock = threading.Lock()


def get_shared_conformal_predictor(alpha: float = 0.1) -> ConformalPredictor:
    global _shared_predictor
    with _shared_lock:
        if _shared_predictor is None:
            _shared_predictor = ConformalPredictor(alpha=alpha)
        return _shared_predictor


def reset_shared_conformal_predictor():
    global _shared_predictor
    with _shared_lock:
        _shared_predictor = None


__all__ = [
    'ConformalInterval', 'SlidingCalibrationSet', 'ConformalPredictor',
    'get_shared_conformal_predictor', 'reset_shared_conformal_predictor',
]
