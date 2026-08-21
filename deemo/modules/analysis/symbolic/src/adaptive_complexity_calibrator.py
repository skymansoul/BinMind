#
# 自适应复杂度校准器 - 在线检测约束求解时间预测器的精度退化并触发重校准
#
# ConstraintComplexityEstimator 用 SGD 线性回归预测 Z3 求解时间
# 在符号执行的长运行周期中，约束特征分布随探索区域变化而漂移
# （如从数值计算密集区进入字符串处理区），导致初始回归系数失效
#
# 本模块不替代 Estimator--而是在其外侧包装一层漂移检测逻辑：
#   1. 用指数移动平均 (EMA) 追踪预测误差
#   2. 当 EMA 超过阈值或连续 N 次误差超标时，触发重校准
#   3. 重校准策略：增大学习率临时加速适应，或回退到启发式初始权重
#
# 权衡：EMA 的半衰期越短，对瞬时噪声越敏感（误触发重校准）；
# 半衰期越长，对真实漂移的响应越慢（预测器长期失效）
# 当前默认半衰期 50 次求解（约 5-30 秒），在灵敏度和稳定性间取折中

import math
import time
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field

# ConstraintComplexityEstimator 和 ConstraintFeatures 定义在 symexec_opt_passes 中
# 此处仅做类型引用层面的耦合--不 import 具体实现，由调用方注入
# 这保持了模块的零依赖特性，也意味着 calibrator 可以用在任何实现了
# predict(features)->float + 更新(features, actual_time) 接口的预测器上。


@dataclass
class DriftState:
    """漂移检测的状态快照"""
    ema_error: float = 0.0
    consecutive_violations: int = 0
    total_predictions: int = 0
    last_recalibration_time: float = 0.0
    recalibration_count: int = 0


class AdaptiveComplexityCalibrator:
    """在线检测预测精度退化，触发自适应重校准

    调用方在每个求解周期后调用 observe(predicted, actual)
    calibrator 内部维护预测误差的 EMA。当误差系统性偏离基线时
    触发回调--调用方自行决定是临时提学习率还是重置权重
    """

    def __init__(self,
                 ema_halflife: int = 50,
                 error_threshold: float = 2.0,
                 consecutive_threshold: int = 8,
                 min_recalibration_interval: float = 30.0):
        """
        ema_halflife: EMA 半衰期（求解次数），默认 50
        error_threshold: 当 |ema_error| 超过此值（秒）时触发警告
        consecutive_threshold: 连续超限次数达到此值时强制重校准
        min_recalibration_interval: 两次重校准的最小间隔（秒），防抖
        """
        self._halflife = ema_halflife
        self._alpha = 1.0 - math.exp(math.log(0.5) / ema_halflife)
        self._error_threshold = error_threshold
        self._consecutive_threshold = consecutive_threshold
        self._min_interval = min_recalibration_interval

        self._state = DriftState()
        self._baseline_error: Optional[float] = None
        self._recalibration_handlers: List[callable] = []

    def observe(self, predicted: float, actual: float) -> DriftState:
        """记录一次预测-实际对，更新 EMA 并检测漂移

        返回当前 DriftSt 供调用方判断是否需要干预
        """
        error = abs(predicted - actual)
        state = self._state
        state.total_predictions += 1

        # EMA 更新
        if state.total_predictions == 1:
            state.ema_error = error
        else:
            state.ema_error = (self._alpha * error +
                               (1.0 - self._alpha) * state.ema_error)

        # 基线误差：前 20 次预测的简单平均作为"正常"精度参照
        if state.total_predictions <= 20:
            if self._baseline_error is None:
                self._baseline_error = error
            else:
                n = min(state.total_predictions, 20)
                self._baseline_error = (self._baseline_error * (n - 1) + error) / n

        # 漂移判定：EMA 偏离基线超过阈值
        baseline = self._baseline_error or 0.5
        if state.ema_error > baseline * self._error_threshold:
            state.consecutive_violations += 1
        else:
            state.consecutive_violations = max(0, state.consecutive_violations - 1)

        # 触发重校准条件
        if self._should_recalibrate(state):
            self._trigger_recalibration(state)

        return DriftState(
            ema_error=round(state.ema_error, 4),
            consecutive_violations=state.consecutive_violations,
            total_predictions=state.total_predictions,
            last_recalibration_time=state.last_recalibration_time,
            recalibration_count=state.recalibration_count,
        )

    def _should_recalibrate(self, state: DriftState) -> bool:
        if state.consecutive_violations < self._consecutive_threshold:
            return False
        elapsed = time.time() - state.last_recalibration_time
        if elapsed < self._min_interval:
            return False
        return True

    def _trigger_recalibration(self, state: DriftState):
        state.last_recalibration_time = time.time()
        state.recalibration_count += 1
        state.consecutive_violations = 0
        # 重置基线--重校准后预测精度应恢复到新水平
        self._baseline_error = None
        for handler in self._recalibration_handlers:
            try:
                handler(state)
            except Exception:
                pass

    def on_recalibration(self, handler: callable):
        """注册重校准回调。handler 接收 DriftSt 参数"""
        self._recalibration_handlers.append(handler)

    def recommended_learning_rate(self, base_lr: float = 0.01) -> float:
        """根据漂移程度临时学习率

        连续超限次数越多 → 学习率越高（加速适应新分布）
        上限为 base_lr * 5，避免单步更新过冲
        """
        state = self._state
        if state.consecutive_violations <= 2:
            return base_lr
        boost = min(5.0, 1.0 + state.consecutive_violations * 0.5)
        return base_lr * boost

    def should_reset_weights(self) -> bool:
        """连续超限超过 2 倍阈值时，直接重置为启发式初始权重

        此时 SGD 增量调整已无法有效追踪分布变化--需要硬重置
        """
        return self._state.consecutive_violations >= self._consecutive_threshold * 2

    def get_state(self) -> DriftState:
        return DriftState(
            ema_error=round(self._state.ema_error, 4),
            consecutive_violations=self._state.consecutive_violations,
            total_predictions=self._state.total_predictions,
            last_recalibration_time=self._state.last_recalibration_time,
            recalibration_count=self._state.recalibration_count,
        )
