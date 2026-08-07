# 修改记录:
# 2025-08-09 08:22 — 初始实现：基于事件计数的补丁效力衰减检测
# 2025-08-10 14:51 — 引入 Bayesian 更新：观测数据更新衰减模型的后验
# 2025-08-12 11:08 — 多信号融合：执行迹偏离 + 内存布局漂移 + 调用图变化

"""Live Patch Efficacy Watchdog — 运行时补丁效力监控。

与 temporal_reliability 的关键差异：
  temporal_reliability 是静态模型：R(t) = R₀ · exp(-λ·t) · d(env)。
  本模块是动态监控：从运行时观测数据推断补丁的实际效力衰减，
  反馈修正静态模型的参数。

观测信号（三重验证）：
  1. 执行迹偏离度：补丁代码路径的运行时频率变化
  2. 内存布局漂移：堆/栈对象偏移与补丁假设的偏移比较
  3. 调用图变化：补丁插入的函数是否仍被正确调用

Bayesian 更新机制：
  先验 = temporal_reliability 的 R(t) 估计
  似然 = 观测信号与预期值的偏差
  后验 = 更新后的效力估计（用于触发 refresh 告警）

// 设计依据：
//   - 现有 patch presence 工具可检测补丁是否被应用（binary presence），
//     但不能检测补丁是否仍有效（runtime efficacy）。
//   - 本模块填补这一空白：从 "patch present" 到 "patch effective"。
//   - CUSUM 漂移检测借鉴工业过程控制，
//     本模块对三个独立信号各自运行 CUSUM，多数投票触发告警。
"""

import os
import math
import time
import hashlib
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Set
from enum import Enum
from collections import deque

_log = logging.getLogger(__name__)


class EfficacyState(str, Enum):
    HEALTHY = "healthy"                  # 效力 ≥ 0.90
    DEGRADING = "degrading"              # 0.50 ≤ 效力 < 0.90
    INEFFECTIVE = "ineffective"          # 效力 < 0.50
    UNKNOWN = "unknown"


@dataclass
class WatchdogSignal:
    """单次观测信号。"""
    timestamp: float = 0.0
    # 执行迹偏离度 (0..1, 0=完美匹配)
    trace_divergence: float = 0.0
    # 内存布局漂移 (0..1)
    memory_drift: float = 0.0
    # 调用图变化 (0..1)
    callgraph_churn: float = 0.0
    # 合成效力指标
    composite_efficacy: float = 1.0


@dataclass
class EfficacyReport:
    """效力监控报告。"""
    patch_id: str = ""
    state: EfficacyState = EfficacyState.UNKNOWN
    current_efficacy: float = 1.0
    initial_efficacy: float = 1.0      # 补丁应用时的初始效力
    prior_efficacy: float = 1.0         # 静态模型预测值
    posterior_efficacy: float = 1.0     # Bayesian 更新后值
    observations_count: int = 0
    # 三个 CUSUM 检测器状态
    cusum_trace: float = 0.0
    cusum_memory: float = 0.0
    cusum_callgraph: float = 0.0
    # 告警
    alert_triggered: bool = False
    alert_reason: str = ""
    recommendation: str = ""
    last_observation_at: float = 0.0

    def to_dict(self) -> Dict:
        return {
            'patch_id': self.patch_id,
            'state': self.state.value,
            'efficacy': round(self.current_efficacy, 4),
            'prior': round(self.prior_efficacy, 4),
            'posterior': round(self.posterior_efficacy, 4),
            'observations': self.observations_count,
            'cusum': [round(self.cusum_trace, 4),
                      round(self.cusum_memory, 4),
                      round(self.cusum_callgraph, 4)],
            'alert': self.alert_triggered,
            'alert_reason': self.alert_reason,
            'recommendation': self.recommendation,
            'last_obs_at': self.last_observation_at,
        }


# CUSUM 漂移检测器（三通道）

class CUSUMDetector:
    """单信号 CUSUM 累积和漂移检测。

    参数：
      threshold: 累积和超此值触发漂移告警
      drift_allowance: 允许的正常波动幅度
    """

    def __init__(self, threshold: float = 2.0, drift_allowance: float = 0.05):
        self._threshold = threshold
        self._drift = drift_allowance
        self._cusum_pos = 0.0
        self._cusum_neg = 0.0
        self._value_count = 0

    def update(self, value: float) -> Tuple[float, bool]:
        """输入新观测值，返回 (累积和, 是否触发)。"""
        z = value - self._drift
        self._cusum_pos = max(0.0, self._cusum_pos + z)
        self._cusum_neg = max(0.0, self._cusum_neg - z)
        self._value_count += 1
        triggered = (self._cusum_pos > self._threshold or
                     self._cusum_neg > self._threshold)
        return max(self._cusum_pos, self._cusum_neg), triggered

    def reset(self):
        self._cusum_pos = 0.0
        self._cusum_neg = 0.0

    @property
    def current_value(self) -> float:
        return max(self._cusum_pos, self._cusum_neg)


# Bayesian 效力更新器

class BayesianEfficacyUpdater:
    """使用观测信号对静态效力估计做 Bayesian 更新。

    模型：
      先验：R_prior ~ Beta(α₀, β₀)，从 temporal_reliability 的 R(t) 映射
      似然：观测信号 composite_efficacy 视为二项试验的成功概率
      后验：Beta(α₀ + 观测成功数, β₀ + 观测失败数)

    Beta 分布的共轭性保证更新为闭式解，不需要 MCMC。
    """

    def __init__(self, prior_mean: float = 0.95, prior_strength: float = 5.0):
        # prior_strength = α₀ + β₀，越大表示对先验越有信心
        self._alpha_0 = prior_mean * prior_strength
        self._beta_0 = (1.0 - prior_mean) * prior_strength
        self._alpha = self._alpha_0
        self._beta = self._beta_0
        self._obs_successes = 0.0
        self._obs_failures = 0.0

    def set_prior(self, efficacy: float, confidence: float = 5.0):
        """从外部估计设置先验（如 temporal_reliability 的输出）。"""
        self._alpha_0 = efficacy * confidence
        self._beta_0 = (1.0 - efficacy) * confidence
        self._alpha = self._alpha_0
        self._beta = self._beta_0

    def update(self, signal: WatchdogSignal):
        """用一次观测更新后验。"""
        # 将 composite_efficacy 映射为伪计数
        eff = max(0.001, min(0.999, signal.composite_efficacy))
        weight = 0.5 + 0.5 * (1.0 - max(signal.trace_divergence,
                                         signal.memory_drift,
                                         signal.callgraph_churn))
        self._obs_successes += eff * weight
        self._obs_failures += (1.0 - eff) * weight
        self._alpha = self._alpha_0 + self._obs_successes
        self._beta = self._beta_0 + self._obs_failures

    @property
    def posterior_mean(self) -> float:
        return self._alpha / (self._alpha + self._beta) if (self._alpha + self._beta) > 0 else 0.5

    @property
    def posterior_std(self) -> float:
        total = self._alpha + self._beta
        if total <= 0:
            return 0.0
        variance = (self._alpha * self._beta) / (total * total * (total + 1))
        return math.sqrt(variance)

    @property
    def prior_mean(self) -> float:
        return self._alpha_0 / (self._alpha_0 + self._beta_0) if (self._alpha_0 + self._beta_0) > 0 else 0.5


# 效力监控主引擎

class EfficacyWatchdog:
    """补丁效力运行时监控。

    用法:
        dog = EfficacyWatchdog(patch_id='CVE-2024-0001', prior_efficacy=0.95)
        signal = dog.observe(trace_div=0.02, mem_drift=0.01, cg_churn=0.0)
        if dog.report.alert_triggered:
            print(f"补丁效力下降: {dog.report.recommendation}")
    """

    def __init__(self, patch_id: str = "",
                 prior_efficacy: float = 0.95,
                 prior_confidence: float = 5.0):
        self.patch_id = patch_id
        self._cusum_trace = CUSUMDetector(threshold=2.0, drift_allowance=0.03)
        self._cusum_memory = CUSUMDetector(threshold=2.5, drift_allowance=0.04)
        self._cusum_cg = CUSUMDetector(threshold=3.0, drift_allowance=0.05)
        self._bayes = BayesianEfficacyUpdater(prior_efficacy, prior_confidence)
        self._signals: deque = deque(maxlen=100)  # 滚动窗口
        self._report = EfficacyReport(patch_id=patch_id,
                                       initial_efficacy=prior_efficacy)
        self._window_size = 8  # 用于异常检测的滑动窗口大小

    def observe(self, trace_divergence: float = 0.0,
                memory_drift: float = 0.0,
                callgraph_churn: float = 0.0) -> EfficacyReport:
        """提交一次观测并返回更新后的效力报告。"""
        now = time.time()

        # 合成效力 = 1 - max(三信号加权)
        composite = 1.0 - max(
            0.40 * trace_divergence,
            0.35 * memory_drift,
            0.25 * callgraph_churn,
        )
        composite = max(0.0, min(1.0, composite))

        signal = WatchdogSignal(
            timestamp=now,
            trace_divergence=trace_divergence,
            memory_drift=memory_drift,
            callgraph_churn=callgraph_churn,
            composite_efficacy=composite,
        )
        self._signals.append(signal)

        # 更新三个 CUSUM 检测器
        c1, t1 = self._cusum_trace.update(trace_divergence)
        c2, t2 = self._cusum_memory.update(memory_drift)
        c3, t3 = self._cusum_cg.update(callgraph_churn)

        # Bayesian 更新
        self._bayes.update(signal)

        # 多数投票告警（至少 2/3 检测器触发）
        alert_votes = sum([t1, t2, t3])
        alert = alert_votes >= 2

        # 效力状态判定
        efficacy = self._bayes.posterior_mean
        if efficacy >= 0.90:
            state = EfficacyState.HEALTHY
        elif efficacy >= 0.50:
            state = EfficacyState.DEGRADING
        else:
            state = EfficacyState.INEFFECTIVE

        # 告警原因
        reasons = []
        if t1: reasons.append("执行迹偏离")
        if t2: reasons.append("内存布局漂移")
        if t3: reasons.append("调用图变化")
        reason = "; ".join(reasons) if reasons else ""

        # 建议
        if state == EfficacyState.INEFFECTIVE:
            rec = "立即刷新补丁——效力已不可接受"
        elif state == EfficacyState.DEGRADING and alert:
            rec = "安排补丁重新评估，当前效力 %.1f%%" % (efficacy * 100)
        elif state == EfficacyState.DEGRADING:
            rec = "持续监控，下次观测窗口内关注效力趋势"
        else:
            rec = "无需操作"

        self._report = EfficacyReport(
            patch_id=self.patch_id,
            state=state,
            current_efficacy=efficacy,
            initial_efficacy=self._report.initial_efficacy,
            prior_efficacy=self._bayes.prior_mean,
            posterior_efficacy=efficacy,
            observations_count=len(self._signals),
            cusum_trace=c1, cusum_memory=c2, cusum_callgraph=c3,
            alert_triggered=alert,
            alert_reason=reason,
            recommendation=rec,
            last_observation_at=now,
        )
        return self._report

    def efficacy_trend(self, window: int = 10) -> List[float]:
        """最近 window 次观测的效力趋势线。"""
        recent = list(self._signals)[-window:]
        return [s.composite_efficacy for s in recent]

    def is_degrading(self) -> bool:
        """趋势检测：最近窗口的效力是否持续下降。"""
        trend = self.efficacy_trend(self._window_size)
        if len(trend) < 3:
            return False
        # 简单线性回归斜率
        n = len(trend)
        x_mean = (n - 1) / 2.0
        y_mean = sum(trend) / n
        num = sum((i - x_mean) * (trend[i] - y_mean) for i in range(n))
        den = sum((i - x_mean) ** 2 for i in range(n))
        if den == 0:
            return False
        slope = num / den
        return slope < -0.01  # 持续下降

    def reset(self, new_prior: float = None):
        """重置监控器（补丁刷新后调用）。"""
        if new_prior is not None:
            self._bayes.set_prior(new_prior)
        self._cusum_trace.reset()
        self._cusum_memory.reset()
        self._cusum_cg.reset()
        self._signals.clear()
        self._report = EfficacyReport(patch_id=self.patch_id,
                                       initial_efficacy=new_prior or 0.95)

    @property
    def report(self) -> EfficacyReport:
        return self._report
