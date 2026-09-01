# EWMA 替代简单滑动窗口: 近期样本权重指数衰减, 对瞬态尖峰鲁棒
# 增加三阶累积量 (偏度) 监控: 分布非对称性先于均值漂移出现

"""分析管道漂移度量收集器 - 多维度信号的时间序列追踪

长运行分析管道 (fuzzing/symbex/sandbox) 持续数天至数周
分析质量随时间缓慢退化:
- 求解器缓存污染 -> Z3 求解延迟中位数上移 2-5x
- 符号状态膨胀 -> 路径多样性在 24h 后自然衰减 40-60%
- 污点精度退化 -> 寄存器部分写入累积误差

传统监控仅追踪 覆盖率/发现的崩溃数--这些是滞后指标
当覆盖率停滞时管道可能已退化数小时

本模块追踪 6 个先行指标--在质量退化达到不可接受水平前触发校准:
1. 求解器延迟趋势 (EWMA + 偏度)
2. 约束复杂度蠕变
3. 路径多样性熵
4. 状态队列深度
5. 污点传播置信度
6. 覆盖率边际收益 (Deltacoverage / Deltatime)
"""

from __future__ import annotations

import math
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


# 指数加权移动平均 (EWMA) - 鲁棒的信号平滑器

class EWMA:
    """指数加权移动平均

    与简单滑动窗口的区别:
    - 滑动窗口对旧样本突然退出窗口时的阶跃敏感
    - EWMA 的权重连续衰减, 不产生阶跃
    - 衰减因子 alpha: 1/(span+1), span=100 -> alpha≈0.01

    .mean: 一阶矩 (位置)
    .var:  二阶矩 (散布)
    .skew: 三阶累积量 (偏度) - 分布方向性变化的早期信号
    """

    def __init__(self, span: int = 100):
        self._alpha = 2.0 / (span + 1)
        self._initialized = False
        self.mean = 0.0
        self._m2 = 0.0                   # 二阶累积量
        self._m3 = 0.0                   # 三阶累积量

    def update(self, value: float) -> None:
        if not self._initialized:
            self.mean = value
            self._m2 = 0.0
            self._m3 = 0.0
            self._initialized = True
            return

        delta = value - self.mean
        # 一阶: Welford 在线均值
        self.mean += self._alpha * delta
        # 二阶: 在线方差
        delta2 = value - self.mean
        self._m2 = (1 - self._alpha) * (self._m2 + self._alpha * delta * delta2)
        # 三阶: 在线偏度
        delta3 = value - self.mean
        self._m3 = (1 - self._alpha) * (
            self._m3 + self._alpha * (3 * delta2 * self._m2 - self._alpha * delta * delta * delta)
        )

    @property
    def variance(self) -> float:
        return max(0.0, self._m2)

    @property
    def std(self) -> float:
        return math.sqrt(self.variance) if self.variance > 1e-12 else 0.0

    @property
    def skewness(self) -> float:
        """偏度: >0 右偏 (少数高值拉高均值), <0 左偏"""
        if self.variance < 1e-12:
            return 0.0
        return self._m3 / (self.variance ** 1.5)

    def snapshot(self) -> Dict[str, float]:
        return {
            "mean": self.mean,
            "std": self.std,
            "skewness": self.skewness,
            "alpha": self._alpha,
        }


# 信号收集器

@dataclass
class MetricSnapshot:
    timestamp: float
    solver_latency_ms: float = 0.0
    constraint_size: int = 0
    path_entropy: float = 0.0
    state_queue_depth: int = 0
    taint_confidence_mean: float = 0.0
    coverage_marginal_gain: float = 0.0


class DriftMetricCollector:
    """收集并平滑 6 个分析管道质量度量

    每个度量使用独立的 EWMA 实例
    调用方以固定间隔 (如每 60 秒) 调用 collect() 记录当前状态
    """

    def __init__(self, span: int = 100, history_size: int = 200):
        self._ewma: Dict[str, EWMA] = {
            "solver_latency": EWMA(span),
            "constraint_size": EWMA(span),
            "path_entropy": EWMA(span),
            "state_queue_depth": EWMA(span),
            "taint_confidence": EWMA(span),
            "coverage_gain": EWMA(span),
        }
        # 保留原始快照的有限历史--用于离线分析和趋势可视化
        self._history: deque = deque(maxlen=history_size)
        self._collect_count = 0
        self._start_time = time.monotonic()

    def collect(self, snapshot: MetricSnapshot) -> None:
        self._ewma["solver_latency"].update(snapshot.solver_latency_ms)
        self._ewma["constraint_size"].update(float(snapshot.constraint_size))
        self._ewma["path_entropy"].update(snapshot.path_entropy)
        self._ewma["state_queue_depth"].update(float(snapshot.state_queue_depth))
        self._ewma["taint_confidence"].update(snapshot.taint_confidence_mean)
        self._ewma["coverage_gain"].update(snapshot.coverage_marginal_gain)

        self._history.append(snapshot)
        self._collect_count += 1

    def get_trend(self, metric: str) -> Dict[str, float]:
        if metric not in self._ewma:
            return {}
        return self._ewma[metric].snapshot()

    def get_all_trends(self) -> Dict[str, Dict[str, float]]:
        return {name: e.snapshot() for name, e in self._ewma.items()}

    @property
    def uptime_seconds(self) -> float:
        return time.monotonic() - self._start_time

    @property
    def collect_count(self) -> int:
        return self._collect_count

    def get_history(self, metric: str, n: int = 50) -> List[float]:
        values = []
        for snap in list(self._history)[-n:]:
            if metric == "solver_latency":
                values.append(snap.solver_latency_ms)
            elif metric == "constraint_size":
                values.append(float(snap.constraint_size))
            elif metric == "path_entropy":
                values.append(snap.path_entropy)
            elif metric == "state_queue_depth":
                values.append(float(snap.state_queue_depth))
            elif metric == "taint_confidence":
                values.append(snap.taint_confidence_mean)
            elif metric == "coverage_gain":
                values.append(snap.coverage_marginal_gain)
        return values


# 边际覆盖率收益 - 检测覆盖率平台的先行指标

class CoverageMarginalTracker:
    """追踪覆盖率边际收益--比覆盖率绝对值更早发现停滞

    原理: 覆盖率曲线通常是凹的--每新增 1% 覆盖率需要的
    时间指数增长。当边际收益 (Deltacoverage / Deltatime) 低于基线
    N 个标准差时, 覆盖率实质上已停滞--即使绝对值仍在微增
    """

    def __init__(self, window_size: int = 30, threshold_sigma: float = 2.5):
        self._window = deque(maxlen=window_size)
        self._ewma = EWMA(span=50)
        self._threshold_sigma = threshold_sigma

    def update(self, marginal_gain: float) -> None:
        self._window.append(marginal_gain)
        self._ewma.update(marginal_gain)

    def is_stagnating(self) -> bool:
        if len(self._window) < 10:
            return False
        recent_avg = sum(self._window) / len(self._window)
        baseline = self._ewma.mean
        sigma = self._ewma.std

        if sigma < 1e-9:
            return recent_avg < baseline * 0.1

        z_score = (recent_avg - baseline) / sigma
        return z_score < -self._threshold_sigma

    @property
    def current_gain_rate(self) -> float:
        return self._ewma.mean


# 污点传播置信度追踪器

class TaintConfidenceTracker:
    """追踪污点传播的置信度趋势

    污点传播的精度在长时间运行中因以下原因退化:
    - 部分寄存器写入的累积误差 (AH:AL 重叠未准确追踪)
    - SIMD 操作中 lane 对应关系的误判
    - 间接跳转目的地的保守近似 (under-tainting)

    置信度 = 确定性传播 / (确定性传播 + 保守近似传播)
    比率持续下降表示污点模型偏离实际数据流
    """

    def __init__(self, span: int = 100):
        self._ewma = EWMA(span)
        self._precise_count = 0
        self._approximate_count = 0

    def record(self, precise: int, approximate: int) -> float:
        self._precise_count += precise
        self._approximate_count += approximate
        total = precise + approximate
        if total == 0:
            return 0.0
        confidence = precise / total
        self._ewma.update(confidence)
        return confidence

    @property
    def confidence(self) -> float:
        return self._ewma.mean

    @property
    def is_degrading(self) -> bool:
        """置信度是否在显著下降--偏度持续负值表示左偏 (向低值倾斜)"""
        return self._ewma.skewness < -0.5 and self._ewma.mean < 0.7
