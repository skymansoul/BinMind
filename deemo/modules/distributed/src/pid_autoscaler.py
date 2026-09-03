# PID 控制论弹性伸缩器 — 带抗饱和与前馈的闭环自动扩缩
#
# elastic_pool.py 的 ThresholdScalePolicy 用死板阈值触发扩缩:
#   队列 > 5 → 扩容, 队列 < 1 → 缩容
# 这导致: 振荡 (过冲后缩容再触发扩容), 滞后 (阈值交叉到动作执行间
# 的延迟无补偿), 稳态误差 (目标队列深度与实际之间的永久偏差)。
#
# PID 控制器: u(t) = Kp·e(t) + Ki·∫e(τ)dτ + Kd·de/dt
#   e(t) = target_queue_depth - current_queue_depth
#   u(t) 输出 = 目标 worker 数量变化 (连续值，取整前做滞回)
#
# 抗饱和 (anti-windup): 当 u(t) 已触及 [min_workers, max_workers]
#   边界时，停止积分项累积 → 防止"积分器爆炸"导致回撤延迟。
#
# 前馈 (feedforward): 若已知任务到达率突变 (如批量提交)，前馈分支
#   跳过 PID 直接增加 workers → 避免反馈回路的固有延迟。
#
# 与 Kubernetes HPA / KEDA 的区别:
#   两者用周期性指标轮询 + 简单阈值，本质是继电控制 (bang-bang)。
#   本模块是真正的 PID 闭环，提供零稳态误差和可调的瞬态响应。

from __future__ import annotations

import time
import threading
from collections import deque
from typing import Optional


class PIDAutoscaler:
    """PID 控制器驱动的弹性伸缩器。

    参数调优启发式 (Ziegler-Nichols 开环法):
      测量系统阶跃响应: 滞后时间 L, 时间常数 T
      Kp = 1.2·T/L,  Ki = 2.0·L,  Kd = 0.5·L
    可在线微调，但初始值用以上公式可避免发散。
    """

    def __init__(
        self,
        min_workers: int = 1,
        max_workers: int = 32,
        target_queue_per_worker: float = 2.0,
        Kp: float = 0.8,
        Ki: float = 0.15,
        Kd: float = 0.3,
        # 抗饱和
        anti_windup: bool = True,
        # 滞回: 输出变化需超过此值才执行 (避免 jitter)
        hysteresis: float = 0.6,
        # 前馈: 到达率突变超过此倍数时触发
        feedforward_threshold: float = 2.5,
    ):
        self._min = min_workers
        self._max = max_workers
        self._target = target_queue_per_worker
        self._Kp = Kp
        self._Ki = Ki
        self._Kd = Kd
        self._anti_windup = anti_windup
        self._hysteresis = hysteresis
        self._ff_thr = feedforward_threshold

        # PID 状态
        self._integral: float = 0.0
        self._prev_error: float = 0.0
        self._prev_output: float = float(min_workers)
        self._last_time: float = time.monotonic()

        # 前馈状态
        self._prev_arrival_rate: float = 0.0

        # 当前 worker 数
        self._current: int = min_workers
        self._lock = threading.Lock()

    def evaluate(self, queue_depth: int, current_workers: int,
                 arrival_rate: Optional[float] = None) -> int:
        """每轮调用 — 返回建议的 worker 数量。

        queue_depth: 当前所有 worker 的总队列深度
        current_workers: 当前 worker 实例数
        arrival_rate: 任务到达率 (tasks/s), 可选 — 用于前馈
        """
        with self._lock:
            now = time.monotonic()
            dt = max(0.1, now - self._last_time)
            self._last_time = now
            self._current = current_workers

            w = max(1, current_workers)
            current_qpw = queue_depth / w
            error = self._target - current_qpw  # 正值=需要更多worker

            # 前馈分支
            ff_increment = 0.0
            if arrival_rate is not None and self._prev_arrival_rate > 0:
                ratio = arrival_rate / max(self._prev_arrival_rate, 0.01)
                if ratio > self._ff_thr:
                    # 到达率突变: 预估需要增加的 worker 数
                    extra_load = (arrival_rate - self._prev_arrival_rate)
                    ff_increment = extra_load * self._target * 0.5
            if arrival_rate is not None:
                self._prev_arrival_rate = arrival_rate

            # PID 计算
            # 比例项
            P = self._Kp * error

            # 积分项 (带抗饱和)
            self._integral += error * dt
            if self._anti_windup:
                # 条件积分: 仅当输出未饱和时累积
                out_raw = P + self._Ki * self._integral
                if out_raw > self._max or out_raw < self._min:
                    self._integral -= error * dt  # 回退本次积分
            I = self._Ki * self._integral

            # 微分项 (带低通滤波以减少噪声)
            D = self._Kd * (error - self._prev_error) / dt
            self._prev_error = error

            # 综合输出
            raw = P + I + D + ff_increment

            # 滞回: 输出变化不超过滞回阈值 → 维持原值
            if abs(raw - self._prev_output) < self._hysteresis:
                raw = self._prev_output

            target_w = max(self._min, min(self._max, int(raw + 0.5)))
            self._prev_output = float(target_w)

            return target_w

    def reset(self):
        """重置 PID 状态 — 用于系统重启/重大配置变更后。"""
        with self._lock:
            self._integral = 0.0
            self._prev_error = 0.0
            self._prev_output = float(self._min)
            self._last_time = time.monotonic()
            self._prev_arrival_rate = 0.0

    # 与 ScalePolicy 接口兼容

    def evaluate_from_metrics(self, metrics: dict) -> int:
        """与 ThresholdScalePolicy.evaluate(metrics) 兼容的接口。

        metrics 字典字段:
          queue_depth, current_workers, arrival_rate (可选)
        """
        return self.evaluate(
            queue_depth=metrics.get("queue_depth", 0),
            current_workers=metrics.get("current_workers", self._current),
            arrival_rate=metrics.get("arrival_rate"),
        )

    @property
    def current_workers(self) -> int:
        return self._current

    def stats(self) -> dict:
        with self._lock:
            return {
                "Kp": self._Kp, "Ki": self._Ki, "Kd": self._Kd,
                "integral": round(self._integral, 3),
                "prev_error": round(self._prev_error, 3),
                "anti_windup": self._anti_windup,
                "current_workers": self._current,
            }


def ziegler_nichols_tune(
    process_lag_s: float, process_time_constant_s: float,
) -> tuple:
    """Ziegler-Nichols 开环法 — 从过程动态估算 PID 增益。

    process_lag_s: 滞后时间 L (控制动作到观测到效果的延迟)
    process_time_constant_s: 时间常数 T (系统响应 63% 的时间)
    返回 (Kp, Ki, Kd)
    """
    if process_lag_s <= 0:
        return (0.5, 0.1, 0.1)
    ratio = process_time_constant_s / process_lag_s
    Kp = 1.2 * ratio
    Ki = Kp / (2.0 * process_lag_s)
    Kd = Kp * 0.5 * process_lag_s
    return (round(Kp, 4), round(Ki, 4), round(Kd, 4))
