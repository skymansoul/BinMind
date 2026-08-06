# Worker 池弹性扩缩容 — 基于队列积压指标自动调节实例数
# 引用 pull-based worker 调度: 空闲时主动拉取任务，减少冷启动延迟
# 自适应扩缩: 基于队列积压指标自动调节实例数
# 预测性扩缩: 基于线性外推的预调度
#
# 策略组合：阈值扩缩 + 线性预测 + 冷却保护
# 通过回调控制 worker 生命周期（进程/FaaS/Pod），不耦合具体运行时

from __future__ import annotations
from abc import ABC, abstractmethod
from abc import ABC, abstractmethod

import time
import threading
import logging
from collections import deque
from typing import Callable, Optional, List

_log = logging.getLogger(__name__)


# ===== 策略接口层 =====

class ScalePolicy(ABC):
    """扩缩策略抽象基类 — evaluate 返回目标 worker 数量。子类实现须为纯函数，不得包含副作用。"""

    @abstractmethod
    def evaluate(self, metrics: dict) -> int:
        ...


# ===== 阈值策略实现 =====

class ThresholdScalePolicy(ScalePolicy):
    """基于队列深度的三段阈值扩缩。

    阈值区间：
    - scale_up_threshold: 单 worker 积压超此值 → 扩容
    - scale_down_threshold: 单 worker 积压低此值 → 缩容
    - target_queue_per_worker: 单 worker 目标并发数

    弹性策略: 负载超阈值增实例，低于阈值减实例。
    差异在于 Arrow 以 GPU 利用率为指标，此处以队列深度为指标。
    """

    def __init__(
        self,
        min_workers: int = 1,
        max_workers: int = 16,
        scale_up_threshold: float = 5.0,
        scale_down_threshold: float = 1.0,
        target_queue_per_worker: float = 2.0,
        step: int = 1,
    ):
        self.min_workers = min_workers
        self.max_workers = max_workers
        self.scale_up_thr = scale_up_threshold
        self.scale_down_thr = scale_down_threshold
        self.target_per = target_queue_per_worker
        self.step = step

    def evaluate(self, metrics: dict) -> int:
        """metrics 须含: queue_depth, active_workers"""
        qd = metrics.get("queue_depth", 0)
        aw = max(metrics.get("active_workers", 1), 1)

        per_worker = qd / aw
        if per_worker > self.scale_up_thr:
            return min(aw + self.step, self.max_workers)
        if per_worker < self.scale_down_thr:
            return max(aw - self.step, self.min_workers)
        return aw


# ===== 预测策略 — 最小二乘线性外推 =====

class PredictiveScalePolicy(ScalePolicy):
    """基于近期队列深度序列的线性外推预扩容。

    预测性扩缩: 以最小二乘线性回归外推未来负载趋势
    未来一个周期的队列深度。

    窗口建议 10~30：过小则噪声主导，过大则响应滞后。
    """

    def __init__(
        self,
        min_workers: int = 1,
        max_workers: int = 16,
        window: int = 15,
        forecast_horizon: int = 3,
        scale_factor: float = 1.2,
    ):
        self.min_workers = min_workers
        self.max_workers = max_workers
        self.window = window
        self.horizon = forecast_horizon
        self.scale_factor = scale_factor

    def evaluate(self, metrics: dict) -> int:
        history: List[float] = metrics.get("queue_history", [])
        aw = max(metrics.get("active_workers", 1), 1)
        qd = metrics.get("queue_depth", 0)

        if len(history) < self.window:
            return aw  # 历史数据不足，维持当前数量

        recent = history[-self.window:]
        n = len(recent)
        # y = a * x + b 最小二乘拟合
        x_mean = (n - 1) / 2.0
        y_mean = sum(recent) / n
        num = sum((i - x_mean) * (v - y_mean) for i, v in enumerate(recent))
        den = sum((i - x_mean) ** 2 for i in range(n))
        slope = num / den if den != 0 else 0.0
        intercept = y_mean - slope * x_mean

        forecast = intercept + slope * (n - 1 + self.horizon)
        forecast = max(forecast, qd)  # 预测值不低于当前观测值

        target = int(forecast / max(metrics.get("target_per_worker", 2.0), 0.5) * self.scale_factor)
        return max(self.min_workers, min(target, self.max_workers))


# ===== 冷却期护卫 =====

class CooldownGuard:
    """扩缩操作间的强制冷却间隔。

    防止在阈值边界反复振荡（flapping）。
    缩容冷却比扩容更长：缩容后若短时间又需扩容，冷启动代价高。
    冷启动率是弹性调度的关键瓶颈 (实测可达 43%)。
    """

    def __init__(self, scale_up_cooldown: float = 15.0, scale_down_cooldown: float = 60.0):
        self._up_cd = scale_up_cooldown
        self._down_cd = scale_down_cooldown
        self._last_scale_up: float = 0.0
        self._last_scale_down: float = 0.0

    def can_scale_up(self) -> bool:
        return time.monotonic() - self._last_scale_up >= self._up_cd

    def can_scale_down(self) -> bool:
        return time.monotonic() - self._last_scale_down >= self._down_cd

    def record_scale_up(self):
        self._last_scale_up = time.monotonic()

    def record_scale_down(self):
        self._last_scale_down = time.monotonic()


# ===== 池控制器主类 =====

class ElasticPool:
    """Worker 池弹性控制器。

    流程：
    1. 周期采集指标（队列深度、活跃 worker 数）
    2. 执行扩缩策略评估
    3. 通过回调通知外部创建/销毁 worker

    不管理实际 worker 运行时（Celery 进程、K8s Pod、FaaS 函数），仅输出决策。

    用法：
        pool = ElasticPool(scale_up_cb=start_worker_fn, scale_down_cb=stop_worker_fn)
        pool.start()
        ...
        pool.stop()
    """

    def __init__(
        self,
        scale_up_cb: Callable[[int], None] = None,
        scale_down_cb: Callable[[int], None] = None,
        metrics_provider: Callable[[], dict] = None,
        policy: ScalePolicy = None,
        interval: float = 5.0,
    ):
        self._on_scale_up = scale_up_cb or (lambda n: _log.info("scale up → %d", n))
        self._on_scale_down = scale_down_cb or (lambda n: _log.info("scale down → %d", n))
        self._get_metrics = metrics_provider or (lambda: {})
        self._policy = policy or ThresholdScalePolicy()
        self._interval = interval
        self._guard = CooldownGuard()
        self._active_workers = 1
        self._queue_history: deque = deque(maxlen=60)
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()

    # ---- 启停控制 ----

    def start(self):
        if self._thread is not None:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="elastic-pool")
        self._thread.start()
        _log.info("elastic pool started (interval=%.1fs)", self._interval)

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=10)
            self._thread = None

    # ---- 主循环逻辑 ----

    def _loop(self):
        while not self._stop.is_set():
            try:
                self._tick()
            except Exception:
                _log.exception("elastic pool tick error")
            self._stop.wait(self._interval)

    def _tick(self):
        metrics = self._get_metrics()
        qd = metrics.get("queue_depth", 0)
        self._queue_history.append(qd)
        metrics["queue_history"] = list(self._queue_history)
        metrics["active_workers"] = self._active_workers

        target = self._policy.evaluate(metrics)

        if target > self._active_workers and self._guard.can_scale_up():
            delta = target - self._active_workers
            _log.info("scaling up: %d → %d (+%d)", self._active_workers, target, delta)
            self._active_workers = target
            self._guard.record_scale_up()
            self._on_scale_up(delta)

        elif target < self._active_workers and self._guard.can_scale_down():
            delta = self._active_workers - target
            _log.info("scaling down: %d → %d (-%d)", self._active_workers, target, delta)
            self._active_workers = target
            self._guard.record_scale_down()
            self._on_scale_down(delta)

    # ---- 手动干预接口 ----

    def set_worker_count(self, n: int):
        old = self._active_workers
        self._active_workers = max(1, n)
        if self._active_workers > old:
            self._on_scale_up(self._active_workers - old)
        elif self._active_workers < old:
            self._on_scale_down(old - self._active_workers)

    @property
    def active_workers(self) -> int:
        return self._active_workers

    @property
    def state(self) -> dict:
        return {
            "active_workers": self._active_workers,
            "queue_history_len": len(self._queue_history),
        }
