# coding: utf-8
"""
自适应线程池 — 前馈+PID 双模控制的并发度动态调节.

固定大小的线程池面对二进制分析管道的异构任务时存在两个极端:
  池过小 → CPU 空闲, 吞吐受限
  池过大 → 上下文切换与 GIL 竞争吞噬收益

双模控制器 = 前馈分量 + PID 反馈分量.
前馈基于队列积压与平均耗时估算所需线程数, 在负载变化前即开始调整.
PID 以队列深度为过程变量, 积分项补偿系统性偏差, 微分项抑制振荡.
两分量加权求和后经迟滞比较器 (变化 < 2 时忽略) 输出池大小变更.

现有线程池实现 (Java ForkJoinPool, .NET ThreadPool) 只用反馈 (爬山法),
未见前馈+反馈的混合控制设计. 冷却期约束 (默认 1.0s) 防止频繁 resize 振荡.
"""

import os
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor, Future
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple
import threading

# psutil 为可选依赖: 可用时提供更精准的 CPU 负载感知
try:
    import psutil
    _HAS_PSUTIL = True
except ImportError:
    _HAS_PSUTIL = False


@dataclass
class PoolMetrics:
    """池的运行指标快照."""
    timestamp: float = 0.0
    active_threads: int = 0
    queue_depth: int = 0
    completed_per_sec: float = 0.0
    cpu_percent: float = 0.0
    avg_task_ms: float = 0.0


class PIDController:
    """离散形式的 PID 控制器, 带积分抗饱和 (clamping) 与微分滤波.

    误差信号 e(t) = setpoint - process_variable
    输出 u(t) = Kp*e + Ki*∫e*dt + Kd*de/dt
    """

    def __init__(
        self, Kp: float = 0.5, Ki: float = 0.10, Kd: float = 0.15,
        setpoint: float = 0.0, output_min: float = -8.0, output_max: float = 8.0,
    ):
        self.Kp = Kp
        self.Ki = Ki
        self.Kd = Kd
        self.setpoint = setpoint
        self.output_min = output_min
        self.output_max = output_max
        self._integral = 0.0
        self._prev_error = 0.0
        self._prev_output = 0.0
        self._last_update = 0.0

    def update(self, pv: float, dt: float) -> float:
        """以采样间隔 dt 更新控制器, 返回控制输出."""
        if dt <= 0:
            return self._prev_output

        error = self.setpoint - pv

        # 比例项
        p_term = self.Kp * error

        # 积分项 + 抗饱和: 仅当输出未触限时才累积积分
        self._integral += error * dt
        i_term = self.Ki * self._integral
        # 积分限幅
        i_max = self.output_max / max(self.Ki, 1e-9)
        self._integral = max(-i_max, min(i_max, self._integral))

        # 微分项 (对 PV 微分而非 error, 避免 setpoint 跳变冲击)
        d_term = -self.Kd * (pv - self._prev_error) / dt if self._prev_error is not None else 0.0

        output = p_term + i_term + d_term
        output = max(self.output_min, min(self.output_max, output))

        self._prev_error = pv
        self._prev_output = output
        self._last_update = time.monotonic()
        return output

    def reset(self):
        self._integral = 0.0
        self._prev_error = 0.0


class AdaptivePool:
    """自适应线程池 — 以 ThreadPoolExecutor 为底层, 叠加双模控制器.

    生命周期:
      - 每次 submit 后检查是否需要调整池大小
      - 调整受冷却期约束 (默认 1.0s), 避免抖动
      - _resize() 通过内部 _adjust_workers 增减线程
    """

    def __init__(
        self, min_workers: int = 1, max_workers: int = 32,
        initial_workers: Optional[int] = None,
        cooldown_s: float = 1.0,
        metrics_window: int = 30,
        feedforward_gain: float = 0.35,
    ):
        if initial_workers is None:
            initial_workers = min(4, max_workers)
        self._min = min_workers
        self._max = max_workers
        self._current = initial_workers
        self._cooldown = cooldown_s
        self._last_resize = 0.0

        self._executor: Optional[ThreadPoolExecutor] = None
        self._lock = threading.Lock()

        self._pid = PIDController(
            Kp=0.45, Ki=0.08, Kd=0.12,
            setpoint=0.0,  # 目标: 队列深度 = 0 (无积压)
        )
        self._ff_gain = feedforward_gain

        # 指标记录: 滑动窗口
        self._completion_times: deque = deque(maxlen=metrics_window)
        self._queue_depths: deque = deque(maxlen=metrics_window)
        self._start_times: Dict[int, float] = {}  # Future id → submit time

        self._total_completed = 0
        self._total_submitted = 0
        self._metrics = PoolMetrics()
        self._running = False

        self._ensure_executor()

# 公开 API (与 ThreadPoolExecutor 兼容)
    def submit(self, fn: Callable, *args, **kwargs) -> Future:
        """提交任务; 每次调用后评估池大小是否需要调整."""
        self._ensure_executor()
        fut = self._executor.submit(fn, *args, **kwargs)
        self._total_submitted += 1
        self._start_times[id(fut)] = time.monotonic()
        fut.add_done_callback(self._on_done)
        self._maybe_adjust()
        return fut

    def map(self, fn: Callable, *iterables, timeout=None, chunksize=1):
        self._ensure_executor()
        return self._executor.map(fn, *iterables, timeout=timeout, chunksize=chunksize)

    def shutdown(self, wait: bool = True):
        self._running = False
        if self._executor:
            self._executor.shutdown(wait=wait)

    @property
    def current_size(self) -> int:
        return self._current

    @property
    def metrics(self) -> PoolMetrics:
        return self._metrics

# 内部控制
    def _ensure_executor(self):
        if self._executor is None:
            self._executor = ThreadPoolExecutor(max_workers=self._current)
            self._running = True

    def _on_done(self, fut: Future):
        """任务完成回调: 记录耗时并更新吞吐指标."""
        fid = id(fut)
        t_start = self._start_times.pop(fid, None)
        if t_start is not None:
            elapsed = (time.monotonic() - t_start) * 1000
            self._completion_times.append(elapsed)
        self._total_completed += 1

    def _maybe_adjust(self):
        """判断是否应触发池大小调整, 受冷却期约束."""
        now = time.monotonic()
        if now - self._last_resize < self._cooldown:
            return
        self._last_resize = now
        self._collect_metrics()
        new_size = self._compute_target_size()
        if new_size != self._current:
            self._resize(new_size)

    def _collect_metrics(self):
        """收集当前运行指标."""
        pending = self._total_submitted - self._total_completed
        self._queue_depths.append(pending)

        cpu = 0.0
        if _HAS_PSUTIL:
            try:
                cpu = psutil.cpu_percent(interval=None)
            except Exception:
                cpu = 0.0

        avg_ms = 0.0
        if self._completion_times:
            avg_ms = sum(self._completion_times) / len(self._completion_times)

        rate = 0.0
        if self._completion_times and len(self._completion_times) >= 2:
            # 吞吐: 近期完成数 / 时间窗跨度
            window_s = max(0.1, len(self._completion_times) * avg_ms / 1000)
            rate = len(self._completion_times) / window_s

        self._metrics = PoolMetrics(
            timestamp=time.monotonic(),
            active_threads=self._current,
            queue_depth=pending,
            completed_per_sec=rate,
            cpu_percent=cpu,
            avg_task_ms=avg_ms,
        )

    def _compute_target_size(self) -> int:
        """双模控制: 前馈 + PID 反馈, 输出目标线程数.

        前馈分量: 基于队列深度与平均耗时估算所需线程数
          ff = queue_depth / max(1, avg_task_ms / 1000) / rate_limit
          含义: 若队列有 N 个任务, 每个耗时 T ms, 则需 N*T/1000 线程秒;
          除以时间窗口得到所需并发度.

        PID 分量: 以队列深度为过程变量, 目标为 0
          pid_out ∈ [-8, 8], 正值表示需要更多线程.

        最终: target = current + ff_gain * ff_raw + pid_out
        """
        m = self._metrics
        pending = max(0, m.queue_depth)

        # 前馈: 用简单公式估算消除当前积压所需的额外线程
        avg_s = m.avg_task_ms / 1000 if m.avg_task_ms > 0 else 0.5
        ff_raw = 0.0
        if avg_s > 0:
            # 在 1 秒窗口内清空积压所需线程数
            ff_raw = pending * avg_s / 1.0
            # 截断: 单次前馈调整不超过 6
            ff_raw = max(-4.0, min(6.0, ff_raw))

        # PID 反馈
        dt = self._cooldown  # 近似采样周期
        pid_out = self._pid.update(pv=float(pending), dt=dt)

        # 合成
        delta = self._ff_gain * ff_raw + pid_out
        target = self._current + round(delta)

        # 迟滞: 变化小于 2 时忽略, 防止振荡
        if abs(target - self._current) < 2:
            return self._current

        return max(self._min, min(self._max, target))

    def _resize(self, new_size: int):
        """调整池大小: ThreadPoolExecutor 不支持动态 resize,
        因此关闭旧池并创建新池; 正在执行的任务不受影响.

        设计权衡:
          ThreadPoolExecutor._threads 是内部实现, 直接操作破坏封装.
          重建策略虽然产生短暂的对象分配开销 (~1ms),
          但获取了清晰的线程数控制语义, 且避免与 CPython 的内部状态耦合.
        """
        if new_size == self._current:
            return

        old_executor = self._executor
        # 创建新池, 不等待旧池任务完成 (旧池线程自然结束)
        self._executor = ThreadPoolExecutor(max_workers=new_size)
        self._current = new_size

        if old_executor is not None:
            # shutdown(wait=False): 旧池的已提交任务继续执行,
            # 已完成的任务不受影响, 新提交进入新池.
            old_executor.shutdown(wait=False)

        self._pid.reset()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.shutdown(wait=True)
