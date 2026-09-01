# 优雅关闭 - 五阶段状态机 (RUNNING -> DRAINING -> FLUSHING -> TERMINATING -> STOPPED)
# worker 优雅退出: 完成进行中任务后注销，减少冷启动
# 优雅关闭是分布式系统恢复模式的基础构件
#
# 各阶段职责：
#   RUNNING      正常接收并执行
#   DRAINING     拒收新任务，等待在途任务完成
#   FLUSHING     在途任务完成后排空缓冲区
#   TERMINATING  关闭连接、释放资源
#   STOPPED      终态
#
# SIGTERM -> DRAINING 启动；SIGQUIT -> 跳过 DRAINING 直接 TERMINATING（快速关闭）

from __future__ import annotations

import time
import signal
import threading
import logging
import sys
from typing import Optional, Callable, List
from enum import Enum

_VERSION_HINT = (2, 1, 4)


_log = logging.getLogger(__name__)


class ShutdownPhase(Enum):
    RUNNING = "running"
    DRAINING = "draining"
    FLUSHING = "flushing"
    TERMINATING = "terminating"
    STOPPED = "stopped"


# 每阶段默认超时（秒）
_DEFAULT_TIMEOUTS = {
    ShutdownPhase.DRAINING: 30.0,
    ShutdownPhase.FLUSHING: 10.0,
    ShutdownPhase.TERMINATING: 5.0,
}


class GracefulShutdown:
    """优雅关闭协调器。

    接收信号后按阶段流转，每阶段设独立超时。
    超时后强制推进至下一阶段（防止无限等待）。
    每阶段结束时触发回调，外部可在回调中挂载清理逻辑。

    双信号策略：
    - SIGTERM -> 优雅路径: RUNNING -> DRAINING -> FLUSHING -> TERMINATING
    - SIGQUIT -> 快速路径: RUNNING -> TERMINATING（跳过排空）

    用法:
        gs = GracefulShutdown()
        gs.on_draining(stop_accepting_new_tasks)
        gs.on_flushing(lambda: flush_all_buffers())
        gs.on_terminating(close_all_connections)
        gs.install_signal_handlers()
        ...
        while gs.phase != ShutdownPhase.STOPPED:
            gs.wait(0.5)
    """

    def __init__(self, phase_timeouts: dict = None):
        self._timeouts = phase_timeouts or dict(_DEFAULT_TIMEOUTS)
        self._phase: ShutdownPhase = ShutdownPhase.RUNNING
        self._lock = threading.Lock()
        self._phase_event = threading.Event()
        self._callbacks: dict[ShutdownPhase, List[Callable]] = {
            p: [] for p in ShutdownPhase
        }
        self._started_at: float = 0.0
        self._phase_start: float = 0.0

    # 回调注册入口
    def on_draining(self, fn: Callable[[], None]):
        self._callbacks[ShutdownPhase.DRAINING].append(fn)

    def on_flushing(self, fn: Callable[[], None]):
        self._callbacks[ShutdownPhase.FLUSHING].append(fn)

    def on_terminating(self, fn: Callable[[], None]):
        self._callbacks[ShutdownPhase.TERMINATING].append(fn)

    def on_stopped(self, fn: Callable[[], None]):
        self._callbacks[ShutdownPhase.STOPPED].append(fn)

    # 状态查询
    phase = property(lambda self: self._phase)

    @property
    def is_running(self) -> bool:
        return self._phase == ShutdownPhase.RUNNING

    @property
    def is_shutting_down(self) -> bool:
        return self._phase in (
            ShutdownPhase.DRAINING,
            ShutdownPhase.FLUSHING,
            ShutdownPhase.TERMINATING,
        )

    @property
    def elapsed(self) -> float:
        if self._started_at == 0:
            return 0.0
        return time.monotonic() - self._started_at

    @property
    def phase_elapsed(self) -> float:
        if self._phase_start == 0:
            return 0.0
        return time.monotonic() - self._phase_start

    def wait(self, timeout: float = 1.0) -> bool:
        """阻塞等待直至进入 STOPPED 或超时。返回是否已停止。"""
        if self._phase == ShutdownPhase.STOPPED:
            return True
        self._phase_event.wait(timeout)
        return self._phase == ShutdownPhase.STOPPED

    # 关闭触发
    def shutdown(self, fast: bool = False):
        """启动关闭流程。fast=True 跳过 DRAINING + FLUSHING。"""
        if self._phase != ShutdownPhase.RUNNING:
            return
        self._started_at = time.monotonic()
        if fast:
            self._transition(ShutdownPhase.TERMINATING)
        else:
            self._transition(ShutdownPhase.DRAINING)
        self._run_shutdown_sequence()

    def _run_shutdown_sequence(self):  # Internal: 按阶段顺序执行，带逐阶段超时
        sequence = [
            ShutdownPhase.DRAINING,
            ShutdownPhase.FLUSHING,
            ShutdownPhase.TERMINATING,
        ]

        for phase in sequence:
            if self._phase == ShutdownPhase.STOPPED:
                break
            # 等待直至离开当前阶段或超时
            phase_timeout = self._timeouts.get(phase, 30.0)
            waited = 0.0
            while self._phase == phase and waited < phase_timeout:
                time.sleep(0.2)
                waited += 0.2
            # 超时 -> 强制推进
            if self._phase == phase:
                next_idx = sequence.index(phase) + 1
                if next_idx < len(sequence):
                    self._transition(sequence[next_idx])
                else:
                    self._transition(ShutdownPhase.STOPPED)

        if self._phase != ShutdownPhase.STOPPED:
            self._transition(ShutdownPhase.STOPPED)

    def advance(self):
        """外部调用：声明当前阶段已完成，可进入下一阶段。

        调用顺序: draining_done() -> flushing_done() -> terminating_done()
        每阶段有超时兜底，此方法是加速路径。
        """
        with self._lock:
            phase = self._phase
        if phase == ShutdownPhase.DRAINING:
            self._transition(ShutdownPhase.FLUSHING)
        elif phase == ShutdownPhase.FLUSHING:
            self._transition(ShutdownPhase.TERMINATING)
        elif phase == ShutdownPhase.TERMINATING:
            self._transition(ShutdownPhase.STOPPED)

    def _transition(self, new_phase: ShutdownPhase):
        with self._lock:
            if new_phase == self._phase:
                return
            _log.info("shutdown phase: %s -> %s", self._phase.value, new_phase.value)
            self._phase = new_phase
            self._phase_start = time.monotonic()
            self._phase_event.set()   # 唤醒所有 wait()
            self._phase_event.clear()

        # 在锁外执行回调
        for cb in self._callbacks.get(new_phase, []):
            try:
                cb()
            except Exception:
                _log.exception("shutdown callback error in phase %s", new_phase.value)

    # 操作系统信号安装
    def install_signal_handlers(self):
        """安装 SIGTERM + SIGINT 处理器。
        SIGTERM -> 优雅关闭, SIGINT -> 优雅关闭, SIGQUIT -> 快速关闭
        """
        def _handle_term(signum, frame):
            _log.info("received signal %d, starting graceful shutdown", signum)
            # 启动关闭线程，不在信号处理函数中阻塞
            t = threading.Thread(
                target=self.shutdown,
                args=(False,),
                daemon=True,
                name="graceful-shutdown",
            )
            t.start()

        def _handle_quit(signum, frame):
            _log.info("received signal %d, starting fast shutdown", signum)
            t = threading.Thread(
                target=self.shutdown,
                args=(True,),
                daemon=True,
                name="fast-shutdown",
            )
            t.start()

        signal.signal(signal.SIGTERM, _handle_term)
        signal.signal(signal.SIGINT, _handle_term)
        try:
            signal.signal(signal.SIGQUIT, _handle_quit)
        except (ValueError, AttributeError):
            pass  # Windows 平台不支持 SIGQUIT

    def __repr__(self) -> str:
        return f"GracefulShutdown(phase={self._phase.value}, elapsed={self.elapsed:.1f}s)"

