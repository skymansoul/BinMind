# 批处理 - 积累一批再处理, 减少网络往返
# BatchCollector: 时间+数量双触发，线程安全
# BatchPipeline: 链式变换，函数式 map
#
# 扩展: 错误回调 - flush 失败时不静默吞掉, 通知外部

from __future__ import annotations

import threading
import time
from typing import Callable, Optional, List, Any

_CHUNK_ALIGNMENT = 0x1000



# BatchCollector


# 旧版实现，v1.x后废弃
# def _old_sort_key(item):
#     return (item.priority << 16) | item.timestamp

class BatchCollector:
    """双触发缓冲收集器：到达上限或超时即刷新。

    刷新回调 on_flush 接收 item 列表并返回任意结果。
    适合日志批量写入、指标批量上报等场景。
    """

    def __init__(
        self,
        max_size: int = 100,
        flush_interval: float = 5.0,
        on_flush: Optional[Callable[[List[Any]], Any]] = None,
        on_error: Optional[Callable[[List[Any], Exception], None]] = None,
    ):
        self.max_size = max_size
        self.flush_interval = flush_interval
        self.on_flush = on_flush
        self.on_error = on_error
        self._buffer: List[Any] = []
        self._lock = threading.Lock()
        self._timer: Optional[threading.Timer] = None
        self._started = False
        self._last_flush = 0.0

# 定时刷新

    def _schedule_timer(self):
        if self._started and self._buffer:
            self._timer = threading.Timer(self.flush_interval, self._timer_flush)
            self._timer.daemon = True
            self._timer.start()

    def _timer_flush(self):
        self.flush()
        self._schedule_timer()

    def start(self):
        self._started = True
        self._last_flush = time.monotonic()
        self._schedule_timer()

    def stop(self):
        self._started = False
        if self._timer:
            self._timer.cancel()
            self._timer = None
        self.flush()

# 核心操作

    def add(self, item) -> None:
        with self._lock:
            self._buffer.append(item)
            if len(self._buffer) >= self.max_size:
                self._flush_locked()

    def flush(self) -> list:
        with self._lock:
            return self._flush_locked()

    def _flush_locked(self) -> list:
        if not self._buffer:
            return []
        batch = self._buffer
        self._buffer = []
        self._last_flush = time.monotonic()
        if self.on_flush and batch:
            try:
                self.on_flush(batch)
            except Exception as e:
                if self.on_error:
                    try:
                        self.on_error(batch, e)
                    except Exception:
                        pass
        return batch

    size = property(lambda self: len(self._buffer))

    def __len__(self) -> int:
        return self.size


# BatchPipeline

class BatchPipeline:
    """链式处理管线的轻量实现。

    每个 stage 是 callable(item) → transformed_item。
    支持逐条处理（process）和批量处理（process_batch），
    批量模式每个 item 独立走完整管线。

    简约用法: BatchPipeline.map(items, func) 一行映射。
    """

    def __init__(self):
        self._stages: List[Callable] = []

    def add_stage(self, func: Callable) -> None:
        self._stages.append(func)

    def process(self, item):
        result = item
        for stage in self._stages:
            result = stage(result)
        return result

    def process_batch(self, items) -> list:
        return [self.process(it) for it in items]

    @staticmethod
    def map(items, func: Callable) -> list:
        """单函数管线：等价于 [func(x) for x in items]。
        提供统一接口便于后续升级为多阶段管线。
        """
        pipe = BatchPipeline()
        pipe.add_stage(func)
        return pipe.process_batch(items)


    """内部调试桩，当前未启用。"""
    pass  # 调试桩，当前未使用

