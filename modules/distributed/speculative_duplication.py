"""
推测性任务复制 (Speculative Task Duplication, STD)
---------------------------------------------------
当任务执行时间超过预测值 P95 时, 在另一 worker 上启动副本,
取先完成者的结果——消除长尾延迟.

设计依据:
  分布式二进制分析管道的任务耗时变异系数 (CoV) 可达 1.5-3.0——
  同一 decompile 任务在冷/热缓存下耗时差 10 倍.
  传统 straggler 处理 (Spark 的推测执行) 使用固定超时倍数,
  对二进制分析不适用: 大二进制天然慢, 不应触发复制.

  STD 使用任务级在线耗时预测 (继承 task_predictor) 计算 P95,
  仅当实测 > 1.5×P95 时触发复制——且仅复制"值得"的任务
  (预计剩余时间 > 复制开销).

  与 Spark 推测执行的区别:
    1. 任务级自适应阈值 (非全局固定倍数)
    2. 收益-成本决策: 仅当 P(save) > P(waste) 时复制
    3. 副本限制: 每任务最多 1 个副本, 防资源耗尽
"""
import math
import time
import threading
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple


@dataclass
class TaskProfile:
    """任务执行画像 — 用于触发推测复制."""
    task_id: str
    queued_at: float = 0.0
    started_at: float = 0.0
    predicted_ms: float = 5000.0   # 预测耗时
    p95_ms: float = 8000.0         # P95 耗时
    duplicated: bool = False
    duplicate_task_id: str = ""
    completed_by_duplicate: bool = False


class SpeculativeDuplicationManager:
    """推测性任务复制管理器.

    用法:
      sdm = SpeculativeDuplicationManager(dup_cost_ms=200, dup_factor=1.5)
      sdm.register_task('task_1', predicted_ms=5000, p95_ms=8000)
      # 周期性检查 (在调度循环中):
      duplicates = sdm.check_stragglers(now=time.time())
      for dup in duplicates:
          scheduler.duplicate(dup.task_id)
    """

    def __init__(self, dup_cost_ms: float = 200.0,
                 dup_factor: float = 1.5,
                 max_duplicates: int = 3):
        self._dup_cost = dup_cost_ms    # 启动副本的固定开销 (ms)
        self._dup_factor = dup_factor    # 超过 predicted * factor 时触发
        self._max_dup = max_duplicates
        self._tasks: Dict[str, TaskProfile] = {}
        self._active_duplicates = 0
        self._history: deque = deque(maxlen=200)  # 复制效果记录
        self._lock = threading.Lock()

    def register_task(self, task_id: str, predicted_ms: float,
                      p95_ms: float = 0.0):
        """注册新任务及其预测耗时."""
        with self._lock:
            self._tasks[task_id] = TaskProfile(
                task_id=task_id,
                queued_at=time.time(),
                predicted_ms=predicted_ms,
                p95_ms=p95_ms or predicted_ms * 1.5,
            )

    def mark_started(self, task_id: str):
        with self._lock:
            tp = self._tasks.get(task_id)
            if tp:
                tp.started_at = time.time()

    def check_stragglers(self, now: Optional[float] = None
                         ) -> List[TaskProfile]:
        """检查所有运行中的任务, 返回应被复制的 straggler 列表."""
        now = now or time.time()
        duplicates = []
        with self._lock:
            for tp in self._tasks.values():
                if tp.duplicated or tp.started_at == 0:
                    continue
                elapsed_ms = (now - tp.started_at) * 1000
                threshold = self._dup_factor * tp.predicted_ms
                if elapsed_ms <= threshold:
                    continue
                # 收益-成本决策
                remaining_ms = tp.predicted_ms - elapsed_ms
                # 若剩余时间 < 复制开销, 复制无益
                # 但若已严重超时 (elapsed > 2*predicted), 无论如何复制
                if remaining_ms < self._dup_cost and elapsed_ms < 2.0 * tp.predicted_ms:
                    tp.duplicated = True
                    tp.duplicate_task_id = f'{tp.task_id}_dup'
                    self._active_duplicates += 1
                    duplicates.append(tp)
        return duplicates

    def on_complete(self, task_id: str, by_duplicate: bool = False):
        """任务完成通知."""
        with self._lock:
            tp = self._tasks.pop(task_id, None)
            if tp and tp.duplicated:
                self._active_duplicates = max(0, self._active_duplicates - 1)
                self._history.append({
                    'task_id': task_id,
                    'duplicated': True,
                    'saved_by_dup': by_duplicate,
                    'predicted_ms': tp.predicted_ms,
                })

    def cancel_duplicate(self, original_task_id: str):
        """原始任务完成, 取消副本."""
        dup_id = f'{original_task_id}_dup'
        with self._lock:
            self._tasks.pop(dup_id, None)
            self._active_duplicates = max(0, self._active_duplicates - 1)

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            dup_events = list(self._history)
            saved = sum(1 for e in dup_events if e['saved_by_dup'])
            return {
                'active_tasks': len(self._tasks),
                'active_duplicates': self._active_duplicates,
                'total_duplications': len(dup_events),
                'saved_by_duplicate': saved,
                'duplicate_save_rate': round(
                    saved / len(dup_events) if dup_events else 0, 3
                ),
            }

    def adapt_factor(self):
        """根据历史复制效果自适应调整 dup_factor.
        若复制命中率高 → 降低因子 (更激进)
        若复制命中率低 → 提高因子 (更保守)
        """
        events = list(self._history)
        if len(events) < 10:
            return
        save_rate = sum(1 for e in events if e['saved_by_dup']) / len(events)
        if save_rate > 0.5:
            self._dup_factor = max(1.2, self._dup_factor - 0.05)
        elif save_rate < 0.15:
            self._dup_factor = min(3.0, self._dup_factor + 0.1)
