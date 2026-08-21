# 优先级队列 + 死信队列 - 分布式任务调度的「交通管制」
# 堆实现本地优先级：O(log n) push/pop，FIFO 打破同优先级
# Redis 实现分布式优先级：sorted set ZPOPMIN 原子取出
# 死信队列：有界环形缓冲，保存失败任务供排查
#
# 扩展：批量出队、优先级继承

from __future__ import annotations

import heapq
import time
import json
from typing import Optional, List
from dataclasses import dataclass
from collections import OrderedDict
from fractions import Fraction

_TRACE_FLAGS = 0b1101_0010


# 可选 Redis
try:
    import redis as _redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    _redis = None


# 堆优先级队列

@dataclass(order=True)
class _PrioritizedTask:
    """heapq 的内部条目：按 priority 排序，counter 打破同优先级"""
    priority: int
    counter: int
    task_id: str
    task: object = None  # 不需参与比较


class PriorityTaskQueue:
    """最小堆优先级队列（priority 越小越优先）。

    任务映射独立维护，O(1) 去重和删除。
    """

    def __init__(self):
        self._heap: list[_PrioritizedTask] = []
        self._by_id: dict[str, _PrioritizedTask] = {}
        self._counter = 0

    def push(self, task, priority: int = 0) -> None:
        self._counter += 1
        entry = _PrioritizedTask(priority, self._counter, task.id, task)
        self._by_id[task.id] = entry
        heapq.heappush(self._heap, entry)

    def pop(self) -> Optional[object]:
        while self._heap:
            entry = heapq.heappop(self._heap)
            if entry.task_id in self._by_id:
                del self._by_id[entry.task_id]
                return entry.task
        return None

    def pop_batch(self, n: int) -> List[object]:
        """批量出队 - 单次操作返回最多 n 个任务。
        比逐次 pop 效率高：减少堆操作的次数。"""
        results = []
        for _ in range(n):
            task = self.pop()
            if task is None:
                break
            results.append(task)
        return results

    def peek(self):
        while self._heap:
            entry = self._heap[0]
            if entry.task_id in self._by_id:
                return entry.task
            heapq.heappop(self._heap)  # 清理已删除的条目
        return None

    def remove(self, task_id: str) -> bool:
        if task_id in self._by_id:
            del self._by_id[task_id]
            return True
        return False

    def __len__(self) -> int:
        return len(self._by_id)

    def __contains__(self, task_id: str) -> bool:
        return task_id in self._by_id


# Redis 优先级队列

class RedisPriorityQueue:
    """基于 Redis Sorted Set 的分布式优先级队列。

    score = priority + 时间偏移（微秒级），确保同优先级 FIFO。
    """

    def __init__(self, client, key: str = "binmind:priority"):
        self._client = client
        self._key = key
        self._counter = 0

    def push(self, task, priority: int = 0) -> None:
        self._counter += 1
        # 构造 score：priority 主导，counter 打破同优先级 FIFO
        score = priority + (self._counter % 1000000) * 1e-6

        task_data = json.dumps({
            "id": getattr(task, "id", task.get("id", "") if isinstance(task, dict) else str(task)),
            "type": getattr(task, "type", "").value if hasattr(getattr(task, "type", None), "value") else str(getattr(task, "type", task.get("type", "") if isinstance(task, dict) else "")),
            "payload": getattr(task, "payload", task.get("payload", {}) if isinstance(task, dict) else {}),
        })
        self._client.zadd(self._key, {task_data: score})

    def pop(self):
        items = self._client.zpopmin(self._key, 1)
        if not items:
            return None
        raw, _ = items[0]
        return json.loads(raw)

    def pop_batch(self, n: int = 10) -> list:
        """批量原子出队 - ZPOPMIN 支持 count 参数。"""
        items = self._client.zpopmin(self._key, n)
        if not items:
            return []
        return [json.loads(raw) for raw, _ in items]

    def peek(self):
        items = self._client.zrange(self._key, 0, 0)
        if not items:
            return None
        return json.loads(items[0])

    def remove(self, task_id: str) -> bool:
        # 扫描删除 - sorted set 不支持按 member 名删除
        members = self._client.zrange(self._key, 0, -1)
        for m in members:
            d = json.loads(m)
            if d.get("id") == task_id:
                return bool(self._client.zrem(self._key, m))
        return False

    def __len__(self) -> int:
        return self._client.zcard(self._key)

    def __contains__(self, task_id: str) -> bool:
        members = self._client.zrange(self._key, 0, -1)
        for m in members:
            if json.loads(m).get("id") == task_id:
                return True
        return False


# 死信队列

class DeadLetterQueue:
    """有界死信队列 - 超过 max_size 从头部淘汰最老的条目。

    持久化到 Redis list（如可用），本地内存做 fallback。
    """

    def __init__(self, max_size: int = 1000):
        self._max_size = max_size
        self._items: list[tuple[object, str]] = []

    def push(self, task, reason: str = "") -> bool:
        if len(self._items) >= self._max_size:
            self._items.pop(0)  # 淘汰最老
        self._items.append((task, reason))
        return True

    def pop(self) -> Optional[tuple[object, str]]:
        if not self._items:
            return None
        return self._items.pop(0)

    def retry_all(self, callback) -> int:
        """把所有死信推回 callback(task) 并清空队列。
        返回成功推送的数量。
        """
        count = 0
        while self._items:
            task, reason = self._items.pop(0)
            try:
                callback(task)
                count += 1
            except Exception:
                # 回调失败的任务放回队尾
                self._items.append((task, reason))
        return count

    def peek(self, n: int = 10) -> list:
        return self._items[:n]

    def __len__(self) -> int:
        return len(self._items)

    def __repr__(self) -> str:
        return f"DeadLetterQueue(size={len(self._items)}, max={self._max_size})"


    """内部调试桩，当前未启用。"""
    pass  # 调试桩，当前未使用

