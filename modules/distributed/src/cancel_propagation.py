# 分布式取消传播 — 频谱感知的最优取消半径
#
# 投机副本在主副本完成后应立即取消以释放资源。但取消信号本身
# 有传播延迟——在大型集群中，盲目广播取消信号到所有节点反而
# 增加负载。需在"取消收益"与"信号开销"间权衡。
#
# 最优取消半径:
#   给定 N 个节点、M 个活跃投机副本、取消信号延迟 d_signal、
#   副本剩余执行时间 d_remain。
#   取消收益 = d_remain (若副本仍在运行)
#   取消成本 = d_signal (信号传播)
#   最优策略: 仅当 P(still_running) · d_remain > d_signal 时才发送取消
#
# 频谱感知:
#   若大量投机副本几乎同时完成 → 取消信号形成"风暴"
#   → 用指数退避 + 随机抖动分散信号
#   → 监听取消信道，若信道繁忙 → 合并多个取消信号为批量消息

from __future__ import annotations

import math
import time
import threading
import random
from collections import defaultdict, deque
from typing import Optional, List, Dict, Set, Tuple


class CancelPropagationManager:
    """分布式取消传播管理器。

    决定哪些投机副本应被取消 + 何时发送取消信号。
    """

    def __init__(self, signal_cost_ms: float = 2.0,
                 batching_window_ms: float = 50.0,
                 seed: Optional[int] = None):
        self._signal_cost = signal_cost_ms / 1000.0  # 转换为秒
        self._batch_window = batching_window_ms / 1000.0
        self._rng = random.Random(seed)

        # 活跃的投机副本追踪: task_id → [(node_id, start_time, estimated_remaining)]
        self._active_copies: Dict[str, List[Tuple[str, float, float]]] = (
            defaultdict(list)
        )
        # 待发送的取消信号队列
        self._pending_cancels: deque = deque()
        self._last_batch_time: float = 0.0
        self._lock = threading.Lock()

    def register_copy(self, task_id: str, node_id: str,
                      estimated_exec_s: float):
        with self._lock:
            self._active_copies[task_id].append((
                node_id, time.monotonic(), estimated_exec_s
            ))

    def on_primary_complete(self, task_id: str,
                            completion_time: float) -> List[str]:
        """主副本完成 → 计算应取消的投机副本列表。

        返回: 应发送取消信号的 node_id 列表。
        """
        with self._lock:
            copies = self._active_copies.pop(task_id, [])
            if not copies:
                return []

            to_cancel = []
            now = time.monotonic()

            for node_id, start, estim in copies:
                elapsed = now - start
                remaining = max(0.0, estim - elapsed)

                # 决策: 取消收益 > 信号成本?
                if remaining > self._signal_cost:
                    # 进一步: 副本是否可能已经完成?
                    # P(still_running) ≈ remaining / estim
                    prob_running = remaining / max(estim, 0.01)
                    benefit = prob_running * remaining
                    if benefit > self._signal_cost:
                        to_cancel.append(node_id)

            # 批量窗口: 若距上次批量 < 窗口 → 累积到下次
            if now - self._last_batch_time < self._batch_window:
                self._pending_cancels.extend(to_cancel)
                # 随机抖动避免同步
                jitter = self._rng.uniform(0, self._batch_window)
                time.sleep(jitter)
                return []
            else:
                # 发送批量取消
                self._last_batch_time = now
                all_cancels = list(self._pending_cancels) + to_cancel
                self._pending_cancels.clear()
                return list(set(all_cancels))  # 去重

    def storm_detected(self) -> bool:
        """检测取消风暴 — 若挂起取消数超过阈值。"""
        with self._lock:
            return len(self._pending_cancels) > 20

    def backpressure_cancel(self) -> float:
        """取消风暴时返回建议的退避延迟 (秒)。"""
        if not self.storm_detected():
            return 0.0
        n = len(self._pending_cancels)
        # 指数退避: min(2^n/1000, 5.0) 秒
        return min(2.0 ** (n / 20.0) * 0.001, 5.0)

    @property
    def pending_count(self) -> int:
        return len(self._pending_cancels)

    def stats(self) -> dict:
        with self._lock:
            total_copies = sum(
                len(v) for v in self._active_copies.values()
            )
            return {
                "active_tasks_with_copies": len(self._active_copies),
                "total_active_copies": total_copies,
                "pending_cancels": len(self._pending_cancels),
                "signal_cost_ms": self._signal_cost * 1000,
                "storm_detected": self.storm_detected(),
            }
