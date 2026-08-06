# 推测复制管理器 — 自适应副本数量 + 过早终止的预算最优投机
#
# SpeculativeExecutor (speculative_exec.py) 对关键路径任务发起投机副本，
# 但副本数量固定 (max_speculative_copies=3)。两个次优性:
#   1. 固定副本数: 若所有副本都慢 → 浪费；若单一副本不够 → 延迟高
#   2. 无过早终止: 主副本完成后投机副本仍在运行 → 纯浪费
#
# 本模块的自适应推测复制:
#   1. 副本数 c 在线调节: c* = argmin_c E[cost] = c·overhead + P(all_slow|c)·delay
#     其中 P(all_slow|c) = Π_i P(task_i > timeout) ≈ (tail_prob)^c
#     对 each candidate c, 计算期望代价 → 选最小者
#   2. 过早终止: 主副本或任一副本完成后，广播取消信号给其余副本
#      (需底层执行框架支持 interrupt/cancel)
#   3. 预算池: 全局投机预算 B_global, 各任务按边际收益竞争预算
#      → 避免单个任务过度投机

from __future__ import annotations

import math
import time
import threading
from collections import deque
from typing import Optional, List, Dict, Tuple


class SpeculativeDuplicationManager:
    """自适应推测复制管理器。

    维护每个任务的执行时间尾概率模型 + 全局投机预算。
    """

    def __init__(self, global_budget: int = 10,
                 max_copies_per_task: int = 5,
                 min_tail_prob: float = 0.02):
        self._global_budget = global_budget
        self._max_copies = max_copies_per_task
        self._min_tail = min_tail_prob
        self._active_speculations: int = 0
        self._task_history: Dict[str, deque] = {}  # task_id → exec times
        self._lock = threading.Lock()

    def optimal_copies(self, task_id: str, nominal_time: float,
                       timeout: float) -> int:
        """计算最优投机副本数 — 期望代价最小化。

        E[cost|c] = c·overhead_cost + tail_prob^c · delay_cost
        overhead_cost ≈ nominal_time * 0.1 (10% 额外资源)
        delay_cost ≈ timeout (若全部副本超时)
        """
        history = self._task_history.get(task_id, deque())
        tail_prob = self._tail_probability(task_id, timeout)

        best_c = 1
        best_cost = float('inf')
        for c in range(1, min(self._max_copies + 1,
                              self._global_budget - self._active_speculations + 1)):
            overhead = c * nominal_time * 0.1
            delay = (tail_prob ** c) * timeout
            cost = overhead + delay
            if cost < best_cost:
                best_cost = cost
                best_c = c

        return best_c

    def _tail_probability(self, task_id: str, timeout: float) -> float:
        """P(exec_time > timeout) — 从历史数据的经验尾概率。"""
        history = self._task_history.get(task_id)
        if not history or len(history) < 3:
            return max(self._min_tail, math.exp(-timeout))  # 先验: 指数尾
        n = len(history)
        exceed = sum(1 for t in history if t > timeout)
        return max(self._min_tail, exceed / n)

    def record_execution(self, task_id: str, exec_time: float):
        with self._lock:
            if task_id not in self._task_history:
                self._task_history[task_id] = deque(maxlen=50)
            self._task_history[task_id].append(exec_time)

    def acquire_budget(self, copies: int) -> bool:
        """尝试从全局预算中获取 c 份投机额度。"""
        with self._lock:
            if self._active_speculations + copies <= self._global_budget:
                self._active_speculations += copies
                return True
            return False

    def release_budget(self, copies: int):
        with self._lock:
            self._active_speculations = max(
                0, self._active_speculations - copies
            )

    def marginal_benefit(self, task_id: str, nominal_time: float,
                         timeout: float) -> float:
        """第一份额外投机的边际收益 (用于跨任务预算竞争)。"""
        tail = self._tail_probability(task_id, timeout)
        # 收益 = P(主副本超时且投机副本也超时被避免) ≈ tail * (1-tail)
        return tail * (1.0 - tail) * timeout

    @property
    def available_budget(self) -> int:
        return self._global_budget - self._active_speculations

    def stats(self) -> dict:
        with self._lock:
            return {
                "global_budget": self._global_budget,
                "active_speculations": self._active_speculations,
                "available_budget": self.available_budget,
                "tracked_tasks": len(self._task_history),
            }
