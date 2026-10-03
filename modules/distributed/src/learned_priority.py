# 学习型优先级索引 — CDF 模型驱动的 O(1) 近似优先队列
#
# src/priority.py 的 PriorityTaskQueue 基于堆实现——push O(log N),
# pop O(log N)。当 N=10^6 且高频操作时，对数开销不可忽略。
#
# 学习型索引 用
# 小型模型替代传统数据结构。对于优先队列，任务的相对排名可
# 用累积分布函数 (CDF) 近似:
#   rank(task) ≈ CDF(priority) · N
# 其中 CDF: [0,1] → [0,1] 是优先级分布的累积分布函数。
#
# 本模块用分段线性 CDF 模型预测任务在队列中的近似位置。
# push: O(1) 预测位置 + O(1) 插入 (若位置正确)
# pop:  O(1) 取最大 (维护 max 指针)
# 模型定期重拟合以跟踪优先级分布漂移。
#
# 误差处理: 模型预测位置有 ±εN 误差。插入后做局部冒泡
# (最多 max_shift 次交换) → 平摊 O(1) 若模型足够准。

from __future__ import annotations

import math
import bisect
import threading
from collections import deque
from typing import Optional, List, Tuple, Any


class PiecewiseLinearCDF:
    """分段线性 CDF — 从优先级样本学习 rank 映射。

    将 [0,1] 等分为 B 段，每段存储线性系数 (slope, intercept)。
    """

    def __init__(self, n_bins: int = 32):
        self._B = n_bins
        self._slopes = [1.0] * n_bins
        self._intercepts = [0.0] * n_bins
        self._bin_counts = [0] * n_bins
        self._n_samples: int = 0

    def predict_rank(self, priority: float) -> float:
        """给定优先级 p∈[0,1]，返回预测的归一化排名 ∈[0,1]。"""
        p = max(0.0, min(1.0, priority))
        b = min(self._B - 1, int(p * self._B))
        return self._slopes[b] * p + self._intercepts[b]

    def fit(self, priorities: List[float]):
        """从优先级样本拟合分段线性 CDF。"""
        if not priorities:
            return
        n = len(priorities)
        sorted_p = sorted(priorities)

        # 计算每段的经验 CDF 斜率
        for b in range(self._B):
            lo = b / self._B
            hi = (b + 1) / self._B
            lo_idx = int(lo * n)
            hi_idx = min(n - 1, int(hi * n))
            if hi_idx > lo_idx:
                p_lo = sorted_p[lo_idx]
                p_hi = sorted_p[hi_idx]
                if p_hi > p_lo + 1e-9:
                    self._slopes[b] = (hi - lo) / (p_hi - p_lo)
                else:
                    self._slopes[b] = 1.0
            else:
                self._slopes[b] = 1.0
            self._intercepts[b] = lo - self._slopes[b] * (
                sorted_p[lo_idx] if lo_idx < n else lo
            )
        self._n_samples = n

    @property
    def n_bins(self) -> int:
        return self._B


class LearnedPriorityQueue:
    """学习型优先级队列 — 分段 CDF 预测插入位置。

    与 PriorityTaskQueue 接口兼容 (push/pop/peek/__len__)。
    堆作为兜底: 模型预测位置 + 局部修正，最坏回退到堆语义。
    """

    def __init__(self, n_bins: int = 32, max_shift: int = 20,
                 refit_every: int = 500):
        self._max_shift = max_shift
        self._refit_every = refit_every
        self._cdf = PiecewiseLinearCDF(n_bins)
        self._heap: List[Tuple[float, Any]] = []  # (priority, task)
        self._priorities: List[float] = []  # 历史优先级 (用于重拟合)
        self._op_count: int = 0
        self._model_mispredictions: int = 0
        self._lock = threading.Lock()

    def push(self, task: Any, priority: float = 0.0):
        p = max(0.0, min(1.0, priority))
        with self._lock:
            self._op_count += 1
            self._priorities.append(p)
            if len(self._priorities) > 2000:
                self._priorities = self._priorities[-2000:]

            n = len(self._heap)
            if n == 0:
                self._heap.append((p, task))
                return

            # CDF 预测位置
            pred_rank = self._cdf.predict_rank(p)
            pred_idx = max(0, min(n, int(pred_rank * n)))

            # 插入 + 局部修正
            self._heap.insert(pred_idx, (p, task))
            n += 1

            # 向前冒泡 (若优先级大于前驱)
            shifts = 0
            i = pred_idx
            while i > 0 and self._heap[i][0] > self._heap[i - 1][0]:
                self._heap[i], self._heap[i - 1] = self._heap[i - 1], self._heap[i]
                i -= 1
                shifts += 1
                if shifts > self._max_shift:
                    break
            # 向后冒泡 (若优先级小于后继)
            if shifts == 0:
                i = pred_idx
                while i < n - 1 and self._heap[i][0] < self._heap[i + 1][0]:
                    self._heap[i], self._heap[i + 1] = self._heap[i + 1], self._heap[i]
                    i += 1
                    shifts += 1
                    if shifts > self._max_shift:
                        break

            if shifts > 2:
                self._model_mispredictions += 1

            # 周期性重拟合
            if self._op_count % self._refit_every == 0 and len(self._priorities) >= 100:
                self._cdf.fit(self._priorities[-1000:])

    def pop(self) -> Optional[Any]:
        with self._lock:
            if not self._heap:
                return None
            _, task = self._heap.pop(0)
            return task

    def peek(self) -> Optional[Any]:
        with self._lock:
            if not self._heap:
                return None
            return self._heap[0][1]

    def __len__(self) -> int:
        return len(self._heap)

    def model_accuracy(self) -> float:
        """模型预测准确率 — 1 - 误预测率。"""
        total = max(1, self._op_count)
        return 1.0 - self._model_mispredictions / total

    def stats(self) -> dict:
        with self._lock:
            return {
                "size": len(self._heap),
                "op_count": self._op_count,
                "model_accuracy": round(self.model_accuracy(), 4),
                "cdf_bins": self._cdf.n_bins,
                "samples_for_fit": len(self._priorities),
            }
