# 创建: 2026-08-02
# 修改: 2026-08-05 — 增加重要性采样加速稀有事件模拟
#
# 重要性采样加速的离散事件模拟器 — 稀有延迟事件的方差缩减
#
# 评估 P99.9 延迟需要在 1000+ 次模拟中找到约 1 次尾事件。
# 标准 Monte Carlo 的方差 σ²/N 收敛慢——需要 10⁶ 样本估准 P99.9。
#
# 重要性采样 (Importance Sampling, IS):
#   从偏置分布 q (而非真实分布 p) 采样, 用似然比 w=p/q 加权修正。
#   P(X > γ) ≈ (1/N)·Σ I(X_i > γ)·w_i, w_i = p(X_i)/q(X_i)
#   若 q 将概率质量推向尾部, IS 方差可比 naive MC 低 100-1000×。
#
# 本模块的指数倾斜 (exponential tilting):
#   p(x) ∝ exp(-λx) (指数分布基线)
#   q(x) ∝ exp(-(λ-θ)x) = exp(-λ'x) (倾斜分布, λ'=λ-θ)
#   似然比: w(x) = (λ/λ')·exp(-(λ-λ')x)
#   θ 控制倾斜强度——θ 越大尾部采样越多。
# 朴素拒绝采样在非均匀分布上慢 (O(1/p_min))。
#
# 本模块:
#   1. 别名法 (Alias Method): O(K) 预处理, O(1) 采样——
#      从 K 种任务类型的任意离散分布中抽样。
#   2. 离散事件模拟: 事件 = (到达, 调度, 完成)，按时间戳的优先队列。
#   3. 可配置分布: 支持指数、重尾 (Pareto)、突发 (Gamma) 和
#      Hawkes 自激 (调用 hawkes_arrival.py) 的到达间隔。
#   4. 输出: makespan、队列深度时间序列、延迟分位数——
#      供对比不同调度策略的性能。

from __future__ import annotations

import math
import random
import heapq
from collections import deque
from typing import Optional, List, Dict, Callable, Tuple


class AliasSampler:
    """别名法离散采样 — O(1) 时间从任意 K 元分类分布采样。

    Walker-Vose 算法: 将 K 个不等概率事件分解为 K 个等概率桶，
    每桶包含最多两个事件 (主事件 + 别名)。
    """

    def __init__(self, probs: List[float], seed: Optional[int] = None):
        self._K = len(probs)
        self._rng = random.Random(seed)
        total = sum(probs)
        scaled = [p * self._K / total for p in probs]
        self._alias = [0] * self._K
        self._prob = [0.0] * self._K

        small = []
        large = []
        for i, p in enumerate(scaled):
            if p < 1.0:
                small.append(i)
            else:
                large.append(i)

        while small and large:
            s = small.pop()
            l = large.pop()
            self._prob[s] = scaled[s]
            self._alias[s] = l
            scaled[l] = scaled[l] + scaled[s] - 1.0
            if scaled[l] < 1.0:
                small.append(l)
            else:
                large.append(l)

        for s in small:
            self._prob[s] = 1.0
        for l in large:
            self._prob[l] = 1.0

    def sample(self) -> int:
        i = self._rng.randrange(self._K)
        if self._rng.random() < self._prob[i]:
            return i
        return self._alias[i]



class ImportanceSamplingSimulator:
    def __init__(self, n_machines=4, tilt=0.3, seed=None):
        self._M = n_machines; self._tilt = tilt
        self._rng = __import__('random').Random(seed)
        self._results = []; self._weights = []

    def tilted_exp(self, rate):
        return self._rng.expovariate(max(0.01, rate - self._tilt))

    def likelihood_ratio(self, value, orig_rate):
        import math
        tr = max(0.01, orig_rate - self._tilt)
        if tr <= 0: return 1.0
        return (orig_rate/tr) * math.exp(-self._tilt * value)

    def run_replication(self, n_tasks=200, base_arrival_rate=2.0, base_exec_rate=1.0):
        import math
        t = 0.0; mf = [0.0]*self._M; tw = 1.0; ms = 0.0
        for _ in range(n_tasks):
            ia = self.tilted_exp(base_arrival_rate)
            et = self.tilted_exp(base_exec_rate)
            t += max(0.001, ia)
            tw *= self.likelihood_ratio(ia, base_arrival_rate) * self.likelihood_ratio(et, base_exec_rate)
            bm = min(range(self._M), key=lambda m: mf[m])
            st = max(t, mf[bm]); end = st + et; mf[bm] = end
            if end > ms: ms = end
        self._results.append(ms); self._weights.append(tw)
        return ms

    def estimate_tail(self, quantile=0.99):
        import math
        if not self._results: return 0.0, (0.0, 0.0)
        n = len(self._results); tw = sum(self._weights)
        pairs = sorted(zip(self._results, self._weights))
        target = quantile * tw; cum = 0.0; est = pairs[-1][0]
        for val, w in pairs:
            cum += w
            if cum >= target: est = val; break
        se = math.sqrt(sum(w*(r-est)**2 for r,w in pairs)/tw)/math.sqrt(n)
        return est, (max(0, est-1.96*se), est+1.96*se)

    def variance_reduction(self):
        if len(self._results) < 10: return 1.0
        n = len(self._results)
        mn = sum(self._results)/n
        vn = sum((r-mn)**2 for r in self._results)/n
        tw = sum(self._weights)
        mi = sum(r*w for r,w in zip(self._results,self._weights))/tw
        vi = sum(w*(r-mi)**2 for r,w in zip(self._results,self._weights))/tw
        return vn/max(vi, 1e-9)

    n_replications = property(lambda s: len(s._results))

class DiscreteEventSimulator:
    """离散事件任务到达 + 调度模拟器。

    事件类型:
      ARRIVAL:  新任务到达 → 入队 + 调度空闲机器
      COMPLETE: 任务完成 → 释放机器 + 调度下一个就绪任务

    支持多种到达间隔分布 + 执行时间分布。
    调度策略通过 schedule_fn 注入。
    """

    def __init__(self, n_machines: int = 4, seed: Optional[int] = None):
        self._M = n_machines
        self._rng = random.Random(seed)
        self._clock: float = 0.0
        self._event_queue: List[Tuple[float, int, str, dict]] = []
        self._event_id: int = 0
        # 机器状态
        self._machine_free: List[float] = [0.0] * n_machines
        self._pending_queue: deque = deque()
        # 统计
        self._completion_times: List[float] = []
        self._queue_depth_history: List[Tuple[float, int]] = []

    def schedule_arrivals(self, n_tasks: int,
                          inter_arrival_dist: Callable[[], float],
                          exec_time_dist: Callable[[], float],
                          priority_dist: Optional[Callable[[], float]] = None):
        """生成到达事件序列。"""
        t = 0.0
        for i in range(n_tasks):
            t += max(0.001, inter_arrival_dist())
            et = max(0.01, exec_time_dist())
            prio = priority_dist() if priority_dist else 0.5
            self._event_queue.append((t, self._event_id, "ARRIVAL", {
                "task_id": f"T{i}", "exec_time": et, "priority": prio,
            }))
            self._event_id += 1
        heapq.heapify(self._event_queue)

    def run(self, schedule_fn: Optional[Callable] = None) -> dict:
        """运行模拟 — 处理所有事件。

        schedule_fn(task_list, n_machines) → assigned_machine_id
        若不提供 → 使用最快空闲机器 (FIFO)。
        """
        schedule_fn = schedule_fn or (lambda tasks, m: min(
            range(m), key=lambda j: self._machine_free[j]
        ))

        while self._event_queue:
            t, _, event_type, data = heapq.heappop(self._event_queue)
            self._clock = t

            if event_type == "ARRIVAL":
                self._pending_queue.append(data)
                self._record_queue_depth()
                self._try_schedule(schedule_fn)
            elif event_type == "COMPLETE":
                mid = data["machine_id"]
                self._machine_free[mid] = self._clock
                self._completion_times.append(self._clock)
                self._record_queue_depth()
                self._try_schedule(schedule_fn)

        return self.report()

    def _try_schedule(self, schedule_fn):
        while self._pending_queue and any(
            mf <= self._clock for mf in self._machine_free
        ):
            task = self._pending_queue.popleft()
            mid = schedule_fn([task], self._M)
            if mid < 0 or mid >= self._M:
                mid = min(range(self._M), key=lambda j: self._machine_free[j])
            start = max(self._clock, self._machine_free[mid])
            end = start + task["exec_time"]
            self._machine_free[mid] = end
            heapq.heappush(self._event_queue,
                          (end, self._event_id, "COMPLETE",
                           {"machine_id": mid, "task_id": task["task_id"]}))
            self._event_id += 1

    def _record_queue_depth(self):
        self._queue_depth_history.append(
            (self._clock, len(self._pending_queue))
        )

    def report(self) -> dict:
        comps = self._completion_times
        n = len(comps)
        sorted_t = sorted(comps) if comps else [0.0]
        makespan = max(comps) if comps else 0.0
        p50 = sorted_t[n // 2] if n > 0 else 0.0
        p99 = sorted_t[min(n - 1, int(0.99 * n))] if n > 0 else 0.0
        qd_vals = [qd for _, qd in self._queue_depth_history]
        avg_qd = sum(qd_vals) / len(qd_vals) if qd_vals else 0.0
        return {
            "makespan": round(makespan, 3),
            "n_completed": n,
            "p50_completion": round(p50, 3),
            "p99_completion": round(p99, 3),
            "avg_queue_depth": round(avg_qd, 2),
            "machine_utilization": round(
                sum(comps) / max(makespan * self._M, 0.01), 3
            ),
            "n_events": self._event_id,
        }
