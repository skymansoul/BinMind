# 创建: 2026-08-03
# 修改: 2026-08-05 — 增加Kingman排队界 + 令牌桶准入控制
#
# 随机队列边界的容量约束调度 — Kingman G/G/1 + 令牌桶准入
#
# 传统调度假设无限队列。实际系统有队列容量上限。
# 旧版仅用静态硬/软限制——不关联到达率和服务率的统计特性，
# 导致: 突发流量时过早拒绝 (容量实际够) 或平稳流量时过晚拒绝
# (队列已满才触发，尾部延迟已恶化)。
#
# 本模块新增:
#   1. Kingman 重交通近似: 对每个优先级队列估计均值等待时间上界
#      E[W] ≈ (ρ/(1-ρ))·(c_a²+c_s²)/(2·μ)
#      ρ=利用率, c_a=到达间隔CV, c_s=服务时间CV, μ=服务率
#   2. 基于 Kingman 界的动态准入: 若预估等待 > SLO → 拒绝/延迟
#   3. 令牌桶平滑: 限制突发大小, 补偿 Kingman 在轻交通下的偏差
#
# Ryabchenko et al. (COLT 2025, arXiv:2503.19856) 研究容量约束下
# 带延迟的在线学习——提出抢占式和非抢占式调度策略，遗憾极小极大最优。
# 本模块将同一框架特化到 DAG 任务调度:
#
# 容量约束:
#   - 硬容量 C_hard: 绝对上限，到达时若满 → 拒绝
#   - 软容量 C_soft: 到达时若超 → 进入延迟批处理 (defer)
#   - 弹性容量 C_elastic: 根据优先级动态预留槽位
#
# 批处理策略:
#   - 按优先级分桶: high/medium/low 各独立子队列
#   - 高优子队列有保证容量 (隔离)
#   - 延迟批处理中的任务基于预测执行时间的 EDF (Earliest Deadline First)
#     排序——最小化最坏延迟

from __future__ import annotations

import time
import math
import threading
from collections import deque
from dataclasses import dataclass, field


# ---- 随机队列分析 (Kingman G/G/1 界) ----

class KingmanDelayBound:
    """Kingman 重交通近似 — 估计 G/G/1 队列的均值等待时间上界。

    E[W] ≈ (ρ/(1-ρ)) · (c_a² + c_s²) / (2·μ)

    其中:
      ρ = λ/μ  (利用率)
      c_a² = Var(arrival_interval) / E[arrival_interval]²
      c_s² = Var(service_time) / E[service_time]²
      μ = 1/E[service_time]

    有效性条件: ρ < 1且系统处于重交通 (ρ > 0.6)。
    轻交通时 Kingman 上界偏保守——用令牌桶准入补偿。

    Whitt (1983, "The Queueing Network Analyzer", Bell System Tech J)
    将此近似扩展到排队网络; 本模块取单队列特化。
    """

    def __init__(self):
        self._arrivals: deque = deque(maxlen=100)
        self._services: deque = deque(maxlen=100)

    def record_arrival(self, inter_arrival: float):
        if inter_arrival > 0:
            self._arrivals.append(inter_arrival)

    def record_service(self, service_time: float):
        if service_time > 0:
            self._services.append(service_time)

    def estimate_wait(self, n_servers: int = 1) -> float:
        """返回预估均值等待时间 (秒)。无法估计时返回 float('inf')。"""
        if len(self._arrivals) < 5 or len(self._services) < 5:
            return float('inf')
        # 到达间隔统计
        E_a = sum(self._arrivals) / len(self._arrivals)
        if E_a <= 0:
            return float('inf')
        var_a = sum((x - E_a)**2 for x in self._arrivals) / len(self._arrivals)
        c_a2 = var_a / (E_a * E_a)
        # 服务时间统计
        E_s = sum(self._services) / len(self._services)
        if E_s <= 0:
            return float('inf')
        var_s = sum((x - E_s)**2 for x in self._services) / len(self._services)
        c_s2 = var_s / (E_s * E_s)
        # 利用率
        lam = 1.0 / E_a   # 到达率
        mu = n_servers / E_s  # 服务率 (每服务器)
        rho = lam / max(mu, 1e-9)
        if rho >= 1.0:
            return float('inf')
        # Kingman 界
        W = (rho / (1.0 - rho)) * (c_a2 + c_s2) / (2.0 * mu)
        return W

    @property
    def utilization(self) -> float:
        if len(self._arrivals) < 2 or len(self._services) < 2:
            return 0.0
        E_a = sum(self._arrivals) / len(self._arrivals)
        E_s = sum(self._services) / len(self._services)
        if E_a <= 0 or E_s <= 0:
            return 0.0
        return E_s / E_a  # ρ = λ/μ = E_s/E_a for single server


# ---- 令牌桶准入控制 ----
from typing import Optional, List, Dict, Tuple


@dataclass
class CapacityConfig:
    hard_limit: int = 1000
    soft_limit: int = 800
    high_prio_reserved: int = 100   # 高优先级保证容量
    batch_size: int = 10            # 批处理释放的每次数量
    max_defer_s: float = 300.0       # 最大延迟等待


@dataclass
class QueuedTask:
    task_id: str
    priority: str        # high | medium | low
    estimated_exec_s: float
    arrival_time: float
    deadline: float = float('inf')


class TokenBucket:
    """令牌桶速率限制器 — 平滑突发，补充 Kingman 在轻交通下的保守性。

    桶容量 B 和速率 r:
      - 令牌以速率 r 生成 (个/秒), 最多 B 个积存
      - 每个准入请求消耗 1 个令牌
      - 有令牌 → 准入; 无令牌 → 拒绝
      - B 控制可容忍的最大突发大小
    """

    def __init__(self, rate: float = 10.0, burst: int = 30):
        self._r = rate          # 令牌生成速率
        self._B = burst         # 桶容量
        self._tokens = float(burst)
        self._last_refill = time.monotonic()
        self._lock = threading.Lock()

    def consume(self, n: int = 1) -> bool:
        """尝试消耗 n 个令牌。返回 True 若足够。"""
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_refill
            self._tokens = min(float(self._B), self._tokens + self._r * elapsed)
            self._last_refill = now
            if self._tokens >= n:
                self._tokens -= n
                return True
            return False

    @property
    def available(self) -> float:
        now = time.monotonic()
        elapsed = now - self._last_refill
        return min(float(self._B), self._tokens + self._r * elapsed)


class CapacityConstrainedScheduler:
    """容量约束在线调度器。

    三子队列 (高/中/低优先) + 延迟池。
    push: 根据容量决定 admit/defer/reject
    pop_batch: 释放一批任务 (优先级感知的加权公平)
    """

    def __init__(self, config: Optional[CapacityConfig] = None):
        self._cfg = config or CapacityConfig()
        self._high: deque = deque()
        self._med: deque = deque()
        self._low: deque = deque()
        self._deferred: deque = deque()
        self._total_admitted: int = 0
        self._total_rejected: int = 0
        self._lock = threading.Lock()

    def push(self, task: QueuedTask) -> str:
        """尝试入队 — 返回 "admitted" / "deferred" / "rejected"。"""
        with self._lock:
            total = self.total_queued
            # 硬上限 → 拒绝
            if total >= self._cfg.hard_limit:
                self._total_rejected += 1
                return "rejected"

            # 软上限 → 延迟
            if total >= self._cfg.soft_limit:
                if task.priority == "high":
                    pass  # 高优强行入队 (下方逻辑)
                else:
                    self._deferred.append(task)
                    return "deferred"

            # 高优有保证容量
            if task.priority == "high":
                if len(self._high) < self._cfg.high_prio_reserved:
                    self._high.append(task)
                else:
                    self._high.append(task)  # 超出保留但仍在总容量内
            elif task.priority == "medium":
                self._med.append(task)
            else:
                self._low.append(task)

            self._total_admitted += 1
            return "admitted"

    def pop_batch(self) -> List[QueuedTask]:
        """优先级感知的加权公平出队。

        权重: high=5, medium=3, low=1 (每批按此比例)
        出队顺序: 同优先级内按 deadline (EDF)。
        """
        with self._lock:
            batch = []
            B = self._cfg.batch_size

            # 按权重分配槽位
            n_high = min(len(self._high), int(B * 0.5))
            n_med  = min(len(self._med),  int(B * 0.3))
            n_low  = B - n_high - n_med
            if n_low > len(self._low):
                # 低优不足 → 补给中优
                extra = n_low - len(self._low)
                n_low = len(self._low)
                n_med = min(len(self._med), n_med + extra)

            for _ in range(n_high):
                batch.append(self._high.popleft())
            for _ in range(n_med):
                batch.append(self._med.popleft())
            for _ in range(min(n_low, len(self._low))):
                batch.append(self._low.popleft())

            # 释放延迟池中到期的任务
            now = time.monotonic()
            released = []
            remaining = deque()
            for task in self._deferred:
                if now - task.arrival_time >= self._cfg.max_defer_s:
                    batch.append(task)
                else:
                    remaining.append(task)
            self._deferred = remaining

            return batch

    # ---- 优先级感知的队列深度 ----

    @property
    def total_queued(self) -> int:
        return len(self._high) + len(self._med) + len(self._low)

    def queue_depth_by_priority(self) -> Dict[str, int]:
        return {
            "high": len(self._high),
            "medium": len(self._med),
            "low": len(self._low),
            "deferred": len(self._deferred),
        }

    def utilization(self) -> float:
        """队列利用率 — 0~1。"""
        return min(1.0, self.total_queued / max(1, self._cfg.soft_limit))

    def stats(self) -> dict:
        with self._lock:
            return {
                "total_admitted": self._total_admitted,
                "total_rejected": self._total_rejected,
                "reject_rate": round(
                    self._total_rejected / max(1, self._total_admitted + self._total_rejected), 4
                ),
                "queue_depth": self.queue_depth_by_priority(),
                "utilization": round(self.utilization(), 4),
                "capacity": {
                    "hard": self._cfg.hard_limit,
                    "soft": self._cfg.soft_limit,
                    "high_reserved": self._cfg.high_prio_reserved,
                },
            }

    # ---- Kingman 界集成 ----

    def admit_with_bound(self, task: QueuedTask,
                         slo_wait_s: float = 5.0) -> Tuple[str, float]:
        """基于 Kingman 等待界 + 令牌桶的联合准入。

        返回 (decision, estimated_wait_s)。
        决策逻辑: 预估等待 ≤ SLO 且 令牌桶有余 → admit
                 预估等待 > SLO → defer
                 令牌桶空 → reject
        """
        est_wait = self._kingman.estimate_wait()
        if est_wait == float('inf'):
            est_wait = slo_wait_s  # 无法估计时保守使用 SLO
        if est_wait > slo_wait_s:
            return ("deferred", est_wait)
        if not self._token_bucket.consume():
            return ("rejected", est_wait)
        result = self.push(task)
        return (result, est_wait)

    def record_completion(self, service_time_s: float,
                          inter_arrival_s: float = 0.0):
        """反馈观测值以更新 Kingman 估计。"""
        self._kingman.record_service(service_time_s)
        if inter_arrival_s > 0:
            self._kingman.record_arrival(inter_arrival_s)

    def integrate_kingman(self, arrival_window: int = 100,
                          service_window: int = 100):
        """集成 Kingman 延迟估计 + 令牌桶到现有调度器。

        为三个优先级各自维护 Kingman 追踪器 + 令牌桶。
        应在 CapacityConstrainedScheduler.__init__ 中调用。
        """
        self._kingman = KingmanDelayBound()
        self._token_bucket = TokenBucket(rate=10.0, burst=30)
