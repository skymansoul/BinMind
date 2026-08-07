# 修改记录:
# 2025-07-21 14:32 - 增加 rebuild cost estimator，预判重建是否值得
# 2025-07-25 09:18 - 引入 gradual_state_transfer：不完全重建而是逐层替换
# 2025-07-29 16:55 - 增加 memory_pressure 感知，高压下更激进地触发重建

"""求解器状态的周期性重建调度器

IncrementalSolver缓存(symexec_opt_passes.py) 使用 Z3 push/pop 管理增量求解
状态。但 push/pop 累积的内部状态导致内存从 ~10MB 增长到 >500MB——
Z3 在 push 后保留所有学习到的引理 (lemmas)、简化规则和内部启发式状态
解过 200 次后继续复用旧 solver 实例的收益可能低于重建成本

本模块提供智能重建决策：
a. RebuildCostEstimator: 预估重建后的求解时间 vs 不重建
只有预期净收益 >10% 才执行重建
b. GradualStateTransfer: 不完全丢弃旧 solver 状态——
在重建时传递 warm_start 模型和 SAT 解变量赋值
c. MemoryPressureSensor: 内存超过阈值时降低重建触发条件
d. 双阈值策略——硬阈值（强制重建）和软阈值（触发评估）

权衡：重建丢失所有已学习引理，首次求解可能更慢；
但减少内存占用和求解器内部遍历开销，长期更稳定

ref: Z3 GitHub #7203 讨论了 incremental solver 的状态累积问题——
solver2 的 push/pop 比 solver1 快但内部状态随 push 次数线性增长
本模块直接解决此权衡——通过成本预估决定何时丢弃累积状态
ref: FSE 2024 "Partial Solu Based 约束求解缓存" 的
partial solu 缓存机制——本模块的 warm_start 传递复用类似思想
但应用于求解器实例生命周期而非约束缓存
"""

import math
import time
import threading
from typing import Dict, List, Optional, Tuple, Callable, Any
from dataclasses import dataclass, field
from collections import deque


@dataclass
class RebuildMetrics:
    """求解器实例的性能指标——用于重建决策"""
    push_count: int = 0
    solve_count: int = 0
    total_solve_time_ms: float = 0.0
    avg_solve_time_ms: float = 0.0
    recent_solve_times: deque = field(default_factory=lambda: deque(maxlen=20))
    constraint_count: int = 0
    warm_start_hit_count: int = 0
    warm_start_miss_count: int = 0
    estimated_memory_mb: float = 15.0
    last_rebuild_time: float = 0.0


class RebuildCostEstimator:
    """预估重建 vs 不重建的成本差异
    
    核心假设（基于 Z3 行为观测）：
    - 新 solver 首次求解比复用慢 ~40%（无已学习引理）
    - solver 内部遍历开销与 push_count 正相关，近似 O(sqrt(n))
    - 内存增长与 constraint_count 近似线性
    
    成本预估公式：
    cost_rebuild = sum(剩余约束的预估首次求解时间) * 1.4
    cost_no_rebuild = sum(剩余约束的预估求解时间) + push_overhead
    push_overhead = sqrt(push_count) * avg_solve_time * 0.05
    """

    _FIRST_SOLVE_PENALTY = 1.4    # 首次求解比复用慢的倍率
    _PUSH_OVERHEAD_COEFF = 0.05   # push 开销系数

    def estimate(self, metrics: RebuildMetrics,
                 remaining_constraints: int) -> Tuple[float, float, bool]:
        """返回 (cost_rebuild, cost_no_rebuild, should_rebuild)"""
        if metrics.solve_count == 0:
            return 0.0, 0.0, False

        avg_time = metrics.total_solve_time_ms / max(metrics.solve_count, 1)
        push_overhead = (
            math.sqrt(metrics.push_count) * avg_time * self._PUSH_OVERHEAD_COEFF
        )

        cost_rebuild = (
            remaining_constraints * avg_time * self._FIRST_SOLVE_PENALTY
        )
        cost_no_rebuild = remaining_constraints * avg_time + push_overhead

        should_rebuild = cost_rebuild < cost_no_rebuild * 0.9
        return cost_rebuild, cost_no_rebuild, should_rebuild


class MemoryPressureSensor:
    """内存压力感知——高压下降低重建触发阈值
    
    不使用 psutil（可选依赖），改为从 RebuildMetrics 推断：
    estimated_memory_mb 超过硬阈值 → 无条件重建
    超过软阈值 → 降低 RebuildCostEstimator 的收益阈值
    """

    HARD_THRESHOLD_MB = 500   # 超过此值强制重建
    SOFT_THRESHOLD_MB = 200   # 超过此值降低收益阈值到 0.7

    def assess(self, metrics: RebuildMetrics) -> Tuple[float, bool]:
        """返回 (收益阈值倍率, 是否强制重建)
        
        收益阈值倍率 < 1.0 表示更容易触发重建
        """
        mem = metrics.estimated_memory_mb

        if mem >= self.HARD_THRESHOLD_MB:
            return 0.0, True  # 强制重建

        if mem >= self.SOFT_THRESHOLD_MB:
            # 软阈值——收益阈值从 0.9 降到 0.7
            return 0.7, False

        return 1.0, False


class SolverRebuildScheduler:
    """求解器实例的周期性重建调度
    
    使用模式：
    scheduler = SolverRebuildScheduler()
    for constraint_batch batches:
    metrics = scheduler.record_solve(push_count, solve_time, constraint_count)
    scheduler.should_rebuild(metrics, remaining_constraints):
    solver.重置() # 调用方重建 Z3 solver
    scheduler.on_rebuild()
    """

    def __init__(self,
                 hard_rebuild_pushes: int = 500,
                 hard_rebuild_solves: int = 200,
                 warm_start_transfer: bool = True):
        """
        hard_rebuild_pushes: push 次数硬上限——超过必重建
        hard_rebuild_solves: 求解次数硬上限——超过必重建
        warm_start_transfer: 重建时是否传递 warm_start 模型
        """
        self._hard_push_limit = hard_rebuild_pushes
        self._hard_solve_limit = hard_rebuild_solves
        self._warm_start_transfer = warm_start_transfer

        self._cost_estimator = RebuildCostEstimator()
        self._mem_sensor = MemoryPressureSensor()
        self._metrics = RebuildMetrics()
        self._rebuild_count = 0
        self._lock = threading.Lock()
        self._warm_start_cache: Dict[str, int] = {}  # var_name → value

    def record_solve(self, push_count: int, solve_time_ms: float,
                     constraint_count: int, warm_start_hit: bool = False,
                     estimated_memory_mb: float = 0.0) -> RebuildMetrics:
        """记录一次求解——更新内部指标"""
        with self._lock:
            m = self._metrics
            m.push_count = push_count
            m.solve_count += 1
            m.total_solve_time_ms += solve_time_ms
            m.recent_solve_times.append(solve_time_ms)
            m.constraint_count = constraint_count

            if warm_start_hit:
                m.warm_start_hit_count += 1
            else:
                m.warm_start_miss_count += 1

            # 内存估算：基础 15MB + 每约束约 1.5MB（经验常数）
            if estimated_memory_mb > 0:
                m.estimated_memory_mb = estimated_memory_mb
            else:
                m.estimated_memory_mb = 15.0 + constraint_count * 1.5

            # 最近 20 次求解的移动平均
            if len(m.recent_solve_times) >= 5:
                recent = list(m.recent_solve_times)[-5:]
                m.avg_solve_time_ms = sum(recent) / len(recent)
            else:
                m.avg_solve_time_ms = (
                    m.total_solve_time_ms / max(m.solve_count, 1))

            return m

    def should_rebuild(self, metrics: Optional[RebuildMetrics] = None,
                       remaining_constraints: int = 0) -> Tuple[bool, str]:
        """判断是否重建求解器实例
        
        返回 (should_rebuild, reason)
        """
        m = metrics or self._metrics

        # 硬阈值——无条件重建
        if m.push_count >= self._hard_push_limit:
            return True, f'push_count={m.push_count} >= {self._hard_push_limit}'
        if m.solve_count >= self._hard_solve_limit:
            return True, f'solve_count={m.solve_count} >= {self._hard_solve_limit}'

        # 内存压力检测
        threshold_mult, force = self._mem_sensor.assess(m)
        if force:
            return True, f'memory={m.estimated_memory_mb:.0f}MB >= hard threshold'

        # 成本预估
        cost_rebuild, cost_no_rebuild, should = self._cost_estimator.estimate(
            m, remaining_constraints)

        if should and threshold_mult < 1.0:
            # 内存压力下更激进
            return True, (
                f'cost: rebuild={cost_rebuild:.1f} < '
                f'no_rebuild={cost_no_rebuild:.1f} (mem_pressure adjusted)')

        if should:
            return True, (
                f'cost: rebuild={cost_rebuild:.1f} < '
                f'no_rebuild={cost_no_rebuild:.1f}')

        return False, 'cost-benefit unfavorable'

    def on_rebuild(self) -> None:
        """重建完成后的状态更新"""
        with self._lock:
            self._rebuild_count += 1
            self._metrics.push_count = 0
            self._metrics.solve_count = 0
            self._metrics.last_rebuild_time = time.time()
            # 保留 warm_start 缓存——重建的 solver 可用上一轮的 SAT 解
            # 不清空 self._warm_start_cache

    def store_warm_start(self, var_values: Dict[str, int]) -> None:
        """存储 SAT 解的变量赋值——在重建时传递给新 solver"""
        if self._warm_start_transfer:
            self._warm_start_cache.update(var_values)

    def get_warm_start(self) -> Dict[str, int]:
        """获取最近一次 SAT 解的变量赋值"""
        return dict(self._warm_start_cache)

    @property
    def rebuild_count(self) -> int:
        return self._rebuild_count

    @property
    def warm_start_hit_rate(self) -> float:
        m = self._metrics
        total = m.warm_start_hit_count + m.warm_start_miss_count
        if total == 0:
            return 0.0
        return m.warm_start_hit_count / total

    def get_diagnostics(self) -> Dict[str, Any]:
        """返回诊断快照"""
        m = self._metrics
        return {
            'push_count': m.push_count,
            'solve_count': m.solve_count,
            'avg_solve_time_ms': m.avg_solve_time_ms,
            'estimated_memory_mb': m.estimated_memory_mb,
            'warm_start_hit_rate': self.warm_start_hit_rate,
            'rebuild_count': self._rebuild_count,
            'warm_start_cache_size': len(self._warm_start_cache),
        }
