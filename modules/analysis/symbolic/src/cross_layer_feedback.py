# 增加 bidirectional feedback：求解结果反向更新路径新颖度评分
# 引入 novelty_decay 因子，避免历史高分路径永久垄断
# 增加 budget_reclaim 机制：低产路径归还未用完的求解预算

"""跨层优化反馈环-路径多样性管理 ↔ 求解器资源管理

现有系统将路径多样性（path_diversity_core.py）和求解器预算
（symexec_opt_passes.py 的 SolverBudgetManager）作为两个独立层运作
这种分离忽略了二者的天然耦合关系：

高多样性路径 → 探索新代码区域的概率更高 → 值得更多求解时间
求解器预算分配 → 决定哪些路径能继续深入 → 影响后续路径多样性

本模块建立双向信息通道：
Path → Solver direc:
- 路径新颖度评分（基于 SimHash 距离到最近已探索路径）
- 高分路径获得 ≤3x 基准求解预算（entropy_guided_budget 已做）
- 低分路径的预算被回收，分配给高分路径

Solver → Path direc:
- 求解成功且产生新状态的路径 → 提升新颖度评分
- 求解超时/UNSAT 的路径 → 降低评分，减少后续资源投入
- warm_start 命中的路径 → 评分因复用效率而获得轻微提升

ref: DiversePath 仅做路径选择不做求解器资源联动
ref: BandFuzz 使用 Thompson 采样分配 模糊测试 能量
但未反馈到符号执行路径选择-本模块的 bidirectional 设计弥补此缺口
"""

import math
import time
import threading
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from collections import defaultdict


@dataclass
class PathNoveltyScore:
    """路径的新颖度评分及其衰减状态"""
    path_id: str
    simhash: int                       # 64-bit SimHash 指纹
    novelty: float = 1.0               # [0,1]，越高越新颖
    solver_budget_allocated: float = 0.0
    solver_budget_consumed: float = 0.0
    last_update_time: float = 0.0
    solve_success_count: int = 0
    solve_failure_count: int = 0
    decay_factor: float = 1.0          # 随时间衰减的乘数


class CrossLayerFeedbackLoop:
    """路径多样性管理与求解器预算管理的双向反馈环

    使用模式：
    loop = CrossLayerFeedbackLoop()
    for path active_paths:
    budget = loop.allocate_budget(path, base_budget)
    solve_result = solver.solve(path.constraints, timeout=budget)
    loop.record_solve_result(path, solve_result)

    每 allocate_budget 调用会根据当前路径新颖度调整预算；
    每 record_solve_result 调用会根据求解结果更新新颖度
    """

    def __init__(self,
                 base_budget_per_path: float = 5.0,
                 max_budget_multiplier: float = 3.0,
                 novelty_decay_rate: float = 0.95,
                 decay_interval_seconds: float = 60.0,
                 min_novelty_for_bonus: float = 0.3):
        """
        base_budget_per_path: 每条路径的基准求解时间（秒）
        max_budget_multiplier: 高新颖度路径的最大预算倍率
        novelty_decay_r: 每 decay_interval 秒的衰减乘数（<1.0）
        min_novelty_for_bonus: 低于此新颖度的路径不获得预算加成
        """
        self._base_budget = base_budget_per_path
        self._max_multiplier = max_budget_multiplier
        self._decay_rate = novelty_decay_rate
        self._decay_interval = decay_interval_seconds
        self._min_novelty = min_novelty_for_bonus

        self._path_scores: Dict[str, PathNoveltyScore] = {}
        self._reclaim_pool: float = 0.0        # 回收的预算池
        self._lock = threading.Lock()
        self._last_decay_time = time.time()

        # 统计指标
        self._total_allocated: float = 0.0
        self._total_reclaimed: float = 0.0
        self._budget_efficiency: float = 0.0   # 有效求解数 / 总预算

    def _decay_if_needed(self) -> None:
        """周期性衰减所有路径的新颖度-防止早期高分路径永久垄断"""
        now = time.time()
        if now - self._last_decay_time < self._decay_interval:
            return

        elapsed_intervals = (now - self._last_decay_time) / self._decay_interval
        decay = self._decay_rate ** elapsed_intervals

        for score in self._path_scores.values():
            score.decay_factor *= decay
            score.novelty *= decay

        self._last_decay_time = now

    def compute_novelty(self, path_simhash: int,
                        neighbor_simhashes: List[int]) -> float:
        """基于 SimHash 汉明距离计算路径新颖度

        新颖度 = min(汉明距离 / 32, 1.0)，即最近邻距离归一化
        32 是 64-bit SimHash 距离的一半-超过此值认为完全新颖
        """
        if not neighbor_simhashes:
            return 1.0  # 无邻居 → 完全新颖

        min_distance = min(
            bin(path_simhash ^ other).count('1')
            for other in neighbor_simhashes
        )
        return min(min_distance / 32.0, 1.0)

    def allocate_budget(self, path_id: str, path_simhash: int,
                        neighbor_simhashes: List[int],
                        base_override: Optional[float] = None) -> float:
        """为路径分配求解预算

        返回分配的求解时间（秒）。会考虑当前新颖度、回收池余额
        """
        with self._lock:
            self._decay_if_needed()

            novelty = self.compute_novelty(path_simhash, neighbor_simhashes)
            base = base_override if base_override is not None else self._base_budget

            # 新颖度 → 预算倍率映射
            if novelty >= self._min_novelty:
                # 线性映射：新颖度 [min_novel, 1.0] → 倍率 [1.0, max_multiplier]
                bonus = (novelty - self._min_novelty) / (1.0 - self._min_novelty)
                multiplier = 1.0 + bonus * (self._max_multiplier - 1.0)
            else:
                multiplier = 1.0

            allocated = base * multiplier

            # 回收池分配-将低产路径归还的预算重新分配给高产路径
            if novelty > 0.7 and self._reclaim_pool > 0:
                reclaim_bonus = min(self._reclaim_pool * 0.1, base * 0.5)
                allocated += reclaim_bonus
                self._reclaim_pool -= reclaim_bonus

            # 记录/更新路径评分
            if path_id in self._path_scores:
                score = self._path_scores[path_id]
                score.novelty = 0.8 * score.novelty + 0.2 * novelty  # EMA
                score.solver_budget_allocated = allocated
                score.last_update_time = time.time()
            else:
                self._path_scores[path_id] = PathNoveltyScore(
                    path_id=path_id,
                    simhash=path_simhash,
                    novelty=novelty,
                    solver_budget_allocated=allocated,
                    last_update_time=time.time(),
                )

            self._total_allocated += allocated
            return allocated

    def record_solve_result(self, path_id: str, success: bool,
                            actual_time: float,
                            new_states_count: int = 0) -> None:
        """记录求解结果-反向更新路径新颖度

        success=True 且产生了新状态 → 提升新颖度
        success=False (超时/UNSAT) → 降低新颖度
        未用完的预算 → 回收到 reclaim_pool
        """
        with self._lock:
            score = self._path_scores.get(path_id)
            if score is None:
                return

            score.solver_budget_consumed += actual_time

            if success:
                score.solve_success_count += 1
                if new_states_count > 0:
                    # 产生新状态-路径价值高于预期，提升新颖度
                    score.novelty = min(
                        1.0, score.novelty + 0.05 * new_states_count)
            else:
                score.solve_failure_count += 1
                # UNSAT/超时-路径可能已死胡同，降低新颖度
                score.novelty *= 0.85

            # Budget reclaim: 实际消耗小于分配的 50% → 回收差额
            if (score.solver_budget_allocated > 0 and
                    actual_time < score.solver_budget_allocated * 0.5):
                reclaimed = score.solver_budget_allocated - actual_time
                self._reclaim_pool += reclaimed * 0.8  # 80% 回收率
                self._total_reclaimed += reclaimed * 0.8

            # 更新预算效率
            total_consumed = sum(
                s.solver_budget_consumed for s in self._path_scores.values())
            if total_consumed > 0:
                successful = sum(
                    1 for s in self._path_scores.values()
                    if s.solve_success_count > 0)
                self._budget_efficiency = successful / max(total_consumed, 0.001)

    def get_top_novelty_paths(self, n: int = 5) -> List[Tuple[str, float]]:
        """返回当前新颖度最高的 N 条路径-供外部调度器优先选择"""
        with self._lock:
            sorted_paths = sorted(
                self._path_scores.items(),
                key=lambda x: x[1].novelty * x[1].decay_factor,
                reverse=True,
            )
            return [(pid, score.novelty) for pid, score in sorted_paths[:n]]

    def get_low_yield_paths(self, threshold: float = 0.15) -> List[str]:
        """返回求解成功率低于 threshold 的路径 ID-可供外部剪枝决策"""
        with self._lock:
            low_yield = []
            for pid, score in self._path_scores.items():
                total = score.solve_success_count + score.solve_failure_count
                if total >= 5:  # 最少 5 次求解后才做判断
                    success_rate = score.solve_success_count / total
                    if success_rate < threshold:
                        low_yield.append(pid)
            return low_yield

    @property
    def reclaim_pool_balance(self) -> float:
        return self._reclaim_pool

    @property
    def efficiency_score(self) -> float:
        return self._budget_efficiency

    def get_diagnostics(self) -> Dict[str, Any]:
        """返回诊断快照"""
        with self._lock:
            return {
                'active_paths': len(self._path_scores),
                'reclaim_pool': self._reclaim_pool,
                'total_allocated': self._total_allocated,
                'total_reclaimed': self._total_reclaimed,
                'budget_efficiency': self._budget_efficiency,
                'avg_novelty': (
                    sum(s.novelty for s in self._path_scores.values()) /
                    max(len(self._path_scores), 1)
                ),
            }
