# 概率驱动的Concolic调度器 — 基于分支覆盖统计的路径难度估计与求解优先级
#
# 核心问题:
#   concolic_bridge.py 收集路径约束但按FIFO顺序求解——所有分支被同等对待。
#   MCP³ (DigFuzz, NDSS 2019) 证明: 仅将"最难fuzz的路径"(最低概率路径)
#   发送给concolic求解器, 可将concolic贡献的覆盖率从3.8%提升到18.9%。
#
#   "需求启动"(Driller风格): fuzzer卡住→启动concolic——太被动,
#   卡住时可能已错过大量concolic机会。
#   "最优切换"(MDPC): 决策开销(中位65s)远超fuzzing执行(0.002s)——不可行。
#
# 本模块的方法 — 基于覆盖概率的判别式调度:
#   1. 从 coverage_index 获取各分支的覆盖计数
#   2. 估算分支概率: P(br) = cov(br) / (cov(br) + cov(sibling))
#      未覆盖分支用"rule of three": P(br) = 3 / cov(sibling) (95%置信上界)
#   3. 路径概率 = Π P(br_i), br_i ∈ path
#   4. 按路径概率升序: 低概率路径优先发送给concolic求解器
#   5. 概率阈值: 仅当 P(path) < threshold 时才调度concolic
#
# 为什么用分支覆盖率估计难度:
#   - 零先验: 不需要符号执行即可估计
#   - 在线更新: 随fuzzing进行持续精炼
#   - 直观: fuzzer经常覆盖的分支→容易; 很少覆盖的→难
#
# 参考文献:
#   MCP³ / DigFuzz (Zhao et al. NDSS 2019) — 概率路径优先级;
#     本项目取其分支概率计算方法但适配到本模块的concolic调度
#   MultiGo (Lin et al. ACM TOSEM 2025) — 多路径优化 + 概率距离;
#     本项目取其概率+距离融合思想

from __future__ import annotations

import math
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

# 桥接 concolic_bridge.py: 接收 PathConstraint 列表, 每个含
# branch_addr, taken, input_offset 等属性。通过 duck-typing
# 消费, 支持任何实现了相同接口的约束对象。
# 桥接 coverage_index.py: 覆盖率数据来自 CoverageIndex.edges_for(),
# 由调用方在 record_branch() 前自行查询并传入。


@dataclass
class BranchStats:
    """单个分支的覆盖统计"""
    branch_addr: int
    taken_count: int = 0        # 走taken分支的执行次数
    not_taken_count: int = 0    # 走not_taken分支的执行次数
    # 兄弟分支地址 (用于关联统计)
    sibling_addr: int = 0

    @property
    def total(self) -> int:
        return self.taken_count + self.not_taken_count

    def probability(self, taken: bool) -> float:
        """估计该分支走向taken/not_taken的概率 [0, 1]"""
        if taken:
            num = self.taken_count
            den = self.total
            sibling_num = self.not_taken_count
        else:
            num = self.not_taken_count
            den = self.total
            sibling_num = self.taken_count

        if den > 0:
            return num / den
        # 未观测到: rule of three (95%置信上界)
        if sibling_num > 0:
            return 3.0 / sibling_num
        return 0.5  # 完全未知


@dataclass
class PathProbability:
    """一条路径的概率估计——用于concolic调度决策"""
    path_id: str = ""
    # 路径上的约束列表 (branch_addr, taken)
    constraints: List[Tuple[int, bool]] = field(default_factory=list)
    # 路径概率 = Π P(br_i)
    probability: float = 1.0
    # 路径长度 (约束数)
    length: int = 0
    # 是否应调度concolic
    should_dispatch: bool = False
    dispatch_priority: float = 0.0   # 越高越优先


@dataclass
class DispatchDecision:
    """Concolic调度决策"""
    paths_to_solve: List[PathProbability] = field(default_factory=list)
    total_paths_evaluated: int = 0
    dispatched_count: int = 0
    threshold: float = 0.0
    summary: str = ""


class ProbConcolicDispatcher:
    """概率驱动的Concolic调度器。

    典型用法:
        dispatcher = ProbConcolicDispatcher(prob_threshold=0.01)
        # Fuzzing过程中更新分支统计:
        dispatcher.record_branch(0x401000, taken=True)
        dispatcher.record_branch(0x401000, taken=False)
        # 每N轮评估一次:
        paths = [...]  # 收集的路径约束
        decision = dispatcher.evaluate(paths)
        for p in decision.paths_to_solve:
            concolic_engine.solve_and_generate(p.constraints)
    """

    def __init__(self,
                 prob_threshold: float = 0.01,
                 max_dispatch_per_round: int = 5):
        """
        prob_threshold: 路径概率低于此值→调度concolic
        max_dispatch_per_round: 每轮最多调度多少条路径
        """
        self._threshold = prob_threshold
        self._max_dispatch = max_dispatch_per_round
        self._branch_stats: Dict[int, BranchStats] = {}
        self._dispatch_count = 0

    def record_branch(self, branch_addr: int, taken: bool,
                       sibling_addr: int = 0) -> None:
        """记录一次分支执行——用于更新覆盖统计"""
        bs = self._branch_stats.get(branch_addr)
        if bs is None:
            bs = BranchStats(branch_addr=branch_addr,
                              sibling_addr=sibling_addr)
            self._branch_stats[branch_addr] = bs
        if taken:
            bs.taken_count += 1
        else:
            bs.not_taken_count += 1

    def evaluate(self, paths: List[List[Tuple[int, bool]]],
                  ) -> DispatchDecision:
        """评估路径集合并决定哪些需要concolic求解"""
        evaluated: List[PathProbability] = []

        for i, constraints in enumerate(paths):
            if not constraints:
                continue
            pp = PathProbability(
                path_id=f"path_{i}",
                constraints=list(constraints),
                length=len(constraints),
            )
            # 计算路径概率
            prob = 1.0
            for addr, taken in constraints:
                bs = self._branch_stats.get(addr)
                if bs:
                    prob *= bs.probability(taken)
                else:
                    prob *= 0.5  # 未知分支→中性概率
            pp.probability = prob
            pp.should_dispatch = prob < self._threshold
            # 优先级 = -log10(prob) 归一化, 概率越小优先级越高
            pp.dispatch_priority = -math.log10(max(prob, 1e-12)) / 12.0
            evaluated.append(pp)

        # 按优先级降序, 限制每轮调度数
        dispatchable = [p for p in evaluated if p.should_dispatch]
        dispatchable.sort(key=lambda p: -p.dispatch_priority)
        selected = dispatchable[:self._max_dispatch]
        self._dispatch_count += len(selected)

        return DispatchDecision(
            paths_to_solve=selected,
            total_paths_evaluated=len(evaluated),
            dispatched_count=len(selected),
            threshold=self._threshold,
            summary=(f"评估{len(evaluated)}条路径, "
                     f"调度{len(selected)}条 (阈值={self._threshold})"),
        )

    # ---- 诊断 ----

    def branch_difficulty(self, branch_addr: int) -> Optional[float]:
        """返回某分支的难度估计 [0, 1]——1=最难"""
        bs = self._branch_stats.get(branch_addr)
        if bs is None:
            return None
        # 难度 = 低概率分支的互补概率
        prob_taken = bs.probability(True)
        prob_not = bs.probability(False)
        # 最难的分支是概率最低的那个方向
        min_prob = min(prob_taken, prob_not)
        return 1.0 - min_prob

    def stats(self) -> Dict[str, Any]:
        tracked = len(self._branch_stats)
        return {
            "tracked_branches": tracked,
            "total_observations": sum(
                bs.total for bs in self._branch_stats.values()),
            "dispatched_total": self._dispatch_count,
            "threshold": self._threshold,
            "hardest_branches": [
                (hex(addr), round(self.branch_difficulty(addr), 3))
                for addr in sorted(
                    self._branch_stats,
                    key=lambda a: -(self.branch_difficulty(a) or 0))[:5]
            ],
        }

    def reset(self) -> None:
        self._branch_stats.clear()
        self._dispatch_count = 0
