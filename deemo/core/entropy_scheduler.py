"""
熵引导的模糊测试种子调度器。

基于每条覆盖率边的全局稀有度对种子队列进行能量分配——
覆盖稀有边的种子获得更多变异机会。核心公式来自 Entropic (Böhme et al., 2020)
但使用指数遗忘因子替代固定窗口，使历史频次的影响随时间衰减，
让调度器对新发现的边更敏感。

与现有模块的关系:
  - 不同于 adaptive_scheduler.py 的 MAB 方法级调度——entropy_scheduler 是种子级调度
  - 与 fuzzing/src/rarity_weighted_scheduler.py 互补: rarity 基于覆盖频率，
    entropy 在此基础上加入时间衰减，防止旧的高稀有度种子长期霸占队列

关键参数:
  halflife: 覆盖频次计数的半衰期（executions 数）——值越小遗忘越快
  min_energy / max_energy: 单次变异能量上下界

参考:
  Böhme et al., 2020, IEEE S&P, "Entropic: Boosting Fuzzing with Information Theory"
    — 香农熵度量种子信息量 + 稀有边高能量分配
  T-Scheduler (She et al., 2024, AsiaCCS) — Beta-Bernoulli Thompson Sampling 的
    替代方案；本模块采用确定性指数衰减，避免随机采样的方差
"""

from __future__ import annotations

import logging
import math
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

_log = logging.getLogger(__name__)


class EntropySeedScheduler:
    """
    基于香农熵的种子能量调度器。

    每个种子追踪其覆盖的边集合。调度器维护每条边的全局覆盖频次
    （含指数遗忘），在 select() 时按种子信息量分配能量。
    """

    def __init__(
        self,
        halflife: float = 10000.0,
        min_energy: float = 1.0,
        max_energy: float = 100.0,
        decay_base: float = 0.9999,
    ):
        """
        Args:
            halflife: 覆盖计数的半衰期 (executions)，数值越小遗忘越快
            min_energy: 单轮最低能量
            max_energy: 单轮最高能量
            decay_base: 每次 execution 的衰减因子——0.9999 ≈ 半衰期 7000 execs
        """
        self.halflife = halflife
        self.min_energy = min_energy
        self.max_energy = max_energy
        self.decay_base = decay_base

        # 每条边的全局覆盖频次 (浮点——支持衰减)
        self._edge_freq: Dict[int, float] = defaultdict(float)
        # 种子及其覆盖边集
        self._seed_edges: Dict[str, Set[int]] = {}
        # 种子能量
        self._seed_energy: Dict[str, float] = {}
        # 全局执行计数——驱动衰减
        self._total_execs: int = 0

    def register_seed(self, seed_id: str, covered_edges: List[int]) -> None:
        """
        注册新种子及其覆盖的边。

        若种子已存在则追加新边（增量更新）。
        """
        if seed_id not in self._seed_edges:
            self._seed_edges[seed_id] = set()
            self._seed_energy[seed_id] = self.min_energy

        new_edges = set(covered_edges) - self._seed_edges[seed_id]
        for e in new_edges:
            self._edge_freq[e] += 1.0
        self._seed_edges[seed_id] |= new_edges

    def record_execution(self, hit_edges: List[int], seed_id: str = "") -> None:
        """
        记录一次执行命中的边——更新全局频次并衰减历史。

        每次记录触发:
          1. 全局 execution 计数 +1
          2. 所有边频次 × decay_base（指数衰减）
          3. 本次命中的边频次 +1

        若提供 seed_id 则同时更新该种子覆盖集。
        """
        self._total_execs += 1

        # 衰减全部边频次
        for e in list(self._edge_freq.keys()):
            self._edge_freq[e] *= self.decay_base
            if self._edge_freq[e] < 0.001:
                del self._edge_freq[e]

        # 本次命中
        for e in hit_edges:
            self._edge_freq[e] = self._edge_freq.get(e, 0.0) + 1.0

        if seed_id and seed_id in self._seed_edges:
            self._seed_edges[seed_id] |= set(hit_edges)

        # 周期性重新计算能量——每 500 execs
        if self._total_execs % 500 == 0:
            self._recompute_energies()

    def _recompute_energies(self) -> None:
        """重新计算所有种子的香农信息量。"""
        total_execs = max(1, self._total_execs)
        for sid, edges in self._seed_edges.items():
            if not edges:
                self._seed_energy[sid] = self.min_energy
                continue

            # 香农信息量: I(seed) = Σ_{e∈edges} -log₂( freq(e) / total )
            info = 0.0
            for e in edges:
                freq = max(0.001, self._edge_freq.get(e, 0.001))
                p = freq / total_execs
                info += -math.log2(p)

            # 归一化到 [min_energy, max_energy]
            normalized = info / max(1, math.log2(total_execs))
            energy = self.min_energy + normalized * (self.max_energy - self.min_energy)
            self._seed_energy[sid] = min(self.max_energy, max(self.min_energy, energy))

    def select_seed(self) -> Optional[str]:
        """
        按能量比例随机选择一个种子。

        高信息量种子被选中的概率更大，但不保证必然选中——
        保留低概率探索的随机性（类似 softmax 选择而非 argmax）。

        Returns:
            种子 ID 或 None（队列为空时）
        """
        if not self._seed_energy:
            return None

        total = sum(self._seed_energy.values())
        if total <= 0:
            return None

        import random
        r = random.uniform(0, total)
        cum = 0.0
        for sid, energy in self._seed_energy.items():
            cum += energy
            if r <= cum:
                return sid

        return list(self._seed_energy.keys())[-1]

    def get_energy(self, seed_id: str) -> float:
        """获取指定种子的当前能量值——供外部日志和实验追踪。"""
        return self._seed_energy.get(seed_id, self.min_energy)

    def top_seeds(self, n: int = 5) -> List[Tuple[str, float]]:
        """返回能量最高的 n 个种子。"""
        sorted_seeds = sorted(
            self._seed_energy.items(), key=lambda x: -x[1]
        )
        return sorted_seeds[:n]

    def stats(self) -> Dict[str, Any]:
        """调度器统计快照。"""
        return {
            "total_execs": self._total_execs,
            "active_seeds": len(self._seed_edges),
            "tracked_edges": len(self._edge_freq),
            "total_energy": round(sum(self._seed_energy.values()), 1),
            "top_energy": round(max(self._seed_energy.values()) if self._seed_energy else 0, 1),
            "avg_energy": round(
                sum(self._seed_energy.values()) / max(1, len(self._seed_energy)), 1
            ),
        }
