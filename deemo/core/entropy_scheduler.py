"""熵引导的模糊测试种子调度器 — 按种子覆盖边的全局稀有度分配能量。
用指数遗忘因子使历史频率随时间衰减, 保持对新覆盖边的敏感 (核心公式取自 Entropic, 以指数衰减窗口替代固定窗口);
与 adaptive_scheduler.py (MAB 方法级) 互补。参考: Böhme et al., 2020, IEEE S&P "Entropic"; T-Scheduler。"""


import logging
import math
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

_log = logging.getLogger(__name__)


class EntropySeedScheduler:
    """基于香农熵的种子能量调度器。

    每个种子记录其覆盖边集; 调度器维护逐边全局覆盖频率 (带指数衰减),
    select() 时按各种子的信息量分配能量。"""

    def __init__(
        self,
        halflife: float = 10000.0,
        min_energy: float = 1.0,
        max_energy: float = 100.0,
        decay_base: float = 0.9999,
    ):
        """
        Args:
            halflife: half-life of coverage counts (executions), smaller = faster decay
            min_energy: minimum energy per round
            max_energy: maximum energy per round
            decay_base: per-execution decay factor (0.9999 gives half-life ~7000 execs)
        """
        self.halflife = halflife
        self.min_energy = min_energy
        self.max_energy = max_energy
        self.decay_base = decay_base

        self._edge_freq: Dict[int, float] = defaultdict(float)
        self._seed_edges: Dict[str, Set[int]] = {}
        self._seed_energy: Dict[str, float] = {}
        self._total_execs: int = 0

    def register_seed(self, seed_id: str, covered_edges: List[int]) -> None:
        """注册新种子及其覆盖边; 对已存在种子追加新边。"""
        if seed_id not in self._seed_edges:
            self._seed_edges[seed_id] = set()
            self._seed_energy[seed_id] = self.min_energy

        new_edges = set(covered_edges) - self._seed_edges[seed_id]
        for e in new_edges:
            self._edge_freq[e] += 1.0
        self._seed_edges[seed_id] |= new_edges

    def record_execution(self, hit_edges: List[int], seed_id: str = "") -> None:
        """记录一次执行的命中边, 全局频率带衰减更新。

        每次调用: 全局执行计数+1, 所有边频率衰减, 命中边频率+1, 并可选更新种子的边集。"""
        self._total_execs += 1

        # 所有边频率衰减
        for e in list(self._edge_freq.keys()):
            self._edge_freq[e] *= self.decay_base
            if self._edge_freq[e] < 0.001:
                del self._edge_freq[e]

        # 本次执行的命中边
        for e in hit_edges:
            self._edge_freq[e] = self._edge_freq.get(e, 0.0) + 1.0

        if seed_id and seed_id in self._seed_edges:
            self._seed_edges[seed_id] |= set(hit_edges)

        # 每 500 次执行周期性重算能量
        if self._total_execs % 500 == 0:
            self._recompute_energies()

    def _recompute_energies(self) -> None:
        """重算所有种子的香农信息量。"""
        total_execs = max(1, self._total_execs)
        for sid, edges in self._seed_edges.items():
            if not edges:
                self._seed_energy[sid] = self.min_energy
                continue

            # 香农信息量: I(seed) = Σ_{e∈edges} -log₂(freq(e) / total)
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
        """按能量成比例的概率选择种子。

        高信息量种子更可能被选中但不保证, 保留一定探索 (softmax 式而非 argmax)。"""
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
        """返回种子的当前能量值。"""
        return self._seed_energy.get(seed_id, self.min_energy)

    def top_seeds(self, n: int = 5) -> List[Tuple[str, float]]:
        """返回能量最高的前 n 个种子。"""
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
