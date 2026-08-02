# 2026-07-31

"""能量调度策略 -- 可插拔的种子能量分配算法集合。

参考:
  AFLFast (USENIX 2020)    -- explore/coe/quad/lin/fast 五种功率调度
  EcoFuzz (USENIX 2020)    -- 自适应exploration/exploitation状态切换
  pAFL    (ICCNS 2024)     -- UCB自适应能量分配
  TMS-Fuzz (JSS 2026)      -- Thompson Sampling能量分配

能量是 AFL 系模糊测试中的核心概念: 每个种子被分配一个"能量"值,
高能量表示该种子将被更高频地选取并在每次被选中时执行更多变异轮次。

不同策略适用于不同阶段:
  - 初期 (ramp-up): explore 策略偏向新鲜种子
  - 中期 (exploration): coe (Cut-Off Exponential) 折中
  - 后期 (exploitation): quad 策略让已被证明高产的老种子多变异
"""

import math
import random
import time
from enum import Enum
from typing import Dict, List, Optional, Sequence


class EnergyPolicy(str, Enum):
    """能量策略枚举。"""
    EXPLORE = "explore"      # AFLFast: 对新发现的种子分配更多能量
    COE = "coe"              # Cut-Off Exponential: 频繁使用的种子能量指数衰减
    QUAD = "quad"            # 二次型: 执行时间短+覆盖率高的种子获得更多
    LIN = "lin"              # 线性: 能量正比于覆盖率/执行时间
    FAST = "fast"            # AFLFast默认: 与种子被选中次数成反比
    ADAPTIVE = "adaptive"    # EcoFuzz风格: 探索/利用状态自适应切换
    UCB_ENERGY = "ucb_energy"  # pAFL风格: UCB决定能量, 与调度器解耦


# ===== 能量计算函数 =====

def energy_explore(seed_finds: int, total_finds: int,
                   seed_cycles: int, total_cycles: int,
                   base_energy: float = 1.0) -> float:
    """AFLFast explore: 给新发现的种子更多能量。

    能量 ∝ (seed_finds / seed_cycles) * (total_cycles / total_finds)
    即"该种子的发现效率"与"整体发现密度"之比。
    """
    if seed_cycles <= 0 or total_finds <= 0:
        return base_energy
    seed_eff = seed_finds / seed_cycles
    global_density = total_cycles / total_finds
    return base_energy * seed_eff * global_density


def energy_coe(seed_finds: int, seed_cycles: int,
               coef: float = 0.5) -> float:
    """Cut-Off Exponential: 能量随周期指数衰减, 新发现重置。

    公式: energy = coef + (1 - coef) * 2^(-seed_cycles / seed_finds)
    当 seed_finds = 0 时, 能量降至 coef (地板)。
    AFLFast 中 coef 默认为 0.5。
    """
    if seed_finds <= 0:
        return coef
    exp_term = 2.0 ** (-seed_cycles / seed_finds)
    return coef + (1.0 - coef) * exp_term


def energy_quad(exec_time_ms: float, edge_count: int,
                generation: int, base: float = 1.0) -> float:
    """二次型: 快速+高覆盖+低代数 → 高能量。

    能量 ∝ edge_count² / (exec_time_ms * generation)
    鼓励对"短执行时间、多覆盖、新种子"的深度变异。
    """
    exec_t = max(1.0, exec_time_ms)
    gen = max(1, generation)
    return base * (edge_count ** 2) / (exec_t * gen)


def energy_lin(edge_count: int, exec_time_ms: float,
               base: float = 1.0) -> float:
    """线性: 能量 ∝ edge_count / exec_time_ms。"""
    exec_t = max(1.0, exec_time_ms)
    return base * edge_count / exec_t


def energy_fast(pick_count: int, base: float = 100.0) -> float:
    """AFLFast默认: 能量与选中次数成反比。

    每被选中一次, 能量减半。新种子获得 full energy。
    自然达成"探索新种子优先"的效果。
    """
    if pick_count <= 0:
        return base
    return base / (2.0 ** pick_count)


# ===== EcoFuzz 风格的自适应策略 =====

class AdaptiveEnergyPolicy:
    """EcoFuzz (2020) 风格的自适应能量策略。

    核心思想:
      - 当整体覆盖率增长快 (exploration 阶段), 偏向给新种子多能量
      - 当整体增长慢 (exploitation 阶段), 转向给高产老种子多能量

    通过最近 N 个周期的新增覆盖边数判断当前阶段,
    切换对应系数。不需要外部指定阶段标签。
    """

    def __init__(self, window: int = 10,
                 explore_threshold: float = 2.0):
        """
        window: 追踪最近多少个周期的覆盖增长
        explore_threshold: 新增边/周期低于此值则切换为 exploitation
        """
        self.window = window
        self.explore_threshold = explore_threshold
        self._edge_growth_history: List[float] = []
        self._current_mode: str = "explore"  # explore / exploit

    def update(self, new_edges: int) -> None:
        """记录一个周期的新增覆盖边数。"""
        self._edge_growth_history.append(float(new_edges))
        if len(self._edge_growth_history) > self.window:
            self._edge_growth_history.pop(0)

        self._recompute_mode()

    def _recompute_mode(self) -> None:
        if len(self._edge_growth_history) < 3:
            self._current_mode = "explore"
            return
        avg_growth = sum(self._edge_growth_history) / len(self._edge_growth_history)
        self._current_mode = (
            "explore" if avg_growth >= self.explore_threshold else "exploit"
        )

    def compute_energy(self, seed_meta: dict, base: float = 1.0) -> float:
        """根据当前模式和种子元数据计算能量。

        探索模式: 偏向新种子 (低代数、小pick_count)
        利用模式: 偏向高产种子 (高 edge_count、低 exec_time)
        """
        gen = seed_meta.get("generation", 0)
        edge_cnt = seed_meta.get("edge_count", 0)
        exec_time = seed_meta.get("exec_time_ms", 10.0)
        picks = seed_meta.get("pick_count", 0)

        if self._current_mode == "explore":
            # 偏向新种子
            gen_factor = 1.0 / (1.0 + gen)
            return base * gen_factor * (1.0 / (1.0 + picks))
        else:
            # 偏向高产种子
            cov_factor = math.log2(1 + edge_cnt)
            time_factor = 1.0 / max(1.0, exec_time / 10.0)
            return base * cov_factor * time_factor

    @property
    def mode(self) -> str:
        return self._current_mode


# ===== UCB 能量分配 (pAFL 2024 风格) =====

class UCBEnergyAllocator:
    """基于 UCB 的能量分配器 [pAFL 2024]。

    每个种子有 n_i (被选中次数) 和 r_i (发现数), 能量由 UCB 上界决定。
    这与 UCB 调度器的区别:
      - UCB 调度器: 决定"选谁"
      - UCB 能量分配器: 决定"给已选中的种子分配多少轮变异"

    pAFL 原文将二者解耦: 调度用 MAB, 能量用 UCB。
    """

    def __init__(self, max_energy: float = 200.0,
                 explore_weight: float = 2.0):
        self.max_energy = max_energy
        self.c = explore_weight
        self._total_rounds: int = 0
        self._pick_counts: Dict[str, int] = {}
        self._success_counts: Dict[str, int] = {}

    def allocate(self, seed_id: str, base_energy: float = 10.0) -> float:
        """计算该种子应得的变异轮数。"""
        n_i = self._pick_counts.get(seed_id, 0)
        total = max(1, self._total_rounds)

        if n_i == 0:
            # 未选择过的种子 → 高能量鼓励探索
            return self.max_energy

        s_i = self._success_counts.get(seed_id, 0)
        avg_success = s_i / n_i
        explore_bonus = self.c * math.sqrt(math.log(total) / n_i)

        ucb_val = avg_success + explore_bonus
        return min(self.max_energy, base_energy * ucb_val * 10)

    def record(self, seed_id: str, success: bool) -> None:
        self._pick_counts[seed_id] = self._pick_counts.get(seed_id, 0) + 1
        if success:
            self._success_counts[seed_id] = self._success_counts.get(seed_id, 0) + 1
        self._total_rounds += 1


# ===== 统一的能量计算门面 =====

class EnergyComputer:
    """能量计算器 -- 委托到具体策略函数。"""

    def __init__(self, policy: EnergyPolicy = EnergyPolicy.FAST,
                 base_energy: float = 10.0):
        self.policy = policy
        self.base = base_energy
        self._adaptive = AdaptiveEnergyPolicy() if policy == EnergyPolicy.ADAPTIVE else None
        self._ucb = UCBEnergyAllocator() if policy == EnergyPolicy.UCB_ENERGY else None
        self._pick_counts: Dict[str, int] = {}
        self._total: int = 0

    def compute(self, seed_meta: dict) -> float:
        seed_id = seed_meta.get("id", "")
        edge_cnt = seed_meta.get("edge_count", 0)
        exec_time = seed_meta.get("exec_time_ms", 10.0)
        gen = seed_meta.get("generation", 0)
        finds = seed_meta.get("finds", 0)
        cycles = seed_meta.get("cycles", 1)
        total_finds = seed_meta.get("total_finds", 1)
        total_cycles = seed_meta.get("total_cycles", 1)

        self._total += 1
        if seed_id:
            self._pick_counts[seed_id] = self._pick_counts.get(seed_id, 0) + 1
        picks = self._pick_counts.get(seed_id, 0)

        if self.policy == EnergyPolicy.EXPLORE:
            e = energy_explore(finds, total_finds, cycles, total_cycles, self.base)
        elif self.policy == EnergyPolicy.COE:
            e = energy_coe(finds, cycles)
        elif self.policy == EnergyPolicy.QUAD:
            e = energy_quad(exec_time, edge_cnt, gen, self.base)
        elif self.policy == EnergyPolicy.LIN:
            e = energy_lin(edge_cnt, exec_time, self.base)
        elif self.policy == EnergyPolicy.FAST:
            e = energy_fast(picks, self.base)
        elif self.policy == EnergyPolicy.ADAPTIVE:
            if self._adaptive is None:
                self._adaptive = AdaptiveEnergyPolicy()
            full_meta = {**seed_meta, "pick_count": picks}
            e = self._adaptive.compute_energy(full_meta, self.base)
        elif self.policy == EnergyPolicy.UCB_ENERGY:
            if self._ucb is None:
                self._ucb = UCBEnergyAllocator()
            e = self._ucb.allocate(seed_id, self.base)
        else:
            e = self.base

        return max(0.1, e)  # 地板: 每个种子至少 0.1 的能量

    def notify_new_find(self, seed_id: str) -> None:
        if self._ucb is not None:
            self._ucb.record(seed_id, True)

    def notify_no_find(self, seed_id: str) -> None:
        if self._ucb is not None:
            self._ucb.record(seed_id, False)

    def update_adaptive(self, new_edges_this_cycle: int) -> None:
        """仅 Adaptive 策略使用: 更新每周期新增覆盖边数。"""
        if self._adaptive is not None:
            self._adaptive.update(new_edges_this_cycle)

    @property
    def adaptive_mode(self) -> Optional[str]:
        if self._adaptive is not None:
            return self._adaptive.mode
        return None


# ===== 便捷函数 =====

def compute_energy(seed_meta: dict, policy: str = "fast",
                   base_energy: float = 10.0) -> float:
    """模块级便捷入口: 用指定策略计算种子能量。"""
    try:
        p = EnergyPolicy(policy.lower())
    except ValueError:
        p = EnergyPolicy.FAST
    ec = EnergyComputer(p, base_energy=base_energy)
    return ec.compute(seed_meta)
