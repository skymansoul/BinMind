# 种子能量决定其在下一轮被选中的概率和变异次数。
# 核心思想: 对"有前途"的种子（触发新覆盖、罕见路径）赋予更高能量。
import math
import time
from typing import Dict, List, Tuple, Optional, Set
from collections import defaultdict


class PowerSchedule:
    """能量调度基类。子类实现assign_energy(seed_id, seed_info) -> float。

    能量值域 [0.1, 10.0]，低于0.1表示种子接近淘汰。
    高于5.0表示高优先级集中变异。
    """

    MIN_ENERGY = 0.1
    MAX_ENERGY = 10.0

    def assign_energy(self, seed_id: str,
                      seed_info: Dict) -> float:
        raise NotImplementedError

    def clamp(self, energy: float) -> float:
        return energy if self.MIN_ENERGY <= energy <= self.MAX_ENERGY else (
            self.MIN_ENERGY if energy < self.MIN_ENERGY else self.MAX_ENERGY)

    def name(self) -> str:
        return self.__class__.__name__


class AFLFastSchedule(PowerSchedule):
    """AFLFast能量调度: 路径频率越低 -> 能量越高。

    核心公式: energy = 2^(log2(MAX) * (1 - freq/total))
    低频路径获得指数级更多变异机会，高频路径能量递减。

    参考能量调度策略 (执行频率驱动)
    """

    def __init__(self, power_exponent: float = 1.0):
        self._exp = power_exponent  # AFLFast的power schedule指数
        self._path_counts: Dict[str, int] = defaultdict(int)
        self._total_execs = 0
        # 记录每种seed对应的路径ID
        self._seed_path: Dict[str, str] = {}  # seed_id -> path_id

    def record_execution(self, seed_id: str, path_id: str) -> None:
        self._path_counts[path_id] += 1
        self._total_execs += 1
        self._seed_path[seed_id] = path_id

    def assign_energy(self, seed_id: str,
                      seed_info: Dict) -> float:
        path_id = self._seed_path.get(seed_id)
        if path_id is None or self._total_execs == 0:
            return 1.0

        freq = self._path_counts.get(path_id, 1)
        # 归一化频率 -> 越小能量越高
        rarity = 1.0 - (freq / max(1, self._total_execs))
        # 幂律: rareness高的种子获得更多变异
        energy = 2.0 ** (8.0 * rarity * self._exp)
        return self.clamp(energy)

    def path_stats(self) -> Dict[str, int]:
        return dict(self._path_counts)


class FairFuzzSchedule(PowerSchedule):
    """FairFuzz风格调度: 覆盖了罕见边（被极少种子触发的边）的种子
    赋予高能量。罕见边=全局边命中计数在最低10%分位以下。

    核心思想: 修改罕见边的输入字节应受保护（不随意变异），
    而覆盖罕见边的种子应被频繁选中以扩大对罕见区域的探索。

    参考Lemieux & Sen. ASE 2018, Section 4.
    """

    def __init__(self, rare_percentile: float = 10.0):
        """
        rare_percentile: 边命中计数在此分位以下的视为罕见边
        """
        self._rare_pct = rare_percentile
        self._edge_counts: Dict[int, int] = defaultdict(int)
        self._seed_edges: Dict[str, Set[int]] = defaultdict(set)
        self._rare_threshold: int = 1

    def record_edges(self, seed_id: str, edges: Set[int]) -> None:
        for e in edges:
            self._edge_counts[e] += 1
        self._seed_edges[seed_id].update(edges)
        # 更新罕见阈值
        if len(self._edge_counts) >= 10:
            counts = sorted(self._edge_counts.values())
            idx = max(0, len(counts) * self._rare_pct // 100 - 1)
            self._rare_threshold = counts[idx]

    def assign_energy(self, seed_id: str,
                      seed_info: Dict) -> float:
        edges = self._seed_edges.get(seed_id, set())
        if not edges:
            return 1.0

        rare_count = sum(
            1 for e in edges
            if self._edge_counts.get(e, 0) <= self._rare_threshold)
        # 含罕见边数越多 -> 能量越高（指数递增，上限10）
        if rare_count == 0:
            return 0.5
        energy = 1.0 + math.log2(rare_count + 1) * 2.0
        return self.clamp(energy)


class EcoFuzzSchedule(PowerSchedule):
    """EcoFuzz自适应节能调度: 用对抗多臂老虎机 (Adversarial MAB) 模型，
    将种子分为三态: 探索态/利用态/停滞态。
    对停滞态种子赋予极低能量以节省计算资源。

    三态判定:
    - EXPLORE: 最近N轮内产生了新覆盖
    - EXPLOIT: 未产生新覆盖但路径罕见（频率<均值）
    - STAGNANT: 长时间无新覆盖且路径常见

    参考自适应能量分配策略
    """

    EXPLORE = 'explore'
    EXPLOIT = 'exploit'
    STAGNANT = 'stagnant'

    def __init__(self, stagnation_rounds: int = 10):
        self._stagnation = stagnation_rounds
        self._path_freq: Dict[str, int] = defaultdict(int)
        self._seed_last_new: Dict[str, int] = {}  # seed -> 最后出新覆盖的轮次
        self._round = 0
        self._seed_path: Dict[str, str] = {}

    def record_execution(self, seed_id: str, path_id: str,
                         new_coverage: bool) -> None:
        self._path_freq[path_id] += 1
        self._seed_path[seed_id] = path_id
        if new_coverage:
            self._seed_last_new[seed_id] = self._round

    def advance_round(self) -> None:
        self._round += 1

    def _classify(self, seed_id: str) -> str:
        last_new = self._seed_last_new.get(seed_id, -1)
        rounds_since = self._round - last_new
        path_id = self._seed_path.get(seed_id, "")
        if rounds_since <= 3:
            return self.EXPLORE
        avg_freq = (sum(self._path_freq.values()) /
                    max(1, len(self._path_freq)))
        freq = self._path_freq.get(path_id, 0)
        if rounds_since > self._stagnation and freq > avg_freq:
            return self.STAGNANT
        return self.EXPLOIT

    def assign_energy(self, seed_id: str,
                      seed_info: Dict) -> float:
        state = self._classify(seed_id)
        if state == self.EXPLORE:
            return 5.0
        elif state == self.EXPLOIT:
            path_id = self._seed_path.get(seed_id, "")
            freq = self._path_freq.get(path_id, 1)
            avg = sum(self._path_freq.values()) / max(
                1, len(self._path_freq))
            rarity = max(0.1, 1.0 - freq / max(1, avg))
            return self.clamp(1.0 + rarity * 4.0)
        else:  # STAGNANT
            return 0.15


class MobFuzzStyleSchedule(PowerSchedule):
    """MobFuzz多目标优化调度: 结合覆盖率增长速率与崩溃发现率两个目标。

    使用简单加权和而非完整多目标进化算法 (NSGA-II复杂度不适用于
    每种子实时调度)。覆盖率权重w_cov + 崩溃权重w_crash = 1.0。

    参考Zhang et al. 2024, "MobFuzz", Section IV.
    """

    def __init__(self, cov_weight: float = 0.6):
        self._w_cov = cov_weight
        self._w_crash = 1.0 - cov_weight
        self._seed_cov_gain: Dict[str, float] = defaultdict(float)
        self._seed_crash_count: Dict[str, int] = defaultdict(int)
        self._global_cov_gain: List[float] = []
        self._global_crash_count: List[int] = []

    def record(self, seed_id: str, new_edges: int,
               crash: bool) -> None:
        if new_edges > 0:
            self._seed_cov_gain[seed_id] += new_edges
            self._global_cov_gain.append(new_edges)
        if crash:
            self._seed_crash_count[seed_id] += 1
            self._global_crash_count.append(1)

    def assign_energy(self, seed_id: str,
                      seed_info: Dict) -> float:
        cov_gain = self._seed_cov_gain.get(seed_id, 0.0)
        crash_cnt = self._seed_crash_count.get(seed_id, 0.0)

        # 归一化到 [0, 1]（与全局均值比较）
        avg_cov = (sum(self._global_cov_gain) /
                   max(1, len(self._global_cov_gain)))
        avg_crash = (sum(self._global_crash_count) /
                     max(1, len(self._global_crash_count)))

        cov_score = min(1.0, cov_gain / max(0.01, avg_cov))
        crash_score = min(1.0, crash_cnt / max(0.01, avg_crash))

        composite = self._w_cov * cov_score + self._w_crash * crash_score
        return self.clamp(0.3 + composite * 8.0)


class WeightedScheduler:
    """调度器聚合器: 管理多个PowerSchedule实例，维护每个种子的
    多维特征（覆盖增长、路径频率、发现时间），对每个种子计算加权能量。

    对外接口: select_seed(corpus) -> 最高能量种子
    """

    def __init__(self):
        self._schedules: List[PowerSchedule] = []
        self._weights: List[float] = []
        self._seed_info: Dict[str, Dict] = defaultdict(dict)

    def add_schedule(self, schedule: PowerSchedule,
                     weight: float = 1.0) -> None:
        self._schedules.append(schedule)
        self._weights.append(weight)

    def update_seed(self, seed_id: str, **info) -> None:
        self._seed_info[seed_id].update(info)

    def compute_energy(self, seed_id: str) -> float:
        """聚合所有调度器的加权能量"""
        if not self._schedules:
            return 1.0
        total_weight = sum(self._weights)
        if total_weight == 0:
            return 1.0
        energy = 0.0
        info = self._seed_info.get(seed_id, {})
        for sched, w in zip(self._schedules, self._weights):
            energy += w * sched.assign_energy(seed_id, info)
        return energy / total_weight

    def select_seed(self, seed_ids: List[str]) -> str:
        """返回能量最高的种子ID"""
        if not seed_ids:
            return ""
        best_id = seed_ids[0]
        best_energy = self.compute_energy(best_id)
        for sid in seed_ids[1:]:
            e = self.compute_energy(sid)
            if e > best_energy:
                best_energy = e
                best_id = sid
        return best_id

    def ranked_seeds(self, seed_ids: List[str],
                     top_k: int = 0) -> List[Tuple[str, float]]:
        """返回按能量降序的 (seed_id, energy) 列表"""
        scored = [(sid, self.compute_energy(sid)) for sid in seed_ids]
        scored.sort(key=lambda x: -x[1])
        if top_k > 0:
            return scored[:top_k]
        return scored

    def schedule_names(self) -> List[str]:
        return [s.name() for s in self._schedules]
