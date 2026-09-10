"""多目标Pareto最优种子归档 -- 跨代保留非支配种子, 防止裁剪时丢失潜在高价值个体.

  AMOS2          -- 状态依赖/独立种子度量 + AHP-TOPSIS 排序
  NSGA-II         -- 快速非支配排序算法
  HypE            -- 基于超体积的进化多目标优化
  EcoFuzz                        -- exploration/exploitation 自适应切换

设计目标:
  fuzzing 中种子的 "质量" 是多维度的: 覆盖面、执行速度、代数新鲜度、
  稀有度……单目标加权求和必然会丢失处于某个维度极端优秀的种子。
  维护一个 Pareto 前沿归档, 确保在每个目标维度上不可替代的种子
  被显式保留, 不因在另一个维度上的弱势被裁剪。

目标维度 (可按需扩展):
  1. 覆盖边数 (最大化)   — 看过的程序区域多
  2. 执行速度倒数 (最大化) — 越快越好 (1 / exec_time_ms)
  3. 代数新鲜度 (最大化)  — 1 / (1 + generation), 偏好年轻种子
  4. 稀有度评分 (最大化)  — 来自 SEAFuzz 的结构稀有度概念
"""

import json
import math
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, FrozenSet, List, Optional, Set, Tuple

# 归档文件标识
_ARCHIVE_MAGIC = b"BMPA"  # BinMind Pareto Archive

@dataclass
class ParetoEntry:
    """Pareto 归档中的一条记录。"""
    seed_id: str
    objectives: Tuple[float, ...]       # 各目标维度的取值 (值越大越优)
    generation: int                      # 归档该种子时的代数
    archived_at: float = field(default_factory=time.time)
    metadata: dict = field(default_factory=dict)

def _dominates(a: Tuple[float, ...], b: Tuple[float, ...]) -> bool:
    """判断 a 是否 Pareto-支配 b: a 在所有维度 ≥ b, 且至少一个维度严格 >。

    所有目标均已转换为最大化方向, 因此 > 表示更优。
    """
    at_least_one_strict = False
    for va, vb in zip(a, b):
        if va < vb:
            return False
        if va > vb:
            at_least_one_strict = True
    return at_least_one_strict

def _non_dominated_sort(objectives: List[Tuple[float, ...]]
                        ) -> List[List[int]]:
    """NSGA-II 快速非支配排序。

    返回按前沿层级分组的索引列表: fronts[0] = Pareto前沿, fronts[1] = 次优层, ...
    复杂度 O(M·N²), M = 目标数, N = 个体数。
    """
    n = len(objectives)
    dominated_count = [0] * n          # 支配当前个体的个体数
    dominates_list: List[List[int]] = [[] for _ in range(n)]  # 当前个体支配的个体列表

    for i in range(n):
        for j in range(n):
            if i == j:
                continue
            if _dominates(objectives[i], objectives[j]):
                dominates_list[i].append(j)
            elif _dominates(objectives[j], objectives[i]):
                dominated_count[i] += 1

    fronts: List[List[int]] = []
    # 第一前沿: 不被任何个体支配
    front0 = [i for i in range(n) if dominated_count[i] == 0]
    fronts.append(front0)

    current_front = 0
    while fronts[current_front]:
        next_front = []
        for i in fronts[current_front]:
            for j in dominates_list[i]:
                dominated_count[j] -= 1
                if dominated_count[j] == 0:
                    next_front.append(j)
        current_front += 1
        if next_front:
            fronts.append(next_front)
        else:
            break

    return fronts

class ParetoArchive:
    """维护跨代 Pareto 前沿的种子归档器。

    语义:
      - 接收 (seed_id, objectives) 元组
      - 内部维护非支配前沿: 仅保留在所有维度上互不支配的种子
      - 当新种子被归档的种子支配时, 丢弃
      - 当新种子支配已归档种子时, 移除被支配者
      - 当超体积超过上限时, 根据 hypervolume 贡献度裁剪

    与现有模块的关系:
      - CorpusManager.prune(): 裁剪前调用 get_retained_ids() 获取必须保留的种子
      - Scheduler.pick_seed(): 可选地偏向 Pareto 前沿上的种子
    """

    def __init__(self, n_objectives: int = 4,
                 max_archive_size: int = 200,
                 objective_names: Optional[List[str]] = None):
        """
        n_objectives: 目标维度数 (固定为4时可覆盖默认场景)
        max_archive_size: 归档最大容量, 超出时按超体积贡献裁剪
        objective_names: 各目标维度的可读名称 (用于统计输出)
        """
        self.n_objectives = n_objectives
        self.max_archive_size = max_archive_size
        self.objective_names = objective_names or [
            "edge_count", "inv_exec_time", "generation_freshness", "rarity"
        ]
        self._entries: Dict[str, ParetoEntry] = {}
        # 点用于 hypervolume 计算 (每个维度的最小值)
        self._reference_point: Optional[Tuple[float, ...]] = None
        self._total_submitted: int = 0
        self._total_accepted: int = 0

    # //// 提交候选种子 ////
    def submit(self, seed_id: str, objectives: Tuple[float, ...],
               metadata: Optional[dict] = None) -> bool:
        """提交一个候选种子评估其 Pareto 最优性。

        返回 True 若该种子被接受进入归档 (即不被任何已归档种子支配)。
        """
        self._total_submitted += 1
        if len(objectives) != self.n_objectives:
            raise ValueError(
                f"Expected {self.n_objectives} objectives, got {len(objectives)}"
            )

        # 检查是否被已有条目支配
        for existing in self._entries.values():
            if _dominates(existing.objectives, objectives):
                return False  # 被支配, 拒绝

        # 移除被新种子支配的已有条目
        dominated_keys = [
            sid for sid, ent in self._entries.items()
            if _dominates(objectives, ent.objectives)
        ]
        for sid in dominated_keys:
            del self._entries[sid]

        gen = metadata.get("generation", 0) if metadata else 0
        entry = ParetoEntry(
            seed_id=seed_id,
            objectives=objectives,
            generation=gen,
            metadata=metadata or {},
        )
        self._entries[seed_id] = entry
        self._total_accepted += 1

        # 超容量裁剪
        if len(self._entries) > self.max_archive_size:
            self._prune_by_hypervolume()

        # 更新参考点
        self._update_reference_point()

        return True

    # //// 查询 ////
    def contains(self, seed_id: str) -> bool:
        return seed_id in self._entries

    def get_objectives(self, seed_id: str) -> Optional[Tuple[float, ...]]:
        ent = self._entries.get(seed_id)
        return ent.objectives if ent else None

    def get_retained_ids(self) -> FrozenSet[str]:
        """返回归档中所有应被保留的种子ID集合。

        调用者在执行队列裁剪时应确保不删除这些种子。
        """
        return frozenset(self._entries.keys())

    def is_pareto_optimal(self, seed_id: str) -> bool:
        return seed_id in self._entries

    # //// 超体积贡献度裁剪 ////
    def _prune_by_hypervolume(self) -> None:
        """基于超体积贡献度的归档裁剪。

        对归档中的每个条目计算其对当前 Pareto 前沿的超体积贡献,
        移除贡献最小的条目。重复直到满足容量限制。

        hypervolume 贡献 = 该点到参考点构成的超矩形中,
        不被其他 Pareto 点支配的体积部分。
        实际计算中, 使用 Lebesgue 测度的近似: 各维度到参考点距离的乘积加权。
        """
        if not self._entries:
            return

        ref = self._reference_point or self._compute_nadir_point()
        self._reference_point = ref

        while len(self._entries) > self.max_archive_size:
            contributions: List[Tuple[str, float]] = []
            for sid, ent in self._entries.items():
                hvc = self._hypervolume_contribution(ent.objectives, ref, sid)
                contributions.append((sid, hvc))

            # 移除贡献最小者
            contributions.sort(key=lambda x: x[1])
            worst_sid = contributions[0][0]
            del self._entries[worst_sid]

    def _hypervolume_contribution(self, objectives: Tuple[float, ...],
                                   reference: Tuple[float, ...],
                                   exclude_id: str) -> float:
        """计算 exclude_id 对当前前沿的超体积贡献。

        简化: 各维度到参考点距离的乘积, 同时检查是否有其他条目
        在该维度上提供了更大的覆盖。
        """
        other_points = [
            ent.objectives for sid, ent in self._entries.items()
            if sid != exclude_id
        ]

        contribution = 1.0
        for dim in range(self.n_objectives):
            # 该维度上该点超过参考点的距离
            margin = max(0.0, objectives[dim] - reference[dim])

            # 若其他 Pareto 点在该维度上更优, 则贡献被部分覆盖
            others_max = max(
                (p[dim] for p in other_points), default=reference[dim]
            )
            if others_max > objectives[dim]:
                # 该点的超体积部分被其他点"吞噬"
                margin *= max(0.0, 1.0 - (others_max - objectives[dim]) / max(1e-6, others_max - reference[dim]))

            contribution *= max(1e-6, margin)

        return contribution

    def _compute_nadir_point(self) -> Tuple[float, ...]:
        """计算当前前沿的 nadir 点 (各维度最小值)。"""
        if not self._entries:
            return tuple(0.0 for _ in range(self.n_objectives))

        mins = [float('inf')] * self.n_objectives
        for ent in self._entries.values():
            for dim in range(self.n_objectives):
                if ent.objectives[dim] < mins[dim]:
                    mins[dim] = ent.objectives[dim]
        return tuple(mins)

    def _update_reference_point(self) -> None:
        """更新参考点为 nadir 点下方 10% (为 hypervolume 留余量)。"""
        nadir = self._compute_nadir_point()
        self._reference_point = tuple(v * 0.9 if v > 0 else -0.1
                                      for v in nadir)

    # //// 特征提取辅助函数 ////
    @staticmethod
    def objectives_from_seed(seed, edge_coverage: Optional[Set[int]] = None,
                             exec_time_ms: float = 10.0,
                             rarity_score: float = 0.5) -> Tuple[float, ...]:
        """从种子元数据提取 Pareto 优化的目标向量。

        所有维度转换为最大化方向:
          0. edge_count:     已覆盖边数 (越大越好)
          1. inv_exec_time:  1 / exec_time_ms (越快越好)
          2. freshness:      1 / (1 + generation) (代数越低越好)
          3. rarity:         稀有度评分 (越大越独特)

        这个函数使 ParetoArchive 与现有 Seed 数据模型无缝对接。
        """
        cov = edge_coverage or getattr(seed, 'coverage', set())
        edge_count = float(len(cov))

        exec_t = max(0.01, exec_time_ms)
        inv_exec = 1.0 / exec_t

        gen = getattr(seed, 'generation', 0)
        freshness = 1.0 / (1.0 + gen)

        rarity = max(0.0, min(1.0, rarity_score))

        return (edge_count, inv_exec, freshness, rarity)

    # //// 统计 ////
    def stats(self) -> dict:
        n = len(self._entries)
        if n == 0:
            return {
                "archive_size": 0,
                "acceptance_ratio": 0.0,
                "fronts": 0,
            }

        objs = [ent.objectives for ent in self._entries.values()]
        fronts = _non_dominated_sort(objs)

        return {
            "archive_size": n,
            "total_submitted": self._total_submitted,
            "acceptance_ratio": self._total_accepted / max(1, self._total_submitted),
            "pareto_fronts": len(fronts),
            "front_0_size": len(fronts[0]) if fronts else 0,
            "per_dimension_best": {
                self.objective_names[dim]: max(p[dim] for p in objs)
                for dim in range(self.n_objectives)
            },
            "reference_point": self._reference_point,
        }

    # //// 持久化 ////
    def serialize(self) -> bytes:
        """序列化为二进制块, 与 CorpusManager 的种子持久化格式兼容。"""
        payload = {
            "n_objectives": self.n_objectives,
            "max_archive_size": self.max_archive_size,
            "objective_names": self.objective_names,
            "entries": [
                {
                    "seed_id": ent.seed_id,
                    "objectives": list(ent.objectives),
                    "generation": ent.generation,
                    "archived_at": ent.archived_at,
                    "metadata": ent.metadata,
                }
                for ent in self._entries.values()
            ],
        }
        json_bytes = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        # 格式: [magic:4B][json_len:4B][json]
        header = _ARCHIVE_MAGIC + len(json_bytes).to_bytes(4, "little")
        return header + json_bytes

    @classmethod
    def deserialize(cls, data: bytes) -> Optional["ParetoArchive"]:
        """从二进制块反序列化。"""
        if len(data) < 8 or data[:4] != _ARCHIVE_MAGIC:
            return None

        json_len = int.from_bytes(data[4:8], "little")
        json_bytes = data[8:8 + json_len]
        try:
            payload = json.loads(json_bytes.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None

        archive = cls(
            n_objectives=payload["n_objectives"],
            max_archive_size=payload.get("max_archive_size", 200),
            objective_names=payload.get("objective_names"),
        )
        for ent_data in payload.get("entries", []):
            ent = ParetoEntry(
                seed_id=ent_data["seed_id"],
                objectives=tuple(ent_data["objectives"]),
                generation=ent_data.get("generation", 0),
                archived_at=ent_data.get("archived_at", 0.0),
                metadata=ent_data.get("metadata", {}),
            )
            archive._entries[ent.seed_id] = ent

        archive._update_reference_point()
        return archive

    def clear(self) -> None:
        self._entries.clear()
        self._reference_point = None
        self._total_submitted = 0
        self._total_accepted = 0
