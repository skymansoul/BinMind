"""拓扑覆盖导航器 (Topological Coverage Navigator, TCN) — 连通分量 + 边界检测.

修改记录:
2025-08-03 10:27 - Vietoris-Rips 1-骨架 + 连通分量追踪 (β₀)
2025-08-04 14:55 - landmark 稀疏近似 + 覆盖流形边界检测
2025-08-06 08:39 - 谱嵌入多样性评分
2025-08-20 09:34 - 修正: 标注仅计算 β₀ 连通分量, 非完整持久同调 (无 β₁ 环检测)

参考: Edelsbrunner & Harer, Carlsson.
Maggs ANU thesis 提供了 TDA+fuzzing 的理论框架。
当前实现仅计算 β₀ (连通分量数), 尚未实现完整的持久图 (barcode) 和 β₁ (环) 检测。
未来可通过整合 Ripser 等库升级为完整持久同调。"""

# 核心假设:
#   覆盖位图将种子映射到高维空间。这些点形成簇, 簇间有空隙。
#   持久同调揭示覆盖流形的拓扑特征:
#     β₀ (连通分量数): 发现了多少独立的程序行为区域
#     持久图: 哪些覆盖簇是持久的 (真区域) vs 短暂的 (噪声)
#   与传统覆盖率的关键差异: 覆盖率看 "多少条边", TCN 看 "边的组织方式"。

# 与 ISRG/PathCluster 互补: ISRG 看局部覆盖关系, PathCluster 看局部路径关系, TCN 看全局拓扑结构。

import math
import random
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

from .persistence_homology import (
    jaccard_distance, maximin_landmarks, single_linkage_persistence,
    detect_frontier_boundaries,
    _EPSILON, _N_LANDMARKS, _PERSISTENCE_MIN_LIFETIME, _BOUNDARY_ALPHA,
)


_MAX_POINTS = 2048


@dataclass
class CoveragePoint:
    """覆盖流形中的一个点."""
    seed_id: str
    coverage_fingerprint: FrozenSet[int] = field(default_factory=frozenset)
    barcode: int = 0
    density: float = 0.0
    is_landmark: bool = False
    persistence: float = 0.0
    dimension: int = 0


@dataclass
class TopologicalFeature:
    """持久图中一个有意义的拓扑特征."""
    dimension: int
    birth_radius: float
    death_radius: float
    persistence: float
    point_indices: List[int] = field(default_factory=list)
    representative_seeds: List[str] = field(default_factory=list)


class TopologicalCoverageNavigator:
    """基于持久同调的覆盖流形导航器.

    将 fuzzing 探索映射为 Vietoris-Rips 复形上的拓扑特征发现,
    使用 β₀ 和持久图指导探索方向, 识别前沿边界种子。
    """

    def __init__(self, epsilon: float = _EPSILON,
                 n_landmarks: int = _N_LANDMARKS):
        self.epsilon = epsilon
        self.n_landmarks = n_landmarks
        self._points: Dict[str, CoveragePoint] = {}
        self._landmarks: List[str] = []
        self._persistence_features: List[TopologicalFeature] = []
        self._component_labels: Dict[str, int] = {}
        self._component_sizes: Dict[int, int] = defaultdict(int)
        self._frontier_points: List[str] = []
        self._total_insertions: int = 0
        self._last_persistence_time: float = 0.0

    # //// 点的添加 ////
    def add_point(self, seed_id: str, coverage: Set[int]) -> None:
        fp = self._fingerprint(coverage)
        if seed_id in self._points and self._points[seed_id].coverage_fingerprint == fp:
            return
        self._points[seed_id] = CoveragePoint(
            seed_id=seed_id, coverage_fingerprint=fp)
        self._total_insertions += 1
        if len(self._points) > _MAX_POINTS:
            self._evict_oldest()
        if (len(self._points) >= self.n_landmarks
                and self._total_insertions % 50 == 0
                and time.time() - self._last_persistence_time > 10.0):
            self.compute_persistence()

    # //// 持久同调计算 ////
    def compute_persistence(self) -> List[TopologicalFeature]:
        """计算覆盖流形的持久同调.

        landmark 稀疏近似: maximin 采样 → pairwise distances →
        single-linkage 聚类 → β₀ 持久图。
        """
        if len(self._points) < 10:
            return []
        pt_ids = list(self._points.keys())
        fps = {sid: self._points[sid].coverage_fingerprint for sid in pt_ids}

        # landmark 选择
        self._landmarks = maximin_landmarks(pt_ids, fps, self.n_landmarks)
        for sid in self._landmarks:
            self._points[sid].is_landmark = True

        # 持久同调
        raw_features = single_linkage_persistence(self._landmarks, fps)
        features = []
        for rf in raw_features:
            features.append(TopologicalFeature(
                dimension=rf["dimension"],
                birth_radius=rf["birth"],
                death_radius=rf["death"] if rf["death"] != float('inf') else 1.0,
                persistence=rf["persistence"],
                point_indices=rf["point_indices"],
                representative_seeds=rf["representative_seeds"],
            ))
        self._persistence_features = features

        # 分量标签
        self._component_labels.clear()
        self._component_sizes.clear()
        # 重新计算分量分配
        self._assign_components()
        self._last_persistence_time = time.time()
        return features

    def _assign_components(self) -> None:
        """将点分配到连通分量."""
        lm_set = set(self._landmarks)
        fps = {sid: self._points[sid].coverage_fingerprint
               for sid in self._points}
        # 对每个非 landmark 点, 分配到最近的 landmark 的分量
        comp_id = 0
        for feat in self._persistence_features:
            for seed_id in feat.representative_seeds:
                if seed_id not in self._component_labels:
                    self._component_labels[seed_id] = comp_id
                    self._component_sizes[comp_id] += 1
            comp_id += 1
        for sid in self._points:
            if sid not in self._component_labels:
                min_d = 2.0; best_comp = -1
                fp = fps[sid]
                for lm in lm_set:
                    if lm in self._component_labels:
                        d = jaccard_distance(fp, fps[lm])
                        if d < min_d:
                            min_d = d
                            best_comp = self._component_labels[lm]
                if best_comp >= 0:
                    self._component_labels[sid] = best_comp
                    self._component_sizes[best_comp] += 1

    # //// 边界检测 ////
    def detect_frontier_boundaries(self) -> List[str]:
        """返回探索前沿边界种子 ID."""
        if len(self._points) < 10:
            return []
        pt_ids = list(self._points.keys())
        fps = {sid: self._points[sid].coverage_fingerprint for sid in pt_ids}
        # 计算密度
        dens = {}
        for sid in pt_ids:
            fp = fps[sid]
            nbrs = sum(1 for o in pt_ids
                      if o != sid and jaccard_distance(fp, fps[o]) <= self.epsilon)
            dens[sid] = nbrs / max(1, len(pt_ids) - 1)
            self._points[sid].density = dens[sid]
        self._frontier_points = detect_frontier_boundaries(
            pt_ids, fps, dens, self.epsilon, _BOUNDARY_ALPHA)
        return list(self._frontier_points)

    def suggest_frontier_seeds(self, top_k: int = 5) -> List[str]:
        if not self._frontier_points:
            self.detect_frontier_boundaries()
        ranked = sorted(self._frontier_points,
                       key=lambda sid: self._points[sid].density)
        return ranked[:top_k]

    # //// 拓扑特征查询 ////
    def component_count(self) -> int:
        return len(set(c for c in self._component_labels.values() if c >= 0))

    def largest_component_size(self) -> int:
        return max(self._component_sizes.values()) if self._component_sizes else 0

    def topological_diversity_score(self, seed_id: str) -> float:
        comp = self._component_labels.get(seed_id)
        if comp is None or comp < 0:
            return 0.5
        comp_size = self._component_sizes.get(comp, 1)
        total = len(self._points)
        rarity = 1.0 - (comp_size / max(1, total))
        is_frontier = 1.2 if seed_id in self._frontier_points else 1.0
        return min(1.0, rarity * is_frontier)

    def persistence_diagram_summary(self) -> Dict[int, List[Tuple[float, float]]]:
        diagram: Dict[int, List[Tuple[float, float]]] = {0: [], 1: []}
        for feat in self._persistence_features:
            death = feat.death_radius if feat.death_radius != float('inf') else 1.0
            diagram[feat.dimension].append((feat.birth_radius, death))
        return diagram

    # //// 统计 ////
    def stats(self) -> dict:
        n = len(self._persistence_features)
        sig = sum(1 for f in self._persistence_features if f.persistence > 0.3)
        return {
            "points_in_manifold": len(self._points),
            "landmarks": len(self._landmarks),
            "connected_components (beta_0)": self.component_count(),
            "largest_component_size": self.largest_component_size(),
            "persistence_features_found": n,
            "significant_features": sig,
            "frontier_boundary_seeds": len(self._frontier_points),
            "epsilon": self.epsilon,
            "total_insertions": self._total_insertions,
        }

    def clear(self) -> None:
        self._points.clear(); self._landmarks.clear()
        self._persistence_features.clear()
        self._component_labels.clear(); self._component_sizes.clear()
        self._frontier_points.clear(); self._total_insertions = 0

    # //// 内部辅助 ////
    @staticmethod
    def _fingerprint(coverage: Set[int]) -> FrozenSet[int]:
        if len(coverage) <= 500:
            return frozenset(coverage)
        n_buckets = 512
        buckets = [0x7FFFFFFF] * n_buckets
        for edge in coverage:
            bucket = edge % n_buckets
            if edge < buckets[bucket]:
                buckets[bucket] = edge
        return frozenset(b for b in buckets if b != 0x7FFFFFFF)

    def _evict_oldest(self) -> None:
        protected = set(self._landmarks) | set(self._frontier_points)
        evictable = [sid for sid in self._points if sid not in protected]
        n_evict = max(1, len(evictable) // 5)
        for sid in evictable[:n_evict]:
            del self._points[sid]
            self._component_labels.pop(sid, None)
