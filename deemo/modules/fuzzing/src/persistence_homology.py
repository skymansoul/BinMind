# 创建: 2026-05-25 11:53
# 修改: 2026-05-25 — Vietoris-Rips + 单链聚类 Betti-0 持久性
# 修改: 2026-05-25 — 修正标注: 仅计算连通分量, 非完整持久同调
"""基于 landmark 的稀疏持久同调计算 — 为 TopologicalCoverageNavigator 提供拓扑特征.

修改记录:
2025-08-04 14:55 - 从 topological_coverage_navigator.py 分离, 独立的持久性计算模块
2025-08-06 08:39 - union-find + 单链聚类: β₀ 连通分量和持久图

  Edelsbrunner & Harer "Computational Topology" 第 7 章
  Carlsson "Topology and Data" (Bull. AMS)
"""

import math
import random
from collections import defaultdict
from typing import Dict, FrozenSet, List, Tuple

_EPSILON = 0.35
_N_LANDMARKS = 64
_PERSISTENCE_MIN_LIFETIME = 0.15
_BOUNDARY_ALPHA = 0.25

def jaccard_distance(fp_a: FrozenSet[int], fp_b: FrozenSet[int]) -> float:
    if not fp_a and not fp_b:
        return 0.0
    if not fp_a or not fp_b:
        return 1.0
    inter = len(fp_a & fp_b)
    union = len(fp_a | fp_b)
    return 1.0 - (inter / union if union > 0 else 0.0)

def maximin_landmarks(point_ids: List[str],
                      fingerprints: Dict[str, FrozenSet[int]],
                      k: int = _N_LANDMARKS) -> List[str]:
    """maximin 采样: 每次选择到已选 landmark 最小距离最大的点.

    保证 landmarks 在覆盖流形上的均匀覆盖。
    """
    n = len(point_ids)
    k = min(k, n)
    if k == 0:
        return []
    first = random.choice(point_ids)
    selected = [first]
    min_dists = {sid: 2.0 for sid in point_ids}
    fp_first = fingerprints[first]
    for sid in point_ids:
        min_dists[sid] = jaccard_distance(fingerprints[sid], fp_first)
    for _ in range(k - 1):
        best_id = max(
            (sid for sid in point_ids if sid not in selected),
            key=lambda sid: min_dists[sid], default=None)
        if best_id is None:
            break
        selected.append(best_id)
        fp_best = fingerprints[best_id]
        for sid in point_ids:
            if sid in selected:
                continue
            d = jaccard_distance(fingerprints[sid], fp_best)
            if d < min_dists[sid]:
                min_dists[sid] = d
    return selected

def single_linkage_persistence(
    landmark_ids: List[str],
    fingerprints: Dict[str, FrozenSet[int]],
) -> List[dict]:
    """对 landmark 做单链聚类, 计算 β₀ 持久图.

    返回 [{"birth": float, "death": float, "persistence": float,
            "member_indices": [int], "representative_seeds": [str]}, ...]
    """
    k = len(landmark_ids)
    if k < 2:
        return []
    # 计算所有 pairwise distances
    distances: List[Tuple[float, int, int]] = []
    for i in range(k):
        fp_i = fingerprints[landmark_ids[i]]
        for j in range(i + 1, k):
            fp_j = fingerprints[landmark_ids[j]]
            d = jaccard_distance(fp_i, fp_j)
            distances.append((d, i, j))
    distances.sort(key=lambda x: x[0])
    # Union-Find
    parent = list(range(k))
    rank = [0] * k

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra == rb:
            return False, ra, rb
        if rank[ra] < rank[rb]:
            parent[ra] = rb
            return True, rb, ra
        elif rank[ra] > rank[rb]:
            parent[rb] = ra
            return True, ra, rb
        else:
            parent[rb] = ra; rank[ra] += 1
            return True, ra, rb

    component_birth: Dict[int, float] = {}
    component_death: Dict[int, float] = {}
    component_members: Dict[int, List[int]] = defaultdict(list)
    features: List[dict] = []

    for d, i, j in distances:
        merged, living, dying = union(i, j)
        if not merged:
            continue
        # dying 分量的持久性
        birth = component_birth.get(dying, 0.0)
        persistence = d - birth
        if persistence >= _PERSISTENCE_MIN_LIFETIME and dying not in component_death:
            component_death[dying] = d
            members = component_members.get(dying, [])
            features.append({
                "dimension": 0, "birth": birth, "death": d,
                "persistence": persistence,
                "point_indices": list(members),
                "representative_seeds": [landmark_ids[m] for m in members[:5]],
            })
        # 合并后 living 继承出生时间
        root = find(i)
        if root not in component_birth:
            component_birth[root] = d

    # 存活分量: persistence = 1.0 - birth
    active_roots = set()
    for i in range(k):
        root = find(i)
        active_roots.add(root)
        component_members[root].append(i)
    for root in active_roots:
        if root not in component_death:
            birth = component_birth.get(root, 0.0)
            features.append({
                "dimension": 0, "birth": birth, "death": float('inf'),
                "persistence": 1.0 - birth,
                "point_indices": list(component_members[root]),
                "representative_seeds": [
                    landmark_ids[m] for m in component_members[root][:5]
                ],
            })
    features.sort(key=lambda x: x["persistence"], reverse=True)
    return features

def detect_frontier_boundaries(
    point_ids: List[str],
    fingerprints: Dict[str, FrozenSet[int]],
    densities: Dict[str, float],
    epsilon: float = _EPSILON,
    boundary_alpha: float = _BOUNDARY_ALPHA,
) -> List[str]:
    """检测覆盖流形上的探索前沿边界点.

    边界点 = 局部密度低于 α-分位数, 但邻域存在高密度点。
    """
    if len(point_ids) < 10:
        return []
    # 密度阈值
    sd = sorted(densities.values())
    ti = int(len(sd) * boundary_alpha)
    d_thresh = sd[ti] if ti < len(sd) else 0
    frontier = []
    for sid in point_ids:
        if densities[sid] > d_thresh:
            continue
        fp = fingerprints[sid]
        has_dense = any(
            o != sid and jaccard_distance(fp, fingerprints[o]) <= epsilon
            and densities[o] > d_thresh
            for o in point_ids
        )
        if has_dense:
            frontier.append(sid)
    return frontier
