"""Sinkhorn 算法 — 熵正则化最优传输的迭代求解器.

从 optimal_transport_seed.py 分离, 减少单文件体积。
参考: Cuturi "Sinkhorn Distances" (NeurIPS)
"""

import math
from typing import FrozenSet, List, Tuple

_CONVERGENCE_TOL = 1e-6
_SPARSE_EPSILON = 0.01


def jaccard_dist(fp_a: FrozenSet[int], fp_b: FrozenSet[int]) -> float:
    if not fp_a and not fp_b:
        return 0.0
    if not fp_a or not fp_b:
        return 1.0
    inter = len(fp_a & fp_b)
    union = len(fp_a | fp_b)
    return 1.0 - (inter / union if union > 0 else 0.0)


def fingerprint(coverage: set) -> FrozenSet[int]:
    if len(coverage) <= 500:
        return frozenset(coverage)
    n_buckets = 512
    buckets = [0x7FFFFFFF] * n_buckets
    for edge in coverage:
        bucket = edge % n_buckets
        if edge < buckets[bucket]:
            buckets[bucket] = edge
    return frozenset(b for b in buckets if b != 0x7FFFFFFF)


def sinkhorn_ot(src_fps: List[FrozenSet[int]],
                tgt_fps: List[FrozenSet[int]],
                epsilon: float = 0.1,
                max_iters: int = 200,
                sparse_cutoff: float = _SPARSE_EPSILON
                ) -> Tuple[List[Tuple[int, int, float]], float]:
    """Sinkhorn 算法求解熵正则化最优传输.

    返回 ([(i, j, transport_weight), ...], wasserstein_cost)
    """
    n, m = len(src_fps), len(tgt_fps)
    if n == 0 or m == 0:
        return [], 0.0

    # 成本矩阵
    C = [[0.0] * m for _ in range(n)]
    max_cost = 0.0
    for i in range(n):
        for j in range(m):
            d = jaccard_dist(src_fps[i], tgt_fps[j])
            C[i][j] = d
            if d > max_cost:
                max_cost = d
    if max_cost < 1e-8:
        return [(i, i, 1.0 / max(n, m)) for i in range(min(n, m))], 0.0

    u = [1.0] * n
    v = [1.0] * m
    for _ in range(max_iters):
        u_old = list(u)
        for j in range(m):
            s = sum(math.exp(-C[i][j] / epsilon) * u[i] for i in range(n))
            v[j] = (1.0 / m) / max(1e-15, s)
        for i in range(n):
            s = sum(math.exp(-C[i][j] / epsilon) * v[j] for j in range(m))
            u[i] = (1.0 / n) / max(1e-15, s)
        change = sum(abs(u[i] - u_old[i]) for i in range(n))
        if change < _CONVERGENCE_TOL:
            break

    transfers = []
    total_cost = 0.0
    for i in range(n):
        for j in range(m):
            p_ij = u[i] * math.exp(-C[i][j] / epsilon) * v[j]
            if p_ij > sparse_cutoff:
                transfers.append((i, j, p_ij))
                total_cost += p_ij * C[i][j]
    return transfers, total_cost
