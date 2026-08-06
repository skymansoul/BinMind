"""因果推断统计工具 — Fisher Z 检验, Pearson 相关系数, 偏相关.

从 causal_graph.py 分离, 减少单文件体积。
"""

import math
from itertools import combinations
from typing import Dict, List, Set


_MIN_SAMPLES_FOR_TEST = 10


def pearson_r(x: List[float], y: List[float]) -> float:
    n = len(x)
    mx = sum(x) / n
    my = sum(y) / n
    cov = sum((xi - mx) * (yi - my) for xi, yi in zip(x, y))
    sx = math.sqrt(sum((xi - mx) ** 2 for xi in x))
    sy = math.sqrt(sum((yi - my) ** 2 for yi in y))
    if sx < 1e-12 or sy < 1e-12:
        return 0.0
    return max(-1.0, min(1.0, cov / (sx * sy)))


def partial_correlation(x: List[float], y: List[float],
                        conditioning: Set[str],
                        data: Dict[str, List[float]]) -> float:
    """逐步残差化计算偏相关系数."""
    n = min(len(x), len(y))
    cond_vars = [v for v in conditioning if v in data]
    if not cond_vars:
        return pearson_r(x, y)
    rx = list(x[:n])
    ry = list(y[:n])
    for cv in cond_vars:
        cv_vals = data[cv][:n]
        r_xc = pearson_r(rx, cv_vals)
        r_yc = pearson_r(ry, cv_vals)
        rx = [xi - r_xc * ci for xi, ci in zip(rx, cv_vals)]
        ry = [yi - r_yc * ci for yi, ci in zip(ry, cv_vals)]
    return pearson_r(rx, ry)


def fisher_independent(a: str, b: str, conditioning: Set[str],
                       data: Dict[str, List[float]],
                       alpha: float = 0.05) -> bool:
    """Fisher Z 检验: 零假设 ρ_{ab·Z}=0, p>alpha → 条件独立."""
    vals_a = data.get(a, [])
    vals_b = data.get(b, [])
    n = min(len(vals_a), len(vals_b))
    if n < _MIN_SAMPLES_FOR_TEST:
        return False
    vals_a = vals_a[:n]; vals_b = vals_b[:n]
    if not conditioning:
        r = pearson_r(vals_a, vals_b)
    else:
        r = partial_correlation(vals_a, vals_b, conditioning, data)
    if abs(r) >= 1.0:
        return False
    z = 0.5 * math.log((1.0 + r) / (1.0 - r))
    se = 1.0 / math.sqrt(n - len(conditioning) - 3)
    z_score = abs(z) / max(1e-12, se)
    return z_score < 1.96  # alpha=0.05 → z_critical=1.96


def subsets_up_to(s: Set[str], k: int):
    """生成 s 的大小 ≤ k 的所有子集."""
    s = list(s)
    for size in range(min(k, len(s)) + 1):
        yield from ({s[i] for i in idx} for idx in combinations(range(len(s)), size))
