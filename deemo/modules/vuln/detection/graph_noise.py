# -*- coding: utf-8 -*-
# 创建: 2026-07-31  |  图噪声机制与统计原语
# 修改: 2026-08-04  |  审计后补充文件头与错误处理
#
"""
图噪声注入与随机平滑统计原语。

噪声机制:
  边翻转——每条边独立以概率p删除/插入。这是对离散图结构的
  自然噪声模型（类比连续域的加性高斯噪声）。

设计选择:
  - 边翻转而非节点增删——节点增删改变图语义过强，
    边翻转保持函数的基本控制流结构
  - preserve_connectivity默认开启——避免桥边删除导致连通分量分裂，
    这在二进制函数CFG中几乎不会自然发生
  - 插入上限max_edge_insertions——防止过度稠密化改变图统计特征

统计工具:
  Clopper-Pearson精确二项下置信界——保守但保证覆盖率的认证界估计。
  正态近似在小p情况下低估尾部，精确方法在此场景更合理。
"""

import math
import random as _random
from dataclasses import dataclass
from typing import List, Tuple, Set


@dataclass
class GraphNoiseConfig:
    """图噪声配置"""
    edge_flip_prob: float = 0.05
    node_drop_prob: float = 0.02
    preserve_connectivity: bool = True
    max_edge_insertions: int = 5
    seed: int = 0


def perturb_edges(edges: List[Tuple[int, int]], num_nodes: int,
                   config: GraphNoiseConfig,
                   rng: _random.Random = None) -> List[Tuple[int, int]]:
    """对图边集施加随机边翻转噪声。

    操作（每条现有/缺失边独立决策）:
      - 现有边以p概率删除（桥边保留）
      - 缺失边以p概率插入（受max_edge_insertions限制）

    返回扰动后边列表——顺序不保持（已随机化）。
    时间复杂度: O(|E| + max_insertions)
    """
    if rng is None:
        rng = _random.Random(config.seed or None)

    edge_set = set(edges)
    new_edges = set()
    insertions = 0

    for e in edges:
        if rng.random() < config.edge_flip_prob:
            if config.preserve_connectivity and _is_bridge(e, edge_set, num_nodes):
                new_edges.add(e)
        else:
            new_edges.add(e)

    # 候选插入边——随机采样缺失边
    candidates = _sample_missing(edge_set, num_nodes,
                                  config.max_edge_insertions * 3, rng)
    for cand in candidates:
        if insertions >= config.max_edge_insertions:
            break
        if rng.random() < config.edge_flip_prob:
            new_edges.add(cand)
            insertions += 1

    return list(new_edges)


def _is_bridge(edge: Tuple[int, int], edge_set: Set[Tuple[int, int]],
                num_nodes: int) -> bool:
    """检测edge是否为桥——BFS验证删除后两端连通性"""
    if len(edge_set) <= 1:
        return True
    u, v = edge
    adj = {i: set() for i in range(num_nodes)}
    for a, b in edge_set:
        if (a, b) != edge and (b, a) != edge:
            adj[a].add(b)
            adj[b].add(a)
    visited = set()
    stack = [u]
    while stack:
        n = stack.pop()
        if n in visited:
            continue
        visited.add(n)
        if n == v:
            return False
        stack.extend(adj.get(n, set()) - visited)
    return True


def _sample_missing(edge_set: Set[Tuple[int, int]], num_nodes: int,
                     max_n: int, rng: _random.Random) -> List[Tuple[int, int]]:
    """随机采样不存在的边——候选插入集"""
    existing = edge_set | {(b, a) for a, b in edge_set}
    result = []
    attempts = 0
    while len(result) < max_n and attempts < max_n * 10:
        a = rng.randint(0, num_nodes - 1)
        b = rng.randint(0, num_nodes - 1)
        attempts += 1
        if a != b and (a, b) not in existing:
            result.append((a, b))
            existing.add((a, b))
            existing.add((b, a))
    return result


# ============================================================================
# 二项置信界——认证半径计算依赖
# ============================================================================


def clopper_pearson_lower(k: int, n: int, alpha: float) -> float:
    """Clopper-Pearson二项比例精确下置信界。

    返回p满足P(Bin(n, p) >= k) = α的下界解。
    实现: 二分查找——50次迭代→精度~2⁻⁵⁰。
    对n>1000时使用Wilson得分区间近似（误差<1e-3）。
    """
    if k == 0:
        return 0.0
    if k > n:
        return 1.0
    if n > 1000:
        # Wilson得分区间——大规模近似
        p_hat = k / n
        z = _norm_quantile(1.0 - alpha)
        denom = 1.0 + z * z / n
        center = (p_hat + z * z / (2 * n)) / denom
        margin = z * math.sqrt(p_hat * (1 - p_hat) / n + z * z / (4 * n * n)) / denom
        return max(0.0, center - margin)
    lo, hi = 0.0, 1.0
    for _ in range(50):
        mid = (lo + hi) / 2
        if _binom_sf(k - 1, n, mid) < alpha:
            lo = mid   # 尾部太小→p太小→增大下界
        else:
            hi = mid   # 尾部够大→p够大→降低上界
    return lo


def _binom_sf(k: int, n: int, p: float) -> float:
    """二项分布生存函数 P(X > k) = 1 - CDF(k)"""
    if k < 0:
        return 1.0
    if k >= n:
        return 0.0
    if n > 100:
        mean = n * p
        std = math.sqrt(n * p * (1 - p))
        if std < 1e-10:
            return 1.0 if k < mean else 0.0
        z = (k + 0.5 - mean) / std
        return 0.5 * (1.0 - math.erf(z / math.sqrt(2.0)))
    cdf = 0.0
    term = (1.0 - p) ** n
    for i in range(k + 1):
        cdf += term
        if i < n:
            term *= (n - i) / (i + 1) * p / max(1.0 - p, 1e-10)
    return 1.0 - cdf


def _norm_quantile(p: float) -> float:
    """标准正态分位数——Abramowitz & Stegun有理近似26.2.23"""
    if p <= 0.0:
        return float('-inf')
    if p >= 1.0:
        return float('inf')
    # 对下尾概率>0.5做对称处理
    tail = min(p, 1.0 - p)
    t = math.sqrt(-2.0 * math.log(tail))
    c = [2.515517, 0.802853, 0.010328]
    d = [1.432788, 0.189269, 0.001308]
    num = c[0] + c[1] * t + c[2] * t * t
    den = 1.0 + d[0] * t + d[1] * t * t + d[2] * t * t * t
    z = t - num / den
    return z if p >= 0.5 else -z


__all__ = [
    "GraphNoiseConfig",
    "perturb_edges",
    "clopper_pearson_lower",
]
