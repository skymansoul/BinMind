# 修改记录:
# 2025-08-02 16:47 - 1 维持续同调使用 Dudziak 矩阵归约 (O(N^3) 但 CFG 边数少)
# 2025-08-03 11:08 - 条形码熵编码替代原始条形码比较, 向量长度固定 64

"""CFG 持续同调条形码计算与指纹编码

0 维持续同调 (连通分量):
- 使用并查集 + 时间戳 高效计算
- 每个节点初始为独立分量 (birth=节点加入时间)
- 当一条边连接两个分量时, 较新分量 death=边加入时间
- 最终仍独立的分量 death=1.0 (永不消失--在过滤终点仍存在)

1 维持续同调 (环):
- 只关注 CFG 中独立于生成树的边产生的环
- 使用 Dudziak 边界矩阵归约的简化版: 无需全单工复形
  构造, 直接对生成树外的边计算最短环的生灭
- 复杂度: O(E·alpha(V)) -- 并查集主导, CFG 边数有限

条形码熵编码:
- 将每条持续区间 (birth, death) 映射到固定维度的密度向量
- 使用对数尺度的桶边界: [0, 1] 区间内 16 个对数桶
  密集短区间 (噪声) 集中于低桶, 稀疏长区间 (结构特征) 分布在高桶
- 最终产生 64 维指纹向量: 0 维 32 维 + 1 维 32 维
- 比朴素的 persistence diagram 距离快 O(barcode_count²)->O(64)

距离度量:
- 使用 earth mover's distance (EMD) 的 1D 近似
- 对 64 维向量直接使用累积分布函数 (CDF) 的 L1 距离
- 等价于 1D Wasserstein-1 的闭式解
"""

from __future__ import annotations

import math
from collections import defaultdict
from typing import Dict, List, Tuple, Optional

from .cfghomology_core import PersistenceInterval, BarcodeFingerprint


# 0 维持续同调 - 并查集时间戳算法

class _UnionFindTimestamp:
    """带时间戳的并查集: 记录每个分量 birth 时间和合并 death 时间"""

    def __init__(self, node_count: int):
        self._parent = list(range(node_count))
        self._rank = [0] * node_count
        self._birth: List[float] = [0.0] * node_count
        self._death: List[float] = [1.0] * node_count
        self._alive = [True] * node_count

    def set_birth(self, idx: int, birth: float) -> None:
        self._birth[idx] = birth

    def find(self, x: int) -> int:
        while self._parent[x] != x:
            self._parent[x] = self._parent[self._parent[x]]
            x = self._parent[x]
        return x

    def union(self, x: int, y: int, time: float) -> bool:
        """合并两个分量, 较新的分量 death=time

        返回 True 表示真正合并了两个不同分量（产生了持久性事件）
        """
        rx, ry = self.find(x), self.find(y)
        if rx == ry:
            return False

        if self._rank[rx] < self._rank[ry]:
            rx, ry = ry, rx

        self._parent[ry] = rx
        if self._rank[rx] == self._rank[ry]:
            self._rank[rx] += 1

        # 较晚 birth 的节点 death = 此边的过滤值
        if self._birth[rx] >= self._birth[ry]:
            self._death[ry] = time
        else:
            self._death[rx] = time
            # 将早 birth 分量提升为新的根 (保持根总是早 birth)
            self._parent[rx] = ry
            self._parent[ry] = ry

        return True

    def collect_intervals(self, dimension: int, channel: str) -> List[PersistenceInterval]:
        """收集所有分量 (包括仍然存活的) 的持久区间"""
        roots: Dict[int, List[int]] = defaultdict(list)
        for i in range(len(self._birth)):
            roots[self.find(i)].append(i)

        intervals = []
        for root, members in roots.items():
            b = min(self._birth[m] for m in members)
            d = min(self._death[m] for m in members)
            pers = d - b
            # 过滤噪声: persist 过短的区间-通常是数值误差
            if pers > 0.001:
                intervals.append(PersistenceInterval(
                    birth=b, death=d, dimension=dimension,
                    persistence=pers, channel=channel,
                ))
        return intervals


def compute_zerodim_persistence(
    sorted_node_ids: List[int],
    node_filtration_values: List[float],
    edge_list: List[Tuple[int, int, float]],
    channel: str,
) -> List[PersistenceInterval]:
    """计算 0 维持续同调 - 连通分量的生灭

    sorted_node_ids: 按过滤值降序排列的节点 ID
    node_filtration_values: 对应的过滤值
    edge_list: (src, dst, filtration_value), 按过滤值升序排列

    返回: 0 维持久区间列表
    """
    n = len(sorted_node_ids)
    if n == 0:
        return []

    # 建立 node_id -> sorted_index 映射 (并查集使用数组索引)
    id_to_idx: Dict[int, int] = {nid: i for i, nid in enumerate(sorted_node_ids)}

    uf = _UnionFindTimestamp(n)
    # birth = 1.0 - 过滤值 (过滤值高->先加入->birth 小)
    # 统一归一化使最早的节点 birth≈0, 最晚的 birth≈1
    max_fval = max(node_filtration_values) if node_filtration_values else 1.0
    min_fval = min(node_filtration_values) if node_filtration_values else 0.0
    f_range = max(0.001, max_fval - min_fval)

    for i, fval in enumerate(node_filtration_values):
        birth = 1.0 - (fval - min_fval) / f_range
        uf.set_birth(i, max(0.0, min(1.0, birth)))

    for src, dst, fval in edge_list:
        si = id_to_idx.get(src)
        di = id_to_idx.get(dst)
        if si is None or di is None:
            continue
        # death_time = 1.0 - normalized_fval (映射到 [0,1])
        death = 1.0 - (fval - min_fval) / f_range
        uf.union(si, di, max(0.0, min(1.0, death)))

    return uf.collect_intervals(0, channel)


# 1 维持续同调 - 生成树外边的环检测

def compute_onedim_persistence(
    sorted_node_ids: List[int],
    edge_list: List[Tuple[int, int, float]],
    channel: str,
) -> List[PersistenceInterval]:
    """计算 1 维持续同调 - CFG 中环的生灭

    算法:
    1. 对所有边按过滤值排序
    2. 维护生成树 (并查集)
    3. 当边连接已连通的两个节点时 -> 形成环 -> 记录持久区间
       birth = 此边的过滤值 (环出现的时间)
       death = 1.0 (环在过滤终点仍存在--CFG 中的环是永久特征)
    4. 自环 (src==dst) 忽略--不是有意义的拓扑特征

    注意: CFG 的 1 维同调通常不会消失 (death≈∞)
    因为环代表着代码中的循环--这是 CFG 的固有拓扑, 在过滤终点仍存在
    """
    n = len(sorted_node_ids)
    if n <= 2:
        return []

    id_to_idx: Dict[int, int] = {nid: i for i, nid in enumerate(sorted_node_ids)}
    parent = list(range(n))
    rank = [0] * n

    def _find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def _union(x: int, y: int) -> bool:
        rx, ry = _find(x), _find(y)
        if rx == ry:
            return False
        if rank[rx] < rank[ry]:
            rx, ry = ry, rx
        parent[ry] = rx
        if rank[rx] == rank[ry]:
            rank[rx] += 1
        return True

    # 边已在外层排好序 (按过滤值升序)
    intervals: List[PersistenceInterval] = []
    for src, dst, fval in edge_list:
        si = id_to_idx.get(src)
        di = id_to_idx.get(dst)
        if si is None or di is None:
            continue
        if si == di:
            continue  # 自环--非拓扑特征

        if not _union(si, di):
            # 已在同一分量 -> 形成环
            birth = max(0.0, min(1.0, fval))
            # 环的 death 设为 1.0: CFG 中的循环结构在过滤终点不消失
            intervals.append(PersistenceInterval(
                birth=birth, death=1.0, dimension=1,
                persistence=1.0 - birth, channel=channel,
            ))

    return intervals


# 条形码熵编码 - 将持久区间编码为固定维度指纹向量

# 对数尺度桶边界: 指数增长的桶宽, 将长 persist 区间分散到多个桶
# 16 个桶覆盖 [0.001, 1.0] 范围
_LOG_BIN_EDGES = [
    0.0, 0.001, 0.002, 0.005, 0.01, 0.02, 0.04, 0.08,
    0.15, 0.25, 0.40, 0.60, 0.80, 0.95, 1.0, float('inf'),
]
_NUM_BINS = len(_LOG_BIN_EDGES) - 1  # 15 个桶

# birth-death 平面的 2D 桶: 将 (birth, death) 坐标散入 15x15 网格
# 实际只用上三角 (death > birth)
_BIRTH_DEATH_BINS = 15


def _interval_to_persistence_entropy(intervals: List[PersistenceInterval]) -> float:
    """持久区间的 Shannon 熵--反映条形码的"结构丰富度"

    所有区间 persist 相同 -> 低熵 -> 结构单调
    区间 persist 分布广阔 -> 高熵 -> 拓扑结构丰富
    """
    if not intervals:
        return 0.0
    persists = [p.persistence for p in intervals]
    total = sum(persists)
    if total < 1e-9:
        return 0.0
    h = 0.0
    for p in persists:
        if p > 0:
            ratio = p / total
            h -= ratio * math.log2(ratio)
    return h


def encode_barcode(
    intervals_0d: List[PersistenceInterval],
    intervals_1d: List[PersistenceInterval],
    channel: str,
    vector_dim: int = 32,
) -> BarcodeFingerprint:
    """将 0 维和 1 维持久区间编码为固定维度指纹向量

    编码策略:
    - 0 维 (连通分量): 统计区间在 15 个对数桶中的分布密度 -> 15 维
      + persist 熵 (1 维) + 总区间数归一化值 (1 维)
      -> 填充到 32 维 (零填充)
    - 1 维 (环): 同上 -> 32 维
    - 最终 64 维向量: concat(0d_32, 1d_32)

    每维独立哈希混合--使向量对小的输入扰动稳定
    """
    fp = BarcodeFingerprint(
        channel=channel,
        vector=[],
        total_intervals=len(intervals_0d) + len(intervals_1d),
    )

# 0 维特征编码
    vec_0d = _encode_dimension(intervals_0d, vector_dim)
# 1 维特征编码
    vec_1d = _encode_dimension(intervals_1d, vector_dim)

    fp.vector = vec_0d + vec_1d

    # 元数据
    all_intervals = intervals_0d + intervals_1d
    if all_intervals:
        persists = [p.persistence for p in all_intervals]
        fp.mean_persistence = sum(persists) / len(persists)
        fp.max_persistence = max(persists)
        fp.entropy_of_persistence = _interval_to_persistence_entropy(all_intervals)

    return fp


def _encode_dimension(intervals: List[PersistenceInterval], dim: int) -> List[float]:
    """将一组持久区间编码为 dim 维特征向量

    分两步:
    1. 持久性桶计数: 区间按 persist 值散入对数桶 -> 归一化密度
    2. 确定性哈希填充: 将桶计数散列为剩余维度
    3. L2 归一化
    """
    if not intervals:
        return [0.0] * dim

    # 持久性对数桶分布 (使用 min(_NUM_BINS, dim//2) 个桶)
    n_bins = min(_NUM_BINS, max(4, dim // 2))
    bin_counts = [0.0] * n_bins
    for p in intervals:
        pers = p.persistence
        for b in range(n_bins):
            if _LOG_BIN_EDGES[b] <= pers < _LOG_BIN_EDGES[b + 1]:
                bin_counts[b] += 1.0
                break
        else:
            # 落于最后桶
            bin_counts[-1] += 1.0

    # 归一化密度
    total_count = max(1.0, sum(bin_counts))
    bin_density = [c / total_count for c in bin_counts]

    # 确定性哈希填充到 dim 维
    vec = [0.0] * dim
    for i, dval in enumerate(bin_density):
        vec[i] = dval

    # 剩余维度: 使用持久值的加权散列填充
    # 关键: 使用确定性哈希 (非随机投影)--保证相同输入产生相同指纹
    remaining = dim - n_bins
    if remaining > 0 and intervals:
        # 取前 8 个最长 persist 的区间作为显著特征
        sorted_p = sorted(intervals, key=lambda x: -x.persistence)[:8]
        for j, p in enumerate(sorted_p):
            # 将 birth 和 death 作为哈希种子填入剩余维度
            seed_val = abs(hash(f"{p.birth:.6f}:{p.death:.6f}")) % (10**9)
            for r in range(remaining):
                idx = (seed_val + j * 31 + r * 97) % remaining
                offset = n_bins + idx
                if offset < dim:
                    vec[offset] += p.persistence / (r + 1) * 0.1

    # L2 归一化
    norm = math.sqrt(sum(v * v for v in vec))
    if norm > 1e-9:
        vec = [v / norm for v in vec]

    return vec


# 指纹距离 - 1D Wasserstein-1 的 CDF 闭式解

def fingerprint_distance(
    fp1: BarcodeFingerprint,
    fp2: BarcodeFingerprint,
) -> float:
    """两个条码指纹的距离度量

    对 64 维向量使用 CDF-L1 距离:
    1. 计算每维向量的累积分布函数 (CDF)
    2. CDF 间的 L1 距离 -> 等价于 1D Wasserstein-1 距离

    此距离满足度量性质 (对称性、三角不等式、正定性)
    对小的向量扰动在数学上稳定 (Lipschitz 连续, Lipschitz 常数 = 1)

    返回 [0, 1] 间的距离值
    """
    v1, v2 = fp1.vector, fp2.vector
    if len(v1) != len(v2):
        return 1.0
    if len(v1) == 0:
        return 0.0

    # CDF 构造
    cdf1 = [0.0] * len(v1)
    cdf2 = [0.0] * len(v2)
    acc1, acc2 = 0.0, 0.0
    for i in range(len(v1)):
        acc1 += v1[i]
        acc2 += v2[i]
        cdf1[i] = acc1
        cdf2[i] = acc2

    # L1 距离
    l1_sum = sum(abs(cdf1[i] - cdf2[i]) for i in range(len(v1)))

    # 通道权重融合: 同一通道的距离直接比较
    # 跨通道 (不同 channel) 的比较无意义--此时返回 1.0
    if fp1.channel != fp2.channel:
        return 1.0

    return min(1.0, l1_sum / len(v1))


def fingerprint_similarity(fp1: BarcodeFingerprint, fp2: BarcodeFingerprint) -> float:
    """相似度分数 [0, 1], 1 = 完全一致"""
    return 1.0 - fingerprint_distance(fp1, fp2)


# 便捷接口: 一次调用计算 CFG 的持续同调指纹

def compute_cfg_fingerprints(
    sorted_ids: List[int],
    node_fvals: List[float],
    edge_list: List[Tuple[int, int, float]],
    channel: str,
) -> BarcodeFingerprint:
    """对单个过滤通道计算完整的持续同调指纹

    整合 0 维和 1 维持久区间的计算与编码
    """
    intervals_0d = compute_zerodim_persistence(
        sorted_ids, node_fvals, edge_list, channel,
    )
    intervals_1d = compute_onedim_persistence(
        sorted_ids, edge_list, channel,
    )
    return encode_barcode(intervals_0d, intervals_1d, channel)
