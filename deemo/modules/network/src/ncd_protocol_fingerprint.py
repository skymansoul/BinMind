# 归一化压缩距离(NCD)协议指纹识别 —— 无需解析的协议实现聚类。
#
# NCD来自Kolmogorov复杂度理论: 若两对象相似, 联合压缩长度≈单独压缩长度。
# NCD(x,y) = (C(xy) - min(C(x),C(y))) / max(C(x),C(y))
# NCD∈[0,1+ε], 0=完全相同, ~1=完全无关。
#
# 应用于协议指纹: 同一协议的不同实现(如OpenSSL/GnuTLS/MbedTLS)在
# 响应中包含不同的实现特征(密码套件顺序/扩展字段/填充策略)。
# 这些特征不需解析即可通过NCD捕获——压缩算法自动学习字节级冗余模式。
#
# 优于解析方法的场景:
#   1. 协议无公开解析器(自定义/私有协议)
#   2. 多协议混合环境(无需识别协议类型即可聚类)
#   3. 加密载荷(压缩算法对密文的统计模式敏感)

from __future__ import annotations

import zlib
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class NcdDistance:
    """一对样本的NCD距离"""
    sample_a: int     # 样本索引
    sample_b: int
    ncd: float        # ∈ [0, ~1.2], 0=完全相同
    cx: int           # C(x) compressed size
    cy: int           # C(y)
    cxy: int          # C(x+y) joint compressed size


@dataclass
class ProtocolCluster:
    """NCD聚类结果 —— 一组相似协议响应的集合"""
    cluster_id: int
    members: List[int]          # 样本索引列表
    centroid_idx: int           # 离群心最近的成员索引
    intra_distance: float       # 簇内平均NCD
    size: int


@dataclass
class NcdFingerprintReport:
    """NCD指纹识别完整报告"""
    total_samples: int
    distance_matrix: List[List[float]]  # N×N上三角
    clusters: List[ProtocolCluster]
    unclustered: List[int]     # 未聚类的样本索引
    cluster_count: int
    mean_pairwise_ncd: float   # 所有对的平均NCD
    # 指纹解释
    fingerprint_notes: str = ""


def normalized_compression_distance(x: bytes, y: bytes,
                                     compressor=None) -> float:
    """计算两字节序列的归一化压缩距离。

    compressor: 默认zlib(level=6), 可替换为bz2/lzma。
    zlib压缩率适中+速度快→适合在线指纹场景。
    """
    if not x and not y:
        return 0.0
    if not x or not y:
        return 1.0

    comp = compressor or (lambda d: zlib.compress(d, 6))
    cx = len(comp(x))
    cy = len(comp(y))
    cxy = len(comp(x + y))

    if max(cx, cy) == 0:
        return 0.0
    return (cxy - min(cx, cy)) / max(cx, cy)


def compute_distance_matrix(samples: List[bytes],
                             compressor=None
                             ) -> List[NcdDistance]:
    """计算N个样本的成对NCD距离矩阵(上三角)。

    复杂度O(N²), 对N≤100的协议指纹场景可行。
    每个样本压缩3次(C(x), C(y), C(xy)), 总计约3N²次压缩——可缓存。
    """
    comp = compressor or (lambda d: zlib.compress(d, 6))
    n = len(samples)
    distances: List[NcdDistance] = []

    # 缓存各样本的压缩长度
    compressed_sizes = [None] * n
    for i in range(n):
        compressed_sizes[i] = len(comp(samples[i]))

    for i in range(n):
        for j in range(i + 1, n):
            cxy = len(comp(samples[i] + samples[j]))
            ncd_val = (cxy - min(compressed_sizes[i], compressed_sizes[j])
                       ) / max(compressed_sizes[i], compressed_sizes[j], 1)
            distances.append(NcdDistance(
                sample_a=i, sample_b=j,
                ncd=round(max(ncd_val, 0.0), 5),
                cx=compressed_sizes[i],
                cy=compressed_sizes[j],
                cxy=cxy,
            ))

    return distances


def cluster_by_ncd(distances: List[NcdDistance],
                    n_samples: int,
                    threshold: float = 0.15
                    ) -> Tuple[List[ProtocolCluster], List[int]]:
    """基于NCD阈值的单链接凝聚聚类。

    NCD ≤ threshold的样本对视为同一实现族。
    单链接=若A与B同簇且B与C同簇, 则A与C同簇。
    """
    # 构建邻接表(NCD ≤ threshold)
    adj: Dict[int, List[int]] = defaultdict(list)
    for d in distances:
        if d.ncd <= threshold:
            adj[d.sample_a].append(d.sample_b)
            adj[d.sample_b].append(d.sample_a)

    # 连通分量→簇
    visited: Set[int] = set()
    clusters: List[ProtocolCluster] = []
    unclustered: List[int] = []
    cid = 0

    for i in range(n_samples):
        if i in visited:
            continue
        if i not in adj:
            unclustered.append(i)
            visited.add(i)
            continue
        # BFS找连通分量
        comp = []
        queue = [i]
        while queue:
            node = queue.pop(0)
            if node in visited:
                continue
            visited.add(node)
            comp.append(node)
            queue.extend(adj.get(node, []))

        if len(comp) >= 2:
            # 选离群心最近的成员: 簇内平均NCD最小者
            centroid = min(comp, key=lambda m: sum(
                d.ncd for d in distances
                if (d.sample_a == m and d.sample_b in comp) or
                   (d.sample_b == m and d.sample_a in comp)
            ) / max(len(comp) - 1, 1))

            # 簇内平均NCD
            intra = 0.0
            intra_count = 0
            for d in distances:
                if d.sample_a in comp and d.sample_b in comp:
                    intra += d.ncd
                    intra_count += 1
            intra_avg = intra / max(intra_count, 1)

            clusters.append(ProtocolCluster(
                cluster_id=cid, members=comp, centroid_idx=centroid,
                intra_distance=round(intra_avg, 5), size=len(comp)))
            cid += 1
        else:
            unclustered.extend(comp)

    return clusters, unclustered


def fingerprint_samples(samples: List[bytes],
                         labels: Optional[List[str]] = None,
                         cluster_threshold: float = 0.15
                         ) -> NcdFingerprintReport:
    """便捷入口: 协议响应样本→NCD矩阵→聚类→指纹报告。

    samples: 协议响应字节列表(来自不同实现/版本)
    labels: 可选标签(如["openssl_3.0", "gnutls_3.8", ...])
    cluster_threshold: NCD≤此值视为同族(默认0.15=非常相似)
    """
    n = len(samples)
    if n < 2:
        return NcdFingerprintReport(
            total_samples=n, distance_matrix=[], clusters=[],
            unclustered=list(range(n)), cluster_count=0,
            mean_pairwise_ncd=0.0)

    distances = compute_distance_matrix(samples)
    clusters, unclustered = cluster_by_ncd(distances, n, cluster_threshold)

    # 距离矩阵(上三角紧凑形式→N×N)
    matrix = [[0.0] * n for _ in range(n)]
    for d in distances:
        matrix[d.sample_a][d.sample_b] = d.ncd
        matrix[d.sample_b][d.sample_a] = d.ncd

    mean_ncd = (sum(d.ncd for d in distances) /
                max(len(distances), 1))

    # 生成指纹注释
    notes = ""
    if labels:
        for c in clusters:
            c_labels = [labels[i] for i in c.members if i < len(labels)]
            notes += (f"簇{c.cluster_id}: {c_labels}, "
                     f"簇内NCD={c.intra_distance:.4f}\n")
        if unclustered:
            u_labels = [labels[i] for i in unclustered if i < len(labels)]
            notes += f"未聚类: {u_labels}\n"

    return NcdFingerprintReport(
        total_samples=n,
        distance_matrix=matrix,
        clusters=clusters,
        unclustered=unclustered,
        cluster_count=len(clusters),
        mean_pairwise_ncd=round(mean_ncd, 5),
        fingerprint_notes=notes.strip(),
    )


def identify_unknown(sample: bytes,
                      known_samples: List[bytes],
                      known_labels: List[str],
                      ) -> Tuple[str, float]:
    """识别未知样本: 计算与已知样本的NCD→最近邻标签+置信度。

    置信度 = 1 - NCD_to_nearest(归一化到[0,1])。
    NCD<0.1→高置信度匹配, NCD>0.5→低置信度(可能为未知实现)。
    """
    if not known_samples:
        return "unknown", 0.0

    min_ncd = 2.0
    min_idx = 0
    for i, known in enumerate(known_samples):
        ncd = normalized_compression_distance(sample, known)
        if ncd < min_ncd:
            min_ncd = ncd
            min_idx = i

    confidence = max(0.0, 1.0 - min_ncd)
    label = known_labels[min_idx] if confidence > 0.5 else "unknown"
    return label, round(confidence, 4)


__all__ = [
    "NcdDistance", "ProtocolCluster", "NcdFingerprintReport",
    "normalized_compression_distance", "compute_distance_matrix",
    "cluster_by_ncd", "fingerprint_samples", "identify_unknown",
]
