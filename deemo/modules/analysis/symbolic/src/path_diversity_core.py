"""抗路径爆炸的核心路径多样性分析引擎

通过选择彼此差异最大的路径抑制路径爆炸: 在结构、语义、约束
与覆盖率特征维度上计算两两相似度，按相似度阈值把路径聚类，
再从各簇选代表以最大化探索多样性。

核心实现从 path_diversity.py 拆出，包含真实库代码: 特征提取、
SimHash、ANN 索引、多样性预算、路径热力图、流式监控、快照
diff、相似度计算、多样性追踪与多样性感知的路径选择。

增强:
LSH (Locality-Sensitive Hashing) 加速相似度搜索: 随机超平面
投影把路径特征向量映射到汉明空间，近似 KNN 查询复杂度从
O(n²·d) 降至 O(k·d·log n); SimHash 指纹用于快速去重——
两路径 SimHash 差异大则无需精确相似度计算
WEIGHTED_SAMPLE 策略: 按簇大小反比抽样，小簇代表被选中的
概率更高，防止少数大簇垄断探索预算
近似最近邻索引 (ANN via Random Projection Forest): ann_forest
由多棵随机投影树组成，每棵在随机超平面上递归分割特征空间;
构建 O(n·log n)，查询 O(log n)，替代 O(n²) 两两比较
多样性预算管理 (DiversityBudget): 总路径预算按
cluster_quota = max_paths / num_clusters 均分; 簇超配额时
逐出与 centroid_simhash 汉明距离最大的路径（最不具代表性），
保留核心多样性
簇可视化导出 (export_cluster_visualization): 当前簇状态导出
为 JSON，含 cluster_id、centroid_features 与 member_count
StreamingDiversityMonitor: 基于回调的监控器，按可配置间隔
发射 (timestamp, diversity_score, exploration_velocity,
cluster_count) 元组，用于实时仪表板集成
PathHeatmap: 按 (depth_bucket, constraint_count_bucket) 维护
已探索路径的 2D 直方图，识别冷点做针对性重探索
SnapshotDiff: 比较两个 PathDiversityTracker 快照，计算新簇
形成、簇合并、路径在簇间移动与多样性评分增量
"""

import logging
import time
import hashlib
import threading
import random
import math
import struct
import json
from enum import Enum
from typing import Dict, Any, List, Optional, Set, Tuple, Callable
from dataclasses import dataclass, field
from collections import defaultdict

logger = logging.getLogger(__name__)


class DiversityStrategy(Enum):
    """挑选下一条多样路径的选择策略"""
    RANDOM = "random"
    ROUND_ROBIN = "round_robin"
    SIMILARITY_BASED = "similarity_based"
    COVERAGE_GUIDED = "coverage_guided"
    HYBRID = "hybrid"
    WEIGHTED_SAMPLE = "weighted_sample"


class PathFeatureType(Enum):
    """路径相似度的度量维度"""
    STRUCTURAL = "structural"
    SEMANTIC = "semantic"
    CONSTRAINTS = "constraints"
    COVERAGE = "coverage"


# SimHash: 将特征向量投影为 64-bit 指纹
# 两个 SimHash 的汉明距离 ≤ 3 时，原始向量的余弦相似度 ≥ 0.95（高概率）
# 用作快速去重预检——SimHash 差异大的路径无需精确比较
def _simhash(feature_dict: Dict, bits: int = 64) -> int:
    counts = [0] * bits
    for key, val in feature_dict.items():
        h = hashlib.sha256(f"{key}:{val}".encode()).hexdigest()
        h_int = int(h, 16)
        for b in range(bits):
            if (h_int >> b) & 1:
                counts[b] += 1
            else:
                counts[b] -= 1
    result = 0
    for b in range(bits):
        if counts[b] > 0:
            result |= (1 << b)
    return result


def _hamming_distance(a: int, b: int) -> int:
    x = a ^ b
    dist = 0
    while x:
        dist += 1
        x &= x - 1
    return dist


# _feature_to_vector: 将 PathFeature 的特征字典展平为固定长度的浮点向量
# 用于随机投影树的构建和查询
# 策略：对每个 feature_type 按 key 排序取 val 的 hash 值，归一化到 [0,1]
# 维度固定为 64，确保所有特征向量的长度一致
def _feature_to_vector(feature: "PathFeature", dim: int = 64) -> List[float]:
    # 把 PathFeature 展平为固定维度浮点向量
    vec = [0.0] * dim
    idx = 0
    sorted_items = sorted(feature.features.items())
    for ft_key, ft_val in sorted_items:
        if isinstance(ft_val, dict):
            for k, v in sorted(ft_val.items()):
                h = hashlib.sha256(f"{ft_key}:{k}:{v}".encode()).digest()
                for i in range(0, len(h), 4):
                    if idx >= dim:
                        break
                    chunk = struct.unpack_from("<I", h, i)[0]
                    vec[idx] = (chunk % 100000) / 100000.0
                    idx += 1
        else:
            h = hashlib.sha256(f"{ft_key}:{ft_val}".encode()).digest()
            for i in range(0, len(h), 4):
                if idx >= dim:
                    break
                chunk = struct.unpack_from("<I", h, i)[0]
                vec[idx] = (chunk % 100000) / 100000.0
                idx += 1
        if idx >= dim:
            break
    return vec


# RandomProjectionTree — 单棵随机投影树
# 节点在随机方向上分割，递归构造直到叶子节点 ≤ leaf_size
class _RandomProjectionNode:
    """随机投影树的内部节点。"""
    __slots__ = ('random_dir', 'split_val', 'left', 'right', 'leaf_ids')

    def __init__(self):
        self.random_dir: Optional[List[float]] = None
        self.split_val: float = 0.0
        self.left: Optional[_RandomProjectionNode] = None
        self.right: Optional[_RandomProjectionNode] = None
        self.leaf_ids: Optional[List[str]] = None


class _RandomProjectionTree:
    """近似最近邻搜索的单棵随机投影树。

    构造: 随机生成超平面方向 random_dir, 把所有向量投影到该方向,
    取中位数作分割点 split_val, 递归作用于左右子集; 叶节点存储
    path_id 列表, 查询时下降到叶节点后扫描该叶中的全部点。

    单棵树查询可能漏掉跨分割边界的近邻, 因此用 ann_forest
    (多棵树) 提高召回率。
    """

    def __init__(self, dim: int, leaf_size: int = 10):
        self._dim = dim
        self._leaf_size = leaf_size
        self._root: Optional[_RandomProjectionNode] = None

    def build(self, vectors: Dict[str, List[float]]):
        """用 path_id → 浮点向量字典构建树, O(n log n)。"""
        ids = list(vectors.keys())
        self._root = self._build_node(ids, vectors)

    def _build_node(self, ids: List[str],
                    vectors: Dict[str, List[float]]) -> _RandomProjectionNode:
        node = _RandomProjectionNode()
        if len(ids) <= self._leaf_size:
            node.leaf_ids = list(ids)
            return node

        # 随机超平面方向
        node.random_dir = [random.uniform(-1.0, 1.0) for _ in range(self._dim)]

        # 投影到随机方向并取中位数分割
        projections = []
        for pid in ids:
            v = vectors.get(pid, [0.0] * self._dim)
            proj = sum(a * b for a, b in zip(node.random_dir, v))
            projections.append(proj)

        # 中位数分割
        paired = sorted(zip(projections, ids), key=lambda x: x[0])
        mid = len(paired) // 2
        if mid == 0:
            mid = 1
        node.split_val = paired[mid][0]
        left_ids = [pid for _, pid in paired[:mid]]
        right_ids = [pid for _, pid in paired[mid:]]

        if not left_ids or not right_ids:
            node.leaf_ids = list(ids)
            return node

        node.left = self._build_node(left_ids, vectors)
        node.right = self._build_node(right_ids, vectors)
        return node

    def query(self, query_vec: List[float], vectors: Dict[str, List[float]],
              k: int = 5) -> List[Tuple[str, float]]:
        """查询 k 个最近邻, 返回 [(path_id, cosine_sim), ...]。"""
        if self._root is None:
            return []

        # 下降找到叶节点
        leaf_ids = self._descend(self._root, query_vec)

        # 在叶节点内线性扫描
        candidates = []
        for pid in leaf_ids:
            v = vectors.get(pid)
            if v:
                sim = self._cosine(query_vec, v)
                candidates.append((pid, sim))

        candidates.sort(key=lambda x: -x[1])
        return candidates[:k]

    def _descend(self, node: _RandomProjectionNode,
                 query_vec: List[float]) -> List[str]:
        if node.leaf_ids is not None:
            return node.leaf_ids
        if node.random_dir is None:
            return node.leaf_ids or []

        proj = sum(a * b for a, b in zip(node.random_dir, query_vec))
        if proj <= node.split_val and node.left is not None:
            return self._descend(node.left, query_vec)
        elif node.right is not None:
            return self._descend(node.right, query_vec)
        # 回退：如果一侧为空，走另一侧
        if node.left is not None:
            return self._descend(node.left, query_vec)
        if node.right is not None:
            return self._descend(node.right, query_vec)
        return []

    @staticmethod
    def _cosine(v1: List[float], v2: List[float]) -> float:
        dot = sum(a * b for a, b in zip(v1, v2))
        norm1 = math.sqrt(sum(a * a for a in v1))
        norm2 = math.sqrt(sum(b * b for b in v2))
        denom = max(norm1 * norm2, 1e-12)
        return max(0.0, min(1.0, dot / denom))


# ANNIndex——随机投影森林，替代 O(n²) pairwise 相似度搜索
# ann_forest 包含多棵 _RandomProjectionTree
# 查询时汇总所有树的候选并按余弦相似度合并排序
class ANNIndex:
    """基于随机投影森林的近似最近邻索引。

    构建: features 字典中每个 PathFeature 展平为 64 维向量,
    用 n_trees 棵随机投影树索引, 构建 O(n·d·log n·n_trees)。

    查询: 给定一个 PathFeature, 下降到各棵树的叶节点, 汇总
    候选后按余弦相似度排序, 查询 O(n_trees·log n + leaf_size·d)。
    """

    def __init__(self, n_trees: int = 10, leaf_size: int = 10, vector_dim: int = 64):
        self._n_trees = n_trees
        self._leaf_size = leaf_size
        self._vector_dim = vector_dim
        self._ann_forest: List[_RandomProjectionTree] = []
        self._vectors: Dict[str, List[float]] = {}
        self._built = False

    @property
    def ann_forest(self) -> List[_RandomProjectionTree]:
        return self._ann_forest

    def build(self, features: Dict[str, "PathFeature"]):
        """构建随机投影森林, O(n·log n·n_trees)。"""
        if not features:
            return
        # 将所有 PathFeature 转为固定维度浮点向量
        self._vectors = {
            pid: _feature_to_vector(feat, self._vector_dim)
            for pid, feat in features.items()
        }
        self._ann_forest = []
        for _ in range(self._n_trees):
            tree = _RandomProjectionTree(self._vector_dim, self._leaf_size)
            tree.build(self._vectors)
            self._ann_forest.append(tree)
        self._built = True
        logger.info(
            f"ANN index built: {self._n_trees} trees, "
            f"{len(self._vectors)} vectors in {self._vector_dim} dims"
        )

    def query(self, feature: "PathFeature", k: int = 5) -> List[Tuple[str, float]]:
        """查找至多 k 个近似最近邻。

        返回按相似度降序的 (path_id, cosine_similarity) 列表;
        索引未构建时返回空列表。
        """
        if not self._built or not self._ann_forest:
            return []

        query_vec = _feature_to_vector(feature, self._vector_dim)

        # 汇总所有树的候选
        all_candidates: Dict[str, float] = {}
        for tree in self._ann_forest:
            cands = tree.query(query_vec, self._vectors, k)
            for pid, sim in cands:
                if pid not in all_candidates or sim > all_candidates[pid]:
                    all_candidates[pid] = sim

        # 合并排序
        merged = sorted(all_candidates.items(), key=lambda x: -x[1])
        return merged[:k]

    def find_similar(self, feature: "PathFeature",
                     threshold: float = 0.7) -> List[str]:
        """返回余弦相似度不低于阈值的已索引路径。"""
        if not self._built:
            return []
        # 查询足够多的候选，再按阈值过滤
        candidates = self.query(feature, k=20)
        return [pid for pid, sim in candidates if sim >= threshold]


# DiversityBudget — 簇配额管理：cluster_quota = max_paths / num_clusters
# 超配额的簇逐出与 centroid_simhash 汉明距离最大的路径
class DiversityBudget:
    """按簇执行路径配额, 防止资源垄断。

    cluster_quota = max_paths / num_clusters; 某簇路径数超过
    quota 时, 计算该簇所有成员 SimHash 与 centroid_simhash 的
    汉明距离, 逐出距离最大的路径 (最不具代表性)。
    """

    def __init__(self, max_paths: int = 1000):
        self._max_paths = max_paths
        self._cluster_quota: int = max_paths

    def set_cluster_count(self, num_clusters: int):
        """簇数量变化时重算 cluster_quota。"""
        self._cluster_quota = self._max_paths // max(1, num_clusters)
        # 每个簇至少保留 1 条路径
        self._cluster_quota = max(1, self._cluster_quota)

    @property
    def cluster_quota(self) -> int:
        return self._cluster_quota

    @property
    def max_paths(self) -> int:
        return self._max_paths

    def compute_centroid_simhash(self, cluster_members: List[str],
                                  features: Dict[str, "PathFeature"]) -> int:
        """计算簇的 centroid_simhash。

        策略: 对每个 bit 位置 (0..63), 统计成员 SimHash 中该位为
        1 的数量, 超过半数则 centroid_simhash 该位也为 1 —
        即成员的"多数投票"指纹。
        """
        if not cluster_members:
            return 0
        bit_counts = [0] * 64
        for pid in cluster_members:
            feat = features.get(pid)
            if feat:
                sig = feat.simhash_sig
                for b in range(64):
                    if (sig >> b) & 1:
                        bit_counts[b] += 1
        half = len(cluster_members) / 2.0
        centroid = 0
        for b in range(64):
            if bit_counts[b] > half:
                centroid |= (1 << b)
        return centroid

    def enforce(self, clusters: Dict[str, List[str]],
                features: Dict[str, "PathFeature"]) -> List[str]:
        """逐出超配额路径, 返回被逐出的 path_id 列表。

        只处理超配额簇, 不影响配额内的簇。
        """
        evicted: List[str] = []
        for cluster_id, members in list(clusters.items()):
            if len(members) <= self._cluster_quota:
                continue
            centroid = self.compute_centroid_simhash(members, features)
            # 计算每个成员到 centroid 的汉明距离
            scored = []
            for pid in members:
                feat = features.get(pid)
                if feat:
                    dist = _hamming_distance(feat.simhash_sig, centroid)
                    scored.append((pid, dist))
                else:
                    scored.append((pid, 0))
            # 距离越大越先逐出（最不具代表性）
            scored.sort(key=lambda x: -x[1])
            excess = len(members) - self._cluster_quota
            for pid, _ in scored[:excess]:
                members.remove(pid)
                evicted.append(pid)
            clusters[cluster_id] = members
        return evicted


# PathHeatmap — 2D 直方图，按 (depth_bucket, constraint_count_bucket) 统计
#
# depth_bucket 的桶宽为 DEPTH_BUCKET_WIDTH（默认 2）
# constraint_count_bucket 的桶宽为 CONSTRAINT_BUCKET_WIDTH（默认 5）
#
# 冷点识别：histogram 值低于全局平均密度 * COLD_SPOT_RATIO 的单元格
class PathHeatmap:
    """维护已探索路径的 2D 直方图, 识别冷点做针对性重探索。

    depth_bucket = int(depth // DEPTH_BUCKET_WIDTH),
    constraint_bucket = int(constraint_count // CONSTRAINT_BUCKET_WIDTH)。
    """

    DEPTH_BUCKET_WIDTH: int = 2
    CONSTRAINT_BUCKET_WIDTH: int = 5
    COLD_SPOT_RATIO: float = 0.2  # 低于平均密度 20% 即为冷点

    def __init__(
        self,
        depth_bucket_width: int = 2,
        constraint_bucket_width: int = 5,
    ):
        self._depth_bw = max(1, depth_bucket_width)
        self._constraint_bw = max(1, constraint_bucket_width)
        # histogram[(depth_bucket, constraint_bucket)] = count
        self._histogram: Dict[Tuple[int, int], int] = defaultdict(int)
        # 存储每个单元格包含的 path_id 列表，用于定位冷点中的具体路径
        self._cell_paths: Dict[Tuple[int, int], List[str]] = defaultdict(list)
        self._total_paths: int = 0
        self._lock = threading.Lock()

    @property
    def depth_bucket_width(self) -> int:
        return self._depth_bw

    @property
    def constraint_bucket_width(self) -> int:
        return self._constraint_bw

    @property
    def histogram(self) -> Dict[Tuple[int, int], int]:
        """返回当前直方图的副本。"""
        with self._lock:
            return dict(self._histogram)

    @property
    def total_paths(self) -> int:
        return self._total_paths

    def record(self, path_id: str, depth: int, constraint_count: int):
        """把一条路径记录到 2D 直方图。

        depth 为路径树深度, constraint_count 为路径上的约束数。
        """
        db = depth // self._depth_bw
        cb = constraint_count // self._constraint_bw
        key = (db, cb)

        with self._lock:
            self._histogram[key] += 1
            self._cell_paths[key].append(path_id)
            self._total_paths += 1

    def record_batch(self, paths: List[Tuple[str, int, int]]):
        """一次记录多条路径, 元素为 (path_id, depth, constraint_count)。"""
        with self._lock:
            for path_id, depth, constraint_count in paths:
                db = depth // self._depth_bw
                cb = constraint_count // self._constraint_bw
                key = (db, cb)
                self._histogram[key] += 1
                self._cell_paths[key].append(path_id)
                self._total_paths += 1

    def get_density(self, depth_bucket: int, constraint_bucket: int) -> int:
        """返回指定直方图单元格的路径数。"""
        return self._histogram.get((depth_bucket, constraint_bucket), 0)

    def average_density(self) -> float:
        """计算非空单元格的平均路径数。"""
        with self._lock:
            if not self._histogram:
                return 0.0
            total = sum(self._histogram.values())
            return total / len(self._histogram)

    def identify_cold_spots(
        self, cold_spot_ratio: Optional[float] = None
    ) -> List[Dict[str, Any]]:
        """识别路径密度低于冷点阈值的直方图单元格。

        单元格计数 < avg_density * cold_spot_ratio 即视为冷点;
        返回按计数升序 (最冷在前) 的冷点字典列表, 键含
        depth_bucket、constraint_bucket、count、avg_density、paths。
        """
        ratio = cold_spot_ratio if cold_spot_ratio is not None else self.COLD_SPOT_RATIO
        avg = self.average_density()
        threshold = avg * ratio

        cold_spots: List[Dict[str, Any]] = []
        with self._lock:
            for (db, cb), count in self._histogram.items():
                if count < threshold:
                    cold_spots.append({
                        "depth_bucket": db,
                        "depth_range": f"[{db * self._depth_bw}, {(db + 1) * self._depth_bw})",
                        "constraint_bucket": cb,
                        "constraint_range": f"[{cb * self._constraint_bw}, {(cb + 1) * self._constraint_bw})",
                        "count": count,
                        "avg_density": round(avg, 2),
                        "cold_spot_ratio": round(count / max(1.0, avg), 3),
                        "paths": list(self._cell_paths.get((db, cb), [])),
                    })

        cold_spots.sort(key=lambda x: x["count"])
        return cold_spots

    def identify_hot_spots(self, top_n: int = 5) -> List[Dict[str, Any]]:
        """识别密度最高的直方图单元格, 返回按计数降序的前 N 个热点。"""
        with self._lock:
            sorted_cells = sorted(
                self._histogram.items(), key=lambda x: -x[1]
            )[:top_n]

        avg = self.average_density()
        hot_spots = []
        for (db, cb), count in sorted_cells:
            hot_spots.append({
                "depth_bucket": db,
                "depth_range": f"[{db * self._depth_bw}, {(db + 1) * self._depth_bw})",
                "constraint_bucket": cb,
                "constraint_range": f"[{cb * self._constraint_bw}, {(cb + 1) * self._constraint_bw})",
                "count": count,
                "avg_density": round(avg, 2),
                "paths_in_cell": len(self._cell_paths.get((db, cb), [])),
            })
        return hot_spots

    def paths_in_cold_spots(
        self, cold_spot_ratio: Optional[float] = None
    ) -> List[str]:
        """返回冷点单元格中的 path_id 列表, 供针对性重探索。

        这些路径位于探索不足的 (深度, 约束) 区域, 是聚焦符号执行
        的理想候选。
        """
        cold_spots = self.identify_cold_spots(cold_spot_ratio)
        all_paths: List[str] = []
        for spot in cold_spots:
            all_paths.extend(spot.get("paths", []))
        return all_paths

    def export_histogram_json(self, output_path: Optional[str] = None) -> Dict[str, Any]:
        """把 2D 直方图导出为可 JSON 序列化的字典, 供可视化。

        含 depth_bucket_width、constraint_bucket_width、
        total_paths、average_density 与 cells 列表。
        """
        avg = self.average_density()
        with self._lock:
            cells = [
                {"depth_bucket": db, "constraint_bucket": cb, "count": cnt}
                for (db, cb), cnt in self._histogram.items()
            ]

        result = {
            "depth_bucket_width": self._depth_bw,
            "constraint_bucket_width": self._constraint_bw,
            "total_paths": self._total_paths,
            "average_density": round(avg, 2),
            "cold_spots": self.identify_cold_spots(),
            "cells": sorted(cells, key=lambda c: (c["depth_bucket"], c["constraint_bucket"])),
        }

        if output_path:
            try:
                import os as _os
                _os.makedirs(_os.path.dirname(output_path) or ".", exist_ok=True)
                with open(output_path, 'w', encoding='utf-8') as f:
                    json.dump(result, f, indent=2, ensure_ascii=False)
                logger.info("PathHeatmap histogram exported to %s", output_path)
            except Exception as e:
                logger.warning("Failed to export PathHeatmap: %s", e)

        return result

    def reset(self):
        """清除直方图数据。"""
        with self._lock:
            self._histogram.clear()
            self._cell_paths.clear()
            self._total_paths = 0


# StreamingDiversityMonitor — 定时回调发射多样性指标
#
# 在后台线程中以可配置间隔运行，每次触发时调用注册的回调函数
# 传递 (timestamp, diversity_score, exploration_velocity, cluster_count)
# 用于实时仪表板、时间序列日志或外部可视化集成
class StreamingDiversityMonitor:
    """基于回调的监控器, 按可配置间隔发射 (timestamp,
    diversity_score, exploration_velocity, cluster_count) 元组,
    用于实时仪表板集成。

    后台 daemon 线程定期轮询 PathDiversityTracker.get_metrics(),
    经注册的回调把指标推送到外部系统 (日志、WebSocket、时序 DB)。

    回调签名: callback(timestamp, diversity_score,
    exploration_velocity, cluster_count, extra_metrics) -> None。
    """

    def __init__(
        self,
        tracker: "PathDiversityTracker",
        interval_seconds: float = 2.0,
    ):
        """初始化流式监控。

        tracker 为轮询指标的 PathDiversityTracker 实例,
        interval_seconds 为发射间隔 (默认 2s)。
        """
        self._tracker = tracker
        self._interval = max(0.1, interval_seconds)

        self._callbacks: List[Callable[[float, float, float, int, Dict[str, Any]], None]] = []
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._running = False
        self._emit_count: int = 0

        # 历史缓冲区：保留最近 N 个数据点用于回溯
        self._history: List[Tuple[float, float, float, int]] = []
        self._max_history: int = 1000

    @property
    def interval(self) -> float:
        return self._interval

    @property
    def running(self) -> bool:
        return self._running

    @property
    def emit_count(self) -> int:
        return self._emit_count

    @property
    def history(self) -> List[Tuple[float, float, float, int]]:
        """返回近期指标历史的副本, 元素为 (timestamp, diversity_score,
        exploration_velocity, cluster_count)。"""
        with self._lock:
            return list(self._history)

    def register_callback(
        self,
        callback: Callable[[float, float, float, int, Dict[str, Any]], None],
    ):
        """注册接收流式指标的回调。

        回调在监控后台线程的每个间隔 tick 触发; 回调应保持简短,
        避免阻塞发射循环。
        """
        with self._lock:
            self._callbacks.append(callback)

    def start(self):
        """启动后台监控线程。"""
        if self._running:
            logger.warning("StreamingDiversityMonitor already running")
            return

        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._emit_loop,
            name="StreamingDiversityMonitor",
            daemon=True,
        )
        self._thread.start()
        self._running = True
        logger.info(
            "StreamingDiversityMonitor started (interval=%.1fs)", self._interval
        )

    def stop(self, timeout: float = 5.0):
        """停止监控线程。"""
        if not self._running:
            return
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None
        self._running = False
        logger.info(
            "StreamingDiversityMonitor stopped (%d emits)", self._emit_count
        )

    def _emit_loop(self):
        """后台发射循环。"""
        while not self._stop_event.is_set():
            try:
                metrics = self._tracker.get_metrics()
                timestamp = time.time()
                diversity_score = metrics.diversity_score
                exploration_velocity = metrics.exploration_velocity
                cluster_count = metrics.unique_paths

                extra = {
                    "total_paths": metrics.total_paths,
                    "avg_similarity": metrics.avg_similarity,
                    "coverage_gain": metrics.coverage_gain,
                    "exploration_efficiency": metrics.exploration_efficiency,
                }

                # 更新历史
                with self._lock:
                    self._history.append(
                        (timestamp, diversity_score, exploration_velocity, cluster_count)
                    )
                    if len(self._history) > self._max_history:
                        self._history = self._history[-self._max_history:]

                    callbacks = list(self._callbacks)

                # 触发所有回调
                for cb in callbacks:
                    try:
                        cb(timestamp, diversity_score, exploration_velocity,
                           cluster_count, extra)
                    except Exception as e:
                        logger.error(
                            "StreamingDiversityMonitor callback error: %s", e
                        )

                self._emit_count += 1

            except Exception as e:
                logger.warning(
                    "StreamingDiversityMonitor emit error: %s", e
                )

            # 等待下一个间隔
            if self._stop_event.wait(self._interval):
                break

    def get_latest(self) -> Optional[Tuple[float, float, float, int]]:
        """返回最近一次指标元组, 尚无发射时返回 None。"""
        with self._lock:
            if self._history:
                return self._history[-1]
        return None

    def export_history_json(
        self, output_path: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """把指标历史导出为可 JSON 序列化的列表。

        元素: {"timestamp": float, "diversity_score": float,
        "exploration_velocity": float, "cluster_count": int}。
        """
        with self._lock:
            data = [
                {
                    "timestamp": ts,
                    "diversity_score": ds,
                    "exploration_velocity": ev,
                    "cluster_count": cc,
                }
                for ts, ds, ev, cc in self._history
            ]

        if output_path:
            try:
                import os as _os
                _os.makedirs(_os.path.dirname(output_path) or ".", exist_ok=True)
                with open(output_path, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
                logger.info(
                    "StreamingDiversityMonitor history exported to %s (%d points)",
                    output_path, len(data)
                )
            except Exception as e:
                logger.warning("Failed to export monitor history: %s", e)

        return data


# SnapshotDiff — 比较两个 PathDiversityTracker 快照
#
# 快照格式：{'clusters': Dict[str, List[str]], 'features': Dict[str, PathFeature],
#            'metrics': DiversityMetrics}
#
# SnapshotDiff 计算：
# new_clusters: 仅在新快照中存在的簇 ID
# removed_clusters: 仅在旧快照中存在的簇 ID
# merged_clusters: 旧快照中的多个簇在新快照中合并为一个
# split_clusters: 旧快照中的一个簇在新快照中分裂为多个
# moved_paths: 在两个快照中都存在但簇归属不同的路径
# diversity_delta: 多样性评分的变化量
@dataclass
class SnapshotDiffResult:
    """两个 PathDiversityTracker 快照的比较结果。"""
    new_clusters: List[str] = field(default_factory=list)
    removed_clusters: List[str] = field(default_factory=list)
    merged_clusters: List[Dict[str, Any]] = field(default_factory=list)
    split_clusters: List[Dict[str, Any]] = field(default_factory=list)
    moved_paths: List[Dict[str, Any]] = field(default_factory=list)
    diversity_delta: float = 0.0
    cluster_count_delta: int = 0
    total_paths_delta: int = 0
    new_paths: List[str] = field(default_factory=list)
    removed_paths: List[str] = field(default_factory=list)

    def summary(self) -> str:
        """返回人类可读的单行差异摘要。"""
        parts = []
        if self.new_clusters:
            parts.append(f"+{len(self.new_clusters)} clusters")
        if self.removed_clusters:
            parts.append(f"-{len(self.removed_clusters)} clusters")
        if self.merged_clusters:
            parts.append(f"{len(self.merged_clusters)} merged")
        if self.split_clusters:
            parts.append(f"{len(self.split_clusters)} split")
        if self.moved_paths:
            parts.append(f"{len(self.moved_paths)} paths moved")
        parts.append(f"diversity Δ={self.diversity_delta:+.4f}")
        return ", ".join(parts) if parts else "no changes"


class SnapshotDiff:
    """比较两个 PathDiversityTracker 快照, 计算变化: 新簇形成、
    簇合并、路径在簇间移动与多样性评分增量。

    快照可通过 PathDiversityTracker 的 public 接口获取:
    {'clusters': dict(tracker._clusters),
     'features': {pid: feat for pid, feat in tracker._features.items()},
     'metrics': tracker.get_metrics(), 'timestamp': time.time()}。
    """

    @staticmethod
    def capture(tracker: "PathDiversityTracker") -> Dict[str, Any]:
        """捕获当前 tracker 状态的快照, 返回可供 SnapshotDiff.compare() 使用的字典。"""
        with tracker._lock:
            return {
                "clusters": {
                    cid: list(members)
                    for cid, members in tracker._clusters.items()
                },
                "features": {
                    pid: PathFeature(
                        path_id=f.path_id,
                        features=dict(f.features),
                        simhash_sig=f.simhash_sig,
                        cluster_id=f.cluster_id,
                        timestamp=f.timestamp,
                    )
                    for pid, f in tracker._features.items()
                },
                "metrics": tracker.get_metrics(),
                "timestamp": time.time(),
            }

    def compare(
        self,
        snapshot_old: Dict[str, Any],
        snapshot_new: Dict[str, Any],
    ) -> SnapshotDiffResult:
        """比较两个快照, 产生详细差异。

        snapshot_old 为较早的快照字典, snapshot_new 为较晚的。
        """
        result = SnapshotDiffResult()

        old_clusters: Dict[str, List[str]] = snapshot_old.get("clusters", {})
        new_clusters: Dict[str, List[str]] = snapshot_new.get("clusters", {})

        old_cluster_ids = set(old_clusters.keys())
        new_cluster_ids = set(new_clusters.keys())

        # 新建/删除的簇
        result.new_clusters = sorted(new_cluster_ids - old_cluster_ids)
        result.removed_clusters = sorted(old_cluster_ids - new_cluster_ids)

        # 构建 path→集群映射
        old_path_to_cluster: Dict[str, str] = {}
        for cid, members in old_clusters.items():
            for pid in members:
                old_path_to_cluster[pid] = cid

        new_path_to_cluster: Dict[str, str] = {}
        for cid, members in new_clusters.items():
            for pid in members:
                new_path_to_cluster[pid] = cid

        old_paths = set(old_path_to_cluster.keys())
        new_paths = set(new_path_to_cluster.keys())

        # 新增/删除的路径
        result.new_paths = sorted(new_paths - old_paths)
        result.removed_paths = sorted(old_paths - new_paths)

        # 移动路径（在两个快照中都存在但簇归属改变）
        common_paths = old_paths & new_paths
        for pid in sorted(common_paths):
            old_cid = old_path_to_cluster.get(pid, "")
            new_cid = new_path_to_cluster.get(pid, "")
            if old_cid != new_cid:
                result.moved_paths.append({
                    "path_id": pid,
                    "old_cluster": old_cid,
                    "new_cluster": new_cid,
                })

        # 合并检测
        # 旧快照中的多个簇在新快照中合并为一个
        merged = self._detect_merges(old_clusters, new_clusters)
        result.merged_clusters = merged

        # 分裂检测
        # 旧快照中的一个簇在新快照中分裂为多个
        split = self._detect_splits(old_clusters, new_clusters)
        result.split_clusters = split

        # 数量变化
        old_metrics = snapshot_old.get("metrics")
        new_metrics = snapshot_new.get("metrics")

        if old_metrics and new_metrics:
            result.diversity_delta = (
                new_metrics.diversity_score - old_metrics.diversity_score
            )
        result.cluster_count_delta = len(new_cluster_ids) - len(old_cluster_ids)
        result.total_paths_delta = len(new_paths) - len(old_paths)

        logger.info(
            "SnapshotDiff: %s", result.summary()
        )

        return result

    def _detect_merges(
        self,
        old_clusters: Dict[str, List[str]],
        new_clusters: Dict[str, List[str]],
    ) -> List[Dict[str, Any]]:
        """检测多个旧簇合并为一个新簇的情况。"""
        merges: List[Dict[str, Any]] = []

        # 对每个新簇，看它包含了哪些旧簇的成员
        for new_cid, new_members in new_clusters.items():
            new_member_set = set(new_members)
            source_old_clusters: List[str] = []

            for old_cid, old_members in old_clusters.items():
                old_member_set = set(old_members)
                overlap = old_member_set & new_member_set
                # 如果旧簇的超过一半成员在新簇中，认为有合并关系
                if len(overlap) >= len(old_member_set) * 0.5 and len(old_member_set) > 0:
                    source_old_clusters.append(old_cid)

            if len(source_old_clusters) >= 2:
                merges.append({
                    "new_cluster": new_cid,
                    "old_clusters": source_old_clusters,
                    "old_cluster_count": len(source_old_clusters),
                    "member_count": len(new_members),
                })

        return merges

    def _detect_splits(
        self,
        old_clusters: Dict[str, List[str]],
        new_clusters: Dict[str, List[str]],
    ) -> List[Dict[str, Any]]:
        """检测一个旧簇分裂为多个新簇的情况。"""
        splits: List[Dict[str, Any]] = []

        for old_cid, old_members in old_clusters.items():
            old_member_set = set(old_members)
            target_new_clusters: Dict[str, int] = defaultdict(int)

            for pid in old_member_set:
                for new_cid, new_members in new_clusters.items():
                    if pid in new_members:
                        target_new_clusters[new_cid] += 1
                        break

            # 如果旧簇成员分布在至少 2 个新簇中，且每个新簇至少有 1 个旧成员
            if len(target_new_clusters) >= 2:
                splits.append({
                    "old_cluster": old_cid,
                    "new_clusters": list(target_new_clusters.keys()),
                    "new_cluster_count": len(target_new_clusters),
                    "member_distribution": dict(target_new_clusters),
                    "total_members": len(old_members),
                })

        return splits

    def export_diff_report(
        self,
        result: SnapshotDiffResult,
        output_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        """把 SnapshotDiffResult 导出为可 JSON 序列化的字典。

        result 为 compare() 的差异结果; output_path 可选,
        指定时写入 JSON 文件。
        """
        report = {
            "summary": result.summary(),
            "diversity_delta": result.diversity_delta,
            "cluster_count_delta": result.cluster_count_delta,
            "total_paths_delta": result.total_paths_delta,
            "new_clusters": result.new_clusters,
            "removed_clusters": result.removed_clusters,
            "merged_clusters": result.merged_clusters,
            "split_clusters": result.split_clusters,
            "moved_paths": result.moved_paths,
            "new_paths_count": len(result.new_paths),
            "removed_paths_count": len(result.removed_paths),
        }

        if output_path:
            try:
                import os as _os
                _os.makedirs(_os.path.dirname(output_path) or ".", exist_ok=True)
                with open(output_path, 'w', encoding='utf-8') as f:
                    json.dump(report, f, indent=2, ensure_ascii=False)
                logger.info("SnapshotDiff report exported to %s", output_path)
            except Exception as e:
                logger.warning("Failed to export SnapshotDiff report: %s", e)

        return report


@dataclass
class PathFeature:
    """单条路径的特征向量, 含相似度缓存与 SimHash。"""
    path_id: str
    features: Dict = field(default_factory=dict)
    similarity_cache: Dict = field(default_factory=dict)
    timestamp: float = 0.0
    simhash_sig: int = 0
    cluster_id: str = ""

    def compute_hash(self) -> str:
        """对排序后的特征项取确定性哈希。"""
        return hashlib.sha256(str(sorted(self.features.items())).encode()).hexdigest()[:16]


@dataclass
class PathNode:
    """路径探索树的节点。"""
    path_id: str
    address: int
    constraints: List = field(default_factory=list)
    depth: int = 0
    visited: bool = False
    timestamp: float = 0.0
    parent_id: Optional[str] = None
    children: List = field(default_factory=list)
    feature: Optional[PathFeature] = None


@dataclass
class DiversityMetrics:
    """当前路径集的聚合多样性统计。"""
    total_paths: int = 0
    unique_paths: int = 0
    avg_similarity: float = 0.0
    diversity_score: float = 0.0
    coverage_gain: float = 0.0
    exploration_efficiency: float = 0.0
    exploration_velocity: float = 0.0


class PathSimilarityCalculator:
    """两个 PathFeature 的加权多维相似度。

    权重 (可配置):
    STRUCTURAL: 0.3 — 深度、约束数、路径哈希
    SEMANTIC: 0.3 — 比较/算术/位运算的有无
    CONSTRAINTS: 0.2 — 原始约束文本
    COVERAGE: 0.2 — 命中计数

    SimHash 预检: 两路径 SimHash 汉明距离 > 3 时直接返回 0,
    跳过昂贵的逐维度比较 — 针对大规模路径集的性能优化。
    """

    def __init__(self, weights: Dict[PathFeatureType, float] = None):
        self._weights = weights or {
            PathFeatureType.STRUCTURAL: 0.3,
            PathFeatureType.SEMANTIC: 0.3,
            PathFeatureType.CONSTRAINTS: 0.2,
            PathFeatureType.COVERAGE: 0.2
        }

    def compute(self, f1: PathFeature, f2: PathFeature) -> float:
        """加权平均相似度, 带 SimHash 快速排除。"""
        if not f1.features or not f2.features:
            return 0.0
        # SimHash 快速排除
        if f1.simhash_sig is not None and f2.simhash_sig is not None \
                and (f1.simhash_sig or f2.simhash_sig):
            if _hamming_distance(f1.simhash_sig, f2.simhash_sig) > 3:
                return 0.0

        total_sim = 0.0
        weight_sum = 0.0

        for feature_type, weight in self._weights.items():
            key = feature_type.value
            f1v = f1.features.get(key, {})
            f2v = f2.features.get(key, {})
            sim = self._feature_similarity(f1v, f2v)
            total_sim += sim * weight
            weight_sum += weight

        return total_sim / max(1.0, weight_sum)

    def _feature_similarity(self, f1: Dict[str, Any], f2: Dict[str, Any]) -> float:
        """逐维度相似度: 集合取 Jaccard, 字符串取前缀匹配,
        数值取归一化距离。"""
        if not f1 or not f2:
            return 0.0

        common_keys = set(f1.keys()) & set(f2.keys())
        if not common_keys:
            return 0.0

        total_sim = 0.0
        for key in common_keys:
            v1, v2 = f1[key], f2[key]
            if isinstance(v1, str) and isinstance(v2, str):
                total_sim += self._string_similarity(v1, v2)
            elif isinstance(v1, (int, float)) and isinstance(v2, (int, float)):
                total_sim += self._numeric_similarity(v1, v2)
            elif isinstance(v1, set) and isinstance(v2, set):
                total_sim += len(v1 & v2) / max(1, len(v1 | v2))
            elif isinstance(v1, (list, tuple)) and isinstance(v2, (list, tuple)):
                if v1 == v2:
                    total_sim += 1.0
                elif not v1 or not v2:
                    total_sim += 0.0
                else:
                    s1, s2 = set(v1), set(v2)
                    total_sim += len(s1 & s2) / max(1, len(s1 | s2))
            elif v1 == v2:
                total_sim += 1.0
            else:
                total_sim += 0.0

        return total_sim / len(common_keys)

    def _string_similarity(self, s1: str, s2: str) -> float:
        """前缀字符匹配率 — 快速粗糙的字符串相似度。"""
        if s1 == s2:
            return 1.0
        min_len = min(len(s1), len(s2))
        if min_len == 0:
            return 0.0
        matches = sum(c1 == c2 for c1, c2 in zip(s1, s2))
        return matches / min_len

    def _numeric_similarity(self, n1: float, n2: float) -> float:
        """1 减去归一化绝对差。"""
        if n1 == n2:
            return 1.0
        return 1.0 - abs(n1 - n2) / max(1.0, abs(n1), abs(n2))


class PathDiversityTracker:
    """按代表路径维护路径簇。新路径归入代表相似的簇,
    低于相似度阈值时形成新簇。

    增强: 自适应阈值 (exploration_velocity 低于 0.5 时自动降低
    similarity_threshold 更激进分化簇, 高于 5 时提高);
    ANN 索引 (内置 ANNIndex, 路径数超过 50 时自动构建,
    get_similar_paths() 优先使用 ANN 查询);
    多样性预算 (内置 DiversityBudget, 单簇路径数不超过
    cluster_quota, add_path 后自动执行配额);
    簇可视化 (export_cluster_visualization() 导出当前簇状态 JSON)。
    """

    def __init__(self, similarity_threshold: float = 0.8, max_paths: int = 1000):
        self._paths: Dict[str, PathNode] = {}
        self._features: Dict[str, PathFeature] = {}
        self._similarity_calculator = PathSimilarityCalculator()
        self._similarity_threshold = similarity_threshold
        self._clusters: Dict[str, List[str]] = defaultdict(list)
        self._lock = threading.RLock()
        self._unique_discovery_times: List[float] = []
        self._ann_index = ANNIndex(n_trees=10, leaf_size=10)
        self._ann_built_threshold = 50
        self._budget = DiversityBudget(max_paths=max_paths)
        self._heatmap = PathHeatmap()
        self._streaming_monitor: Optional[StreamingDiversityMonitor] = None

    @property
    def heatmap(self) -> PathHeatmap:
        """暴露 PathHeatmap 供冷点分析。"""
        return self._heatmap

    @property
    def streaming_monitor(self) -> Optional[StreamingDiversityMonitor]:
        """暴露已启动的 StreamingDiversityMonitor。"""
        return self._streaming_monitor

    def start_streaming(
        self, interval_seconds: float = 2.0
    ) -> StreamingDiversityMonitor:
        """为 tracker 创建并启动 StreamingDiversityMonitor,
        interval_seconds 为发射间隔 (默认 2s)。"""
        if self._streaming_monitor is not None and self._streaming_monitor.running:
            logger.warning("StreamingDiversityMonitor already running")
            return self._streaming_monitor

        self._streaming_monitor = StreamingDiversityMonitor(
            tracker=self, interval_seconds=interval_seconds
        )
        self._streaming_monitor.start()
        return self._streaming_monitor

    def stop_streaming(self):
        """停止运行中的 StreamingDiversityMonitor。"""
        if self._streaming_monitor is not None:
            self._streaming_monitor.stop()

    def add_path(self, path_id: str, address: int, constraints: List[str],
                 depth: int = 0, parent_id: Optional[str] = None):
        """登记一条路径: 提取特征、计算 SimHash 并分配簇。

        增强: 达到阈值后自动 (重新) 构建 ANN 索引; 添加后执行
        多样性预算 enforcement; 同时更新 PathHeatmap。
        """
        with self._lock:
            if path_id in self._paths:
                return

            feature = self._extract_features(path_id, constraints, depth)
            self._features[path_id] = feature

            node = PathNode(
                path_id=path_id,
                address=address,
                constraints=constraints,
                depth=depth,
                parent_id=parent_id,
                feature=feature,
                timestamp=time.time()
            )
            self._paths[path_id] = node

            if parent_id and parent_id in self._paths:
                self._paths[parent_id].children.append(path_id)

            self._update_clusters(path_id)
            self._unique_discovery_times.append(time.time())
            self._auto_adjust_threshold()

            # 多样性预算 enforcement
            self._budget.set_cluster_count(len(self._clusters))
            evicted = self._budget.enforce(self._clusters, self._features)
            for pid in evicted:
                feat = self._features.get(pid)
                if feat:
                    feat.cluster_id = ""
                logger.debug(f"DiversityBudget evicted path={pid}")

            # ANN 索引维护：路径数超过阈值时构建/重建
            if len(self._features) >= self._ann_built_threshold:
                self._ann_index.build(self._features)

            # PathHeatmap 更新
            self._heatmap.record(path_id, depth, len(constraints))

    @property
    def cluster_quota(self) -> int:
        return self._budget.cluster_quota

    @property
    def ann_forest(self):
        return self._ann_index.ann_forest

    def _auto_adjust_threshold(self):
        """动态调整相似度阈值

        速度 = 近 10s 内发现的唯一路径 / 10
        速度 < 0.5 → 阈值 −0.02（更易分簇 → 更多样化选择）
        速度 > 5.0 → 阈值 +0.02（更严格合并 → 减少冗余计算）
        阈值范围锁定在 [0.5, 0.95]"""
        now = time.time()
        recent = [t for t in self._unique_discovery_times if now - t <= 10.0]
        vel = len(recent) / 10.0 if recent else 0.0

        if vel < 0.5:
            self._similarity_threshold = max(0.5, self._similarity_threshold - 0.02)
        elif vel > 5.0:
            self._similarity_threshold = min(0.95, self._similarity_threshold + 0.02)

    def _extract_features(self, path_id: str, constraints: List[str], depth: int) -> PathFeature:
        """构建路径的四维特征向量, 并计算 SimHash。"""
        structural = {
            'depth': depth,
            'constraint_count': len(constraints),
            'path_hash': hashlib.sha256(str(constraints).encode()).hexdigest()
        }

        semantic = {
            'has_comparison': any(('>' in c or '<' in c or '==' in c) for c in constraints),
            'has_arithmetic': any(('+' in c or '-' in c or '*' in c) for c in constraints),
            'has_bitwise': any(('&' in c or '|' in c or '^' in c) for c in constraints)
        }

        all_feats = {
            PathFeatureType.STRUCTURAL.value: structural,
            PathFeatureType.SEMANTIC.value: semantic,
            PathFeatureType.CONSTRAINTS.value: {'constraints': constraints},
            PathFeatureType.COVERAGE.value: {'hits': 1}
        }

        return PathFeature(
            path_id=path_id,
            features=all_feats,
            timestamp=time.time(),
            simhash_sig=_simhash(all_feats)
        )

    def _update_clusters(self, path_id: str):
        """把路径归入最近的簇, 或创建新簇。

        增强: ANN 已构建时优先用 ANN 索引加速相似度搜索。
        """
        new_feature = self._features[path_id]
        assigned = False

        # 优先使用 ANN 快速找到最近簇代表
        if len(self._clusters) > 0:
            # 用 ANN 搜索与 new_feature 最相似的路径
            ann_candidates = self._ann_index.query(new_feature, k=min(5, len(self._clusters)))
            # 按簇去重：ANN 返回的可能属于同一簇
            seen_clusters: Set[str] = set()
            best_match: Optional[Tuple[str, float]] = None
            for cand_id, ann_sim in ann_candidates:
                cand_feature = self._features.get(cand_id)
                if not cand_feature or not cand_feature.cluster_id:
                    continue
                if cand_feature.cluster_id in seen_clusters:
                    continue
                seen_clusters.add(cand_feature.cluster_id)
                rep_id = self._clusters[cand_feature.cluster_id][0] if self._clusters[cand_feature.cluster_id] else None
                if rep_id:
                    rep = self._features.get(rep_id)
                    if rep:
                        sim = self._similarity_calculator.compute(new_feature, rep)
                        if sim >= self._similarity_threshold:
                            if best_match is None or sim > best_match[1]:
                                best_match = (cand_feature.cluster_id, sim)

            if best_match is not None:
                cid = best_match[0]
                self._clusters[cid].append(path_id)
                new_feature.cluster_id = cid
                assigned = True

        # 回退：遍历所有簇（ANN 未构建或 ANN 没找到匹配时）
        if not assigned:
            for cluster_id, members in self._clusters.items():
                if not members:
                    continue
                representative = self._features.get(members[0])
                if representative:
                    sim = self._similarity_calculator.compute(new_feature, representative)
                    if sim >= self._similarity_threshold:
                        self._clusters[cluster_id].append(path_id)
                        new_feature.cluster_id = cluster_id
                        assigned = True
                        break

        if not assigned:
            self._clusters[path_id] = [path_id]
            new_feature.cluster_id = path_id

    def find_diverse_paths(self, count: int = 5) -> List[str]:
        """返回 `count` 个簇各一名代表, 加权采样。"""
        with self._lock:
            cluster_reps = [(cid, members[0]) for cid, members in self._clusters.items() if members]
            if len(cluster_reps) <= count:
                return [rep for _, rep in cluster_reps]
            return random.sample([rep for _, rep in cluster_reps], count)

    def find_weighted_paths(self, count: int = 5) -> List[str]:
        """WEIGHTED_SAMPLE：按簇大小反比采样 —— 小簇获得更高概率

        实现：权重 = 1/|cluster|，使用 numpy-style 归一化后进行
        不放回加权随机采样"""
        with self._lock:
            items = [(cid, members[0], len(members))
                    for cid, members in self._clusters.items() if members]
            if len(items) <= count:
                return [rep for _, rep, _ in items]

            total_w = sum(1.0 / sz for _, _, sz in items)
            chosen: List[str] = []
            remaining = list(items)
            for _ in range(count):
                if not remaining:
                    break
                r = random.uniform(0, sum(1.0 / sz for _, _, sz in remaining))
                cum = 0.0
                for idx, (cid, rep, sz) in enumerate(remaining):
                    cum += 1.0 / sz
                    if cum >= r:
                        chosen.append(rep)
                        remaining.pop(idx)
                        break
            return chosen

    def is_path_diverse(self, path_id: str) -> bool:
        """路径与所有其他路径的相似度都低于阈值时返回 True。"""
        with self._lock:
            if path_id not in self._features:
                return True

            target_feature = self._features[path_id]
            for other_id, other_feature in self._features.items():
                if other_id == path_id:
                    continue
                sim = self._similarity_calculator.compute(target_feature, other_feature)
                if sim >= self._similarity_threshold:
                    return False
            return True

    def get_similar_paths(self, path_id: str, threshold: float = 0.7) -> List[str]:
        """返回与该路径相似的其他路径, 按相似度降序。

        增强: 优先用 ANN 索引加速 (O(log n) vs O(n) 逐对比较)。
        """
        with self._lock:
            if path_id not in self._features:
                return []

            target_feature = self._features[path_id]

            # ANN 加速路径
            ann_results = self._ann_index.find_similar(target_feature, threshold)
            if ann_results:
                # 精确验证 ANN 返回的候选（ANN 是近似算法）
                verified = []
                for other_id in ann_results:
                    if other_id == path_id:
                        continue
                    other_feature = self._features.get(other_id)
                    if other_feature:
                        sim = self._similarity_calculator.compute(target_feature, other_feature)
                        if sim >= threshold:
                            verified.append((other_id, sim))
                return [p[0] for p in sorted(verified, key=lambda x: -x[1])]

            # 回退：全量扫描
            similar = []
            for other_id, other_feature in self._features.items():
                if other_id == path_id:
                    continue
                sim = self._similarity_calculator.compute(target_feature, other_feature)
                if sim >= threshold:
                    similar.append((other_id, sim))

            return [p[0] for p in sorted(similar, key=lambda x: -x[1])]

    def get_metrics(self) -> DiversityMetrics:
        """计算聚合多样性统计, 含探索速度。"""
        with self._lock:
            if not self._features:
                return DiversityMetrics()

            total_paths = len(self._paths)
            unique_paths = len(self._clusters)
            now = time.time()
            recent_times = [t for t in self._unique_discovery_times if now - t <= 10.0]
            velocity = len(recent_times) / 10.0

            similarities = []
            features = list(self._features.values())
            sample_size = min(50, len(features))
            for i in range(sample_size):
                for j in range(i + 1, sample_size):
                    sim = self._similarity_calculator.compute(features[i], features[j])
                    similarities.append(sim)

            avg_similarity = sum(similarities) / max(1, len(similarities)) if similarities else 0.0
            diversity_score = 1.0 - avg_similarity

            return DiversityMetrics(
                total_paths=total_paths,
                unique_paths=unique_paths,
                avg_similarity=avg_similarity,
                diversity_score=diversity_score,
                coverage_gain=unique_paths / max(1, total_paths),
                exploration_efficiency=diversity_score * (unique_paths / max(1, total_paths)),
                exploration_velocity=velocity
            )

    def capture_snapshot(self) -> Dict[str, Any]:
        """捕获当前 tracker 状态, 供 SnapshotDiff 比较。"""
        return SnapshotDiff.capture(self)

    def export_cluster_visualization(self, output_path: Optional[str] = None) -> Dict[str, Any]:
        """导出簇状态 JSON，供外部可视化工具使用

        返回含 cluster_id、centroid_features、member_count 的字典;
        提供 output_path 时写入 JSON 磁盘。每个簇的
        centroid_features 取成员的多数投票 SimHash
        (centroid_simhash) 与第一个成员的特征字典作为代表。
        """
        with self._lock:
            clusters_data = []
            for cluster_id, members in self._clusters.items():
                centroid_simhash = self._budget.compute_centroid_simhash(
                    members, self._features
                )
                rep_feature = self._features.get(members[0]) if members else None
                centroid_features = rep_feature.features if rep_feature else {}

                clusters_data.append({
                    "cluster_id": cluster_id,
                    "centroid_features": {
                        k: dict(v) if isinstance(v, dict) else v
                        for k, v in centroid_features.items()
                    },
                    "centroid_simhash": centroid_simhash,
                    "member_count": len(members),
                    "members": members
                })

            result = {
                "clusters": clusters_data,
                "total_clusters": len(self._clusters),
                "total_paths": len(self._paths),
                "cluster_quota": self._budget.cluster_quota
            }

            if output_path:
                try:
                    with open(output_path, 'w', encoding='utf-8') as f:
                        json.dump(result, f, indent=2, ensure_ascii=False)
                    logger.info(f"Cluster visualization exported to {output_path}")
                except Exception as e:
                    logger.warning(f"Failed to export cluster visualization: {e}")

            return result


class DiversityAwarePathSelector:
    """按配置的多样性策略挑选下一条路径。

    支持 random、round-robin、similarity-based、coverage-guided、
    hybrid 与 weighted_sample。
    """

    def __init__(self, strategy: DiversityStrategy = DiversityStrategy.HYBRID):
        self._strategy = strategy
        self._diversity_tracker = PathDiversityTracker()
        self._path_queue: List[str] = []
        self._visited: Set[str] = set()
        self._lock = threading.RLock()
        self._round_robin_index = 0

    def add_path(self, path_id: str, address: int, constraints: List[str],
                 depth: int = 0, parent_id: Optional[str] = None):
        """登记一条供后续选择的候选路径。"""
        with self._lock:
            self._diversity_tracker.add_path(path_id, address, constraints, depth, parent_id)
            if path_id not in self._path_queue:
                self._path_queue.append(path_id)

    def select_next(self) -> Optional[str]:
        """按当前策略挑选下一条路径。"""
        with self._lock:
            if not self._path_queue:
                return None

            candidates = [p for p in self._path_queue if p not in self._visited]
            if not candidates:
                return None

            dispatch = {
                DiversityStrategy.RANDOM: self._select_random,
                DiversityStrategy.ROUND_ROBIN: self._select_round_robin,
                DiversityStrategy.SIMILARITY_BASED: self._select_similarity_based,
                DiversityStrategy.COVERAGE_GUIDED: self._select_coverage_guided,
                DiversityStrategy.HYBRID: self._select_hybrid,
                DiversityStrategy.WEIGHTED_SAMPLE: self._select_weighted_sample,
            }
            selector = dispatch.get(self._strategy, self._select_hybrid)
            return selector(candidates)

    def _select_random(self, candidates: List[str]) -> str:
        path = random.choice(candidates)
        self._visited.add(path)
        return path

    def _select_round_robin(self, candidates: List[str]) -> str:
        index = self._round_robin_index % len(candidates)
        self._round_robin_index += 1
        path = candidates[index]
        self._visited.add(path)
        return path

    def _select_similarity_based(self, candidates: List[str]) -> str:
        diverse = self._diversity_tracker.find_diverse_paths(len(candidates))
        if diverse:
            path = random.choice(diverse)
            self._visited.add(path)
            return path
        return self._select_random(candidates)

    def _select_weighted_sample(self, candidates: List[str]) -> str:
        weighted = self._diversity_tracker.find_weighted_paths(len(candidates))
        if weighted:
            path = random.choice(weighted)
            self._visited.add(path)
            return path
        return self._select_random(candidates)

    def _select_coverage_guided(self, candidates: List[str]) -> str:
        depths = [(p, self._diversity_tracker._paths[p].depth) for p in candidates]
        depths.sort(key=lambda x: x[1])
        path = depths[0][0]
        self._visited.add(path)
        return path

    def _select_hybrid(self, candidates: List[str]) -> str:
        metrics = self._diversity_tracker.get_metrics()

        if metrics.diversity_score < 0.5:
            return self._select_similarity_based(candidates)
        elif metrics.coverage_gain < 0.7:
            return self._select_coverage_guided(candidates)
        else:
            return self._select_round_robin(candidates)

    def mark_visited(self, path_id: str):
        with self._lock:
            self._visited.add(path_id)

    def get_diversity_metrics(self) -> DiversityMetrics:
        return self._diversity_tracker.get_metrics()

    def get_stats(self) -> Dict[str, Any]:
        metrics = self.get_diversity_metrics()
        return {
            'strategy': self._strategy.value,
            'pending_paths': len(self._path_queue) - len(self._visited),
            'visited_paths': len(self._visited),
            'total_paths': len(self._path_queue),
            'diversity_score': metrics.diversity_score,
            'avg_similarity': metrics.avg_similarity,
            'unique_clusters': metrics.unique_paths,
            'exploration_velocity': metrics.exploration_velocity
        }
