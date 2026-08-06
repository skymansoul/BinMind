# -*- coding: utf-8 -*-
# 创建: 2026-07-29  |  去重引擎
# 修改: 2026-08-04  |  审计后补充文件头与错误处理
#
"""
崩溃状态语义分析——去重与聚类引擎。

基于寄存器状态嵌入的语义相似度, 将根因相同的崩溃聚类,
产出去重后的唯一崩溃列表+每簇的根因分类+利用性评估。

聚类算法: 贪心凝聚聚类——无需预设簇数K, 自适应相似度阈值。
  1. 初始每崩溃独立成簇
  2. 迭代合并余弦相似度>阈值的最近邻簇对
  3. 更新质心为簇成员的向量均值
  4. 收敛至无簇对可合并

复杂度: O(N²)最坏(N=崩溃数), N≤1000时秒级完成。
阈值: 0.85(同根因)/0.65(可能同根因)——基于实证调参。

与fuzzing_orchestrator.CrashTriager的集成:
  CrashTriager: 入门级去重(栈哈希→是否同一崩溃路径)
  CssaDedupEngine: 专家级去重(状态嵌入→是否同一根因类型)
  互补: Triager做快速初筛, Cssa引擎做精确根因归类
"""

import math
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set

from .cssa_corruption_classifier import (
    CrashState, CorruptionType, CorruptionClassification, CorruptionClassifier,
)
from .cssa_state_embedder import (
    CrashEmbedding, DedupCluster, CrashStateEmbedder,
)

_log = logging.getLogger(__name__)


@dataclass
class DedupResult:
    """语义去重完整输出"""
    clusters: List[DedupCluster] = field(default_factory=list)
    total_crashes: int = 0
    unique_root_causes: int = 0     # 簇数
    # 去重效率
    dedup_ratio: float = 0.0        # 唯一/总数
    # 分类统计
    corruption_type_counts: Dict[str, int] = field(default_factory=dict)
    # 利用性优先级排序
    exploitable_clusters: List[str] = field(default_factory=list)


# ============================================================================
# 去重引擎
# ============================================================================


class CssaDedupEngine:
    """崩溃语义去重引擎——嵌入+聚类+根因归类全链路。

    使用示例:
        engine = CssaDedupEngine()
        result = engine.deduplicate(crashes=[CrashState(...), ...])
        print(f"去重: {result.total_crashes}→{result.unique_root_causes}个根因")
    """

    def __init__(self,
                 similarity_threshold: float = 0.85,
                 tentative_threshold: float = 0.65):
        self._threshold = similarity_threshold
        self._tentative = tentative_threshold
        self._embedder = CrashStateEmbedder()
        self._classifier = CorruptionClassifier()

    def deduplicate(self, crashes: List[CrashState]
                     ) -> DedupResult:
        """对崩溃列表执行语义去重——嵌入→相似度→聚类→分类。

        返回DedupResult含去重簇、根因统计、利用性优先级。
        """
        if not crashes:
            return DedupResult()

        # 嵌入
        embeddings = []
        for i, crash in enumerate(crashes):
            emb = self._embedder.embed(crash, f"crash_{i}_{crash.crash_pc:x}")
            embeddings.append(emb)

        # 聚类
        clusters = self._agglomerative_cluster(embeddings)

        # 对每簇做统一的根因分类——取成员中置信度最高的分类
        dedup_clusters = []
        for cluster in clusters:
            # 取代表崩溃(最接近质心)
            rep = self._find_representative(cluster, embeddings)
            # 对代表崩溃做分类
            rep_crash = crashes[int(rep.crash_id.split('_')[1])]
            classification = self._classifier.classify(rep_crash)

            cluster.crash_id = f"RC_{len(dedup_clusters):04d}"
            cluster.member_count = len(cluster.members)
            cluster.avg_corruption_confidence = classification.confidence
            cluster.dominant_corruption_type = classification.primary_type
            cluster.representative_crash = rep.crash_id
            dedup_clusters.append(cluster)

        # 统计
        type_counts = {}
        for dc in dedup_clusters:
            ct = dc.dominant_corruption_type
            type_counts[ct] = type_counts.get(ct, 0) + 1

        # 利用性排序——高利用性根因优先
        high_exploit_types = {CorruptionType.STACK_OVERFLOW,
                              CorruptionType.USE_AFTER_FREE,
                              CorruptionType.HEAP_OVERFLOW}
        exploitable = [
            dc.cluster_id for dc in dedup_clusters
            if dc.dominant_corruption_type in high_exploit_types]

        return DedupResult(
            clusters=dedup_clusters,
            total_crashes=len(crashes),
            unique_root_causes=len(dedup_clusters),
            dedup_ratio=round(len(dedup_clusters) / max(len(crashes), 1), 3),
            corruption_type_counts=type_counts,
            exploitable_clusters=exploitable,
        )

    def _agglomerative_cluster(self, embeddings: List[CrashEmbedding]
                                ) -> List[DedupCluster]:
        """贪心凝聚聚类——迭代合并最相似簇对。

        终止条件: 无簇对的相似度超过阈值。
        """
        n = len(embeddings)
        # 初始化——每嵌入独立成簇
        clusters = [DedupCluster(
            cluster_id=f"tmp_{i}",
            centroid=list(emb.vector),
            members=[emb.crash_id]) for i, emb in enumerate(embeddings)]

        while True:
            best_sim = 0.0
            best_pair = (-1, -1)
            for i in range(len(clusters)):
                for j in range(i + 1, len(clusters)):
                    sim = self._cosine_sim(clusters[i].centroid,
                                            clusters[j].centroid)
                    if sim > best_sim:
                        best_sim = sim
                        best_pair = (i, j)

            if best_sim < self._threshold or best_pair == (-1, -1):
                break

            # 合并簇i和簇j
            i, j = best_pair
            merged_members = clusters[i].members + clusters[j].members
            # 更新质心为成员嵌入的均值
            member_vecs = []
            for emb in embeddings:
                if emb.crash_id in merged_members:
                    member_vecs.append(emb.vector)
            new_centroid = [sum(v[d] for v in member_vecs) / len(member_vecs)
                            for d in range(len(member_vecs[0]))]
            clusters[i].centroid = new_centroid
            clusters[i].members = merged_members
            clusters.pop(j)

        return clusters

    def _find_representative(self, cluster: DedupCluster,
                               embeddings: List[CrashEmbedding]
                               ) -> CrashEmbedding:
        """找到簇中最接近质心的成员——作为代表崩溃"""
        best_sim = -1.0
        best_emb = None
        for emb in embeddings:
            if emb.crash_id in cluster.members:
                sim = self._cosine_sim(cluster.centroid, emb.vector)
                if sim > best_sim:
                    best_sim = sim
                    best_emb = emb
        return best_emb or embeddings[0]

    @staticmethod
    def _cosine_sim(a: List[float], b: List[float]) -> float:
        if len(a) != len(b) or not a:
            return 0.0
        dot = sum(x * y for x, y in zip(a, b))
        na = math.sqrt(sum(x * x for x in a))
        nb = math.sqrt(sum(y * y for y in b))
        if na < 1e-10 or nb < 1e-10:
            return 0.0
        return dot / (na * nb)


# ============================================================================
# 便捷入口
# ============================================================================


def deduplicate_crashes(crashes: List[CrashState],
                         threshold: float = 0.85) -> DedupResult:
    """崩溃语义去重便捷入口"""
    return CssaDedupEngine(similarity_threshold=threshold).deduplicate(crashes)


def classify_crash(crash: CrashState) -> CorruptionClassification:
    """单崩溃分类便捷入口"""
    return CorruptionClassifier().classify(crash)


__all__ = [
    "DedupResult",
    "CssaDedupEngine",
    "deduplicate_crashes",
    "classify_crash",
]
