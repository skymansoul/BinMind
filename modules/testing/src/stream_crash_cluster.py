# 流式语义崩溃聚类器 — 在线增量聚类 + CFG邻域相似度 + 密度聚类
#
# 核心问题:
#   crash_dedup.py 用栈哈希去重——快速但脆弱: 同一bug因调用路径微小差异
#   (内联/中断/抢占) 产生不同哈希, 导致同一bug被计为多个独立崩溃。
#   crash_cluster.py 做离线聚类——需要等fuzzing结束, 无法实时反馈。
#
#   ECHO 用LCS做在线栈相似度 + 集成到fuzzing循环,
#   但仅适用于有完整栈回溯的内核fuzzing。Igor 用CFG相似度聚类,
#   但为离线分析。GPTrace 用LLM嵌入——延迟高、成本高。
#
# 本模块的方法 — 在线CFG邻域流式聚类:
#   1. 对每个新崩溃, 最小化其输入并采集执行trace
#   2. 从trace构建CFG邻域 (复用 cfg_neighborhood.py)
#   3. 计算与现有簇代表点的邻域签名余弦相似度
#   4. 若相似度 > 阈值 → 归入现有簇; 否则 → 创建新簇
#   5. 实时反馈: 新簇 → 提升该种子的fuzzing能量
#
# 技术优势:
# 在线: 崩溃到达即聚类, 无需等fuzzing结束
# 语义: CFG邻域比栈哈希更鲁棒 (对调用路径扰动不敏感)
# 轻量: 12维签名比对 O(d·k), d=12, k=簇数
#
# 文献:
#   ECHO — LCS栈聚类+在线fuzzing集成;
#     本项目取其在线思想但以CFG邻域替代LCS栈比较
#   Igor — CFG相似度崩溃聚类;
#     本项目取其CFG相似度但适配到流式在线场景
#   GPTrace — LLM嵌入聚类;
#     本项目取其语义聚类目标但以轻量签名替代LLM嵌入

from __future__ import annotations

import math
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

# 桥接 cfg_neighborhood.py: CrashSignature.signature 应为
# NeighborhoodSignatureBuilder.compute() 的12维输出。
# 当前通过 Duck typing 接受任何 List[float] 签名,
# 调用方负责从 cfg_neighborhood 计算签名后传入。


@dataclass
class CrashSignature:
    """崩溃的CFG邻域签名——用于语义比较"""
    crash_id: str
    # 12维签名 (来自 cfg_neighborhood.NeighborhoodSignatureBuilder)
    signature: List[float] = field(default_factory=lambda: [0.0] * 12)
    # 元数据
    crash_pc: int = 0
    crash_type: str = ""
    stack_hash: str = ""
    input_hash: str = ""
    esa_score: float = 0.0
    timestamp: float = 0.0


@dataclass
class CrashCluster:
    """一个崩溃簇——代表同一根因的崩溃集合"""
    cluster_id: int
    # 簇代表点 (中心最近的成员)
    representative: CrashSignature
    # 簇成员
    members: List[CrashSignature] = field(default_factory=list)
    # 簇统计
    size: int = 0
    created_at: float = 0.0
    last_seen_at: float = 0.0
    # 簇标签: 可用于反馈
    is_novel: bool = True          # 是否为新发现的崩溃类型
    priority_score: float = 0.0    # 该簇的优先级 (高→种子应获得更多能量)


@dataclass
class StreamingClusterReport:
    """流式聚类的实时报告"""
    total_crashes: int
    total_clusters: int
    novel_clusters: int             # 本轮新创建的簇
    assigned_to_existing: int       # 归入已有簇的崩溃
    avg_cluster_size: float
    latest_cluster_id: int = -1
    summary: str = ""


class StreamCrashClusterer:
    """流式语义崩溃聚类器。

    典型用法:
        clusterer = StreamCrashClusterer(similarity_threshold=0.85)

        # 每个新崩溃到达时:
        sig = CrashSignature(
            crash_id=hash, signature=neighborhood_sig,
            crash_pc=0x401000, crash_type='SEGV')
        report = clusterer.ingest(sig)

        # 反馈: 若创建了新簇, 提升对应种子能量
        if report.novel_clusters > 0:
            boost_seed_energy(input_hash)
    """

    def __init__(self,
                 similarity_threshold: float = 0.85,
                 max_clusters: int = 256,
                 min_cluster_size_for_feedback: int = 3):
        """
        similarity_threshold: 余弦相似度高于此值→归入同一簇
        max_clusters: 最大簇数, 超出后合并最相似的两个簇
        min_cluster_size_for_feedback: 簇达到此大小后标记为"已确认" (非novel)
        """
        self._threshold = similarity_threshold
        self._max_clusters = max_clusters
        self._min_feedback_size = min_cluster_size_for_feedback

        self._clusters: List[CrashCluster] = []
        self._next_cluster_id = 0
        self._total_crashes = 0
        # 统计
        self._novel_count = 0
        self._assigned_count = 0

    def ingest(self, sig: CrashSignature) -> StreamingClusterReport:
        """摄入一个新崩溃——在线分配或创建簇"""
        self._total_crashes += 1
        sig.timestamp = time.monotonic()
        novel = 0
        assigned = 0

        if not self._clusters:
            # 第一个崩溃 → 创建第一个簇
            cluster = CrashCluster(
                cluster_id=self._next_cluster_id,
                representative=sig,
                members=[sig], size=1,
                created_at=sig.timestamp,
                last_seen_at=sig.timestamp,
                is_novel=True,
                priority_score=1.0,
            )
            self._clusters.append(cluster)
            self._next_cluster_id += 1
            novel = 1
        else:
            # 找最近簇
            best_cluster, best_sim = self._find_nearest_cluster(sig)
            if best_sim >= self._threshold and best_cluster is not None:
                best_cluster.members.append(sig)
                best_cluster.size += 1
                best_cluster.last_seen_at = sig.timestamp
                assigned = 1
                # 达到最小反馈大小 → 不再标记为novel
                if best_cluster.size >= self._min_feedback_size:
                    best_cluster.is_novel = False
                # 若新成员比代表点更接近簇中心, 更新代表点
                if best_sim > 0.98:
                    best_cluster.representative = sig
            else:
                # 创建新簇
                if len(self._clusters) >= self._max_clusters:
                    self._merge_closest_pair()
                cluster = CrashCluster(
                    cluster_id=self._next_cluster_id,
                    representative=sig,
                    members=[sig], size=1,
                    created_at=sig.timestamp,
                    last_seen_at=sig.timestamp,
                    is_novel=True,
                    priority_score=1.0,
                )
                self._clusters.append(cluster)
                self._next_cluster_id += 1
                novel = 1

        self._novel_count += novel
        self._assigned_count += assigned

        # 更新优先级: 最近活跃的大簇 → 高优先级
        self._update_priorities()

        return StreamingClusterReport(
            total_crashes=self._total_crashes,
            total_clusters=len(self._clusters),
            novel_clusters=novel,
            assigned_to_existing=assigned,
            avg_cluster_size=(self._total_crashes
                               / max(1, len(self._clusters))),
            latest_cluster_id=(self._next_cluster_id - 1
                                if novel else best_cluster.cluster_id
                                if self._clusters else -1),
            summary=self._build_summary(),
        )

    def _find_nearest_cluster(self,
                               sig: CrashSignature
                               ) -> Tuple[Optional[CrashCluster], float]:
        """找与签名最相似的已有簇——返回(簇, 相似度)"""
        best_cluster = None
        best_sim = -1.0

        for cluster in self._clusters:
            sim = self._cosine_similarity(
                sig.signature, cluster.representative.signature)
            if sim > best_sim:
                best_sim = sim
                best_cluster = cluster

        return best_cluster, best_sim

    def _merge_closest_pair(self) -> None:
        """合并最相似的两个簇——控制总簇数"""
        if len(self._clusters) < 2:
            return

        best_i, best_j, best_sim = -1, -1, -1.0
        for i in range(len(self._clusters)):
            for j in range(i + 1, len(self._clusters)):
                sim = self._cosine_similarity(
                    self._clusters[i].representative.signature,
                    self._clusters[j].representative.signature)
                if sim > best_sim:
                    best_sim = sim
                    best_i, best_j = i, j

        if best_i >= 0 and best_j >= 0:
            # 将j合并到i
            self._clusters[best_i].members.extend(
                self._clusters[best_j].members)
            self._clusters[best_i].size += self._clusters[best_j].size
            self._clusters[best_i].last_seen_at = max(
                self._clusters[best_i].last_seen_at,
                self._clusters[best_j].last_seen_at)
            self._clusters.pop(best_j)

    def _update_priorities(self) -> None:
        """更新各簇的优先级——最近活跃的大型新簇优先级最高"""
        now = time.monotonic()
        for c in self._clusters:
            age_h = (now - c.last_seen_at) / 3600.0
            recency = math.exp(-age_h)  # 越近越高
            size_boost = math.log1p(c.size) * 0.5
            novelty_boost = 1.5 if c.is_novel else 0.5
            c.priority_score = recency * (1.0 + size_boost) * novelty_boost

    @staticmethod
    def _cosine_similarity(a: List[float], b: List[float]) -> float:
        dot = sum(x * y for x, y in zip(a, b))
        na = math.sqrt(sum(x * x for x in a))
        nb = math.sqrt(sum(y * y for y in b))
        if na < 1e-12 or nb < 1e-12:
            return 0.0
        return max(-1.0, min(1.0, dot / (na * nb)))

    # 查询

    def top_priority_clusters(self, k: int = 5) -> List[CrashCluster]:
        return sorted(self._clusters, key=lambda c: -c.priority_score)[:k]

    def cluster_for_crash(self, crash_id: str) -> Optional[CrashCluster]:
        for c in self._clusters:
            if any(m.crash_id == crash_id for m in c.members):
                return c
        return None

    def stats(self) -> Dict[str, Any]:
        return {
            "total_crashes": self._total_crashes,
            "total_clusters": len(self._clusters),
            "novel_count": self._novel_count,
            "assigned_count": self._assigned_count,
            "avg_size": round(
                self._total_crashes / max(1, len(self._clusters)), 1),
            "clusters": [
                {"id": c.cluster_id, "size": c.size,
                 "novel": c.is_novel, "priority": round(c.priority_score, 3)}
                for c in self.top_priority_clusters(5)
            ],
        }

    def _build_summary(self) -> str:
        n = len(self._clusters)
        avg = self._total_crashes / max(1, n)
        return (f"流式聚类: {self._total_crashes}崩溃→{n}簇, "
                f"平均{avg:.1f}/簇, "
                f"新簇{self._novel_count}, 归入{self._assigned_count}")

    def reset(self) -> None:
        self._clusters.clear()
        self._next_cluster_id = 0
        self._total_crashes = 0
        self._novel_count = 0
        self._assigned_count = 0
