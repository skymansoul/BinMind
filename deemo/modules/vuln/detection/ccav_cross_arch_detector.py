# coding: utf-8
# 创建: 2026-08-06  |  跨架构检测引擎
# 修改: 2026-08-06  |  审计后补充文件头与错误处理
#
"""
对比跨架构漏洞嵌入——跨架构漏洞迁移检测器。

技术问题:
  已知x86_64平台的漏洞特征，
  如何检测同一漏洞在ARM64/MIPS32等其他架构编译产物中的存在？

  传统方法: 重新对每个架构产物执行完整静态分析管线——成本O(K×N)
  本方法: 一次嵌入+跨架构投影，在共享空间做最近邻检索——成本O(N+K)

解决方案:
  1. 训练阶段: 对比学习产出架构无关漏洞嵌入空间（ccav_contrastive_trainer）
  2. 注册阶段: 将已知漏洞的跨架构嵌入注册至索引（含x86/ARM/MIPS变体）
  3. 检测阶段: 对待检测架构的二进制提取嵌入→投影→检索→相似度判定

  核心指标:
    - Top-1召回: 同漏洞跨架构变体是否在检索结果首位
    - 架构不变性: 投影后同函数跨架构嵌入距离 < 不同函数的同架构嵌入距离

与现有模块集成:
  GraphBinaryEmbedder → 提取FunctionGraph嵌入
  CrossArchAligner → 初步跨架构对齐
  CCAV检测器 → 精细对比学习后的跨架构漏洞迁移
"""

import math
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set
from collections import defaultdict

from .ccav_contrastive_trainer import ArchitectureProjector

_log = logging.getLogger(__name__)


# 检测结果


@dataclass
class CrossArchMatch:
    """跨架构漏洞匹配——已知漏洞与新架构产物的相似度"""
    query_func_name: str
    query_arch: str
    matched_vuln_id: str
    matched_arch: str
    similarity: float            # 余弦相似度 [0, 1]
    embedding_distance: float    # 投影后欧几里得距离
    is_same_vuln: bool           # 是否为同一漏洞（基于阈值判定）
    confidence: str = "LOW"      # HIGH | MEDIUM | LOW
    cwe_type: str = ""


@dataclass
class CrossArchDetectionResult:
    """跨架构漏洞检测完整输出"""
    query_function: str
    query_arch: str
    matches: List[CrossArchMatch] = field(default_factory=list)
    # 检测统计
    total_vuln_signatures: int = 0
    top1_similarity: float = 0.0
    # 架构投影信息
    projection_applied: bool = False
    projection_arch: str = ""
    # 判定
    vulnerability_likely_present: bool = False
    recommended_action: str = ""


# 跨架构检测引擎


class CrossArchVulnDetector:
    """跨架构漏洞检测器——一次嵌入，多架构复用。

    工作流程:
      1. 注册阶段: add_signature() 将已知漏洞的嵌入（含多架构变体）注册至索引
      2. 检测阶段: detect() 在投影空间中检索最近邻
      3. 判定: 基于自适应阈值（考虑架构差异与CWE类型）

    自适应阈值设计:
      不设全局固定阈值——不同CWE在不同架构对上的嵌入距离分布不同。
      对每个(CWE, arch_pair)维护距离分位数，检测时使用对应阈值。
      阈值 = P95(同源跨架构距离) —— 若query距离在此之内，判定为同源。
    """

    def __init__(self, similarity_threshold: float = 0.75,
                  projector: ArchitectureProjector = None):
        self._threshold = similarity_threshold
        self._projector = projector
        # 漏洞签名索引: vuln_id → {arch: embedding}
        self._signatures: Dict[str, Dict[str, List[float]]] = {}
        # CWE元数据
        self._cwe_labels: Dict[str, str] = {}
        # 自适应阈值: (cwe, arch_a, arch_b) → distance_threshold
        self._adaptive_thresholds: Dict[Tuple[str, str, str], float] = {}

    def add_signature(self, vuln_id: str, arch: str,
                       embedding: List[float],
                       cwe_type: str = ""):
        """注册漏洞签名——将已知漏洞的嵌入（特定架构）加入索引。

        同一vuln_id可多次调用以注册多架构变体。
        投影器已拟合时，自动投影至共享空间。
        """
        if vuln_id not in self._signatures:
            self._signatures[vuln_id] = {}
        if self._projector and self._projector._fitted:
            embedding = self._projector.project(embedding, arch)
        self._signatures[vuln_id][arch] = embedding
        if cwe_type:
            self._cwe_labels[vuln_id] = cwe_type

    def calibrate_thresholds(self,
                              cross_arch_pairs: List[Tuple[str, str, str,
                                                             List[float], List[float]]]):
        """标定自适应阈值——使用同源跨架构嵌入对。

        参数:
          cross_arch_pairs: [(vuln_id, arch_a, arch_b, emb_a, emb_b), ...]

        对每(CWE, arch_a, arch_b)组合，计算同源嵌入距离的P95作为阈值。
        """
        dists_by_key: Dict[Tuple[str, str, str], List[float]] = defaultdict(list)
        for vuln_id, arch_a, arch_b, emb_a, emb_b in cross_arch_pairs:
            cwe = self._cwe_labels.get(vuln_id, 'UNKNOWN')
            key = (cwe, arch_a, arch_b)
            dists_by_key[key].append(_euclidean(emb_a, emb_b))

        for key, dists in dists_by_key.items():
            if len(dists) < 5:
                continue
            dists_sorted = sorted(dists)
            p95_idx = int(len(dists_sorted) * 0.95)
            self._adaptive_thresholds[key] = dists_sorted[min(p95_idx, len(dists) - 1)]

        _log.info("自适应阈值标定: %d个(CWE, arch_pair)组合", len(self._adaptive_thresholds))

    def detect(self, query_embedding: List[float],
                query_arch: str,
                query_func: str = "",
                top_k: int = 10) -> CrossArchDetectionResult:
        """在签名索引中检索最相似的已知漏洞。

        参数:
          query_embedding: 待检测函数的嵌入向量
          query_arch: 待检测二进制架构
          query_func: 函数名（可选——调试用）
          top_k: 返回的Top-K匹配数

        返回CrossArchDetectionResult。
        """
        result = CrossArchDetectionResult(
            query_function=query_func, query_arch=query_arch)

        if not self._signatures:
            result.recommended_action = "签名库为空——请先注册已知漏洞"
            return result

        # 投影至共享空间
        query_proj = query_embedding
        if self._projector and self._projector._fitted:
            query_proj = self._projector.project(query_embedding, query_arch)
            result.projection_applied = True
            result.projection_arch = query_arch

        matches = []
        for vuln_id, arch_embs in self._signatures.items():
            for sig_arch, sig_emb in arch_embs.items():
                dist = _euclidean(query_proj, sig_emb)
                sim = 1.0 / (1.0 + dist)  # 距离→相似度映射

                cwe = self._cwe_labels.get(vuln_id, '')
                # 自适应阈值
                adap_key = (cwe, query_arch, sig_arch)
                threshold = self._adaptive_thresholds.get(adap_key, self._threshold)
                is_same = sim >= threshold

                if sim >= 0.5:  # 仅返回有意义的匹配
                    matches.append(CrossArchMatch(
                        query_func_name=query_func,
                        query_arch=query_arch,
                        matched_vuln_id=vuln_id,
                        matched_arch=sig_arch,
                        similarity=round(sim, 4),
                        embedding_distance=round(dist, 4),
                        is_same_vuln=is_same,
                        confidence=self._assign_confidence(sim, threshold),
                        cwe_type=cwe))

        matches.sort(key=lambda m: m.similarity, reverse=True)
        result.matches = matches[:top_k]
        result.total_vuln_signatures = len(self._signatures)
        result.top1_similarity = matches[0].similarity if matches else 0.0

        # 判定
        if matches and matches[0].is_same_vuln:
            result.vulnerability_likely_present = True
            top = matches[0]
            result.recommended_action = (
                f"检测到已知漏洞{top.matched_vuln_id}的跨架构变体"
                f"({top.matched_arch}→{query_arch}, "
                f"相似度{top.similarity:.2f})。建议执行针对性验证。")
        elif matches and matches[0].similarity >= 0.6:
            result.recommended_action = (
                f"存在中等相似度匹配——建议人工审查后决定。"
                f"最相似: {matches[0].matched_vuln_id} ({matches[0].similarity:.2f})")
        else:
            result.recommended_action = "未检测到已知漏洞的跨架构变体。"

        return result

    def get_signature_count(self) -> Dict[str, int]:
        """签名库统计——漏洞数×架构覆盖数"""
        total_archs = sum(len(embs) for embs in self._signatures.values())
        return {'vulnerabilities': len(self._signatures),
                'total_embeddings': total_archs}

    @staticmethod
    def _assign_confidence(similarity: float, threshold: float) -> str:
        gap = similarity - threshold
        if gap >= 0.15:
            return "HIGH"
        elif gap >= 0.0:
            return "MEDIUM"
        return "LOW"


# 便捷函数


def _euclidean(a: List[float], b: List[float]) -> float:
    return math.sqrt(sum((x - y) ** 2 for x, y in zip(a, b)))


def detect_cross_arch_vuln(query_embedding: List[float],
                             query_arch: str,
                             signatures: Dict[str, Dict[str, List[float]]],
                             projector: ArchitectureProjector = None,
                             cwe_labels: Dict[str, str] = None,
                             threshold: float = 0.75
                             ) -> CrossArchDetectionResult:
    """跨架构漏洞检测便捷入口——单行调用。

    返回CrossArchDetectionResult。
    """
    detector = CrossArchVulnDetector(
        similarity_threshold=threshold, projector=projector)
    for vuln_id, arch_embs in signatures.items():
        for arch, emb in arch_embs.items():
            detector.add_signature(
                vuln_id, arch, emb,
                cwe_labels.get(vuln_id, '') if cwe_labels else '')
    return detector.detect(query_embedding, query_arch)


__all__ = [
    "CrossArchMatch",
    "CrossArchDetectionResult",
    "CrossArchVulnDetector",
    "detect_cross_arch_vuln",
]
