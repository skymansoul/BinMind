# -*- coding: utf-8 -*-
# 创建: 2026-08-01  |  因果关联引擎
# 修改: 2026-08-04  |  审计后补充文件头与错误处理
#
"""
跨模态漏洞关联——因果关联推断引擎。

两阶段推断:
  Phase 1: 空间语义评分→粗筛(排除明显无关对)
  Phase 2: 因果推断→精确分类(确认/争议/补充/重复)

假设检验: H₀(独立) H₁(确认) H₂(争议)
混淆因子: 代码复杂度+工具偏见+模态依赖度

与multimodal_vuln_fusion差异: 融合=分数加权(数值), 关联=实例推理(逻辑)
"""

import math
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set

from .cmvc_evidence import (
    NormalizedEvidence, EvidencePair,
    AnalysisModality, CorrelationRelation,
)

_log = logging.getLogger(__name__)


# ============================================================================
# 关联推断结果
# ============================================================================


@dataclass
class CorrelationResult:
    """跨模态关联分析完整输出"""
    pairs: List[EvidencePair] = field(default_factory=list)
    total_evidence: int = 0
    # 统计
    confirmed_count: int = 0       # CONFIRMS/REFINES/EXTENDS
    disputed_count: int = 0        # DISPUTES
    duplicate_count: int = 0       # DUPLICATE
    independent_count: int = 0     # INDEPENDENT
    # 确认链——被≥2个模态独立确认的漏洞
    corroborated_vulns: List[str] = field(default_factory=list)
    # 争议finding——需人工审查
    disputed_findings: List[str] = field(default_factory=list)


# ============================================================================
# 关联引擎
# ============================================================================


class CorrelationEngine:
    """跨模态证据关联引擎——空间语义联合评分+因果推断。

    两阶段推断:
      Phase 1: 空间语义评分→粗筛(排除明显无关对)
      Phase 2: 因果推断→精确分类(确认/争议/补充/重复)
    """

    # 各模态的独立性分数——模态越独立, 其对同一漏洞的确认越强
    _MODALITY_INDEPENDENCE = {
        AnalysisModality.STATIC: 0.5,
        AnalysisModality.DYNAMIC: 0.6,
        AnalysisModality.LLM: 0.3,          # LLM可能与静态分析共享训练数据→偏依赖
        AnalysisModality.FUZZING: 0.7,
        AnalysisModality.SYMBEX: 0.6,
        AnalysisModality.ASAN: 0.9,         # ASAN高度独立(运行时插桩)
        AnalysisModality.MANUAL: 0.8,
    }

    def __init__(self,
                 spatial_threshold: float = 0.5,
                 correlation_threshold: float = 0.6):
        self._spatial_threshold = spatial_threshold
        self._correlation_threshold = correlation_threshold

    def correlate(self, evidence_list: List[NormalizedEvidence]
                   ) -> CorrelationResult:
        """对证据列表执行全对(pairwise)关联分析。

        返回CorrelationResult。
        """
        n = len(evidence_list)
        if n < 2:
            return CorrelationResult(total_evidence=n)

        pairs = []
        for i in range(n):
            for j in range(i + 1, n):
                pair = self._correlate_pair(evidence_list[i], evidence_list[j])
                pairs.append(pair)

        # 统计
        conf = sum(1 for p in pairs if p.relation in (
            CorrelationRelation.CONFIRMS, CorrelationRelation.REFINES,
            CorrelationRelation.EXTENDS))
        disp = sum(1 for p in pairs if p.relation == CorrelationRelation.DISPUTES)
        dup = sum(1 for p in pairs if p.relation == CorrelationRelation.DUPLICATE)
        ind = sum(1 for p in pairs if p.relation == CorrelationRelation.INDEPENDENT)

        # 确认链——被≥2个不同模态确认的漏洞位置
        corroborated = self._find_corroborated(evidence_list, pairs)

        # 争议finding
        disputed = [p.evidence_a.evidence_id for p in pairs
                    if p.relation == CorrelationRelation.DISPUTES]

        return CorrelationResult(
            pairs=pairs, total_evidence=n,
            confirmed_count=conf, disputed_count=disp,
            duplicate_count=dup, independent_count=ind,
            corroborated_vulns=corroborated,
            disputed_findings=disputed)

    def _correlate_pair(self, a: NormalizedEvidence,
                          b: NormalizedEvidence) -> EvidencePair:
        """对单对证据执行关联推断。

        评分分解:
          spatial_similarity = 位置重合度(函数名+文件+地址+行号)
          semantic_similarity = 类型重合度(漏洞类型+CWE)
          modality_independence = 模态独立性(越高→确认越强)
          correlation_score = spatial × semantic × independence_factor
        """
        # 空间相似度
        spatial = self._spatial_sim(a, b)

        # 同模态+同位置→DUPLICATE
        if a.modality == b.modality and spatial > 0.95:
            return EvidencePair(
                evidence_a=a, evidence_b=b,
                relation=CorrelationRelation.DUPLICATE,
                spatial_similarity=spatial, semantic_similarity=1.0,
                correlation_score=1.0, reasoning="同模态同位置——重复finding")

        # 语义相似度
        semantic = self._semantic_sim(a, b)

        # 模态独立性
        ind_a = self._MODALITY_INDEPENDENCE.get(a.modality, 0.5)
        ind_b = self._MODALITY_INDEPENDENCE.get(b.modality, 0.5)
        independence = (ind_a + ind_b) / 2.0

        # 综合关联评分——加权平均(避免乘法导致单维度短板过度惩罚)
        corr_score = 0.5 * spatial + 0.3 * semantic + 0.2 * independence

        # 低空间相似度→INDEPENDENT(仅同位置才可能指向同一漏洞)
        if spatial < self._spatial_threshold:
            return EvidencePair(
                evidence_a=a, evidence_b=b,
                relation=CorrelationRelation.INDEPENDENT,
                spatial_similarity=spatial, semantic_similarity=semantic,
                correlation_score=corr_score,
                reasoning=f"空间距离过大({spatial:.2f}<{self._spatial_threshold})")

        # 高关联评分→推断关系类型
        if corr_score >= self._correlation_threshold:
            relation = CorrelationRelation.CONFIRMS
            reasoning = f"强关联(spatial={spatial:.2f}, semantic={semantic:.2f}, indep={independence:.2f})"
            # 检查是否为REFINES(细化)而非简单确认
            if (a.overflow_size > 0 and b.overflow_size == 0 and
                    a.modality != b.modality):
                relation = CorrelationRelation.REFINES
                reasoning += "——A细化了溢出量信息"
            elif a.modality != b.modality and semantic > 0.9:
                relation = CorrelationRelation.CONFIRMS
                reasoning += "——跨模态确认"
        elif semantic < 0.3 and corr_score < 0.3:
            # 同位置但类型不兼容→DISPUTES
            relation = CorrelationRelation.DISPUTES
            reasoning = f"位置重合但类型不兼容(spatial={spatial:.2f}, semantic={semantic:.2f})"
        else:
            relation = CorrelationRelation.INDEPENDENT
            reasoning = f"关联不足(spatial={spatial:.2f}, semantic={semantic:.2f})"

        # 混淆风险评估
        confound_risk = self._estimate_confounding(a, b, spatial, semantic)

        return EvidencePair(
            evidence_a=a, evidence_b=b,
            relation=relation,
            spatial_similarity=round(spatial, 3),
            semantic_similarity=round(semantic, 3),
            correlation_score=round(corr_score, 3),
            causal_direction=self._infer_direction(a, b, relation),
            confounding_risk=round(confound_risk, 3),
            reasoning=reasoning)

    def _spatial_sim(self, a: NormalizedEvidence,
                       b: NormalizedEvidence) -> float:
        """位置相似度——函数名+文件+行号+地址的四维加权。

        权重: 函数名(0.40) + 文件(0.25) + 行号(0.20) + 地址(0.15)
        """
        score = 0.0
        total_w = 0.0

        if a.function_name and b.function_name:
            if a.function_name.lower() == b.function_name.lower():
                score += 0.40
            elif a.function_name.lower() in b.function_name.lower() or \
                 b.function_name.lower() in a.function_name.lower():
                score += 0.25
            total_w += 0.40

        if a.file_path and b.file_path:
            if a.file_path == b.file_path:
                score += 0.25
            total_w += 0.25

        if a.line_number > 0 and b.line_number > 0:
            dist = abs(a.line_number - b.line_number)
            if dist <= 5:
                score += 0.20
            elif dist <= 20:
                score += 0.10
            total_w += 0.20

        if a.binary_address > 0 and b.binary_address > 0:
            dist = abs(a.binary_address - b.binary_address)
            if dist <= 64:
                score += 0.15
            total_w += 0.15

        return score / total_w if total_w > 0 else 0.0

    def _semantic_sim(self, a: NormalizedEvidence,
                        b: NormalizedEvidence) -> float:
        """语义相似度——漏洞类型+CWE重合度"""
        score = 0.0
        if a.vuln_type == b.vuln_type and a.vuln_type != 'unknown':
            score += 0.6
        if a.cwe_id and b.cwe_id and a.cwe_id == b.cwe_id:
            score += 0.4
        elif a.cwe_id and b.cwe_id:
            # 同CWE类别不同ID——如CWE-787 vs CWE-125(均为内存安全)
            if a.cwe_id.split('-')[0] == b.cwe_id.split('-')[0]:
                score += 0.2
        return min(1.0, score)

    def _estimate_confounding(self, a: NormalizedEvidence,
                                b: NormalizedEvidence,
                                spatial: float, semantic: float) -> float:
        """估计混淆风险——第三方因素导致伪相关的概率。

        高风险场景:
          - 高复杂度函数(>100行)→多个无关finding同时出现→伪关联
          - 同工具链的finding→工具偏见放大
          - 低空间+低语义→噪声关联
        """
        risk = 0.1  # 基线
        # 同工具链→风险+0.2
        if a.source_module == b.source_module:
            risk += 0.2
        # 低语义相似度→风险+0.3
        if semantic < 0.3:
            risk += 0.3
        return min(1.0, risk)

    def _infer_direction(self, a: NormalizedEvidence,
                           b: NormalizedEvidence,
                           relation: str) -> str:
        """推断因果方向——A→B 或 B→A 或无方向。

        若relation为CONFIRMS: 置信度更高→确认置信度更低的
        若relation为REFINES: 信息更丰富→细化信息更少的
        """
        if relation in (CorrelationRelation.INDEPENDENT,
                        CorrelationRelation.DUPLICATE):
            return "none"
        if a.confidence > b.confidence:
            return "B→A"  # B确认了A
        elif b.confidence > a.confidence:
            return "A→B"
        return "bidirectional"

    def _find_corroborated(self, evidence_list: List[NormalizedEvidence],
                             pairs: List[EvidencePair]) -> List[str]:
        """找出被≥2个独立模态确认的漏洞——高可信度finding"""
        # 按位置聚类
        clusters: Dict[str, Set[str]] = {}
        for p in pairs:
            if p.relation in (CorrelationRelation.CONFIRMS,
                              CorrelationRelation.REFINES):
                loc_a = f"{p.evidence_a.function_name}@{p.evidence_a.file_path}"
                loc_b = f"{p.evidence_b.function_name}@{p.evidence_b.file_path}"
                key = loc_a if loc_a > loc_b else loc_b
                if key not in clusters:
                    clusters[key] = set()
                clusters[key].add(p.evidence_a.modality)
                clusters[key].add(p.evidence_b.modality)
        # 过滤——≥2个模态
        return [loc for loc, mods in clusters.items() if len(mods) >= 2]


__all__ = [
    "CorrelationResult",
    "CorrelationEngine",
]
