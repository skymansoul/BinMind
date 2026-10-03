# 多模态漏洞评分融合器-将静态分析、LLM判断、历史CVE匹配、二进制特征
# 等异构信号加权聚合为单一可利用性评分。
# AMMF 注意力增强多特征融合和Cascaded Vulnerability
# Attacks HGAT节点-边联合建模。
#
# 融合的模态维度:
# static_score: 传统静态分析危险函数评分 (0-100)
# llm_score: LLM语义漏洞判断 (0-1)
# cve_match_score: CVE数据库匹配置信度 (0-1)
#   - graph_embedding_similarity: 与已知漏洞函数的图相似度 (0-1)
#   - exploitability_score: CWE+checksec利用性评估 (0-10)
#   - age_factor: 漏洞存活时间因子 (log(1+days)/log(1+max_days))
# cvss_normalized: CVSS评分归一化 (0-1)
#   - sandbox_verification: 沙箱验证结果 (0/1 或 0-1置信度)
#
# - 初版仅加权平均
# - 新增证据置信度衰减与模糊积分替代方法

import math, logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

_log = logging.getLogger(__name__)


@dataclass
class ModalEvidence:
    """单模态证据-带置信度元数据的评分条目。"""
    source: str                         # 来源标识: static/llm/cve/graph/exploit/dynamic
    score: float                       # 0-1归一化评分
    confidence: float                   # 该来源置信度 (0-1)
    weight: float = 0.0                # 融合权重
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FusionResult:
    """多模态融合输出-含各维度分解与最终评分。"""
    final_score: float                  # 0-1 综合严重度
    severity_label: str                 # CRITICAL/HIGH/MEDIUM/LOW
    confidence: float                   # 融合置信度
    modalities: List[ModalEvidence] = field(default_factory=list)
    fusion_method: str = "weighted_average"
    evidence_count: int = 0
    evidence_conflicts: List[str] = field(default_factory=list)
    recommendation: str = ""


class MultiModalVulnFuser:
    """多模态漏洞评分融合器-异构信号加权聚合为单一可利用性评分。"""

    # 领域先验权重-静态分析最可靠(可解释)，LLM次之(语义理解但有幻觉)
    _DEFAULT_WEIGHTS = {
        'static': 0.30,
        'cve':    0.25,
        'llm':    0.20,
        'graph':  0.10,
        'exploit': 0.08,
        'dynamic': 0.07,
    }

    def __init__(self, fusion_method: str = "weighted_average",
                 custom_weights: Dict[str, float] = None):
        self.fusion_method = fusion_method
        self.weights = dict(self._DEFAULT_WEIGHTS)
        if custom_weights:
            self.weights.update(custom_weights)

    def fuse(self, evidences: List[ModalEvidence]) -> FusionResult:
        """融合多条证据为单一评分。

        参数:
            evidences: 各模态证据列表

        返回FusionResult。
        """
        if not evidences:
            return FusionResult(
                final_score=0.0, severity_label="LOW", confidence=0.0,
                evidence_count=0)

        # 确保每条证据有权重
        for ev in evidences:
            if ev.weight <= 0:
                ev.weight = self.weights.get(ev.source, 0.10)

        if self.fusion_method == "sugeno":
            return self._fuse_sugeno(evidences)
        else:
            return self._fuse_weighted_avg(evidences)

    def _fuse_weighted_avg(self, evidences: List[ModalEvidence]) -> FusionResult:
        """加权平均融合-置信度衰减权重。

        公式: score = Σ(w_i * c_i * s_i) / Σ(w_i * c_i)
        其中w为先验权重，c为置信度，s为评分。
        """
        weighted_sum = 0.0
        total_weight = 0.0
        conflicts = []

        for ev in evidences:
            effective_w = ev.weight * max(ev.confidence, 0.05)
            weighted_sum += ev.score * effective_w
            total_weight += effective_w

        if total_weight < 1e-6:
            return FusionResult(
                final_score=0.0, severity_label="LOW", confidence=0.0,
                modalities=evidences, evidence_count=len(evidences))

        final_score = weighted_sum / total_weight

        # 检测证据冲突-同来源评分偏差>0.4视为冲突
        source_scores: Dict[str, List[float]] = {}
        for ev in evidences:
            source_scores.setdefault(ev.source, []).append(ev.score)
        for src, scores in source_scores.items():
            if len(scores) >= 2:
                rng = max(scores) - min(scores)
                if rng > 0.4:
                    conflicts.append(
                        f"{src}证据不一致: 范围={rng:.2f} ({min(scores):.2f}-{max(scores):.2f})")

        severity = self._score_to_label(final_score)
        # 融合置信度-证据来源越多元越可信
        unique_sources = len({ev.source for ev in evidences})
        diversity_bonus = min(1.0, unique_sources / len(self._DEFAULT_WEIGHTS))
        avg_confidence = sum(ev.confidence for ev in evidences) / len(evidences)
        fusion_conf = avg_confidence * 0.6 + diversity_bonus * 0.4

        return FusionResult(
            final_score=round(final_score, 3),
            severity_label=severity,
            confidence=round(fusion_conf, 2),
            modalities=evidences,
            fusion_method="weighted_average",
            evidence_count=len(evidences),
            evidence_conflicts=conflicts,
            recommendation=self._gen_recommendation(final_score, severity))

    def _fuse_sugeno(self, evidences: List[ModalEvidence]) -> FusionResult:
        """Sugeno模糊积分融合-适用于互补性强的多模态证据。

        按评分升序排列，对每个证据h(x_i)计算min(h(x_i), g(A_i))，
        取最大值作为积分结果。g为模糊测度(简化为归一化权重累积和)。
        """
        sorted_evs = sorted(evidences, key=lambda e: e.score)
        n = len(sorted_evs)

        # 计算归一化累积权重g(A_i)
        cumulative_ws = []
        cum_w = 0.0
        for ev in sorted_evs:
            frac = ev.weight * ev.confidence
            cum_w += frac
            cumulative_ws.append(cum_w)

        # 归一化
        max_w = cumulative_ws[-1] if cumulative_ws else 1.0
        if max_w < 1e-6:
            max_w = 1.0
        cumulative_ws = [w / max_w for w in cumulative_ws]

        integrals = [min(ev.score, cumulative_ws[i])
                      for i, ev in enumerate(sorted_evs)]
        final_score = max(integrals) if integrals else 0.0

        avg_conf = sum(ev.confidence for ev in evidences) / n if n else 0.0
        severity = self._score_to_label(final_score)

        return FusionResult(
            final_score=round(final_score, 3),
            severity_label=severity,
            confidence=round(avg_conf, 2),
            modalities=evidences,
            fusion_method="sugeno_fuzzy_integral",
            evidence_count=n,
            recommendation=self._gen_recommendation(final_score, severity))

    @staticmethod
    def _score_to_label(score: float) -> str:
        if score >= 0.75:
            return "CRITICAL"
        elif score >= 0.55:
            return "HIGH"
        elif score >= 0.30:
            return "MEDIUM"
        return "LOW"

    def _gen_recommendation(self, score: float, severity: str) -> str:
        if severity == "CRITICAL":
            return ("多个独立模态一致指向严重漏洞，建议立即修复并发布安全公告。"
                    "如有公开PoC则风险升级为紧急。")
        elif severity == "HIGH":
            return ("多模态评分偏高，建议优先安排修复窗口。"
                    "关注是否有公开Exploit可利用。")
        elif severity == "MEDIUM":
            return "评分中等，建议结合人工审计判断是否为可利用的漏洞路径。"
        return "低风险-可能为误报或利用难度极高的理论漏洞。"


# 便捷构造函数

def make_evidence(source: str, score: float, confidence: float = 0.5,
                   **meta) -> ModalEvidence:
    """创建ModalEvidence的便捷函数。"""
    return ModalEvidence(source=source, score=score, confidence=confidence,
                          metadata=meta)


def fuse_vulnerability_scores(
        static_score: float = 0.0,
        llm_score: float = 0.0,
        cve_match_score: float = 0.0,
        graph_similarity: float = 0.0,
        exploitability_score: float = 0.0,
        dynamic_verification: float = 0.0,
        static_conf: float = 0.8,
        llm_conf: float = 0.5,
        cve_conf: float = 0.7,
        graph_conf: float = 0.4,
        exploit_conf: float = 0.6,
        dynamic_conf: float = 0.9,
        method: str = "weighted_average"
) -> FusionResult:
    """一站式融合函数-传入各模态评分获取FusionResult。

    参数:
        static_score: 静态分析分数 (0-1)
        llm_score: LLM判断分数 (0-1)
        cve_match_score: CVE匹配分数 (0-1)
        graph_similarity: 图嵌入相似度 (0-1)
        exploitability_score: 利用性评分 (0-1, 0-10需提前归一化)
        dynamic_verification: 动态验证结果 (0-1)
        static_conf~dynamic_conf: 各模态置信度
        method: 融合方法 ("weighted_average" 或 "sugeno")

    返回FusionResult。
    """
    fuser = MultiModalVulnFuser(fusion_method=method)
    evidences = []
    if static_score > 0:
        evidences.append(make_evidence('static', static_score, static_conf))
    if llm_score > 0:
        evidences.append(make_evidence('llm', llm_score, llm_conf))
    if cve_match_score > 0:
        evidences.append(make_evidence('cve', cve_match_score, cve_conf))
    if graph_similarity > 0:
        evidences.append(make_evidence('graph', graph_similarity, graph_conf))
    if exploitability_score > 0:
        evidences.append(make_evidence('exploit', exploitability_score, exploit_conf))
    if dynamic_verification > 0:
        evidences.append(make_evidence('dynamic', dynamic_verification, dynamic_conf))
    return fuser.fuse(evidences)


# 证据可信度衰减
# 多来源证据若一致性低，整体置信度应衰减。
# Cascaded Vulnerability Attacks论文中HGAT聚合前的可信度校验步骤。

def compute_evidence_discord(evidences: List[ModalEvidence]) -> float:
    """计算证据间不一致度-评分方差规范化为[0,1]。

    0=完全一致，1=完全矛盾。
    """
    if len(evidences) < 2:
        return 0.0
    scores = [ev.score for ev in evidences]
    mu = sum(scores) / len(scores)
    # MAD (Mean Absolute Deviation) 规范化
    mad = sum(abs(s - mu) for s in scores) / len(scores)
    # 2.5倍缩放-满分0.4 MAD视为完全不一致
    return min(1.0, mad * 2.5)
