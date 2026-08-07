# coding: utf-8
# 创建: 2026-06-23  |  CMVC编排引擎
# 修改: 2026-06-23  |  审计后补充文件头与错误处理
#
"""
跨模态漏洞关联——编排引擎。

管线流程:
  1. 证据归一化: 各模态finding→NormalizedEvidence(EvidenceNormalizer)
  2. 初步筛选: 按函数名/文件路径分组→同组内执行全对关联
  3. 因果关联: 空间语义评分+因果推断→确认/争议/补充/重复(CorrelationEngine)
  4. 确认链构建: 被≥2个独立模态确认的漏洞→高可信度列表
  5. 争议标记: 矛盾finding→人工审查队列
  6. 输出: 关联报告——含确认链/争议项/独立finding统计

使用场景:
  在完整分析管线结束后, 将所有finding汇集至本引擎:
    static_findings + llm_reports + fuzz_crashes + dynamic_traces
    → CorrelationReport → 按可信度分层的漏洞清单

与传统分数融合的差异:
  分数融合: [0.8, 0.7, 0.9]→0.82(丢失了"哪个证据贡献了什么"的信息)
  实例关联: 保持每条finding独立可追溯, 仅建立关系边
  分析师可下钻至原始finding验证关联推理——可解释性远高于黑盒融合

与现有模块集成:
  multimodal_vuln_fusion → 分数级融合(输出一个分数)
  cmvc_engine → 实例级关联(输出关系图)
  CSSA → 崩溃分类结果注入为证据
  MEWF → 武器化预测作为证据加权依据
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set
from collections import defaultdict

from .cmvc_evidence import (
    NormalizedEvidence, EvidencePair, EvidenceNormalizer,
    AnalysisModality, CorrelationRelation,
)
from .cmvc_correlation import CorrelationResult, CorrelationEngine

_log = logging.getLogger(__name__)


# 关联报告


@dataclass
class CorroborationChain:
    """确认链——被多个独立模态确认的漏洞"""
    chain_id: str
    location: str                   # "function@file" 标识
    evidences: List[NormalizedEvidence] = field(default_factory=list)
    # 确认强度
    modality_count: int = 0         # 确认的模态数
    avg_confidence: float = 0.0     # 平均置信度
    consensus_level: str = "LOW"    # HIGH(≥3模态) | MEDIUM(2模态) | LOW(1模态)
    # 摘要
    primary_vuln_type: str = ""
    recommendation: str = ""


@dataclass
class CorrelationReport:
    """跨模态关联完整报告"""
    # 确认链
    corroborated: List[CorroborationChain] = field(default_factory=list)
    # 争议项
    disputed: List[EvidencePair] = field(default_factory=list)
    # 独立finding(无关联)
    isolated: List[NormalizedEvidence] = field(default_factory=list)
    # 统计
    total_evidence: int = 0
    total_corroborated_chains: int = 0
    total_disputes: int = 0
    # 方法论
    method: str = "spatial_semantic_correlation_with_causal_inference"


# 编排引擎


class CmvcEngine:
    """跨模态漏洞关联编排引擎。

    使用示例:
        engine = CmvcEngine()
        report = engine.analyze({
            'static': [static_findings],
            'llm': [llm_findings],
            'fuzzing': [fuzz_crashes],
        })

    finding字典格式(各模态最小要求):
      static: {type, function_name, file_path, line_number, confidence, ...}
      fuzzing: {signal, address, crash_instruction, function_name, ...}
      llm: {function_name, vuln_type, score, description, ...}
    """

    def __init__(self):
        self._normalizer = EvidenceNormalizer()
        self._engine = CorrelationEngine()

    def analyze(self, findings_by_modality: Dict[str, List[Dict]]
                 ) -> CorrelationReport:
        """执行跨模态关联分析。

        参数:
          findings_by_modality: {modality_name: [finding_dicts]}

        返回CorrelationReport。
        """
        # 归一化
        all_evidence = []
        for modality, findings in findings_by_modality.items():
            for i, f in enumerate(findings):
                ev = self._normalizer.normalize(
                    f, modality, f"{modality}_{i}")
                all_evidence.append(ev)

        if not all_evidence:
            return CorrelationReport()

        # 按位置分组—降低全对比较的复杂度
        groups = self._group_by_location(all_evidence)

        # 组内全对关联
        all_pairs = []
        all_corroborated = []
        all_disputed = []
        isolated_ids = {ev.evidence_id for ev in all_evidence}

        for loc_key, ev_list in groups.items():
            if len(ev_list) < 2:
                continue
            result = self._engine.correlate(ev_list)
            all_pairs.extend(result.pairs)

            # 标记已关联的evidence
            for p in result.pairs:
                if p.relation != CorrelationRelation.INDEPENDENT:
                    isolated_ids.discard(p.evidence_a.evidence_id)
                    isolated_ids.discard(p.evidence_b.evidence_id)

            # 收集确认链
            for loc in result.corroborated_vulns:
                all_corroborated.append((loc, ev_list))

            # 收集争议
            all_disputed.extend(
                p for p in result.pairs
                if p.relation == CorrelationRelation.DISPUTES)

        # 构建确认链
        chains = self._build_chains(all_corroborated, all_evidence)

        # 独立finding
        isolated = [ev for ev in all_evidence
                     if ev.evidence_id in isolated_ids]

        return CorrelationReport(
            corroborated=chains,
            disputed=all_disputed,
            isolated=isolated,
            total_evidence=len(all_evidence),
            total_corroborated_chains=len(chains),
            total_disputes=len(all_disputed))

    def _group_by_location(self, evidence_list: List[NormalizedEvidence]
                            ) -> Dict[str, List[NormalizedEvidence]]:
        """按(函数名, 文件)分组——同函数finding更可能指向同一漏洞。

        组键: "function_name::file_path"(去重时忽略大小写差异)
        若无函数名→按文件路径分组
        若无文件→归入"ungrouped"
        """
        groups: Dict[str, List[NormalizedEvidence]] = defaultdict(list)
        for ev in evidence_list:
            func = ev.function_name.lower() if ev.function_name else ''
            fpath = ev.file_path.lower() if ev.file_path else ''
            if func:
                key = f"{func}::{fpath}" if fpath else func
            elif fpath:
                key = f"file::{fpath}"
            elif ev.binary_address:
                key = f"addr_{ev.binary_address:x}"
            else:
                key = "ungrouped"
            groups[key].append(ev)
        return dict(groups)

    def _build_chains(self, corroborated: List[Tuple[str, List[NormalizedEvidence]]],
                        all_evidence: List[NormalizedEvidence]
                        ) -> List[CorroborationChain]:
        """从关联结果构建确认链——去重+聚合"""
        chain_map: Dict[str, CorroborationChain] = {}

        for loc_key, ev_list in corroborated:
            if loc_key not in chain_map:
                chain_map[loc_key] = CorroborationChain(
                    chain_id=f"CHAIN_{loc_key.replace('::','_')[:40]}",
                    location=loc_key)

            chain = chain_map[loc_key]
            seen_ids = {e.evidence_id for e in chain.evidences}

            for ev in ev_list:
                if ev.evidence_id not in seen_ids:
                    chain.evidences.append(ev)
                    seen_ids.add(ev.evidence_id)

        # 计算每链的聚合统计
        for chain in chain_map.values():
            modalities = set(e.modality for e in chain.evidences)
            chain.modality_count = len(modalities)
            chain.avg_confidence = (
                sum(e.confidence for e in chain.evidences) /
                max(len(chain.evidences), 1))

            if chain.modality_count >= 3:
                chain.consensus_level = "HIGH"
            elif chain.modality_count >= 2:
                chain.consensus_level = "MEDIUM"
            else:
                chain.consensus_level = "LOW"

            # 主要漏洞类型——取众数
            type_counts = defaultdict(int)
            for ev in chain.evidences:
                if ev.vuln_type != 'unknown':
                    type_counts[ev.vuln_type] += 1
            chain.primary_vuln_type = max(type_counts, key=type_counts.get) if type_counts else 'unknown'

            if chain.consensus_level == "HIGH":
                chain.recommendation = f"高置信度——{chain.modality_count}个独立模态确认，建议优先修复"
            elif chain.consensus_level == "MEDIUM":
                chain.recommendation = "中置信度——建议追加验证以排除模态间伪关联"
            else:
                chain.recommendation = "低置信度——单一模态发现，需额外证据支持"

        return sorted(chain_map.values(),
                      key=lambda c: c.modality_count, reverse=True)


# 便捷入口


def correlate_findings(findings_by_modality: Dict[str, List[Dict]]
                        ) -> CorrelationReport:
    """跨模态关联便捷入口——单行调用"""
    return CmvcEngine().analyze(findings_by_modality)


__all__ = [
    "CorroborationChain",
    "CorrelationReport",
    "CmvcEngine",
    "correlate_findings",
]
