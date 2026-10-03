# coding: utf-8
"""
跨管线关联验证 — 贝叶斯置信度聚合, 多漏洞类型证据互相印证.

方法: 以 def-use 链为桥梁, 构建跨管线证据图, 贝叶斯更新聚合置信度,
仅当 P(E|H) > P(E|¬H) 时纳入证据, 避免无关证据稀释后验.
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Set, Tuple
from collections import defaultdict


class VulnType(Enum):
    HEAP_OVERFLOW = auto()
    USE_AFTER_FREE = auto()
    FORMAT_STRING = auto()
    INTEGER_OVERFLOW = auto()


@dataclass
class EvidenceNode:
    """单条检测证据."""
    vuln_type: VulnType
    address: int           # 代码地址
    confidence: float      # 该管线的独立置信度 [0, 1]
    data_flow_vars: Set[str]  # 涉及的数据流变量
    description: str


@dataclass
class CorrelatedFinding:
    """关联后的发现."""
    primary_type: VulnType
    supporting_types: List[VulnType]
    address: int
    aggregated_confidence: float  # 聚合后的置信度
    individual_confidences: Dict[str, float]
    evidence: List[EvidenceNode]
    verdict: str  # CONFIRMED | LIKELY | POSSIBLE | FILTERED


# 先验概率 (基于 CVE 数据库中各类漏洞的共现频率)
_PRIOR: Dict[VulnType, float] = {
    VulnType.HEAP_OVERFLOW: 0.35,
    VulnType.USE_AFTER_FREE: 0.25,
    VulnType.FORMAT_STRING: 0.10,
    VulnType.INTEGER_OVERFLOW: 0.30,
}

# 条件概率 P(evidence_type | real_vuln_type) — 跨类型关联强度
_CONDITIONAL: Dict[Tuple[VulnType, VulnType], float] = {
    # (real_vuln, evidence_type)
    # Heap overflow 作为真实漏洞时, 其他管线检测到信号的概率
    (VulnType.HEAP_OVERFLOW, VulnType.INTEGER_OVERFLOW): 0.65,
    (VulnType.HEAP_OVERFLOW, VulnType.FORMAT_STRING): 0.15,
    (VulnType.HEAP_OVERFLOW, VulnType.USE_AFTER_FREE): 0.05,
    # Integer overflow 作为源头时
    (VulnType.INTEGER_OVERFLOW, VulnType.HEAP_OVERFLOW): 0.55,
    (VulnType.INTEGER_OVERFLOW, VulnType.FORMAT_STRING): 0.10,
    (VulnType.INTEGER_OVERFLOW, VulnType.USE_AFTER_FREE): 0.02,
    # UAF
    (VulnType.USE_AFTER_FREE, VulnType.HEAP_OVERFLOW): 0.10,
    (VulnType.USE_AFTER_FREE, VulnType.INTEGER_OVERFLOW): 0.02,
    (VulnType.USE_AFTER_FREE, VulnType.FORMAT_STRING): 0.02,
    # Format string
    (VulnType.FORMAT_STRING, VulnType.HEAP_OVERFLOW): 0.05,
    (VulnType.FORMAT_STRING, VulnType.INTEGER_OVERFLOW): 0.05,
    (VulnType.FORMAT_STRING, VulnType.USE_AFTER_FREE): 0.02,
}

# 同类型证据 (自身管线的置信度直接使用)
# 假阳性率 P(evidence | ¬vuln)
_FALSE_POSITIVE_RATE = {
    VulnType.HEAP_OVERFLOW: 0.15,
    VulnType.USE_AFTER_FREE: 0.10,
    VulnType.FORMAT_STRING: 0.20,
    VulnType.INTEGER_OVERFLOW: 0.25,
}


def _var_overlap(vars_a: Set[str], vars_b: Set[str]) -> float:
    """计算两个变量集的 Jaccard 重叠度."""
    if not vars_a or not vars_b:
        return 0.0
    intersection = len(vars_a & vars_b)
    union = len(vars_a | vars_b)
    return intersection / union if union > 0 else 0.0


def _bayesian_update(prior: float, evidence_prob: float,
                     false_positive_rate: float) -> float:
    """贝叶斯更新: P(H|E) = P(E|H)*P(H) / (P(E|H)*P(H) + P(E|¬H)*P(¬H))."""
    numerator = evidence_prob * prior
    denominator = numerator + false_positive_rate * (1.0 - prior)
    if denominator == 0:
        return prior
    return numerator / denominator


class CrossPipelineCorrelator:
    """跨管线关联器 — 贝叶斯置信度聚合.

    输入: 来自不同管线的 EvidenceNode 列表
    输出: 聚合后的 CorrelatedFinding 列表, 按置信度降序

    算法:
      1. 按地址分组 → 候选证据簇
      2. 对每个簇, 以主要类型为假设, 用贝叶斯更新聚合证据
      3. 若聚合置信度 ≥ 阈值 → 保留; 否则过滤
    """

    def __init__(self, confidence_threshold: float = 0.70):
        self.threshold = confidence_threshold
        self._evidence_by_addr: Dict[int, List[EvidenceNode]] = defaultdict(list)

    def add_evidence(self, node: EvidenceNode):
        self._evidence_by_addr[node.address].append(node)

    def correlate(self) -> List[CorrelatedFinding]:
        """执行跨管线关联."""
        findings = []
        for addr, evidence_list in self._evidence_by_addr.items():
            if not evidence_list:
                continue

            # 按类型分组
            by_type: Dict[VulnType, EvidenceNode] = {}
            for ev in evidence_list:
                if ev.vuln_type not in by_type:
                    by_type[ev.vuln_type] = ev
                else:
                    # 保留置信度更高的
                    if ev.confidence > by_type[ev.vuln_type].confidence:
                        by_type[ev.vuln_type] = ev

            # 对每种类型, 以它为假设聚合其他类型的证据
            for primary_type, primary_ev in by_type.items():
                prior = _PRIOR[primary_type]
                posterior = primary_ev.confidence

                supporting = []
                # 先用自身管线的置信度做初始贝叶斯更新
                posterior = _bayesian_update(
                    prior, primary_ev.confidence,
                    _FALSE_POSITIVE_RATE[primary_type])

                # 再用跨类型证据更新 (仅当证据有区分力时)
                for other_type, other_ev in by_type.items():
                    if other_type == primary_type:
                        continue

                    # 检查数据流重叠
                    overlap = _var_overlap(
                        primary_ev.data_flow_vars,
                        other_ev.data_flow_vars)

                    # P(evidence | real_vuln) 结合数据流重叠和类型关联
                    cond = _CONDITIONAL.get(
                        (primary_type, other_type), 0.05)
                    evidence_strength = cond * (0.5 + 0.5 * overlap)

                    fp_rate = _FALSE_POSITIVE_RATE[other_type]
                    # 仅当证据强度 > 假阳性率时才更新
                    # (即证据有助于区分 TP/FP, 而非引入噪声)
                    if evidence_strength > fp_rate:
                        posterior = _bayesian_update(
                            posterior, evidence_strength, fp_rate)
                        if overlap > 0.15:
                            supporting.append(other_type)

                # 判定
                if posterior >= 0.90:
                    verdict = 'CONFIRMED'
                elif posterior >= self.threshold:
                    verdict = 'LIKELY'
                elif posterior >= 0.50:
                    verdict = 'POSSIBLE'
                else:
                    verdict = 'FILTERED'

                findings.append(CorrelatedFinding(
                    primary_type=primary_type,
                    supporting_types=supporting,
                    address=addr,
                    aggregated_confidence=round(posterior, 4),
                    individual_confidences={
                        t.name: e.confidence for t, e in by_type.items()
                    },
                    evidence=evidence_list,
                    verdict=verdict,
                ))

        # 去重: 同一地址的同一类型只保留置信度最高的
        findings.sort(key=lambda f: f.aggregated_confidence, reverse=True)
        seen = set()
        deduped = []
        for f in findings:
            key = (f.address, f.primary_type)
            if key not in seen:
                seen.add(key)
                deduped.append(f)

        return deduped

    def filter_by_verdict(self, findings: List[CorrelatedFinding],
                          min_verdict: str = 'LIKELY') -> List[CorrelatedFinding]:
        """按判定过滤."""
        order = {'CONFIRMED': 0, 'LIKELY': 1, 'POSSIBLE': 2, 'FILTERED': 3}
        threshold = order.get(min_verdict, 3)
        return [f for f in findings if order.get(f.verdict, 3) <= threshold]

    @staticmethod
    def explain(finding: CorrelatedFinding) -> str:
        """生成人类可读的解释."""
        parts = [
            f'{finding.verdict}: {finding.primary_type.name}',
            f'  @0x{finding.address:x} 置信度={finding.aggregated_confidence:.1%}',
        ]
        if finding.supporting_types:
            names = [t.name for t in finding.supporting_types]
            parts.append(f'  关联证据: {", ".join(names)}')
        for ev in finding.evidence:
            parts.append(f'  [{ev.vuln_type.name}] {ev.description}')
        return '\n'.join(parts)


def batch_correlate(
    heap_findings: List[Dict] = None,
    uaf_findings: List[Dict] = None,
    fmt_findings: List[Dict] = None,
    int_overflow_findings: List[Dict] = None,
    threshold: float = 0.70,
) -> Tuple[List[CorrelatedFinding], Dict]:
    """便利批量关联 — 从管线输出字典直接构建 EvidenceNode 并关联, 返回 (filtered_findings, stats)。"""
    heap_findings = heap_findings or []
    uaf_findings = uaf_findings or []
    fmt_findings = fmt_findings or []
    int_overflow_findings = int_overflow_findings or []

    correlator = CrossPipelineCorrelator(confidence_threshold=threshold)
    stats = {'input_heap': len(heap_findings), 'input_uaf': len(uaf_findings),
             'input_fmt': len(fmt_findings),
             'input_int_overflow': len(int_overflow_findings),
             'confidence_boosted': 0, 'filtered': 0, 'confirmed': 0,
             'likely': 0, 'possible': 0, 'input_total': 0}

    total_input = (len(heap_findings) + len(uaf_findings) +
                   len(fmt_findings) + len(int_overflow_findings))
    stats['input_total'] = total_input

    def _add(findings, vtype, addr_key='address'):
        for f in findings:
            addr = f.get(addr_key, 0)
            if isinstance(addr, str):
                try:
                    addr = int(addr, 16)
                except ValueError:
                    addr = hash(addr) & 0xFFFFFFFF
            vars_set = set()
            for key in ('data_flow_vars', 'variables', 'vars'):
                if key in f and isinstance(f[key], (list, set)):
                    vars_set.update(f[key])
            correlator.add_evidence(EvidenceNode(
                vuln_type=vtype,
                address=addr,
                confidence=f.get('confidence', f.get('score', 0.5)),
                data_flow_vars=vars_set,
                description=f.get('description', f.get('operation', str(f))),
            ))

    _add(heap_findings, VulnType.HEAP_OVERFLOW)
    _add(uaf_findings, VulnType.USE_AFTER_FREE)
    _add(fmt_findings, VulnType.FORMAT_STRING)
    _add(int_overflow_findings, VulnType.INTEGER_OVERFLOW)

    findings = correlator.correlate()

    for f in findings:
        if f.aggregated_confidence > f.individual_confidences.get(
                f.primary_type.name, 0):
            stats['confidence_boosted'] += 1
        if f.verdict == 'CONFIRMED':
            stats['confirmed'] += 1
        elif f.verdict == 'LIKELY':
            stats['likely'] += 1
        elif f.verdict == 'POSSIBLE':
            stats['possible'] += 1
        else:
            stats['filtered'] += 1

    filtered = correlator.filter_by_verdict(findings, 'LIKELY')
    return filtered, stats
