#!/usr/bin/env python3
# coding: utf-8
"""
统一可利用性评分系统 — 跨 7 种漏洞类型的标准化风险评分.

将每种检测管线输出映射到统一的 CVSS 风格的评分:
  Score = Base(漏洞类型) × Exploitability(可达性×复杂度) × Impact(机密性×完整性×可用性)

评分维度:
  1. Base Score (0-10): 漏洞类型固有严重度 (基于 CWE/CVSS 3.1)
  2. Exploitability (0-1): 利用条件的可达性 (路径可达 + 输入可控)
  3. Impact (0-1): 成功利用后的影响 (任意写/代码执行/信息泄露)

输出: 标准化 JSON 报告, 适合集成到 CI/CD 或 IDA/Ghidra 插件.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class Severity(Enum):
    NONE = (0.0, 'None')
    LOW = (0.1, 'Low')
    MEDIUM = (4.0, 'Medium')
    HIGH = (7.0, 'High')
    CRITICAL = (9.0, 'Critical')

    @property
    def threshold(self) -> float:
        return self.value[0]

    @property
    def label(self) -> str:
        return self.value[1]

    @classmethod
    def from_score(cls, score: float) -> 'Severity':
        if score >= cls.CRITICAL.threshold:
            return cls.CRITICAL
        if score >= cls.HIGH.threshold:
            return cls.HIGH
        if score >= cls.MEDIUM.threshold:
            return cls.MEDIUM
        if score >= cls.LOW.threshold:
            return cls.LOW
        return cls.NONE


# 基于 CWE/CVSS 3.1 的基准分 (pre-exploitability adjustment)
_BASE_SCORES = {
    'heap_overflow':      8.6,  # CWE-122: 通常可导致任意代码执行
    'use_after_free':     8.6,  # CWE-416: 通常可导致代码执行
    'double_free':        7.5,  # CWE-415: 堆损坏 → 可能代码执行
    'format_string':      7.3,  # CWE-134: 信息泄露+可能任意写
    'integer_overflow':   6.5,  # CWE-190: 本身不直接可利用, 需链式利用
    'off_by_one':         7.8,  # CWE-193: 堆元数据损坏, 精确利用复杂
    'type_confusion':     8.1,  # CWE-843: vtable 劫持 → 代码执行
}


@dataclass
class UnifiedScore:
    vuln_type: str
    base_score: float
    exploitability: float
    impact: float
    total_score: float
    severity: str
    confidence: float
    cvss_vector: str
    details: Dict = field(default_factory=dict)


class ExploitabilityAssessor:
    """利用条件评估器."""

    # 可达性因子
    _REACHABILITY = {
        'direct_input':       0.95,  # 直接来自用户输入 (argv, recv, read)
        'indirect_input':     0.75,  # 间接来自用户输入 (网络解析)
        'internal_data':      0.40,  # 内部数据流 (非直接用户输入)
        'constant':           0.10,  # 编译时常量 (几乎不可利用)
    }

    # 攻击复杂度因子
    _COMPLEXITY = {
        'trivial':      0.95,  # 无缓解措施, 直接利用
        'simple':       0.75,  # 需要基本堆布局控制
        'moderate':     0.50,  # 需要具体堆状态 (如特定 freelist)
        'complex':      0.25,  # 需要多步骤原语组合
        'theoretical':  0.05,  # 理论可达但未见实际利用
    }

    def __init__(self):
        self._input_sources: Dict[str, str] = {}  # var → reachability level
        self._mitigations: List[str] = []  # 检测到的缓解措施

    def set_input_source(self, variable: str, source: str):
        self._input_sources[variable] = source

    def add_mitigation(self, mitigation: str):
        self._mitigations.append(mitigation)

    def assess(self, vuln_type: str, variables: List[str],
               complexity: str = 'moderate') -> Tuple[float, float]:
        """评估可利用性, 返回 (exploitability_score, impact_score)。"""
        # 可达性: 取所有相关变量的最差(最高)可达性
        if variables:
            reach_scores = [
                self._REACHABILITY.get(
                    self._input_sources.get(v, 'internal_data'), 0.4)
                for v in variables
            ]
            max_reach = max(reach_scores)
        else:
            max_reach = 0.40

        # 复杂度
        compl_score = self._COMPLEXITY.get(complexity, 0.50)

        # 缓解措施衰减
        mitigation_factor = 1.0
        for m in self._mitigations:
            if m in ('ASLR', 'PIE'):
                mitigation_factor *= 0.85  # 需要信息泄露
            elif m in ('NX', 'DEP'):
                mitigation_factor *= 0.70  # 需要 ROP
            elif m in ('stack_canary',):
                mitigation_factor *= 0.90
            elif m in ('CFI', 'CFG'):
                mitigation_factor *= 0.50  # 强缓解
            elif m in ('sandbox',):
                mitigation_factor *= 0.60

        exploitability = max_reach * compl_score * mitigation_factor

        # 影响: 基于漏洞类型
        impact_map = {
            'heap_overflow':      0.90,
            'use_after_free':     0.90,
            'double_free':        0.80,
            'format_string':      0.85,
            'integer_overflow':   0.60,
            'off_by_one':         0.75,
            'type_confusion':     0.85,
        }
        impact = impact_map.get(vuln_type, 0.70)

        return round(exploitability, 4), round(impact, 4)


def score_vulnerability(
    vuln_type: str, variables: List[str],
    input_sources: Dict[str, str] = None,
    complexity: str = 'moderate',
    confidence: float = 0.75,
    mitigations: List[str] = None,
) -> UnifiedScore:
    """计算统一可利用性评分。

    参数: vuln_type 漏洞类型 (heap_overflow, use_after_free,
    ...), variables 涉及的数据流变量列表, input_sources {var:
    source_type} 变量到输入源类型, complexity 攻击复杂度
    (trivial/simple/moderate/complex/theoretical), confidence
    检测置信度 [0, 1], mitigations 检测到的缓解措施列表;
    返回 UnifiedScore。
    """
    assessor = ExploitabilityAssessor()

    if input_sources:
        for var, src in input_sources.items():
            assessor.set_input_source(var, src)

    if mitigations:
        for m in mitigations:
            assessor.add_mitigation(m)

    base = _BASE_SCORES.get(vuln_type, 6.0)
    exploit, impact = assessor.assess(vuln_type, variables, complexity)

    # 综合评分 — 简化的 CVSS 风格:
    #   Base (漏洞固有分) × Confidence (检测置信度) × MitigationFactor
    # Exploitability 和 Impact 已含蓄在 Base 中, 仅用 mitigation 做折扣
    mitigation_penalty = 1.0
    for m in (mitigations or []):
        if m in ('CFI', 'CFG'):
            mitigation_penalty *= 0.70
        elif m in ('NX', 'DEP'):
            mitigation_penalty *= 0.85
        elif m in ('ASLR', 'PIE'):
            mitigation_penalty *= 0.90
        elif m in ('sandbox',):
            mitigation_penalty *= 0.80

    # Base 折合为 0-10 区间; exploit/impact 用于降级但不是乘数
    # 让 exploit 接近 1 时不降级, exploit 很低时降级
    exploit_discount = 0.7 + 0.3 * exploit  # [0.7, 1.0] — 即使不可达也有 base 分

    total = base * exploit_discount * mitigation_penalty * confidence

    severity = Severity.from_score(total)

    # 构建 CVSS 风格向量
    vector = (
        f'AV:N/AC:{_complexity_to_cvss(complexity)}/'
        f'PR:N/UI:N/S:U/C:H/I:H/A:H')

    return UnifiedScore(
        vuln_type=vuln_type,
        base_score=round(base, 1),
        exploitability=round(exploit, 3),
        impact=round(impact, 3),
        total_score=round(total, 2),
        severity=severity.label,
        confidence=round(confidence, 3),
        cvss_vector=vector,
        details={
            'variables': variables,
            'complexity': complexity,
            'mitigations': mitigations or [],
        },
    )


def _complexity_to_cvss(complexity: str) -> str:
    return {'trivial': 'L', 'simple': 'L', 'moderate': 'M',
            'complex': 'H', 'theoretical': 'H'}.get(complexity, 'M')


def batch_score(findings: List[Dict]) -> List[UnifiedScore]:
    """批量评分 — 从管线输出字典."""
    scores = []
    for f in findings:
        vuln_type = f.get('type', f.get('vuln_type', 'heap_overflow'))
        variables = f.get('variables', f.get('data_flow_vars', []))
        input_sources = f.get('input_sources', {})
        complexity = f.get('complexity', 'moderate')
        confidence = f.get('confidence', f.get('score', 0.75))
        mitigations = f.get('mitigations', [])

        scores.append(score_vulnerability(
            vuln_type, variables, input_sources,
            complexity, confidence, mitigations))

    # 按总分降序
    scores.sort(key=lambda s: s.total_score, reverse=True)
    return scores


def generate_score_summary(scores: List[UnifiedScore]) -> Dict:
    """生成评分摘要."""
    if not scores:
        return {'total': 0, 'max_score': 0, 'severities': {}}

    sev_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'None': 0}
    for s in scores:
        sev_counts[s.severity] = sev_counts.get(s.severity, 0) + 1

    return {
        'total_findings': len(scores),
        'max_score': max(s.total_score for s in scores),
        'avg_score': round(sum(s.total_score for s in scores) / len(scores), 2),
        'severity_distribution': sev_counts,
        'top_finding': {
            'type': scores[0].vuln_type,
            'score': scores[0].total_score,
            'severity': scores[0].severity,
        } if scores else None,
    }
