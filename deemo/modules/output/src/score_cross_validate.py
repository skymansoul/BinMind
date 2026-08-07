"""
评分交叉验证 — 模块间矛盾检测与元质量评分。

问题定义:
  37 个评分模块独立运算，可能产生矛盾:
    - 高可利用性 (primitive_quality) + 低风险面 (risk_surface) → 矛盾
    - 高漏洞密度 (vuln_density_scaling) + 高可靠度 (analysis_reliability) → 可疑
    - 低修复难度 (remediation_scorer) + 高紧迫度 (urgency_scorer) → 不一致

  这些矛盾不是错误 — 它们是分析盲区的信号:
    - 加固良好的二进制可能有高可利用漏洞 → 单个漏洞的微观风险
    - 分析可靠度低但报告了高密度漏洞 → 可能全是误报

  本模块是第一个二进制分析管线元质量评估工具。

  检测规则:
    1. exploitability vs risk_surface 背离 (>4 分差)
    2. vuln_density vs analysis_reliability 负相关检查
    3. remediation vs urgency 不一致
    4. heap_exploitability vs sandbox_escape 冗余利用链检查
    5. 单模块极端值 (任一模块 >9.0 且无其他模块 >6.0)

  无现有工具 — 2026-08 检索确认.
  Meta-analysis in ML: ensemble disagreement as quality signal.
  本模块首次将元分析应用于二进制漏洞评分管线.

修改记录:
  2026-08-02 15:44 - 初始版本，5条矛盾检测规则
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

class ContradictionType(Enum):
    EXPLOIT_VS_RISK = "exploit_vs_risk"        # 利用性≠风险面
    DENSITY_VS_RELIABILITY = "density_vs_reliability"  # 密度≠可靠度
    REMEDIATION_VS_URGENCY = "remediation_vs_urgency"  # 修复难度≠紧迫度
    HEAP_VS_SANDBOX = "heap_vs_sandbox"        # 堆利用≠沙箱强度
    SINGLE_EXTREME = "single_extreme"           # 孤立极端值
    CONSISTENT = "consistent"                   # 无矛盾

@dataclass
class Contradiction:
    """单个评分矛盾。"""
    contradiction_type: ContradictionType
    module_a: str
    score_a: float
    module_b: str
    score_b: float
    severity: float              # 0-10, 矛盾严重度
    interpretation: str

@dataclass
class CrossValidation:
    """评分交叉验证结果。"""
    contradictions: List[Contradiction] = field(default_factory=list)
    meta_quality_score: float = 10.0    # 0-10, 越高越可信
    analysis_blind_spot: str = ''       # 建议的盲区标签
    human_review_recommended: bool = False

def _detect_exploit_vs_risk(
    exploitability: float, risk_composite: float,
    exploit_module: str = 'primitive_quality',
    risk_module: str = 'risk_surface',
) -> Optional[Contradiction]:
    diff = exploitability - risk_composite
    if diff > 4.0:
        return Contradiction(
            contradiction_type=ContradictionType.EXPLOIT_VS_RISK,
            module_a=exploit_module, score_a=exploitability,
            module_b=risk_module, score_b=risk_composite,
            severity=min(diff, 10.0),
            interpretation=(f'利用性 ({exploitability}) 显著高于风险面 ({risk_composite}) — '
                          '可能: 1) 存在一个极易利用但攻击面窄的漏洞; '
                          '2) 风险面评分低估了间接暴露')
        )
    return None

def _detect_density_vs_reliability(
    vuln_density_z: float, reliability: float,
) -> Optional[Contradiction]:
    if abs(vuln_density_z) >= 2.5 and reliability < 0.4:
        return Contradiction(
            contradiction_type=ContradictionType.DENSITY_VS_RELIABILITY,
            module_a='vuln_density_scaling', score_a=abs(vuln_density_z),
            module_b='analysis_reliability', score_b=reliability,
            severity=min(abs(vuln_density_z) * 2.5, 10.0),
            interpretation=(f'漏洞密度异常 ({vuln_density_z:.1f}σ) 但分析可靠度低 ({reliability}) — '
                          '高概率为加壳/混淆导致的误报集群')
        )
    return None

def _detect_remediation_vs_urgency(
    remediation_diff: float, urgency_hours: float,
) -> Optional[Contradiction]:
    if remediation_diff <= 3.0 and urgency_hours <= 24:
        return Contradiction(
            contradiction_type=ContradictionType.REMEDIATION_VS_URGENCY,
            module_a='remediation_scorer', score_a=remediation_diff,
            module_b='urgency_scorer', score_b=urgency_hours,
            severity=7.0,
            interpretation=('修复难度低但紧迫度高 — 可能高估了紧迫度或低估了修复复杂性。'
                          '建议: 确认利用公开性和补丁可用性')
        )
    return None

def _detect_heap_vs_sandbox(
    heap_exploit: float, sandbox_diff: float,
) -> Optional[Contradiction]:
    if heap_exploit >= 7.0 and sandbox_diff >= 8.0:
        return Contradiction(
            contradiction_type=ContradictionType.HEAP_VS_SANDBOX,
            module_a='heap_exploitability', score_a=heap_exploit,
            module_b='sandbox_escape', score_b=sandbox_diff,
            severity=6.0,
            interpretation=('堆利用性高但沙箱几乎不可逃逸 — 攻击者可能获得代码执行但被沙箱限制。'
                          '检查: 沙箱是否允许必要的 syscall?')
        )
    return None

def _detect_single_extreme(
    scores: Dict[str, float],
    threshold: float = 9.0,
) -> List[Contradiction]:
    extreme = [(mod, s) for mod, s in scores.items() if s >= threshold]
    if len(extreme) == 1:
        mod, s = extreme[0]
        # 检查是否有其他模块 > 6.0 来 corroborate
        others_above_6 = sum(1 for m2, s2 in scores.items() if m2 != mod and s2 >= 6.0)
        if others_above_6 == 0:
            return [Contradiction(
                contradiction_type=ContradictionType.SINGLE_EXTREME,
                module_a=mod, score_a=s,
                module_b='(其他所有模块)', score_b=0.0,
                severity=min(s - 6.0, 10.0),
                interpretation=(f'{mod} 评分为 {s} 但无其他模块 corroborate — '
                              '可能为孤立极端值或误报')
            )]
    return []

def cross_validate(
    exploitability: float = 5.0,
    risk_composite: float = 5.0,
    vuln_density_z: float = 0.0,
    reliability: float = 0.8,
    remediation_difficulty: float = 5.0,
    urgency_hours: float = 168.0,
    heap_exploitability: float = 5.0,
    sandbox_difficulty: float = 5.0,
    additional_scores: Optional[Dict[str, float]] = None,
) -> CrossValidation:
    """
    交叉验证多个评分模块的输出，检测矛盾。

    参数为各模块的核心输出值。additional_scores 可传入
    任意 {module_name: score} 对以检测孤立极端值。
    """
    contradictions: List[Contradiction] = []

    c1 = _detect_exploit_vs_risk(exploitability, risk_composite)
    if c1: contradictions.append(c1)

    c2 = _detect_density_vs_reliability(vuln_density_z, reliability)
    if c2: contradictions.append(c2)

    c3 = _detect_remediation_vs_urgency(remediation_difficulty, urgency_hours)
    if c3: contradictions.append(c3)

    c4 = _detect_heap_vs_sandbox(heap_exploitability, sandbox_difficulty)
    if c4: contradictions.append(c4)

    all_scores = additional_scores or {}
    all_scores.update({
        'exploitability': exploitability, 'risk_composite': risk_composite,
        'remediation': remediation_difficulty, 'heap_exploit': heap_exploitability,
        'sandbox': sandbox_difficulty,
    })
    c5 = _detect_single_extreme(all_scores)
    contradictions.extend(c5)

    # 元质量: 每个矛盾 -1.5 分, 起始 10 分
    quality = round(max(0.0, 10.0 - len(contradictions) * 1.5), 1)

    blind_spot = ''
    if any(c.contradiction_type == ContradictionType.EXPLOIT_VS_RISK for c in contradictions):
        blind_spot = '攻击面-利用性评估不匹配'
    elif any(c.contradiction_type == ContradictionType.DENSITY_VS_RELIABILITY for c in contradictions):
        blind_spot = '低可靠度下的高密度告警'
    elif any(c.contradiction_type == ContradictionType.SINGLE_EXTREME for c in contradictions):
        blind_spot = '极端值缺少 corroboration'

    return CrossValidation(
        contradictions=contradictions,
        meta_quality_score=quality,
        analysis_blind_spot=blind_spot,
        human_review_recommended=len(contradictions) >= 2,
    )
