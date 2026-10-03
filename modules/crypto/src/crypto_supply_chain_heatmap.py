"""
密码学供应链风险热图 — 从多维度密码学审计输出生成综合供应链风险评估。

设计意图:
  既有模块识别单个风险(crypto_aging检测算法老化, crypto_diversity检测实现冗余,
  crypto_cve_matcher检测已知漏洞)。但供应链审计者需要一个全局视图:
    "在这个二进制/固件生态系统中, 密码学供应链的最大风险在哪里?"

  本模块作为31个分析模块之上的元分析层, 将风险聚合为5个供应链维度:
    R1 (代码来源风险): 库来源模糊/蚕食嫌疑/非官方实现。
    R2 (时效性风险): 算法老化/库版本过时/CVE未修复。
    R3 (复杂性风险): 多实现冗余/供应商碎片化/算法过多。
    R4 (合规性风险): 策略违规/标准不符合/许可证冲突。
    R5 (操作风险): 密钥管理不善/熵源弱/对策缺失。

  每个维度输出0-10风险评分, 5维聚合生成供应链风险热图。

  - NIST SP 800-161r1: 供应链风险管理框架(C-SCRM)。
  - OWASP SCVS: 软件组件验证标准。
  - MITRE ATT&CK for Supply Chain: 供应链攻击分类。

边界条件:
  - 风险评分基于可用模块的输出 — 若某维度无输入, 使用保守估计。
  - 多二进制场景下评分做max/avg聚合 — 单个高风险二进制可拉高整体评分。
  - 评分不代表绝对风险 — 需结合威胁模型和资产价值做上下文校准。
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

@dataclass
class SupplyChainRisk:
    dimension: str = ""
    score: float = 0.0             # 0-10, 10=最高风险
    factors: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)
    risk_level: str = "LOW"        # LOW / MEDIUM / HIGH / CRITICAL

@dataclass
class SupplyChainHeatmap:
    target: str = ""               # 二进制名称
    risks: Dict[str, SupplyChainRisk] = field(default_factory=dict)
    overall_score: float = 0.0     # 0-10 加权综合
    overall_risk: str = "LOW"
    top_threats: List[str] = field(default_factory=list)
    mitigation_priority: List[str] = field(default_factory=list)

# R1: 代码来源风险
def _score_provenance_risk(lib_fingerprints=None, watermark_findings=None,
                           cannibalization_matches=None) -> SupplyChainRisk:
    score = 0.0
    factors: List[str] = []
    evidence: List[str] = []

    if lib_fingerprints:
        for lf in lib_fingerprints:
            try:
                lib = getattr(lf, 'lib_name', '')
                conf = getattr(lf, 'confidence', 0.5)
                if conf < 0.6:
                    score += 2.5
                    factors.append(f'{lib}:低置信度识别→来源不确定')
                    evidence.append(f'library={lib} confidence={conf}')
            except Exception:
                pass

    if watermark_findings:
        anomalous = [w for w in watermark_findings
                     if getattr(w, 'severity', '') in ('SUSPICIOUS', 'ANOMALY')]
        if anomalous:
            score += min(5.0, len(anomalous) * 1.5)
            factors.append(f'{len(anomalous)}个可疑水印/异常指纹')

    if cannibalization_matches:
        exact = [m for m in cannibalization_matches
                 if getattr(m, 'match_type', '') == 'EXACT_MATCH']
        if exact:
            score += min(4.0, len(exact) * 2.0)
            factors.append(f'{len(exact)}个精确蚕食匹配→代码来源可疑')

    score = min(10.0, score)
    level = 'CRITICAL' if score >= 8 else 'HIGH' if score >= 5 else 'MEDIUM' if score >= 3 else 'LOW'
    return SupplyChainRisk(dimension='R1_PROVENANCE', score=round(score, 1),
                           factors=factors, evidence=evidence, risk_level=level)

# R2: 时效性风险
def _score_currency_risk(aging_reports=None, cve_matches=None) -> SupplyChainRisk:
    score = 0.0
    factors: List[str] = []

    if aging_reports:
        deprecated = [r for r in aging_reports
                      if getattr(r, 'status', None) and r.status.name in ('DEPRECATED', 'PROHIBITED')]
        if deprecated:
            score += min(6.0, len(deprecated) * 2.0)
            factors.append(f'{len(deprecated)}个已废弃/禁止算法')
        transitioning = [r for r in aging_reports
                         if getattr(r, 'status', None) and r.status.name == 'TRANSITIONING']
        if transitioning:
            score += min(3.0, len(transitioning) * 1.0)
            factors.append(f'{len(transitioning)}个过渡期算法')

    if cve_matches:
        critical_high = [m for m in cve_matches
                         if getattr(m, 'severity', '') in ('CRITICAL', 'HIGH')]
        active_exploit = [m for m in cve_matches
                          if getattr(m, 'exploit_maturity', '') == 'ACTIVE_EXPLOIT']
        if critical_high:
            score += min(5.0, len(critical_high) * 2.0)
            factors.append(f'{len(critical_high)}个HIGH/CRITICAL CVE')
        if active_exploit:
            score += min(5.0, len(active_exploit) * 3.0)
            factors.append(f'{len(active_exploit)}个CVE有活跃利用')

    score = min(10.0, score)
    level = 'CRITICAL' if score >= 8 else 'HIGH' if score >= 5 else 'MEDIUM' if score >= 3 else 'LOW'
    return SupplyChainRisk(dimension='R2_CURRENCY', score=round(score, 1),
                           factors=factors, risk_level=level)

# R3: 复杂性风险
def _score_complexity_risk(diversity_reports=None, algo_names=None,
                           hardware_peripherals=None) -> SupplyChainRisk:
    score = 0.0
    factors: List[str] = []

    if diversity_reports:
        high_div = [r for r in diversity_reports
                    if getattr(r, 'diversity_score', 0) > 0.5]
        if high_div:
            score += min(5.0, len(high_div) * 2.0)
            factors.append(f'{len(high_div)}个算法有高多样性(多实现冗余)')
        total_variants = sum(getattr(r, 'variant_count', 0) for r in diversity_reports)
        if total_variants > 5:
            score += 3.0
            factors.append(f'{total_variants}个独立实现变体')

    if algo_names:
        unique_algos = len(set(algo_names))
        if unique_algos > 8:
            score += 2.5
            factors.append(f'{unique_algos}种不同算法→高认知负担')

    if hardware_peripherals:
        detected_hw = [p for p in hardware_peripherals if getattr(p, 'detected', False)]
        if len(detected_hw) >= 3:
            score += 1.5
            factors.append(f'{len(detected_hw)}个硬件加密外设→多攻击面')

    score = min(10.0, score)
    level = 'HIGH' if score >= 6 else 'MEDIUM' if score >= 3 else 'LOW'
    return SupplyChainRisk(dimension='R3_COMPLEXITY', score=round(score, 1),
                           factors=factors, risk_level=level)

# R4: 合规性风险
def _score_compliance_risk(policy_report=None) -> SupplyChainRisk:
    score = 0.0
    factors: List[str] = []
    if policy_report:
        try:
            score = (100.0 - policy_report.compliance_score) / 10.0
            if policy_report.blocker_count > 0:
                factors.append(f'{policy_report.blocker_count} blockers')
        except Exception:
            score = 3.0

    score = min(10.0, score)
    level = 'CRITICAL' if score >= 8 else 'HIGH' if score >= 5 else 'MEDIUM' if score >= 3 else 'LOW'
    return SupplyChainRisk(dimension='R4_COMPLIANCE', score=round(score, 1),
                           factors=factors, risk_level=level)

# R5: 操作风险
def _score_operational_risk(key_lifecycle_reports=None,
                            entropy_reports=None,
                            countermeasure_checks=None,
                            leakage_report=None) -> SupplyChainRisk:
    score = 0.0
    factors: List[str] = []

    if key_lifecycle_reports:
        not_zeroized = [r for r in key_lifecycle_reports
                        if not getattr(r, 'is_zeroized', True)]
        if not_zeroized:
            score += min(4.0, len(not_zeroized) * 2.0)
            factors.append(f'{len(not_zeroized)}个密钥未清零')

    if entropy_reports:
        weak_entropy = [r for r in entropy_reports
                        if getattr(r, 'grade', None)
                        and r.grade.name in ('LOW', 'CRITICAL')]
        if weak_entropy:
            score += min(5.0, len(weak_entropy) * 2.5)
            factors.append(f'{len(weak_entropy)}个弱熵源')

    if countermeasure_checks:
        absent_cm = [c for c in countermeasure_checks
                     if getattr(c, 'status', '') == 'ABSENT']
        if len(absent_cm) >= 4:
            score += 3.0
            factors.append(f'{len(absent_cm)}/6个对策缺失')

    if leakage_report:
        try:
            lscore = getattr(leakage_report, 'composite_score', 0.0)
            if lscore > 0.6:
                score += lscore * 5.0
                factors.append(f'侧信道泄漏潜力高({lscore:.2f})')
        except Exception:
            pass

    score = min(10.0, score)
    level = 'CRITICAL' if score >= 8 else 'HIGH' if score >= 5 else 'MEDIUM' if score >= 3 else 'LOW'
    return SupplyChainRisk(dimension='R5_OPERATIONAL', score=round(score, 1),
                           factors=factors, risk_level=level)

# 热图生成

def generate_heatmap(target: str = "",
                     **kwargs) -> SupplyChainHeatmap:
    """
    从各模块输出生成供应链风险热图。
    支持关键字参数传入各模块报告。
    """
    risks: Dict[str, SupplyChainRisk] = {}

    risks['R1_PROVENANCE'] = _score_provenance_risk(
        kwargs.get('lib_fingerprints'),
        kwargs.get('watermark_findings'),
        kwargs.get('cannibalization_matches'))

    risks['R2_CURRENCY'] = _score_currency_risk(
        kwargs.get('aging_reports'),
        kwargs.get('cve_matches'))

    risks['R3_COMPLEXITY'] = _score_complexity_risk(
        kwargs.get('diversity_reports'),
        kwargs.get('algo_names'),
        kwargs.get('hardware_peripherals'))

    risks['R4_COMPLIANCE'] = _score_compliance_risk(
        kwargs.get('policy_report'))

    risks['R5_OPERATIONAL'] = _score_operational_risk(
        kwargs.get('key_lifecycle_reports'),
        kwargs.get('entropy_reports'),
        kwargs.get('countermeasure_checks'),
        kwargs.get('leakage_report'))

    # 加权综合: R2(时效性)和R5(操作风险)权重最高
    weights = {'R1_PROVENANCE': 0.15, 'R2_CURRENCY': 0.25,
               'R3_COMPLEXITY': 0.15, 'R4_COMPLIANCE': 0.20,
               'R5_OPERATIONAL': 0.25}
    overall = sum(risks[k].score * weights.get(k, 0.2) for k in risks)

    level = ('CRITICAL' if overall >= 7 else 'HIGH' if overall >= 5
             else 'MEDIUM' if overall >= 3 else 'LOW')

    # 优先缓解: 取得分最高的2个维度
    sorted_risks = sorted(risks.items(), key=lambda x: -x[1].score)
    priorities = [f'{dim}={score:.1f}: {", ".join(risk.factors[:2])}'
                  for dim, risk in sorted_risks[:3] if risk.score >= 2.0]

    threats = []
    for _, risk in sorted_risks:
        for f in risk.factors:
            if f not in threats:
                threats.append(f)

    return SupplyChainHeatmap(
        target=target, risks=risks,
        overall_score=round(overall, 1), overall_risk=level,
        top_threats=threats[:10],
        mitigation_priority=priorities)
