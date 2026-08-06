"""
密码学弹性综合评分 — 将多维度密码学审计输出融合为单一0-100弹性分值。

修改记录:
  2025-08-19 13:45 — 初始实现: 7维加权融合/归一化/置信度加权/弹性等级映射

设计意图:
  既有16个模块各输出独立的评分/报告(泄漏评分/敏捷性/老化/密钥生命周期/熵源/编译器...),
  但无机制将这些独立信号融合为全局的"此密码学实现有多安全"评分。
  安全审计者需要回答的不是"这有3个HIGH风险和2个MEDIUM风险",
  而是"整体弹性评分47/100, 主要拖累因素是密钥未清零和AES-128老化"。

  本模块作为元分析层, 从各子模块输出中提取标准化信号, 加权融合:
    D1 (侧信道抗性, 权重0.20): 来自leakage_scorer — 低泄漏=高分
    D2 (敏捷性, 权重0.18): 来自crypto_agility — 高敏捷=高分
    D3 (算法现代性, 权重0.18): 来自crypto_aging — 未老化=高分
    D4 (密钥管理, 权重0.16): 来自crypto_key_lifecycle — 完整生命周期=高分
    D5 (熵源质量, 权重0.12): 来自entropy_source_auditor — 强熵源=高分
    D6 (编译器安全, 权重0.08): 来自crypto_compiler_prov — CT保留=高分
    D7 (实现纯洁性, 权重0.08): 来自crypto_diversity+whitebox_detector — 单一实现=高分

  各维度输入通过duck typing兼容 — 不强制导入所有依赖模块,
  未提供的维度使用保守默认值(0.5), 并在报告中标记为ESTIMATED。

参考:
  - NIST CSF 2.0 (2024): 网络安全框架 — 治理/识别/保护/检测/响应/恢复六功能,
    本评分映射到"保护"功能中的密码学子域。
  - OWASP Application Security Verification Standard (ASVS) V9 (2024):
    密码学验证要求 — 本评分为ASVS V9的自动化量化实现。
  - CVSS v4.0 (2023): 漏洞评分方法论 — 本评分借鉴其多维度加权融合结构。

边界条件:
  - 评分融合的精度取决于输入质量 — 各子模块的静态分析置信度会传播到综合评分。
  - 未提供的维度不强制要求 — 缺失维度降低综合评分的置信度但不降低分值本身。
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass
class ResilienceInput:
    """单个维度的弹性输入 — 子模块可通过duck typing提供。"""
    dimension: str = ""
    raw_score: float = 0.0      # 子模块的原始输出(0-1或逆向0-1)
    confidence: float = 0.0     # 子模块输出的置信度
    inverted: bool = False      # True=高分表示差(如leakage_scorer), 需反转
    source: str = ""            # 来源模块名


_DEFAULT_WEIGHTS: Dict[str, float] = {
    'side_channel': 0.20,
    'agility': 0.18,
    'algorithm_age': 0.18,
    'key_lifecycle': 0.16,
    'entropy_source': 0.12,
    'compiler_security': 0.08,
    'implementation_purity': 0.08,
}


@dataclass
class ResilienceReport:
    overall_score: float = 0.0         # 0-100
    overall_confidence: float = 0.0
    resilience_level: str = "UNKNOWN"  # CRITICAL/POOR/FAIR/GOOD/STRONG/EXCELLENT
    dimension_scores: Dict[str, float] = field(default_factory=dict)
    dimension_confidences: Dict[str, float] = field(default_factory=dict)
    top_weaknesses: List[str] = field(default_factory=list)
    top_strengths: List[str] = field(default_factory=list)
    estimated_dimensions: List[str] = field(default_factory=list)
    narrative: str = ""


def _normalize_input(dim: str, raw: float, inverted: bool, conf: float) -> Tuple[float, float]:
    """将子模块原始输出归一化到0-1弹性空间(1=最优)。"""
    clamped = max(0.0, min(1.0, raw))
    normalized = 1.0 - clamped if inverted else clamped
    weighted_conf = conf * 0.9 + 0.1
    return normalized, weighted_conf


def _extract_from_leakage_report(report) -> ResilienceInput:
    """从leakage_scorer的LeakageReport提取弹性输入。"""
    try:
        return ResilienceInput(
            dimension='side_channel',
            raw_score=report.composite_score,
            confidence=getattr(report, 'confidence', 0.5),
            inverted=True,  # 高泄漏评分=差
            source='leakage_scorer')
    except Exception:
        return ResilienceInput(dimension='side_channel', raw_score=0.5,
                               confidence=0.3, inverted=True, source='estimated')


def _extract_from_agility_report(report) -> ResilienceInput:
    """从crypto_agility的AgilityReport提取弹性输入。"""
    try:
        return ResilienceInput(
            dimension='agility',
            raw_score=report.composite_score,
            confidence=0.7,
            inverted=True,  # 高僵化评分=差
            source='crypto_agility')
    except Exception:
        return ResilienceInput(dimension='agility', raw_score=0.5,
                               confidence=0.3, inverted=True, source='estimated')


def _extract_from_aging_report(report_or_list) -> ResilienceInput:
    """从crypto_aging的AgingReport列表提取弹性输入 — 取平均老化评分。"""
    try:
        reports = report_or_list if isinstance(report_or_list, list) else [report_or_list]
        if not reports:
            raise ValueError("empty")
        avg_age = sum(getattr(r, 'aging_score', 0.5) for r in reports) / len(reports)
        return ResilienceInput(
            dimension='algorithm_age',
            raw_score=avg_age, confidence=0.75,
            inverted=True, source='crypto_aging')
    except Exception:
        return ResilienceInput(dimension='algorithm_age', raw_score=0.3,
                               confidence=0.3, inverted=True, source='estimated')


def _extract_from_key_lifecycle(report_or_list) -> ResilienceInput:
    """从crypto_key_lifecycle的KeyLifecycleReport提取弹性输入。"""
    try:
        reports = report_or_list if isinstance(report_or_list, list) else [report_or_list]
        if not reports:
            raise ValueError("empty")
        avg_completeness = sum(getattr(r, 'lifecycle_completeness', 0.5)
                               for r in reports) / len(reports)
        any_critical = any(getattr(r, 'risk_level', '') == 'CRITICAL' for r in reports)
        score = avg_completeness * (0.5 if any_critical else 1.0)
        return ResilienceInput(
            dimension='key_lifecycle',
            raw_score=score, confidence=0.70,
            inverted=False, source='crypto_key_lifecycle')
    except Exception:
        return ResilienceInput(dimension='key_lifecycle', raw_score=0.6,
                               confidence=0.3, inverted=False, source='estimated')


def _extract_from_entropy_report(report_or_list) -> ResilienceInput:
    """从entropy_source_auditor的EntropySourceReport提取弹性输入。"""
    try:
        reports = report_or_list if isinstance(report_or_list, list) else [report_or_list]
        if not reports:
            raise ValueError("empty")
        grades = {'HIGH': 1.0, 'MEDIUM': 0.6, 'LOW': 0.3, 'CRITICAL': 0.0}
        best_grade = min(getattr(r, 'grade', None) for r in reports if hasattr(r, 'grade'))
        best_name = best_grade.name if hasattr(best_grade, 'name') else 'MEDIUM'
        score = grades.get(best_name, 0.5)
        return ResilienceInput(
            dimension='entropy_source',
            raw_score=score, confidence=0.80,
            inverted=False, source='entropy_source_auditor')
    except Exception:
        return ResilienceInput(dimension='entropy_source', raw_score=0.6,
                               confidence=0.3, inverted=False, source='estimated')


def _extract_from_compiler_prov(report) -> ResilienceInput:
    """从crypto_compiler_prov的CompilerProvenance提取弹性输入。"""
    try:
        ct_ok = '通常保留' in getattr(report, 'ct_preservation', '')
        simd = getattr(report, 'simd_used', 'NONE')
        # 常量时间保留=高分; SIMD=中性; 手写汇编=中高分
        score = 0.85 if ct_ok else 0.55
        if getattr(report, 'compiler_family', '') == 'HANDWRITTEN_ASM':
            score = 0.70
        return ResilienceInput(
            dimension='compiler_security',
            raw_score=score, confidence=getattr(report, 'confidence', 0.5),
            inverted=False, source='crypto_compiler_prov')
    except Exception:
        return ResilienceInput(dimension='compiler_security', raw_score=0.6,
                               confidence=0.3, inverted=False, source='estimated')


def _extract_from_diversity(report_or_list) -> ResilienceInput:
    """从crypto_diversity的DiversityReport提取弹性输入 — 低多样性=高分。"""
    try:
        reports = report_or_list if isinstance(report_or_list, list) else [report_or_list]
        if not reports:
            raise ValueError("empty")
        avg_div = sum(getattr(r, 'diversity_score', 0.5) for r in reports) / len(reports)
        return ResilienceInput(
            dimension='implementation_purity',
            raw_score=avg_div, confidence=0.65,
            inverted=True, source='crypto_diversity')
    except Exception:
        return ResilienceInput(dimension='implementation_purity', raw_score=0.3,
                               confidence=0.3, inverted=True, source='estimated')


# ── 主评分函数 ──

def compute_resilience(
        leakage_report=None,
        agility_report=None,
        aging_reports: Optional[List] = None,
        key_lifecycle_reports: Optional[List] = None,
        entropy_reports: Optional[List] = None,
        compiler_report=None,
        diversity_reports: Optional[List] = None,
        weights: Optional[Dict[str, float]] = None,
) -> ResilienceReport:
    """
    融合多维度密码学审计输出, 计算综合弹性评分 0-100。
    所有参数可选 — 缺失维度使用保守估计。
    """
    w = weights or _DEFAULT_WEIGHTS

    # 从各子模块提取标准化输入
    inputs: Dict[str, ResilienceInput] = {}
    inputs['side_channel'] = _extract_from_leakage_report(leakage_report)
    inputs['agility'] = _extract_from_agility_report(agility_report)
    inputs['algorithm_age'] = _extract_from_aging_report(aging_reports)
    inputs['key_lifecycle'] = _extract_from_key_lifecycle(key_lifecycle_reports)
    inputs['entropy_source'] = _extract_from_entropy_report(entropy_reports)
    inputs['compiler_security'] = _extract_from_compiler_prov(compiler_report)
    inputs['implementation_purity'] = _extract_from_diversity(diversity_reports)

    # 加权融合
    total_weight = 0.0
    weighted_sum = 0.0
    weighted_conf = 0.0
    dim_scores: Dict[str, float] = {}
    dim_confs: Dict[str, float] = {}
    estimated: List[str] = []

    for dim_name, inp in inputs.items():
        dim_weight = w.get(dim_name, 0.10)
        norm_score, norm_conf = _normalize_input(
            dim_name, inp.raw_score, inp.inverted, inp.confidence)
        weighted_sum += norm_score * dim_weight
        weighted_conf += norm_conf * dim_weight
        total_weight += dim_weight
        dim_scores[dim_name] = round(norm_score * 100, 1)
        dim_confs[dim_name] = round(norm_conf, 2)
        if inp.source == 'estimated':
            estimated.append(dim_name)

    overall = (weighted_sum / total_weight * 100.0) if total_weight > 0 else 50.0
    avg_conf = (weighted_conf / total_weight) if total_weight > 0 else 0.3

    # 弹性等级映射
    if overall >= 90:
        level = 'EXCELLENT'
    elif overall >= 75:
        level = 'STRONG'
    elif overall >= 60:
        level = 'GOOD'
    elif overall >= 40:
        level = 'FAIR'
    elif overall >= 20:
        level = 'POOR'
    else:
        level = 'CRITICAL'

    # 强弱项识别: 取最低3维为弱点, 最高3维为强项
    sorted_dims = sorted(dim_scores.items(), key=lambda x: x[1])
    weaknesses = [f'{d}={s:.0f}' for d, s in sorted_dims[:3] if s < 60]
    strengths = [f'{d}={s:.0f}' for d, s in sorted_dims[-3:] if s >= 75]

    narrative = (f'综合密码学弹性评分 {overall:.0f}/100 [{level}]。'
                 f'{len(estimated)}/{len(dim_scores)}维度为估计值。')

    return ResilienceReport(
        overall_score=round(overall, 1),
        overall_confidence=round(avg_conf, 3),
        resilience_level=level,
        dimension_scores=dim_scores,
        dimension_confidences=dim_confs,
        top_weaknesses=weaknesses,
        top_strengths=strengths,
        estimated_dimensions=estimated,
        narrative=narrative)
