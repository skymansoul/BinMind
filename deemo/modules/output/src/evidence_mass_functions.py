"""
D-S 证据融合的源特化 mass 函数 — 从分析模块输出到 BPA 的映射。

四个分析源各自有不同的可靠性特征，mass 函数反映这些差异:
  - 静态分析: 模式匹配精确度高，误报率已知
  - 动态 fuzz:  崩溃复现+覆盖率双信号，崩溃多样性降低 ignorance
  - LLM 推理:   过度自信，温度+多轮一致性修正，ignorance 下限最高
  - 符号执行:   路径约束满足率，solver 超时→ignorance 大幅提升

与 Shafer (1976) 经典 discounting 的关系:
  传统 discounting 对不可靠源统一降低 mass 并增加 Θ。
  本模块的 discounting 是源特化的 — 每个源的 discount 因子
  取决于该源特有的可靠性信号 (温度的效应 ≠ 误报率的效应)。

修改记录:
  创建 2026-07-31
"""

import math
from modules.output.src.evidence_fusion import EvidenceSource


def _sigmoid_steep(x: float, k: float = 8.0, x0: float = 0.5) -> float:
    return 1.0 / (1.0 + math.exp(-k * (x - x0)))


def mass_from_static(pattern_match_count: int, severity_score: float,
                     false_positive_rate: float = 0.0) -> EvidenceSource:
    mc_norm = min(pattern_match_count / 5.0, 1.0)
    sev_norm = min(severity_score / 10.0, 1.0)
    raw_mass_v = 0.3 * mc_norm + 0.7 * sev_norm
    mass_v = 0.01 + 0.98 * raw_mass_v
    mass_theta = 0.05 + 0.25 * false_positive_rate
    mass_not_v = max(0.0, 1.0 - mass_v - mass_theta)
    return EvidenceSource(
        source_name='static', mass_v=round(mass_v, 6),
        mass_not_v=round(mass_not_v, 6), mass_theta=round(mass_theta, 6),
        confidence=raw_mass_v)


def mass_from_fuzz(crash_repro_rate: float, edge_coverage: float,
                   unique_crashes: int = 0) -> EvidenceSource:
    repro_sig = _sigmoid_steep(crash_repro_rate, k=6.0, x0=0.3)
    cov_sig = _sigmoid_steep(edge_coverage, k=4.0, x0=0.4)
    raw_mass_v = 0.55 * repro_sig + 0.45 * cov_sig
    mass_v = 0.01 + 0.98 * raw_mass_v
    diversity_factor = min(unique_crashes / 10.0, 1.0)
    mass_theta = max(0.03, 0.30 - 0.27 * diversity_factor)
    mass_not_v = max(0.0, 1.0 - mass_v - mass_theta)
    return EvidenceSource(
        source_name='fuzz', mass_v=round(mass_v, 6),
        mass_not_v=round(mass_not_v, 6), mass_theta=round(mass_theta, 6),
        confidence=raw_mass_v)


def mass_from_llm(llm_confidence: float, temperature: float,
                  agreement_count: int = 1) -> EvidenceSource:
    temp_penalty = max(0.0, 1.0 - (temperature - 0.1) / 0.9)
    adjusted_conf = llm_confidence * temp_penalty
    agreement_boost = min((agreement_count - 1) * 0.12, 0.36)
    adjusted_conf = min(adjusted_conf + agreement_boost, 1.0)
    raw_mass_v = _sigmoid_steep(adjusted_conf, k=5.0, x0=0.55)
    mass_v = 0.02 + 0.94 * raw_mass_v
    base_theta = 0.08 + 0.30 * (1.0 - agreement_boost / 0.36)
    mass_theta = min(base_theta, 0.50)
    mass_not_v = max(0.0, 1.0 - mass_v - mass_theta)
    return EvidenceSource(
        source_name='llm', mass_v=round(mass_v, 6),
        mass_not_v=round(mass_not_v, 6), mass_theta=round(mass_theta, 6),
        confidence=llm_confidence)


def mass_from_symbex(path_sat_rate: float, constraint_count: int,
                     solver_timeout: bool = False) -> EvidenceSource:
    sat_sig = _sigmoid_steep(path_sat_rate, k=6.0, x0=0.4)
    constraint_norm = min(constraint_count / 20.0, 1.0)
    raw_mass_v = 0.6 * sat_sig + 0.4 * constraint_norm
    mass_v = 0.01 + 0.98 * raw_mass_v
    if solver_timeout:
        mass_theta = 0.25 + 0.15 * (1.0 - path_sat_rate)
    else:
        mass_theta = 0.03 + 0.12 * (1.0 - path_sat_rate)
    mass_not_v = max(0.0, 1.0 - mass_v - mass_theta)
    return EvidenceSource(
        source_name='symbex', mass_v=round(mass_v, 6),
        mass_not_v=round(mass_not_v, 6), mass_theta=round(mass_theta, 6),
        confidence=raw_mass_v)
