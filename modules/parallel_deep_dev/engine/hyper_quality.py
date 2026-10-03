"""
创建: 2025-01-13
超参优化质量评分 — 从多维度验证结果计算综合分数。
"""



def compute_quality_score(
    syntax_pass_rate: float = 1.0,
    drift_violation_rate: float = 0.0,
    convergence_rate: float = 0.0,
    quality_anomaly_rate: float = 0.0,
    review_pass_rate: float = 1.0,
) -> float:
    """加权组合各维度质量指标。权重反映各维度的相对重要性。"""
    score = (
        0.30 * syntax_pass_rate
        + 0.25 * (1.0 - drift_violation_rate)
        + 0.20 * (1.0 - convergence_rate)
        + 0.15 * (1.0 - quality_anomaly_rate)
        + 0.10 * review_pass_rate
    )
    return max(0.0, min(1.0, score))
