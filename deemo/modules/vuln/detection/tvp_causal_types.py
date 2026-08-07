# coding: utf-8
# 创建: 2026-07-18  |  类型定义与概率原语
# 修改: 2026-07-18  |  审计后补充文件头与错误处理
#
"""
时态漏洞溯源类型定义——贝叶斯因果模型的概率原语与数据结构。

设计依据:
  - 连续型节点: 线性高斯条件分布，避免离散化精度损失
  - 离散型节点: 对数概率表，支持稀疏父节点组合
  - 概率计算全部在对数空间进行，防止浮点下溢
"""

import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


# 数值稳定工具


def logsumexp(values: List[float]) -> float:
    """log-sum-exp——减去最大值防止指数溢出"""
    if not values:
        return float('-inf')
    mx = max(values)
    if mx == float('-inf'):
        return float('-inf')
    return mx + math.log(sum(math.exp(v - mx) for v in values))


def normal_logpdf(x: float, mu: float, sigma: float) -> float:
    """正态分布对数概率密度"""
    if sigma <= 0:
        return float('-inf')
    z = (x - mu) / sigma
    return -0.5 * z * z - math.log(sigma) - 0.9189385332046727


# 因果图节点


@dataclass
class CausalNode:
    """结构因果模型节点。

    is_continuous=False → log_prob_table: 父节点取值组合→当前取值→对数概率
    is_continuous=True  → mu_coeffs: 父节点名→线性系数; sigma: 条件标准差
    """
    name: str
    node_type: str           # root_cause | mediator | confounder | outcome
    parents: List[str] = field(default_factory=list)
    is_continuous: bool = False
    # 离散型
    log_prob_table: Dict[Tuple, Dict[str, float]] = field(default_factory=dict)
    # 连续型
    mu_coeffs: Dict[str, float] = field(default_factory=dict)
    sigma: float = 1.0


# 溯源假设


@dataclass
class ProvenanceHypothesis:
    """单条溯源假设——候选提交作为漏洞引入点"""
    commit_hash: str
    commit_timestamp: float
    author_expertise: float          # [0, 1]
    files_changed: List[str] = field(default_factory=list)
    lines_added: int = 0
    lines_removed: int = 0
    code_churn: float = 0.0          # 归一化变更量 [0, 1]
    # 贝叶斯后验
    prior_prob: float = 1.0
    posterior_prob: float = 0.0
    log_likelihood: float = 0.0
    # 因果元数据
    causal_path: str = ""            # direct_modification|dependency_change|config_change
    confounders: List[str] = field(default_factory=list)


@dataclass
class TemporalProvenanceResult:
    """时态溯源完整输出"""
    vulnerability_id: str
    hypotheses: List[ProvenanceHypothesis] = field(default_factory=list)
    estimated_intro_time: float = 0.0
    time_credible_interval: Tuple[float, float] = (0.0, 0.0)
    model_evidence: float = 0.0
    convergence_flag: bool = False
    confounder_adjustment_applied: bool = False
    top_commit: str = ""
    confidence_level: str = "LOW"


__all__ = [
    "logsumexp",
    "normal_logpdf",
    "CausalNode",
    "ProvenanceHypothesis",
    "TemporalProvenanceResult",
]
