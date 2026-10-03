"""
多维度二进制漏洞分析的统计数据结构。

定义漏洞分布、风险评分、相关分析、变点检测、分布外检测、
趋势分解及 API 响应封装的规范输出类型。

所有模型基于 dataclass，提供标准化 to_dict() 序列化。
StatisticType 枚举作为统计 API 全模块的分发键。
"""

import logging
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Dict, List

_log = logging.getLogger(__name__)


# 统计类型枚举 — 全统计查询的分发键

class StatisticType(StrEnum):
    VULNERABILITY_DISTRIBUTION = "vulnerability_distribution"
    HIGH_RISK_FUNCTIONS = "high_risk_functions"
    SEVERITY_TREND = "severity_trend"
    ANALYSIS_METRICS = "analysis_metrics"
    EXPLOITABILITY_SCORES = "exploitability_scores"
    RISK_MATRIX = "risk_matrix"
    CORRELATION_ANALYSIS = "correlation_analysis"
    CHANGE_POINTS = "change_points"
    OOD_ANALYSIS = "ood_analysis"
    REMEDIATION_ORDER = "remediation_order"


# 漏洞分布与风险模型

@dataclass
class VulnerabilityDistribution:
    """按类型、严重度、架构三维汇总的漏洞计数。"""
    by_type: Dict[str, int]
    by_severity: Dict[str, int]
    by_architecture: Dict[str, int]
    total_vulnerabilities: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            'by_type': self.by_type,
            'by_severity': self.by_severity,
            'by_architecture': self.by_architecture,
            'total_vulnerabilities': self.total_vulnerabilities
        }


@dataclass
class HighRiskFunction:
    """单个函数的聚合漏洞计数与综合风险评分。

    composite_risk = severity_score * (1 + alpha * caller_count)
    其中 alpha=0.15 控制调用图传播系数，避免淹没核心分数。
    """
    function_name: str
    vulnerability_count: int
    severity_score: int
    exploitability_score: int
    address: int
    callers: List[str] = field(default_factory=list)
    composite_risk: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            'function_name': self.function_name,
            'vulnerability_count': self.vulnerability_count,
            'severity_score': self.severity_score,
            'exploitability_score': self.exploitability_score,
            'address': hex(self.address),
            'callers': self.callers,
            'composite_risk': self.composite_risk
        }


@dataclass
class SeverityTrend:
    """按日期排序的各严重度级别的漏洞时序。"""
    dates: list = field(default_factory=list)
    critical: list = field(default_factory=list)
    high: list = field(default_factory=list)
    medium: list = field(default_factory=list)
    low: list = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'dates': self.dates,
            'critical': self.critical,
            'high': self.high,
            'medium': self.medium,
            'low': self.low
        }


@dataclass
class AnalysisMetrics:
    """分析会话的汇总结果与性能聚合。"""
    total_analyses: int
    successful_analyses: int
    failed_analyses: int
    average_time: float
    coverage_rate: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            'total_analyses': self.total_analyses,
            'successful_analyses': self.successful_analyses,
            'failed_analyses': self.failed_analyses,
            'average_time': self.average_time,
            'coverage_rate': self.coverage_rate
        }


# 可利用性与风险评分模型

@dataclass
class ExploitabilityBreakdown:
    """exploitability 分数的五数概括 + 熵度量。

    高熵 → 目标间利用难度差异大；
    低熵 → 同质——要么普遍易利用，要么普遍难利用。
    """
    mean_score: float
    median_score: float
    max_score: float
    min_score: float
    std_dev: float
    score_entropy: float
    total_vulnerabilities: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            'mean_score': self.mean_score,
            'median_score': self.median_score,
            'max_score': self.max_score,
            'min_score': self.min_score,
            'std_dev': self.std_dev,
            'score_entropy': self.score_entropy,
            'total_vulnerabilities': self.total_vulnerabilities
        }


@dataclass
class RiskMatrix:
    """严重度 × 可利用性的二维交叉制表 + 象限标注。

    象限框架基于 EPSS+CVSS 联合决策：
    - critical/high 严重度 + high exploitability → 立即响应
    - 绝对值阈值（严重度>=8, exploitability>=7）保持跨项目可比性。
    """
    cells: Dict[str, Dict[str, int]] = field(default_factory=dict)
    quadrant_labels: Dict[str, str] = field(default_factory=dict)
    total_classified: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            'cells': self.cells,
            'quadrant_labels': self.quadrant_labels,
            'total_classified': self.total_classified
        }


# 时序分解与相关分析模型

@dataclass
class TrendDecomposition:
    """加性分解：原始序列 = 趋势 + 残差。

    趋势项由窗口为 3 的中心移动平均提取。
    残差波动率 = 残差标准差，标记偏离平滑趋势的异常波动期。
    """
    dates: List[str] = field(default_factory=list)
    original: Dict[str, List[float]] = field(default_factory=dict)
    trend: Dict[str, List[float]] = field(default_factory=dict)
    residual: Dict[str, List[float]] = field(default_factory=dict)
    residual_volatility: Dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'dates': self.dates,
            'original': self.original,
            'trend': self.trend,
            'residual': self.residual,
            'residual_volatility': self.residual_volatility
        }


@dataclass
class CorrelationReport:
    """三系数相关矩阵：Pearson / Spearman / Kendall。

    三个维度：
    - Pearson: 线性关联（对离群值敏感）
    - Spearman: 单调关联（对离群值稳健）
    - Kendall: 序数一致率（保守，ties 时可靠）

    三者一致则结论可信；分歧需排查非单调或离群值主导的模式。
    """
    pearson: Dict[str, float] = field(default_factory=dict)
    spearman: Dict[str, float] = field(default_factory=dict)
    kendall: Dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'pearson': self.pearson,
            'spearman': self.spearman,
            'kendall': self.kendall
        }


# 异常与变点检测模型

@dataclass
class ChangePointResult:
    """单严重度级别的 CUSUM 结构变化检测结果。

    change_indices: 标准化 CUSUM 超过阈值的位置，
    表示时序中的结构性均值偏移。
    cusum_scores: 完整累积偏差曲线，用于诊断。
    """
    severity: str
    change_indices: List[int] = field(default_factory=list)
    cusum_scores: List[float] = field(default_factory=list)
    detected: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            'severity': self.severity,
            'change_indices': self.change_indices,
            'cusum_scores': self.cusum_scores,
            'detected': self.detected
        }


@dataclass
class OODReport:
    """基于马氏距离的分布外检测报告。

    标记在 (severity, exploitability, type_frequency) 特征空间中
    异常的漏洞。高分离群值可能指示新型攻击模式、
    评分异常或分析器误报。
    """
    ood_vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    anomaly_scores: List[float] = field(default_factory=list)
    threshold: float = 0.0
    count_flagged: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            'ood_vulnerabilities': self.ood_vulnerabilities,
            'anomaly_scores': self.anomaly_scores,
            'threshold': self.threshold,
            'count_flagged': self.count_flagged
        }


# API 响应封装

@dataclass
class APIResponse:
    """全统计端点查询的统一响应封装。"""
    statistic_type: StatisticType
    data: Any
    timestamp: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            'statistic_type': self.statistic_type.value,
            'data': self.data,
            'timestamp': self.timestamp
        }
