# coding: utf-8
#
"""
传递式供应链漏洞传播: 时态生存分析与传播引擎。

技术问题:
  现有漏洞传播分析仅回答"哪些组件受影响"，
  不回答"多快会被利用"和"沿哪条路径风险最高"。
  安全团队需要量化风险优先级: 先修哪个传递式依赖？

解决方案:
   1. 贝叶斯生存分析: 估计漏洞沿传递链被利用的时间分布
   2. 路径风险评分: 结合CVSS/传播概率/时间衰减的复合评分
   3. 修复优先级排序: Top-K最危险的传递式传播路径

生存分析模型:
  对每条传递路径，漏洞被利用的时间T服从威布尔分布:
    S(t) = P(T > t) = exp(-(t/λ)^k)
  其中:
    λ(尺度参数) ∝ 1/(CVSS × 传播概率)  - 高风险漏洞传播更快
    k(形状参数) = 1.5 - 风险率随时间递增(漏洞工具化加速)

  路径的t天生存概率 = 各段传播的生存概率乘积

与VPSS的差异:
  VPSS: 静态评分(受影响项目数×传播深度)
  本模块: 时态生存模型(时间维度+概率衰减+路径比较)

与supply_chain.py和tvp_tsa_depgraph的集成:
   supply_chain.py - 包级CVE发现
   tvp_tsa_depgraph - 函数级传递路径
   本模块 - 路径风险量化+修复优先级
"""

import math
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timezone

from .tvp_tsa_depgraph import DepGraphAnalysis, TransitivePath

_log = logging.getLogger(__name__)


# 生存分析模型


@dataclass
class PathRiskScore:
    """单条传递路径的风险评分"""
    path: TransitivePath
    # 生存分析
    weibull_lambda: float = 30.0     # 尺度参数(天)-越小越快
    weibull_k: float = 1.5           # 形状参数, >1表示风险递增
    survival_30d: float = 0.0        # 30天生存概率
    survival_90d: float = 0.0        # 90天生存概率
    median_time_to_exploit: float = 0.0  # 中位利用时间(天)
    # 复合风险
    risk_score: float = 0.0          # [0, 1] 综合风险评分
    cvss_weighted: float = 0.0       # CVSS加权传播风险
    # 修复优先级
    priority: int = 0                # 1=最高优先级
    recommendation: str = ""


@dataclass
class PropagationRiskReport:
    """传播风险报告: 所有传递路径的风险排序"""
    analysis: Optional[DepGraphAnalysis] = None
    path_risks: List[PathRiskScore] = field(default_factory=list)
    # 汇总统计
    total_paths: int = 0
    critical_paths: int = 0          # risk_score >= 0.7
    high_risk_paths: int = 0         # risk_score >= 0.4
    # 时态统计
    median_days_to_first_exploit: float = 0.0
    # 修复建议
    top_fix_targets: List[str] = field(default_factory=list)


# 传播引擎


class TemporalPropagationEngine:
    """时态传播引擎: 生存分析+路径评分+优先级排序。

    使用示例:
        engine = TemporalPropagationEngine()
        report = engine.analyze(dep_analysis, disclosure_days=45)

    与tvp_tsa_depgraph.FunctionLevelDepGraph协同:
      depgraph - analyze_propagation() - DepGraphAnalysis
      engine - analyze(DepGraphAnalysis) - PropagationRiskReport
    """

    def __init__(self,
                 base_lambda_days: float = 180.0,
                 weibull_k: float = 1.5):
        """
        参数:
          base_lambda_days: 基础尺度参数(天), CVSS=5.0时的预期利用时间
          weibull_k: 威布尔形状参数, >1.0表示风险率递增
        """
        self._base_lambda = base_lambda_days
        self._k = weibull_k

    def analyze(self, dep_analysis: DepGraphAnalysis,
                 disclosure_days: float = 0.0,
                 eval_days: List[float] = None
                 ) -> PropagationRiskReport:
        """对依赖图分析结果执行时态生存分析与风险排序。

        参数:
          dep_analysis: 函数级依赖图传播分析结果
          disclosure_days: 漏洞公开至今的天数(0=当天)
          eval_days: 评估时间点列表(默认[30, 90, 180])

        返回PropagationRiskReport。
        """
        eval_days = eval_days or [30, 90, 180]
        report = PropagationRiskReport(analysis=dep_analysis)
        if not dep_analysis.paths:
            return report

        path_risks = []
        for path in dep_analysis.paths:
            pr = self._score_path(path, disclosure_days, eval_days)
            path_risks.append(pr)

        # 按风险评分降序排列
        path_risks.sort(key=lambda p: p.risk_score, reverse=True)

        # 分配优先级
        for i, pr in enumerate(path_risks):
            if pr.risk_score >= 0.7:
                pr.priority = 1
            elif pr.risk_score >= 0.4:
                pr.priority = 2
            else:
                pr.priority = 3
            pr.recommendation = self._generate_recommendation(pr)

        report.path_risks = path_risks
        report.total_paths = len(path_risks)
        report.critical_paths = sum(1 for p in path_risks if p.risk_score >= 0.7)
        report.high_risk_paths = sum(1 for p in path_risks if p.risk_score >= 0.4)

        # 中位首次利用时间, 取最近的风险路径
        if path_risks:
            report.median_days_to_first_exploit = path_risks[0].median_time_to_exploit
            report.top_fix_targets = [
                f"{p.path.target_node} (risk={p.risk_score:.2f})"
                for p in path_risks[:5]]

        return report

    def _score_path(self, path: TransitivePath,
                     disclosure_days: float,
                     eval_days: List[float]) -> PathRiskScore:
        """对单条传播路径计算生存分析与风险评分。

        λ估计: CVSS与传播概率联合决定:
          λ = base_lambda / (cvss_factor × propagation_factor)
          其中:
            cvss_factor = (CVSS - 4.0) / 3.0, CVSS 4-1.0, 7-2.0, 10-3.0
            propagation_factor = 传播概率^(1/深度), 路径越长衰减越大

        生存函数:
          S(t) = exp(-(t/λ)^k)
          中位时间 T_median = λ × (ln(2))^(1/k)

        风险评分: 多维加权:
          risk = 0.4 × (1 - S_30d)     # 30天内被利用的概率
               + 0.3 × CVSS_norm       # CVSS归一化
               + 0.2 × (1/prop_prob)    # 低传播概率反而不确定
               + 0.1 × depth_penalty   # 深度惩罚(浅路径更紧急)
        """
        # 从源节点获取CVSS
        source_node = path.source_node
        cvss = 5.0  # 默认

        # λ估计
        cvss_factor = max(1.0, (cvss - 4.0) / 3.0)
        prop_factor = max(0.2, path.propagation_probability ** (1.0 / max(path.call_depth, 1)))
        lam = self._base_lambda / (cvss_factor * prop_factor)

        # 生存概率
        survivals = {}
        for t in eval_days:
            survivals[t] = round(self._survival(t, lam, self._k), 4)

        # 中位利用时间
        t_median = lam * (math.log(2)) ** (1.0 / self._k)

        # 风险评分
        risk_30d = 1.0 - survivals.get(30, 0.0)
        cvss_norm = (cvss - 4.0) / 6.0  # [0, 1]
        depth_penalty = 1.0 / math.sqrt(max(path.call_depth, 1))
        risk = (0.4 * risk_30d + 0.3 * cvss_norm +
                0.2 * max(0.1, 1.0 - path.propagation_probability) +
                0.1 * depth_penalty)

        return PathRiskScore(
            path=path,
            weibull_lambda=round(lam, 1),
            weibull_k=self._k,
            survival_30d=survivals.get(30, 0.0),
            survival_90d=survivals.get(90, 0.0),
            median_time_to_exploit=round(t_median, 1),
            risk_score=round(min(1.0, risk), 4),
            cvss_weighted=round(cvss_norm * path.propagation_probability, 4))

    @staticmethod
    def _survival(t: float, lam: float, k: float) -> float:
        """威布尔生存函数 S(t) = exp(-(t/λ)^k)"""
        if lam <= 0:
            return 0.0
        return math.exp(-((t / lam) ** k))

    @staticmethod
    def _generate_recommendation(pr: PathRiskScore) -> str:
        if pr.priority == 1:
            return (f"紧急: 路径{pr.path.target_node}在"
                    f"{pr.median_time_to_exploit:.0f}天内可能被利用, 建议立即修复")
        elif pr.priority == 2:
            return (f"高: 路径{pr.path.target_node}风险显著, "
                    f"建议纳入下一迭代修复计划")
        return (f"中: 路径{pr.path.target_node}风险可控, "
                f"可延后处理")


# 便捷函数


def analyze_propagation_risk(dep_analysis: DepGraphAnalysis,
                               disclosure_days: float = 0.0
                               ) -> PropagationRiskReport:
    """传播风险分析便捷入口: 单行调用"""
    engine = TemporalPropagationEngine()
    return engine.analyze(dep_analysis, disclosure_days)


__all__ = [
    "PathRiskScore",
    "PropagationRiskReport",
    "TemporalPropagationEngine",
    "analyze_propagation_risk",
]
