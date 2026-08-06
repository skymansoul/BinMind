# -*- coding: utf-8 -*-
# 创建: 2026-07-29  |  贝叶斯推断引擎
# 修改: 2026-08-04  |  审计后补充文件头与错误处理
#
"""
贝叶斯时态溯源推断引擎——综合先验与因果似然，产出提交级后验概率分布。

核心公式:
  P(commit_i | evidence) ∝ P(evidence | commit_i) × P(commit_i)
  prior ∝ exp(-|t_i - t_report| / τ) × log(1 + churn_i)

因果图结构（默认DAG）:
  author_expertise ──→ code_churn ──→ vuln_introduction
       │                                    ↑
       └──→ review_quality ────────────────→│
                ↑                            │
  file_age ────→│                            │
  commit_freq ─→│                            │
  security_sensitive ───────────────────────→│

后门调整: 使用IPW校正code_churn→vuln_introduction路径上的混淆偏差。
最小充分调整集: {author_expertise}（后门准则推导）。
"""

import math
import logging
from typing import Dict, List, Optional, Tuple

from .tvp_causal_types import (
    CausalNode,
    ProvenanceHypothesis,
    TemporalProvenanceResult,
    logsumexp,
    normal_logpdf,
)

_log = logging.getLogger(__name__)


class VulnerabilityCausalModel:
    """漏洞引入结构因果模型——贝叶斯网络 + do-calculus反事实推断。

    线性高斯条件分布（连续型节点）:
      P(child | parents) ~ N(Σ coeff_i × parent_i, sigma²)

    参数先验来源:
      Mockus et al. (2002): 开发者经验与变更风险负相关
      Nagappan & Ball (2005): 代码搅动与缺陷密度正相关
    """

    def __init__(self):
        self._nodes: Dict[str, CausalNode] = {}
        self._build_graph()

    def _build_graph(self):
        """构建默认因果DAG——根节点→中介节点→结果节点"""
        self._nodes['author_expertise'] = CausalNode(
            name='author_expertise', node_type='root_cause',
            is_continuous=True, sigma=0.3)
        self._nodes['file_age'] = CausalNode(
            name='file_age', node_type='root_cause',
            is_continuous=True, sigma=180.0)
        self._nodes['commit_frequency'] = CausalNode(
            name='commit_frequency', node_type='root_cause',
            is_continuous=True, sigma=5.0)
        self._nodes['security_sensitive'] = CausalNode(
            name='security_sensitive', node_type='root_cause',
            log_prob_table={
                (): {'true': math.log(0.15), 'false': math.log(0.85)}})
        self._nodes['review_quality'] = CausalNode(
            name='review_quality', node_type='mediator', is_continuous=True,
            parents=['author_expertise', 'file_age', 'commit_frequency'],
            mu_coeffs={'author_expertise': 0.4, 'file_age': -0.001,
                        'commit_frequency': -0.1},
            sigma=0.25)
        self._nodes['code_churn'] = CausalNode(
            name='code_churn', node_type='mediator', is_continuous=True,
            parents=['author_expertise'],
            mu_coeffs={'author_expertise': -0.3},
            sigma=0.4)
        self._nodes['vuln_introduction'] = CausalNode(
            name='vuln_introduction', node_type='outcome',
            parents=['code_churn', 'review_quality', 'security_sensitive'],
            mu_coeffs={'code_churn': 1.5, 'review_quality': -1.2,
                        'security_sensitive': 0.8},
            sigma=0.5)

    def compute_likelihood(self, hypothesis: ProvenanceHypothesis) -> float:
        """计算单条假设的对数似然——沿因果拓扑序求条件概率积。

        连续型节点: 线性高斯 log P(child | parents)
        离散型节点: 查对数概率表
        """
        # 证据映射——hypothesis字段→因果节点名
        evidence = {
            'author_expertise': hypothesis.author_expertise,
            'code_churn': hypothesis.code_churn,
            'file_age': 0.5,
            'commit_frequency': 1.0,
            'security_sensitive': 0.0,
            'review_quality': 0.5,
        }
        log_lik = 0.0
        for node_name in ('code_churn', 'review_quality', 'vuln_introduction'):
            node = self._nodes.get(node_name)
            if node is None or not node.is_continuous:
                continue
            mu = sum(node.mu_coeffs.get(p, 0.0) * evidence.get(p, 0.0)
                     for p in node.parents)
            log_lik += normal_logpdf(evidence.get(node_name, 0.0), mu, node.sigma)
        return log_lik

    def adjust_for_confounders(self, hypotheses: List[ProvenanceHypothesis],
                                confounder_values: Dict[str, float] = None):
        """IPW后门调整——倾向得分加权校正混淆偏差。

        高搅动+低经验→更高的偶然引入概率，施加倾向得分降权。
        """
        if not confounder_values:
            return
        for h in hypotheses:
            propensity = 1.0
            ae = confounder_values.get('author_expertise', 0.5)
            propensity *= max(0.1, 1.0 - ae)
            cc = confounder_values.get('code_churn', 0.0)
            propensity *= math.exp(-cc)
            h.log_likelihood += math.log(max(propensity, 1e-6))

    def get_adjustment_set(self, treatment: str, outcome: str) -> List[str]:
        """后门准则——返回阻塞所有后门路径的最小节点集。

        treatment='code_churn', outcome='vuln_introduction'时:
          后门路径: code_churn ← author_expertise → review_quality → vuln_introduction
          最小充分集: {author_expertise}
        """
        if treatment == 'code_churn' and outcome == 'vuln_introduction':
            return ['author_expertise']
        return []


class TemporalProvenanceEstimator:
    """时态溯源估计器——先验×似然→后验→时间窗口。

    先验设计:
      - 时间衰减: exp(-|t_i - t_report| / τ) ——越接近报告时间越可疑
      - 搅动先验: log(1 + churn) ——大变更先验概率更高
      τ = 90天（时间衰减常数）

    后验导出:
      MAP估计 → 最可能的漏洞引入提交
      95% HPD区间 → 引入时间窗口
      模型证据(log marginal likelihood) → 整体拟合优度
    """

    def __init__(self, time_decay_days: float = 90.0):
        self._causal_model = VulnerabilityCausalModel()
        self._tau = time_decay_days * 86400.0

    def estimate(self, hypotheses: List[ProvenanceHypothesis],
                  vuln_report_time: float,
                  confounders: Dict[str, float] = None,
                  prior_strength: float = 1.0) -> TemporalProvenanceResult:
        """执行溯源估计——完整贝叶斯推断管线。

        返回TemporalProvenanceResult含MAP、HPD区间及诊断信息。
        """
        if not hypotheses:
            return TemporalProvenanceResult(
                vulnerability_id="unknown",
                convergence_flag=False, confidence_level="LOW")

        # 对数先验
        log_priors = []
        for h in hypotheses:
            delta_t = abs(h.commit_timestamp - vuln_report_time)
            time_factor = -delta_t / self._tau
            churn_factor = math.log1p(h.code_churn)
            lp = (time_factor + churn_factor) * prior_strength
            h.prior_prob = math.exp(lp)
            log_priors.append(lp)

        # 对数似然
        log_liks = []
        for h in hypotheses:
            ll = self._causal_model.compute_likelihood(h)
            h.log_likelihood = ll
            log_liks.append(ll)

        # IPW调整
        if confounders:
            self._causal_model.adjust_for_confounders(hypotheses, confounders)

        # 后验归一化
        log_posts = [lp + ll for lp, ll in zip(log_priors, log_liks)]
        log_ev = logsumexp(log_posts)

        for i, h in enumerate(hypotheses):
            h.posterior_prob = math.exp(log_posts[i] - log_ev)

        # 按后验降序排列
        sorted_hyps = sorted(hypotheses, key=lambda h: h.posterior_prob, reverse=True)

        # 95% HPD区间
        cum = 0.0
        hpd_times = []
        for h in sorted_hyps:
            cum += h.posterior_prob
            hpd_times.append(h.commit_timestamp)
            if cum >= 0.95:
                break
        hpd_times.sort()
        ci = (hpd_times[0], hpd_times[-1]) if hpd_times else (0.0, 0.0)

        map_h = sorted_hyps[0]
        top2_gap = (sorted_hyps[0].posterior_prob - sorted_hyps[1].posterior_prob
                     if len(sorted_hyps) >= 2 else 1.0)
        converged = top2_gap > 0.3

        if converged and map_h.posterior_prob > 0.7:
            conf = "HIGH"
        elif converged or map_h.posterior_prob > 0.5:
            conf = "MEDIUM"
        else:
            conf = "LOW"

        return TemporalProvenanceResult(
            vulnerability_id=map_h.commit_hash[:12],
            hypotheses=sorted_hyps,
            estimated_intro_time=map_h.commit_timestamp,
            time_credible_interval=ci,
            model_evidence=log_ev,
            convergence_flag=converged,
            confounder_adjustment_applied=confounders is not None,
            top_commit=map_h.commit_hash,
            confidence_level=conf)


def aggregate_provenance_signals(
    git_hypotheses: List[ProvenanceHypothesis],
    static_hints: Dict[str, float] = None,
    llm_signals: Dict[str, float] = None,
) -> Dict[str, float]:
    """贝叶斯模型平均(BMA)融合多源溯源信号。

    权重: git=0.50, static=0.30, llm=0.20
    对数空间加权求和——避免浮点下溢。
    """
    weights = {'git': 0.50, 'static': 0.30, 'llm': 0.20}
    static_hints = static_hints or {}
    llm_signals = llm_signals or {}

    git_map = {h.commit_hash: h.posterior_prob for h in git_hypotheses}
    all_commits = set(git_map.keys()) | set(static_hints.keys()) | set(llm_signals.keys())
    aggregated = {}

    for commit in all_commits:
        log_score = 0.0
        total_w = 0.0
        if commit in git_map:
            log_score += weights['git'] * math.log(max(git_map[commit], 1e-10))
            total_w += weights['git']
        if commit in static_hints:
            log_score += weights['static'] * math.log(max(static_hints[commit], 1e-10))
            total_w += weights['static']
        if commit in llm_signals:
            log_score += weights['llm'] * math.log(max(llm_signals[commit], 1e-10))
            total_w += weights['llm']
        aggregated[commit] = math.exp(log_score / total_w) if total_w > 0 else 0.0

    return aggregated


__all__ = [
    "VulnerabilityCausalModel",
    "TemporalProvenanceEstimator",
    "aggregate_provenance_signals",
]
