# 序贯假设检验-在线漏洞检测中的证据累积决策
#
# 核心问题: 现有漏洞检测是单次分类。在持续扫描场景中，
# 同一二进制被多次扫描但各次独立判断-浪费了历史信息。
#
# 技术方案（Wald SPRT + 领域特定的先验估计和证据衰减）:
#   1. Wald序贯概率比检验: 维护证据累积器，每次扫描更新似然比
#   2. 领域定制: 漏洞先验从CVE历史/威胁情报估计，证据随时间指数衰减
#   3. 可控错误率: SPRT框架提供Type I/II error的形式化保证
#
# SPRT是Wald的经典方法。本工作的非平凡改进在于:
# 先验估计: 利用CVE历史和供应商安全记录估计P(H1)
# 证据衰减: 旧扫描证据随时间指数衰减，防止过时信息污染

from __future__ import annotations

import math
import logging
import time
from typing import Dict, List, Optional, Tuple, Any
from collections import defaultdict, deque
from dataclasses import dataclass, field

import numpy as np

logger = logging.getLogger(__name__)


@dataclass
class EvidenceState:
    """单个监控目标的证据累积状态"""
    target_id: str
    log_likelihood_ratio: float = 0.0      # 对数似然比 Σlog(P(x|H1)/P(x|H0))
    n_observations: int = 0
    last_observation_time: float = 0.0
    decision: str = "continue"              # continue / reject_H0 / accept_H0
    observation_history: List[float] = field(default_factory=list)
    prior_log_odds: float = 0.0             # log(P(H1)/P(H0)) 先验


@dataclass
class SPRTConfig:
    """序贯概率比检验配置"""
    alpha: float = 0.01          # Type I error rate (误报率)
    beta: float = 0.05           # Type II error rate (漏报率)
    evidence_decay_days: float = 90.0  # 证据半衰期（天）
    min_observations: int = 3    # 最小观测数才做决策
    max_observations: int = 50   # 最大观测数-强制决策


class SequentialVulnDetector:
    """序贯假设检验-在线漏洞检测中累积证据。

    Wald SPRT决策规则:
      A = (1-β)/α: 接受H1的阈值
      B = β/(1-α): 接受H0的阈值
      若 Λ_n > A → 拒绝H0（判定含漏洞）
      若 Λ_n < B → 接受H0（判定安全）
      否则 → 继续采样

    其中 Λ_n = prior_odds × Π likelihood_ratio_i
    对数空间: log(Λ_n) = log(prior_odds) + Σ log(LR_i)
    """

    def __init__(self, config: Optional[SPRTConfig] = None):
        self.config = config or SPRTConfig()
        self._states: Dict[str, EvidenceState] = {}
        # Wald决策边界（对数空间）
        self._log_A = math.log((1 - self.config.beta) / self.config.alpha)
        self._log_B = math.log(self.config.beta / (1 - self.config.alpha))

    def register_target(self, target_id: str,
                        prior_vuln_prob: Optional[float] = None):
        """注册监控目标，可选指定漏洞先验概率。

        prior_vuln_prob可以是:
          - 基于CVE历史的估计（该供应商过去5年的漏洞密度）
          - 基于代码复杂度的估计（圈复杂度/函数长度）
          - 基于威胁情报的估计（是否有APT组织关注该软件）
        """
        if prior_vuln_prob is None:
            prior_vuln_prob = 0.05  # 默认5%先验

        prior_odds = prior_vuln_prob / (1.0 - prior_vuln_prob)
        self._states[target_id] = EvidenceState(
            target_id=target_id,
            prior_log_odds=math.log(max(prior_odds, 1e-6)),
            last_observation_time=time.time())

    def update(self, target_id: str,
               model_output: float,   # 模型输出的漏洞概率 [0, 1]
               observation_time: Optional[float] = None) -> EvidenceState:
        """观测到新证据后更新累积证据状态。"""
        if observation_time is None:
            observation_time = time.time()

        if target_id not in self._states:
            self.register_target(target_id)

        state = self._states[target_id]

        # 时间衰减: 旧证据权重指数衰减
        if state.n_observations > 0:
            elapsed = (observation_time - state.last_observation_time) / 86400.0
            decay_rate = math.log(2) / self.config.evidence_decay_days
            decay = math.exp(-decay_rate * elapsed)
            state.log_likelihood_ratio *= decay

        # 似然比: LR = P(obs|H1) / P(obs|H0)
        # H1(有漏洞): 高预测概率更可能 → P(p|H1) ∝ p
        # H0(无漏洞): 低预测概率更可能 → P(p|H0) ∝ (1-p)
        # 但避免极端值: 使用clipped LR
        p_clipped = np.clip(model_output, 0.01, 0.99)
        likelihood_ratio = p_clipped / (1.0 - p_clipped)
        log_lr = math.log(likelihood_ratio)

        state.log_likelihood_ratio += log_lr
        state.n_observations += 1
        state.last_observation_time = observation_time
        state.observation_history.append(model_output)

        # 决策
        if state.n_observations >= self.config.min_observations:
            if state.log_likelihood_ratio > self._log_A:
                state.decision = "reject_H0"
            elif state.log_likelihood_ratio < self._log_B:
                state.decision = "accept_H0"

        # 强制决策（达到最大观测数）
        if (state.n_observations >= self.config.max_observations and
            state.decision == "continue"):
            if state.log_likelihood_ratio > 0:
                state.decision = "reject_H0"
            else:
                state.decision = "accept_H0"

        return state

    def get_posterior_probability(self, target_id: str) -> float:
        """计算后验漏洞概率 P(H1 | observations)。

        P(H1|D) = 1 / (1 + exp(-log_posterior_odds))
        其中 log_posterior_odds = log_prior_odds + log_LR
        """
        if target_id not in self._states:
            return 0.0
        state = self._states[target_id]
        log_odds = state.prior_log_odds + state.log_likelihood_ratio
        if log_odds > 50:
            return 1.0
        if log_odds < -50:
            return 0.0
        return 1.0 / (1.0 + math.exp(-log_odds))

    def batch_update(self,
                     observations: List[Tuple[str, float]],
                     current_time: Optional[float] = None
                     ) -> Dict[str, EvidenceState]:
        """批量更新-对一次扫描的多个函数结果同时更新。"""
        if current_time is None:
            current_time = time.time()
        for target_id, model_output in observations:
            self.update(target_id, model_output, current_time)
        return dict(self._states)

    def get_decided_targets(self) -> Tuple[List[str], List[str]]:
        """获取已做出决策的目标。"""
        vuln = []
        benign = []
        for tid, state in self._states.items():
            if state.decision == "reject_H0":
                vuln.append(tid)
            elif state.decision == "accept_H0":
                benign.append(tid)
        return vuln, benign

    def get_undecided_ranking(self) -> List[Tuple[str, float, int]]:
        """获取尚未决策的目标按风险排序。"""
        undecided = []
        for tid, state in self._states.items():
            if state.decision == "continue":
                post = self.get_posterior_probability(tid)
                undecided.append((tid, post, state.n_observations))
        undecided.sort(key=lambda x: -x[1])
        return undecided

    def reset_target(self, target_id: str):
        """重置目标的证据累积（例如新版本发布后）"""
        if target_id in self._states:
            prior = self._states[target_id].prior_log_odds
            self._states[target_id] = EvidenceState(
                target_id=target_id, prior_log_odds=prior,
                last_observation_time=time.time())

    def estimate_prior_from_history(self,
                                    target_id: str,
                                    cve_count: int,
                                    observation_period_days: float) -> float:
        """从历史数据估计漏洞先验概率。

        prior ≈ cve_count / (observation_period_days / 30)
        即: 月均CVE数量的归一化。
        """
        monthly_rate = cve_count / max(1.0, observation_period_days / 30.0)
        prior = min(0.5, max(0.001, monthly_rate / 10.0))
        return prior
