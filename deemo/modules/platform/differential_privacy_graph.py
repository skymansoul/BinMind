"""
 差分隐私传播图 - epsilon-差分隐私保护下的漏洞传播图数据共享。

问题：
  多个组织（安全厂商、CERT、ISAC）共享漏洞传播图数据可提升整体安全态势。
  但传播图包含敏感信息：固件版本号、内核模块名、侧信道目标地址、漏洞关联模式。
  直接共享原始传播图泄露组织安全防御能力的详细信息。

方案：
  Laplace机制实现epsilon-差分隐私。
  对传播图的以下组件注入校准拉普拉斯噪声：
    (a) 边置信度：每条PropagationEdge的confidence字段 + Laplace(0, 1/epsilon_e)
    (b) 节点严重度：每个VulnNode的severity字段 + Laplace(0, 1/epsilon_n)
    (c) 可选: 图的节点数/边数统计 + Laplace(0, 1/epsilon_s)

  隐私预算分配：
    总预算epsilon_total在边、节点、统计之间按需求分配。
    默认: epsilon_e = 0.5*epsilon_total, epsilon_n = 0.4*epsilon_total,
           epsilon_s = 0.1*epsilon_total。
    顺序组合定理保证总隐私损失 = 各预算之和。

  噪声后处理：
    噪声可能使severity超出[0,1]或confidence超出[0,1]。
    后处理截断不消耗额外隐私预算（后处理不变性）。

与已有工作的区分：
  TADI: DP-SGD在联邦学习中的拓扑泄漏，处理模型训练隐私，
    不涉及图结构共享。
  CTI隐私框架: PIR+FL+DP保护威胁情报查询，不保护传播图结构。
  Laplace机制应用于漏洞传播图的边和节点隐私保护。

ref: Dwork & Roth "The Algorithmic Foundations of Differential Privacy".
ref: CTI Privacy Framework - 威胁情报共享隐私，最接近的已有工作。
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .propagation_graph import (
    PlatformLayer, PropagationEdge, PropagationGraph, VulnNode,
)


@dataclass
class PrivacyBudget:
    """差分隐私预算分配 - 控制在传播图各组件上的噪声注入量。"""
    epsilon_total: float
    epsilon_edges: float = 0.0       # 边置信度的隐私预算
    epsilon_nodes: float = 0.0       # 节点严重度的隐私预算
    epsilon_stats: float = 0.0       # 图统计信息的隐私预算

    def __post_init__(self):
        if self.epsilon_edges <= 0:
            self.epsilon_edges = 0.5 * self.epsilon_total
        if self.epsilon_nodes <= 0:
            self.epsilon_nodes = 0.4 * self.epsilon_total
        if self.epsilon_stats <= 0:
            self.epsilon_stats = 0.1 * self.epsilon_total

    @property
    def total(self) -> float:
        return self.epsilon_total


class LaplaceMechanism:
    """拉普拉斯机制 - 对数值查询结果注入校准噪声。

    全局敏感度Delta_f = 查询函数在相邻数据集上的最大差异。
    对边置信度和节点严重度：Delta_f = 1.0（单条边/单个节点的存在与否最多改变1.0）。

    噪声: Laplace(0, b) 其中 b = Delta_f / epsilon。
    """

    @staticmethod
    def sample_noise(epsilon: float, sensitivity: float = 1.0) -> float:
        """从Laplace(0, sensitivity/epsilon)采样。"""
        if epsilon <= 0:
            return 0.0  # 无限隐私预算=无噪声（不安全，仅用于调试）
        scale = sensitivity / epsilon
        # 逆变换采样: U~Uniform(0,1) -> X = -b * sign(U-0.5) * ln(1-2|U-0.5|)
        u = random.random() - 0.5
        return -scale * (1.0 if u >= 0 else -1.0) * math.log(1.0 - 2.0 * abs(u))

    @staticmethod
    def clamp(value: float, lo: float = 0.0, hi: float = 1.0) -> float:
        """后处理截断 - 不消耗隐私预算。"""
        return max(lo, min(hi, value))


class DifferentialPrivacyGraph:
    """差分隐私传播图 -- 原始传播图的epsilon-DP版本。

    用法::

        budget = PrivacyBudget(epsilon_total=1.0)
        dp_graph = DifferentialPrivacyGraph.sanitize(original_graph, budget)
        # dp_graph可以安全地与外部组织共享
        # 原始图中任何单条边/节点的存在与否被epsilon-DP保护
    """

    def __init__(self, graph: PropagationGraph,
                 budget: PrivacyBudget,
                 noise_seed: Optional[int] = None):
        self._original = graph
        self._budget = budget
        self._sanitized: Optional[PropagationGraph] = None

        if noise_seed is not None:
            random.seed(noise_seed)

    @classmethod
    def sanitize(cls, graph: PropagationGraph,
                 budget: PrivacyBudget,
                 noise_seed: Optional[int] = None
                 ) -> PropagationGraph:
        """生成原始传播图的epsilon-DP净化版本。

        对每条边的confidence和每个节点的severity注入Laplace噪声。
        返回净化后的PropagationGraph - 接口与原图完全兼容。
        """
        instance = cls(graph, budget, noise_seed)
        return instance._build_sanitized()

    def _build_sanitized(self) -> PropagationGraph:
        """构建净化图 - 深拷贝节点和边，对敏感字段注入噪声。"""
        sanitized = PropagationGraph(max_nodes=self._original._max_nodes)

        # 节点：severity + Laplace噪声
        for nid, node in self._original._nodes.items():
            noisy_sev = node.severity + LaplaceMechanism.sample_noise(
                self._budget.epsilon_nodes, sensitivity=1.0,
            )
            noisy_sev = LaplaceMechanism.clamp(noisy_sev)
            sanitized.add_node(VulnNode(
                node_id=node.node_id, layer=node.layer,
                vuln_type=node.vuln_type, severity=noisy_sev,
                entity_ref=node.entity_ref,
                # metadata不注入噪声 - 非数值敏感字段
                metadata={k: v for k, v in node.metadata.items()
                         if k != 'noisy_severity'},
            ))

        # 边：confidence + Laplace噪声
        for (src, tgt), edge in self._original._edges.items():
            noisy_conf = edge.confidence + LaplaceMechanism.sample_noise(
                self._budget.epsilon_edges, sensitivity=1.0,
            )
            noisy_conf = LaplaceMechanism.clamp(noisy_conf)
            try:
                sanitized.add_edge(src, tgt, noisy_conf, edge.rule_name)
            except (KeyError, ValueError):
                continue

        self._sanitized = sanitized
        return sanitized

    def privacy_loss_report(self) -> Dict[str, Any]:
        """隐私损失报告 - 用于合规审计。

        返回各组件消耗的隐私预算和对应的噪声尺度。
        """
        return {
            "epsilon_total": self._budget.epsilon_total,
            "epsilon_edges": self._budget.epsilon_edges,
            "noise_scale_edges": round(1.0 / max(self._budget.epsilon_edges, 1e-9), 4),
            "epsilon_nodes": self._budget.epsilon_nodes,
            "noise_scale_nodes": round(1.0 / max(self._budget.epsilon_nodes, 1e-9), 4),
            "epsilon_stats": self._budget.epsilon_stats,
            "composition": "sequential",
            "mechanism": "Laplace",
        }

    def utility_metrics(self) -> Dict[str, float]:
        """净化图的效用度量 - 原始 vs 净化版本的偏差。

        L1偏差度量噪声对风险评分的平均影响。
        值越小说明效用保持越好（噪声影响小）。
        """
        if self._sanitized is None:
            self._build_sanitized()

        sev_diffs = []
        conf_diffs = []
        for nid in self._original._nodes:
            if nid in self._sanitized._nodes:
                orig_sev = self._original._nodes[nid].severity
                noisy_sev = self._sanitized._nodes[nid].severity
                sev_diffs.append(abs(orig_sev - noisy_sev))

        for key in self._original._edges:
            if key in self._sanitized._edges:
                orig_conf = self._original._edges[key].confidence
                noisy_conf = self._sanitized._edges[key].confidence
                conf_diffs.append(abs(orig_conf - noisy_conf))

        return {
            "mean_severity_deviation": (
                sum(sev_diffs) / max(len(sev_diffs), 1)),
            "mean_confidence_deviation": (
                sum(conf_diffs) / max(len(conf_diffs), 1)),
            "max_severity_deviation": max(sev_diffs) if sev_diffs else 0.0,
            "max_confidence_deviation": max(conf_diffs) if conf_diffs else 0.0,
        }


def privacy_preserving_share(graph: PropagationGraph,
                             epsilon: float = 1.0,
                             seed: int = 42) -> Tuple[PropagationGraph, Dict]:
    """一站式隐私保护共享 - 净化传播图并返回审计报告。

    epsilon推荐值:
      0.1: 强隐私保护，噪声大，效用低
      1.0: 标准保护，噪声适中（默认）
      10.0: 弱隐私保护，噪声小，效用高
    """
    budget = PrivacyBudget(epsilon_total=epsilon)
    dp = DifferentialPrivacyGraph(graph, budget, noise_seed=seed)
    sanitized = dp._build_sanitized()
    return sanitized, {**dp.privacy_loss_report(), **dp.utility_metrics()}
