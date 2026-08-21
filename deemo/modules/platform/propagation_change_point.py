"""
传播图变化点检测 — 贝叶斯在线变点检测识别漏洞传播模式的结构性突变。

问题：单CVE轨迹分析无法检测跨多CVE的协调利用活动。当攻击者同时利用
固件/内核/硬件层漏洞时，传播图全局结构发生可检测突变。

方案：Adams & MacKay BOCD算法。对传播图结构指标建立Normal-Gamma
共轭先验高斯观测模型，每时间步更新游程后验 P(r_t|x_{1:t})。

与已有工作区分：Xinzhe thesis 做单CVE趋势分类，不涉及图结构全局
变化检测。本模块从微观(单CVE)提升至宏观(传播生态系统的相变)。

ref: Adams & MacKay — Bayesian Online Changepoint Detection.
"""

from __future__ import annotations

import math
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .propagation_graph import PlatformLayer, PropagationGraph


@dataclass
class GraphSnapshot:
    """传播图在某一时刻的结构快照, 用于时间序列分析。"""
    timestamp: float
    node_count: int
    edge_count: int
    cross_layer_edge_ratio: float       # 跨层边 / 总边
    mean_confidence: float               # 边置信度均值
    mean_severity: float                 # 节点严重度均值
    layer_distribution: Dict[str, int]    # 各层节点数
    density: float                        # 2*|E| / (|V|*(|V|-1))


@dataclass
class ChangePoint:
    """检测到的变化点。"""
    timestamp: float
    metric: str                           # 哪个指标触发了变点
    run_length_at_change: int             # 变点前的游程长度
    posterior_prob: float                 # P(r_t=0 | data)
    snapshot_before: Optional[GraphSnapshot] = None
    snapshot_after: Optional[GraphSnapshot] = None


class BayesianChangePointDetector:
    """单指标贝叶斯变点检测器 — Normal-Gamma共轭先验 + Student-t预测。

    观测模型 x_t~N(μ,σ²)，μ~N(μ₀,(κ₀λ)⁻¹)，λ=1/σ²~Gamma(α₀,β₀)。
    后验超参数更新及预测概率均为闭式解，在线O(1)每步。
    """

    def __init__(self, hazard_rate: float = 0.01,
                 mu0: float = 0.0, kappa0: float = 1.0,
                 alpha0: float = 1.0, beta0: float = 1.0):
        self._hazard = hazard_rate  # P(change at each step) 的常数先验
        self._mu0 = mu0
        self._kappa0 = kappa0
        self._alpha0 = alpha0
        self._beta0 = beta0
        # 游程长度后验: P(r_t | x_{1:t})，存储为对数概率
        self._run_length_log_probs: List[float] = [0.0]  # log P(r_0=0) = 0
        self._observations: List[float] = []

    def update(self, x: float) -> Tuple[float, float]:
        """接收一个新观测，用log-sum-exp更新游程长度后验。

        返回 (P(r_t=0), max run_length probability)。
        BOCD递推: P(r_t|x_{1:t}) ∝ P(x_t|r_{t-1},x^{(r)}) * P(r_{t-1}|x_{1:t-1}) * P(r_t|r_{t-1})
        """
        self._observations.append(x)

        # 构建未归一化的对数联合概率
        # new_joint[r] = log P(r_t=r, x_{1:t})
        n_prev = len(self._run_length_log_probs)
        new_joint = [float('-inf')] * (n_prev + 1)

        # 1. 变点贡献: r_t=0, 从任意 r_{t-1} 以 hazard 概率跳转
        cp_terms = [self._run_length_log_probs[r] + math.log(self._hazard)
                    for r in range(n_prev)]
        max_cp = max(cp_terms)
        new_joint[0] = max_cp + math.log(sum(math.exp(lp - max_cp) for lp in cp_terms))
        new_joint[0] += self._log_predictive(0)  # P(x_t | r_t=0, no history)

        # 2. 增长贡献: r_t = r_{t-1} + 1, 以 (1-hazard) 概率延续
        for r_prev in range(n_prev):
            grow_log = (self._run_length_log_probs[r_prev]
                       + math.log1p(-self._hazard)
                       + self._log_predictive(r_prev))
            new_joint[r_prev + 1] = grow_log

        # 归一化: P(r_t | x_{1:t}) = exp(new_joint) / sum(exp(new_joint))
        max_joint = max(new_joint)
        probs = [math.exp(lp - max_joint) for lp in new_joint]
        total = sum(probs)
        self._run_length_log_probs = [math.log(p / total) for p in probs]

        return math.exp(self._run_length_log_probs[0]), max(probs)

    def _log_predictive(self, run_length: int) -> float:
        """计算 P(x_t | r_{t-1}) 的对数, 使用后验预测 Student-t 分布。"""
        n = min(run_length, len(self._observations))
        if n == 0:
            # 先验预测
            kappa_n = self._kappa0
            alpha_n = self._alpha0
            beta_n = self._beta0
            mu_n = self._mu0
        else:
            xs = self._observations[-n:]
            mean_x = sum(xs) / n
            kappa_n = self._kappa0 + n
            mu_n = (self._kappa0 * self._mu0 + n * mean_x) / kappa_n
            alpha_n = self._alpha0 + n / 2.0
            ss = sum((xi - mean_x) ** 2 for xi in xs)
            beta_n = self._beta0 + 0.5 * ss
            beta_n += (self._kappa0 * n * (mean_x - self._mu0) ** 2) / (2.0 * kappa_n)

        # Student-t log density
        x = self._observations[-1]
        scale = math.sqrt(beta_n * (kappa_n + 1) / (alpha_n * kappa_n))
        df = 2.0 * alpha_n

        # log density of t-distribution
        log_norm = (math.lgamma((df + 1) / 2) - math.lgamma(df / 2)
                    - 0.5 * math.log(df * math.pi) - math.log(scale))
        t_stat = ((x - mu_n) / scale) ** 2
        log_dens = log_norm - (df + 1) / 2 * math.log1p(t_stat / df)

        return log_dens

    @property
    def change_probability(self) -> float:
        """P(r_t = 0 | x_{1:t}) — 当前时刻是变点的概率。"""
        if not self._run_length_log_probs:
            return 0.0
        probs = [math.exp(lp) for lp in self._run_length_log_probs]
        total = sum(probs)
        return probs[0] / total if total > 0 else 0.0


class PropagationChangeDetector:
    """传播图演化变点检测器 — 多指标融合的协调利用活动检测。

    用法::

        detector = PropagationChangeDetector()
        # 每次固件/内核分析完成后，推入新的图快照
        detector.push_snapshot(graph)
        # 检查是否有变点
        changes = detector.recent_changes()
        for cp in changes:
            print(f"Change at {cp.timestamp}: {cp.metric}, prob={cp.posterior_prob:.3f}")
    """

    # 多指标检测器的融合权重——各指标对"协调利用"的敏感度不同
    _METRIC_WEIGHTS = {
        'cross_layer_ratio': 1.5,    # 跨层边比例增大→攻击者桥接多个层
        'density': 1.2,              # 密度增大→新关联被大量发现
        'mean_confidence': 1.0,      # 置信度突增→新证据集中涌现
        'mean_severity': 0.8,        # 严重度突增→高危漏洞集中爆发
    }

    def __init__(self, hazard_rate: float = 0.02,
                 change_threshold: float = 0.30):
        self._hazard = hazard_rate
        self._threshold = change_threshold
        self._detectors: Dict[str, BayesianChangePointDetector] = {
            metric: BayesianChangePointDetector(hazard_rate=hazard_rate)
            for metric in self._METRIC_WEIGHTS
        }
        self._snapshots: List[GraphSnapshot] = []
        self._changes: List[ChangePoint] = []
        self._window = deque(maxlen=50)  # 滑动窗口观测

    def snapshot_from_graph(self, graph: PropagationGraph,
                            timestamp: Optional[float] = None) -> GraphSnapshot:
        """从当前传播图生成结构快照。"""
        import time
        ts = timestamp or time.time()
        n = graph.node_count
        e = graph.edge_count
        cross = sum(1 for _ in graph.cross_layer_edges())

        confs = [edge.confidence for edge in graph._edges.values()]
        sevs = [node.severity for node in graph._nodes.values()]

        layer_dist: Dict[str, int] = {}
        for node in graph._nodes.values():
            layer_dist[node.layer.name] = layer_dist.get(node.layer.name, 0) + 1

        max_edges = n * (n - 1)
        density = (2.0 * e) / max(max_edges, 1)

        return GraphSnapshot(
            timestamp=ts,
            node_count=n,
            edge_count=e,
            cross_layer_edge_ratio=cross / max(e, 1),
            mean_confidence=sum(confs) / max(len(confs), 1),
            mean_severity=sum(sevs) / max(len(sevs), 1),
            layer_distribution=layer_dist,
            density=density,
        )

    def push_snapshot(self, graph: PropagationGraph,
                      timestamp: Optional[float] = None) -> List[ChangePoint]:
        """推入新的传播图快照，返回本轮检测到的变点列表。"""
        snap = self.snapshot_from_graph(graph, timestamp)
        self._snapshots.append(snap)
        self._window.append(snap)

        new_changes: List[ChangePoint] = []

        # 提取各指标当前值
        metric_values = {
            'cross_layer_ratio': snap.cross_layer_edge_ratio,
            'density': snap.density,
            'mean_confidence': snap.mean_confidence,
            'mean_severity': snap.mean_severity,
        }

        # 各指标独立更新贝叶斯检测器
        for metric_name, detector in self._detectors.items():
            val = metric_values[metric_name]
            cp_prob, _ = detector.update(val)

            if cp_prob > self._threshold:
                prev_snap = self._snapshots[-2] if len(self._snapshots) >= 2 else None
                cp = ChangePoint(
                    timestamp=snap.timestamp,
                    metric=metric_name,
                    run_length_at_change=len(detector._observations),
                    posterior_prob=round(cp_prob, 4),
                    snapshot_before=prev_snap,
                    snapshot_after=snap,
                )
                new_changes.append(cp)

        self._changes.extend(new_changes)
        return new_changes

    def recent_changes(self, lookback: int = 10) -> List[ChangePoint]:
        """返回最近若干次检测到的变点。"""
        return self._changes[-lookback:] if self._changes else []

    def campaign_score(self) -> float:
        """协调利用活动评分, 融合多指标变点概率的加权几何平均。

        评分>0.5表示传播图结构正在经历统计显著的相变，可能对应
        一次跨层协调利用活动（如 APT 组织同时利用固件+内核+硬件漏洞）。
        """
        if not self._detectors:
            return 0.0

        weighted_log = 0.0
        total_weight = 0.0
        for metric, detector in self._detectors.items():
            w = self._METRIC_WEIGHTS.get(metric, 1.0)
            prob = detector.change_probability
            if prob > 1e-9:
                weighted_log += w * math.log(prob)
                total_weight += w

        if total_weight == 0:
            return 0.0
        return math.exp(weighted_log / total_weight)

    def push_snapshot_joint(self, graph: PropagationGraph,
                            timestamp: Optional[float] = None
                            ) -> Optional[ChangePoint]:
        """多变量联合变点检测 - 共享游程后验的图级变点识别。

        与独立检测(push_snapshot)的本质区别:
          独立检测: 每个指标有各自的游程后验, 各自独立判断变点。
                    可能cross_layer_ratio检测到变点但density未检测到。
          联合检测: 所有指标共享同一条游程后验链。
                    联合预测似然 = sum_i log P(x_i | r_t, x_{1:t-1}^{(i)})
                    任一指标的突变信号都会拉低所有指标的联合似然,
                    从而增强对协调性结构变化的检测敏感度。

        返回: 若联合后验P(r_t=0)超过阈值, 返回ChangePoint; 否则None。
        """
        snap = self.snapshot_from_graph(graph, timestamp)
        self._snapshots.append(snap)

        metric_values = {
            'cross_layer_ratio': snap.cross_layer_edge_ratio,
            'density': snap.density,
            'mean_confidence': snap.mean_confidence,
            'mean_severity': snap.mean_severity,
        }

        # 联合预测对数似然 = 各指标预测对数似然之和
        joint_log_preds = []
        for r_prev in range(len(self._detectors['cross_layer_ratio']._run_length_log_probs)):
            joint_log = 0.0
            for metric_name, detector in self._detectors.items():
                orig_obs = list(detector._observations)
                # 计算对数预测似然: 仅使用最近r_prev个观测
                detector._observations = orig_obs[-r_prev:] if r_prev > 0 else []
                if r_prev == 0:
                    # 无历史: 使用先验预测(默认对数似然≈0)
                    joint_log += 0.0
                else:
                    joint_log += detector._log_predictive(r_prev)
                detector._observations = orig_obs
            joint_log_preds.append(joint_log)

        # 共享游程后验更新 (BOCD递推)
        prev_log_probs = list(self._detectors['cross_layer_ratio']._run_length_log_probs)
        new_log_probs = [float('-inf')] * (len(prev_log_probs) + 1)

        # r_t=0: 从任意r_{t-1}以hazard概率跳转
        cp_terms = [prev_log_probs[r] + math.log(self._hazard) for r in range(len(prev_log_probs))]
        max_cp = max(cp_terms)
        new_log_probs[0] = max_cp + math.log(sum(math.exp(lp - max_cp) for lp in cp_terms))
        new_log_probs[0] += joint_log_preds[0]  # r=0时无历史

        # r_t = r_{t-1} + 1: 以(1-hazard)概率延续
        for r_prev in range(len(prev_log_probs)):
            grow = prev_log_probs[r_prev] + math.log1p(-self._hazard) + joint_log_preds[r_prev]
            new_log_probs[r_prev + 1] = grow

        # 归一化并同步到所有检测器
        max_joint = max(new_log_probs)
        probs = [math.exp(lp - max_joint) for lp in new_log_probs]
        total = sum(probs)
        shared_log_probs = [math.log(p / total) for p in probs]
        for detector in self._detectors.values():
            detector._run_length_log_probs = list(shared_log_probs)
            detector._observations.append(metric_values.get(
                next(k for k, v in self._detectors.items() if v is detector), 0.5))

        # 检查是否变点
        cp_prob = math.exp(shared_log_probs[0])
        if cp_prob > self._threshold:
            return ChangePoint(
                timestamp=snap.timestamp,
                metric='joint_multivariate',
                run_length_at_change=len(shared_log_probs),
                posterior_prob=round(cp_prob, 4),
                snapshot_before=self._snapshots[-2] if len(self._snapshots) >= 2 else None,
                snapshot_after=snap,
            )
        return None

    def snapshot_count(self) -> int:
        return len(self._snapshots)
