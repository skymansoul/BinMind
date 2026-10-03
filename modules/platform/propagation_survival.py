"""
跨层漏洞生存分析 — 将生存分析范式引入传播图风险建模。

传统风险评分（CVSS、EPSS、VPSS）给出静态分值，不回答最关键的时间问题：
"此漏洞在固件中被利用的预期时间窗口是多久？"
生存分析将漏洞视为"生存主体"——从发现到首次野外利用为"事件"，
未利用的漏洞为右删失观测。

核心能力：
  (a) 按平台层分层的 Kaplan-Meier 生存曲线估计
  (b) Cox 比例风险回归 — 评估协变量（严重度、层跨度、入度）对利用速率的影响
  (c) 条件生存概率预测 — 给定已存活 t 天，预测未来 Δt 天内的利用概率
  (d) 跨层加速因子 — 漏洞传播跨越层边界时，风险比率的非线性调整

  1. 观测数据稀疏 — 多数 CVE 缺乏精确的首次利用时间戳
  2. 可解释性要求 — 保险/合规场景需逐因子归因，黑盒模型不可接受
  3. Cox PH 的半参数性质恰好匹配 — 基准风险函数非参数估计，协变量效应参数化

ref: (VulRG) — 多层级漏洞评分，但未引入时间维度的生存建模。
ref: IEEE TDSC 2025 (MIRAGE) — 静态攻击图，生存分析将静态图转为动态风险曲面。
"""

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .propagation_graph import PlatformLayer, PropagationGraph, VulnNode

@dataclass
class SurvivalEvent:
    """漏洞生存事件 — 一条观测记录。"""
    vuln_id: str
    layer: PlatformLayer
    discovery_time: float          # Unix epoch，漏洞发现时刻
    event_time: Optional[float]    # 首次利用时刻；None=右删失
    observation_end: float         # 观测窗口结束时刻
    covariates: Dict[str, float] = field(default_factory=dict)
    # 协变量：severity, layer_distance_max, indegree, cross_layer_edge_count

class KaplanMeierEstimator:
    """Kaplan-Meier 生存函数估计器 — 按平台层分层。

    单层估计使用乘积极限法：
      S(t) = ∏_{(t_i ≤ t)} (1 - d_i / n_i)
    其中 d_i = t_i 时刻事件数，n_i = t_i 时刻存活个体数。

    跨层比较使用 log-rank 检验（此处实现简化版：比较各层中位生存时间）。
    """

    def __init__(self):
        self._layer_curves: Dict[PlatformLayer, List[Tuple[float, float]]] = {}
        # {layer: [(time, survival_prob), ...]}  — 阶梯函数的关键点
        self._layer_medians: Dict[PlatformLayer, float] = {}

    def fit(self, events: Sequence[SurvivalEvent]) -> None:
        """拟合所有平台层的生存曲线。

        事件按 discovery_time 对齐为相对时间 t=0。
        """
        by_layer: Dict[PlatformLayer, List[Tuple[float, bool]]] = defaultdict(list)
        for ev in events:
            if ev.event_time is not None:
                tte = ev.event_time - ev.discovery_time
                by_layer[ev.layer].append((max(tte, 0.0), True))
            else:
                tte = ev.observation_end - ev.discovery_time
                by_layer[ev.layer].append((max(tte, 0.0), False))

        for layer, obs in by_layer.items():
            obs.sort(key=lambda x: x[0])
            n = len(obs)
            curve: List[Tuple[float, float]] = [(0.0, 1.0)]
            alive = n

            i = 0
            while i < n:
                t = obs[i][0]
                events_at_t = 0
                censored_at_t = 0
                while i < n and obs[i][0] == t:
                    if obs[i][1]:
                        events_at_t += 1
                    else:
                        censored_at_t += 1
                    i += 1

                if events_at_t > 0:
                    prev_s = curve[-1][1]
                    new_s = prev_s * (1.0 - events_at_t / alive)
                    curve.append((t, new_s))
                    if new_s <= 0.5 and len(curve) >= 2 and curve[-1][1] > 0:
                        # 线性插值求中位生存时间
                        t_prev, s_prev = curve[-2]
                        t_cur, s_cur = curve[-1]
                        if s_prev > 0.5 >= s_cur:
                            median = t_prev + (t_cur - t_prev) * (0.5 - s_prev) / (s_cur - s_prev)
                            self._layer_medians[layer] = median

                alive -= (events_at_t + censored_at_t)

            if layer not in self._layer_medians:
                # 未达到中位生存（太多删失或事件不足）— 使用最后观测点
                self._layer_medians[layer] = curve[-1][0] if curve[-1][1] > 0.5 else curve[0][0]

            self._layer_curves[layer] = curve

    def survival_prob(self, layer: PlatformLayer, time: float) -> float:
        """给定平台层和时间（天），返回生存概率 S(t|layer)。"""
        curve = self._layer_curves.get(layer, [(0.0, 1.0)])
        if time <= 0:
            return 1.0
        # 二分查找 time 所在区间
        lo, hi = 0, len(curve) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if curve[mid][0] <= time:
                lo = mid
            else:
                hi = mid - 1
        return curve[lo][1]

    def median_survival(self, layer: PlatformLayer) -> float:
        """返回指定层的中位生存时间（天）；无数据返回 inf。"""
        return self._layer_medians.get(layer, float('inf'))

    def hazard_ratio(self, layer_a: PlatformLayer,
                     layer_b: PlatformLayer, at_time: float = 30.0) -> float:
        """计算两个层在指定时间点的风险比率 h_a(t)/h_b(t)。

        通过数值微分 S(t) 估算累积风险 H(t) = -log S(t)，再差分求 h(t)。
        """
        sa = self.survival_prob(layer_a, at_time)
        sb = self.survival_prob(layer_b, at_time)
        Ha = -math.log(max(sa, 1e-10))
        Hb = -math.log(max(sb, 1e-10))
        if Hb < 1e-10:
            return float('inf') if Ha > 0 else 1.0
        return Ha / Hb

class PropagationSurvivalAnalyzer:
    """传播图生存分析 — 桥接 PropagationGraph 与生存分析模型。

    用法::

        graph = PropagationGraph()
        # ... 填充节点和边 ...
        analyzer = PropagationSurvivalAnalyzer()
        analyzer.fit_from_graph(graph, discovery_times={"node1": 1700000000.0})
        prob = analyzer.prob_exploited_within("node1", days=90)
        # → 该节点对应漏洞在90天内被利用的概率
    """

    # 跨层加速因子 — 漏洞跨层传播时，利用速率乘此因子
    # 值>1表示跨层漏洞被更快利用（攻击面扩大）
    _CROSS_LAYER_ACCELERATION: Dict[Tuple[PlatformLayer, PlatformLayer], float] = {
        (PlatformLayer.FIRMWARE, PlatformLayer.KERNEL): 1.8,
        (PlatformLayer.FIRMWARE, PlatformLayer.HARDWARE): 2.1,
        (PlatformLayer.KERNEL, PlatformLayer.HARDWARE): 1.5,
        (PlatformLayer.KERNEL, PlatformLayer.MOBILE): 1.7,
        (PlatformLayer.KERNEL, PlatformLayer.MALWARE): 2.3,
        (PlatformLayer.HARDWARE, PlatformLayer.MOBILE): 1.4,
        (PlatformLayer.HARDWARE, PlatformLayer.KERNEL): 1.6,
        (PlatformLayer.MOBILE, PlatformLayer.MALWARE): 1.9,
        (PlatformLayer.MOBILE, PlatformLayer.SMART_CONTRACT): 1.3,
        (PlatformLayer.MALWARE, PlatformLayer.SMART_CONTRACT): 1.2,
    }

    def __init__(self):
        self._km = KaplanMeierEstimator()
        from .survival_cox import CoxPHModel
        self._cox = CoxPHModel()
        self._graph: Optional[PropagationGraph] = None
        self._fitted = False

    def fit_from_graph(self, graph: PropagationGraph,
                       discovery_times: Optional[Dict[str, float]] = None,
                       exploitation_times: Optional[Dict[str, float]] = None) -> None:
        """从 PropagationGraph 提取生存事件并拟合模型。

        discovery_times: {node_id: Unix timestamp} — 漏洞发现时刻
        exploitation_times: {node_id: Unix timestamp} — 首次利用时刻；缺失=未利用
        """
        self._graph = graph
        discovery = discovery_times or {}
        exploited = exploitation_times or {}

        events: List[SurvivalEvent] = []
        now = max(
            max(discovery.values()) if discovery else 0.0,
            max(exploited.values()) if exploited else 0.0,
            1.0,  # 回退值
        )

        max_layer_jump = 0.0
        indegree_counts: Dict[str, int] = {}
        cross_layer_counts: Dict[str, int] = {}

        for (src, tgt), edge in graph._edges.items():
            indegree_counts[tgt] = indegree_counts.get(tgt, 0) + 1
            src_layer = graph._nodes[src].layer
            tgt_layer = graph._nodes[tgt].layer
            if src_layer != tgt_layer:
                cross_layer_counts[tgt] = cross_layer_counts.get(tgt, 0) + 1
                jump = abs(int(tgt_layer) - int(src_layer))
                max_layer_jump = max(max_layer_jump, jump)

        for nid, node in graph._nodes.items():
            disc_t = discovery.get(nid, now - 365 * 86400)
            expl_t = exploited.get(nid)
            cov = {
                'severity': node.severity,
                'indegree': min(indegree_counts.get(nid, 0), 20),
                'cross_layer_edges': min(cross_layer_counts.get(nid, 0), 10),
                'layer_depth': float(node.layer.value),
            }
            events.append(SurvivalEvent(
                vuln_id=nid,
                layer=node.layer,
                discovery_time=disc_t,
                event_time=expl_t,
                observation_end=now,
                covariates=cov,
            ))

        self._km.fit(events)
        self._cox.fit(events)
        self._fitted = True

    def prob_exploited_within(self, node_id: str, days: float) -> float:
        """节点漏洞在 days 天内被利用的概率 = 1 - S(days|layer)。"""
        if not self._fitted or self._graph is None:
            return 0.0
        node = self._graph._nodes.get(node_id)
        if node is None:
            return 0.0

        base_surv = self._km.survival_prob(node.layer, days)

        # Cox 协变量风险调整
        cov = {
            'severity': node.severity,
            'indegree': 0.0,
            'cross_layer_edges': 0.0,
            'layer_depth': float(node.layer.value),
        }
        # 计算 indegree 和跨层边数
        indeg = len(self._graph._rev_adj.get(node_id, []))
        cross = 0
        for src_id in self._graph._rev_adj.get(node_id, []):
            if src_id in self._graph._nodes:
                if self._graph._nodes[src_id].layer != node.layer:
                    cross += 1
        cov['indegree'] = float(min(indeg, 20))
        cov['cross_layer_edges'] = float(min(cross, 10))

        hr = self._cox.predict_hazard_ratio(cov)

        # 跨层加速因子的几何平均
        accel = 1.0
        n_accel = 0
        for src_id in self._graph._rev_adj.get(node_id, []):
            if src_id in self._graph._nodes:
                pair = (self._graph._nodes[src_id].layer, node.layer)
                factor = self._CROSS_LAYER_ACCELERATION.get(pair, 1.0)
                accel *= factor
                n_accel += 1
        if n_accel > 0:
            accel = accel ** (1.0 / n_accel)

        adjusted_surv = base_surv ** (hr * accel)
        return max(0.0, min(1.0, 1.0 - adjusted_surv))

    def layer_risk_timeline(self, days: List[int]) -> Dict[str, List[float]]:
        """各平台层在时间序列上的累计利用风险 1-S(t|layer)。"""
        result: Dict[str, List[float]] = {}
        for layer in PlatformLayer:
            probs = [1.0 - self._km.survival_prob(layer, float(d)) for d in days]
            result[layer.name] = probs
        return result

    @property
    def layer_medians(self) -> Dict[str, float]:
        return {layer.name: self._km.median_survival(layer) for layer in PlatformLayer
                if self._km.median_survival(layer) != float('inf')}

    @property
    def cox_coefficients(self) -> Dict[str, float]:
        return dict(self._cox._coefficients)
