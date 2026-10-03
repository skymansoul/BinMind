# 跨向量DDoS关联引擎 —— Granger式因果检验检测协同攻击活动。
# 现有ddos_detector各向量独立检测, 本模块通过互相关+简化Granger
# 发现向量间时序关联→连通分量=协同活动。零训练, 可解释因果图。
# 未见2024-2025文献涉及Granger式跨向量DDoS协同检测。

from __future__ import annotations

import math
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class VectorTimeSeries:
    """单个攻击向量的时间序列"""
    vector_name: str        # "syn"/"udp"/"dns_amp"/"ntp_amp"/"icmp"
    window_counts: List[int] = field(default_factory=list)
    window_timestamps: List[float] = field(default_factory=list)
    max_history: int = 60   # 保留最近60个窗口


@dataclass
class CrossVectorLink:
    """向量间关联边"""
    source_vector: str
    target_vector: str
    correlation: float          # 最大互相关 [-1, 1]
    optimal_lag: int           # 最优滞后窗口数(正=源领先于目标)
    granger_score: float       # 简化Granger检验得分 [0, 1]
    is_significant: bool       # 关联是否显著
    lead_lag_description: str  # "A leads B by N windows"


@dataclass
class CoordinatedCampaign:
    """检测到的协同攻击活动"""
    campaign_id: str
    involved_vectors: List[str]
    correlation_links: List[CrossVectorLink]
    start_window: int
    end_window: int
    severity_score: float       # [0, 1]
    vector_diversity: float     # 使用的向量数/总向量数
    mean_correlation: float     # 平均关联强度
    description: str = ""


@dataclass
class CrossVectorReport:
    """跨向量关联完整报告"""
    total_windows_analyzed: int
    active_campaigns: List[CoordinatedCampaign]
    vector_correlation_matrix: Dict[Tuple[str, str], float]
    independent_vectors: List[str]  # 未参与任何协同的向量
    campaign_count: int
    max_campaign_severity: float


class CrossVectorCorrelator:
    """跨向量关联器 —— 互相关+Granger检验→协同活动检测。"""

    def __init__(self, significance_threshold: float = 0.5,
                 min_windows_for_analysis: int = 10):
        self._threshold = significance_threshold
        self._min_windows = min_windows_for_analysis
        self._series: Dict[str, VectorTimeSeries] = {}

    def register_vector(self, name: str) -> None:
        if name not in self._series:
            self._series[name] = VectorTimeSeries(vector_name=name)

    def feed_counts(self, vector_counts: Dict[str, int],
                    timestamp: float = 0.0) -> None:
        """每个窗口结束时调用: {vector_name → count}"""
        for vname, count in vector_counts.items():
            if vname not in self._series:
                self.register_vector(vname)
            ts = self._series[vname]
            ts.window_counts.append(count)
            ts.window_timestamps.append(timestamp)
            if len(ts.window_counts) > ts.max_history:
                ts.window_counts.pop(0)
                ts.window_timestamps.pop(0)

    def analyze(self) -> CrossVectorReport:
        """分析所有向量的时间序列, 检测协同活动。"""
        active_vectors = [
            name for name, ts in self._series.items()
            if len(ts.window_counts) >= self._min_windows
        ]
        if len(active_vectors) < 2:
            return CrossVectorReport(
                total_windows_analyzed=0, active_campaigns=[],
                vector_correlation_matrix={}, independent_vectors=active_vectors,
                campaign_count=0, max_campaign_severity=0.0)

        # 计算所有向量对的关联
        links: List[CrossVectorLink] = []
        corr_matrix: Dict[Tuple[str, str], float] = {}

        for i, va in enumerate(active_vectors):
            for j in range(i + 1, len(active_vectors)):
                vb = active_vectors[j]
                link = self._compute_cross_correlation(
                    self._series[va], self._series[vb])
                if link:
                    links.append(link)
                    corr_matrix[(va, vb)] = link.correlation
                    if link.is_significant:
                        corr_matrix[(vb, va)] = link.correlation

        # 构建关联图并找连通分量(协同活动)
        campaigns = self._find_campaigns(active_vectors, links)

        # 独立向量
        involved = set()
        for c in campaigns:
            involved.update(c.involved_vectors)
        independent = [v for v in active_vectors if v not in involved]

        max_sev = max((c.severity_score for c in campaigns), default=0.0)

        return CrossVectorReport(
            total_windows_analyzed=max(
                len(self._series[v].window_counts) for v in active_vectors
            ) if active_vectors else 0,
            active_campaigns=campaigns,
            vector_correlation_matrix=corr_matrix,
            independent_vectors=independent,
            campaign_count=len(campaigns),
            max_campaign_severity=round(max_sev, 3),
        )

    def _compute_cross_correlation(self, a: VectorTimeSeries,
                                    b: VectorTimeSeries
                                    ) -> Optional[CrossVectorLink]:
        """计算两向量间的互相关和简化Granger得分, 最大滞后=n//3。"""
        seq_a = a.window_counts
        seq_b = b.window_counts
        n = min(len(seq_a), len(seq_b))
        if n < self._min_windows:
            return None

        max_lag = n // 3
        best_corr = 0.0
        best_lag = 0

        mean_a = sum(seq_a[:n]) / n
        mean_b = sum(seq_b[:n]) / n
        std_a = math.sqrt(sum((x - mean_a) ** 2 for x in seq_a[:n]) / n)
        std_b = math.sqrt(sum((x - mean_b) ** 2 for x in seq_b[:n]) / n)

        if std_a < 1e-6 or std_b < 1e-6:
            return CrossVectorLink(
                source_vector=a.vector_name, target_vector=b.vector_name,
                correlation=0.0, optimal_lag=0, granger_score=0.0,
                is_significant=False,
                lead_lag_description="无变化(常值向量)")

        for lag in range(-max_lag, max_lag + 1):
            corr_sum = 0.0
            count = 0
            for t in range(max(0, -lag), min(n - lag, n)):
                ia, ib = t + lag, t
                if 0 <= ia < n and 0 <= ib < n:
                    corr_sum += ((seq_a[ia] - mean_a) *
                                (seq_b[ib] - mean_b))
                    count += 1
            if count > 0:
                corr = corr_sum / (count * std_a * std_b)
                if abs(corr) > abs(best_corr):
                    best_corr = corr
                    best_lag = lag

        # Granger得分: 仅正滞后有意义(A的历史→B的当前)
        abs_lag = abs(best_lag)
        if abs_lag > 0 and abs_lag < n - 2:
            if best_lag > 0:
                granger = self._simple_granger(seq_a[:n], seq_b[:n], abs_lag)
            elif best_lag < 0:
                granger = self._simple_granger(seq_b[:n], seq_a[:n], abs_lag)
            else:
                granger = 0.0
        else:
            granger = 0.0

        is_sig = abs(best_corr) >= self._threshold
        if best_lag > 0:
            desc = f"{a.vector_name}领先{b.vector_name}{best_lag}个窗口"
        elif best_lag < 0:
            desc = f"{b.vector_name}领先{a.vector_name}{-best_lag}个窗口"
        else:
            desc = f"{a.vector_name}与{b.vector_name}同步"

        return CrossVectorLink(
            source_vector=a.vector_name,
            target_vector=b.vector_name,
            correlation=round(best_corr, 4),
            optimal_lag=best_lag,
            granger_score=round(granger, 4),
            is_significant=is_sig,
            lead_lag_description=desc,
        )

    @staticmethod
    def _simple_granger(seq_a: List[int], seq_b: List[int],
                         lag: int) -> float:
        """简化Granger得分: R²方差缩减 ∈[0,1]。"""
        n = len(seq_a)
        if n < lag + 5 or lag == 0:
            return 0.0

        # 受限模型: B_t = α + ε  (仅B的均值)
        mean_b = sum(seq_b[lag:]) / max(n - lag, 1)
        ssr_restricted = sum((seq_b[t] - mean_b) ** 2
                            for t in range(lag, n))

        # 非受限模型: B_t = α + β*A_{t-lag} + ε
        a_delayed = [seq_a[t - lag] for t in range(lag, n)]
        b_current = [seq_b[t] for t in range(lag, n)]
        m = len(a_delayed)
        if m < 2:
            return 0.0

        mean_ad = sum(a_delayed) / m
        mean_bc = sum(b_current) / m
        # 简单线性回归: β = Cov(A_lag, B) / Var(A_lag)
        cov = sum((a_delayed[i] - mean_ad) * (b_current[i] - mean_bc)
                  for i in range(m))
        var_a = sum((x - mean_ad) ** 2 for x in a_delayed)
        if var_a < 1e-6:
            return 0.0
        beta = cov / var_a
        alpha = mean_bc - beta * mean_ad

        ssr_unrestricted = sum(
            (b_current[i] - (alpha + beta * a_delayed[i])) ** 2
            for i in range(m))

        if ssr_restricted < 1e-6:
            return 0.0
        r2 = 1.0 - ssr_unrestricted / ssr_restricted
        return max(0.0, min(r2, 1.0))

    def _find_campaigns(self, active_vectors: List[str],
                         links: List[CrossVectorLink]
                         ) -> List[CoordinatedCampaign]:
        sig_links = [l for l in links if l.is_significant]
        adj: Dict[str, List[str]] = defaultdict(list)
        for link in sig_links:
            adj[link.source_vector].append(link.target_vector)
            adj[link.target_vector].append(link.source_vector)

        visited: Set[str] = set()
        components: List[List[str]] = []
        for v in active_vectors:
            if v not in visited and v in adj:
                comp = self._bfs(v, adj, visited)
                if len(comp) >= 2:
                    components.append(comp)

        # 每个连通分量→协同活动
        campaigns: List[CoordinatedCampaign] = []
        for idx, comp in enumerate(components):
            # 收集该分量的所有关联边
            comp_links = [
                l for l in sig_links
                if l.source_vector in comp and l.target_vector in comp
            ]
            mean_corr = (sum(abs(l.correlation) for l in comp_links) /
                         max(len(comp_links), 1))
            diversity = len(comp) / max(len(active_vectors), 1)
            severity = min(mean_corr * 0.5 + diversity * 0.5, 1.0)

            campaigns.append(CoordinatedCampaign(
                campaign_id=f"campaign_{idx+1}",
                involved_vectors=comp,
                correlation_links=comp_links,
                start_window=0,   # 由调用方在完整分析中填充
                end_window=0,
                severity_score=round(severity, 3),
                vector_diversity=round(diversity, 3),
                mean_correlation=round(mean_corr, 3),
                description=(f"协同DDoS活动涉及{len(comp)}个向量"
                            f"({', '.join(comp)}), 平均关联{mean_corr:.2f}"),
            ))

        campaigns.sort(key=lambda c: -c.severity_score)
        return campaigns

    @staticmethod
    def _bfs(start: str, adj: Dict[str, List[str]],
              visited: Set[str]) -> List[str]:
        comp: List[str] = []
        queue = [start]
        while queue:
            node = queue.pop(0)
            if node in visited:
                continue
            visited.add(node)
            comp.append(node)
            queue.extend(adj.get(node, []))
        return comp


__all__ = [
    "VectorTimeSeries", "CrossVectorLink", "CoordinatedCampaign",
    "CrossVectorReport", "CrossVectorCorrelator",
]
