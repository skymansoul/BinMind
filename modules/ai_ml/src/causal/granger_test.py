# Granger因果检验 + 时态因果图发现
# 用于 temporal_causal_graph.py 的漏洞类型因果先驱发现

import math
import logging
from typing import Dict, List, Optional, Tuple, Any
from collections import defaultdict
from dataclasses import dataclass, field

import numpy as np
from scipy import stats as _stats

logger = logging.getLogger(__name__)


@dataclass
class CausalEdge:
    source_cwe: str
    target_cwe: str
    f_statistic: float
    p_value: float
    optimal_lag: int
    significance: float
    time_window_start: Optional[int] = None
    time_window_end: Optional[int] = None
    is_significant: bool = False


@dataclass
class CausalGraph:
    nodes: List[str]
    edges: List[CausalEdge]
    adjacency: np.ndarray
    node_influence: Dict[str, float]
    n_significant_edges: int
    total_tests: int


class GrangerCausalityTester:
    """成对Granger因果检验。

    X Granger-causes Y 当且仅当: 给定Y的过去值，
    X的过去值对预测Y有统计显著的额外贡献。
    """

    def __init__(self, max_lag: int = 6, significance_level: float = 0.01):
        self.max_lag = max_lag
        self.alpha = significance_level

    def test_pair(self, x_series: np.ndarray, y_series: np.ndarray,
                  min_lag: int = 1, max_lag: Optional[int] = None) -> CausalEdge:
        if max_lag is None:
            max_lag = self.max_lag
        T = min(len(x_series), len(y_series))
        if T < max_lag + 10:
            return CausalEdge(source_cwe="", target_cwe="",
                            f_statistic=0.0, p_value=1.0, optimal_lag=0,
                            significance=0.0, is_significant=False)
        best_f, best_p, best_lag = 0.0, 1.0, 1
        for lag in range(min_lag, max_lag + 1):
            f_stat, p_val = self._granger_test(x_series, y_series, lag)
            if f_stat > best_f:
                best_f, best_p, best_lag = f_stat, p_val, lag
        sig = -math.log10(max(best_p, 1e-16))
        return CausalEdge(source_cwe="", target_cwe="",
                         f_statistic=float(best_f), p_value=float(best_p),
                         optimal_lag=best_lag, significance=sig,
                         is_significant=(best_p < self.alpha))

    def _granger_test(self, x: np.ndarray, y: np.ndarray,
                      lag: int) -> Tuple[float, float]:
        T = len(x)
        n_obs = T - lag
        if n_obs < 10:
            return 0.0, 1.0
        Y = y[lag:]
        Xr = np.column_stack([np.ones(n_obs)] +
                            [y[lag-i-1:T-i-1] for i in range(lag)])
        Xu = np.column_stack([np.ones(n_obs)] +
                            [y[lag-i-1:T-i-1] for i in range(lag)] +
                            [x[lag-j-1:T-j-1] for j in range(lag)])
        try:
            br = np.linalg.lstsq(Xr, Y, rcond=None)[0]
            ssr_r = np.sum((Y - Xr @ br) ** 2)
            bu = np.linalg.lstsq(Xu, Y, rcond=None)[0]
            ssr_u = np.sum((Y - Xu @ bu) ** 2)
            if ssr_u < 1e-12:
                return 0.0, 1.0
            p = lag
            k = 1 + 2 * lag
            f_stat = ((ssr_r - ssr_u) / p) / (ssr_u / (n_obs - k))
            p_val = 1.0 - _stats.f.cdf(f_stat, p, n_obs - k)
            return float(f_stat), float(p_val)
        except np.linalg.LinAlgError:
            return 0.0, 1.0


class TemporalCausalDiscovery:
    """从CVE时间序列构建漏洞类型因果网络。"""

    def __init__(self, max_lag: int = 6, alpha: float = 0.01):
        self._tester = GrangerCausalityTester(max_lag=max_lag, significance_level=alpha)
        self.alpha = alpha

    def discover_causal_graph(self,
                              cwe_time_series: Dict[str, np.ndarray],
                              min_observations: int = 24) -> CausalGraph:
        cwes = [c for c, ts in cwe_time_series.items() if len(ts) >= min_observations]
        n = len(cwes)
        if n < 2:
            return CausalGraph(nodes=[], edges=[], adjacency=np.zeros((0, 0)),
                              node_influence={}, n_significant_edges=0, total_tests=0)
        edges = []
        n_tests = n * (n - 1)
        adj = np.zeros((n, n), dtype=np.float64)
        for i, source in enumerate(cwes):
            for j, target in enumerate(cwes):
                if i == j:
                    continue
                edge = self._tester.test_pair(
                    cwe_time_series[source], cwe_time_series[target])
                edge.source_cwe = source
                edge.target_cwe = target
                edges.append(edge)
                if edge.is_significant:
                    adj[i, j] = edge.significance
        bonferroni_alpha = self.alpha / max(1, n_tests)
        sig_count = 0
        for edge in edges:
            edge.is_significant = edge.p_value < bonferroni_alpha
            if edge.is_significant:
                sig_count += 1
        influence = self._compute_pagerank(adj, cwes)
        return CausalGraph(nodes=cwes, edges=edges, adjacency=adj,
                          node_influence=influence,
                          n_significant_edges=sig_count, total_tests=n_tests)

    def sliding_window_analysis(self, cwe_time_series, window_size=36, step_size=12):
        max_len = max(len(ts) for ts in cwe_time_series.values())
        windows = []
        for start in range(0, max_len - window_size, step_size):
            window_data = {}
            for cwe, ts in cwe_time_series.items():
                if len(ts) > start + window_size:
                    window_data[cwe] = ts[start:start + window_size]
            if len(window_data) >= 3:
                graph = self.discover_causal_graph(window_data)
                top = sorted([e for e in graph.edges if e.is_significant],
                            key=lambda e: -e.significance)[:5]
                windows.append({
                    'window_start': int(start),
                    'window_end': int(start + window_size),
                    'n_significant': graph.n_significant_edges,
                    'top_pairs': [(e.source_cwe, e.target_cwe, e.significance)
                                  for e in top]})
        return windows

    def _compute_pagerank(self, adjacency, nodes, damping=0.85, max_iter=100):
        n = len(nodes)
        if n == 0:
            return {}
        col_sums = adjacency.sum(axis=0)
        col_sums[col_sums == 0] = 1.0
        M = adjacency / col_sums
        pr = np.ones(n) / n
        for _ in range(max_iter):
            pr_new = (1 - damping) / n + damping * M @ pr
            if np.sum(np.abs(pr_new - pr)) < 1e-8:
                break
            pr = pr_new
        return {nodes[i]: float(pr[i]) for i in range(n)}

    def identify_root_causes(self, cwe_time_series, top_n=10):
        graph = self.discover_causal_graph(cwe_time_series)
        affected = defaultdict(list)
        for edge in graph.edges:
            if edge.is_significant:
                affected[edge.source_cwe].append(edge.target_cwe)
        ranked = sorted(graph.node_influence.items(), key=lambda x: -x[1])
        return [(cwe, influence, affected.get(cwe, []))
                for cwe, influence in ranked[:top_n]]
