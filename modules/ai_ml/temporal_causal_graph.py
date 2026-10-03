# 时态因果图: 从CVE时间序列中发现漏洞类型的因果先驱关系
#
# 核心问题: knowledge_graph.py建模关联关系但不建模因果方向-
# "CWE类型A的高发是否导致CWE类型B的增加？"
# 这类因果知识对漏洞预防策略至关重要。
#
# 方案:
#   1. 按CWE聚合月度CVE计数→多元时间序列
#   2. 成对Granger因果检验: A的过去值是否有助于预测B（在控制B自身的条件下）
#   3. 有向因果图: A→B表示A Granger-causes B，权重=F统计量的-log10(p)
#   4. 滑动窗口时变分析 + PageRank因果影响力排名
#
# 核心实现在 src/causal/granger_test.py

from __future__ import annotations

import logging
from typing import Dict, List, Tuple, Any

import numpy as np

from .src.causal.granger_test import (
    CausalEdge, CausalGraph, GrangerCausalityTester, TemporalCausalDiscovery,
)

logger = logging.getLogger(__name__)


class TemporalCausalGraphAnalyzer:
    """时态因果图分析便捷入口。

    封装因果发现+分析管线: 月度CWE序列因果图构建、
    滑动窗口时变分析、根因类型识别、因果影响力排名。
    """

    def __init__(self, max_lag: int = 6, significance_level: float = 0.01):
        self._discovery = TemporalCausalDiscovery(
            max_lag=max_lag, alpha=significance_level)
        self._tester = GrangerCausalityTester(
            max_lag=max_lag, significance_level=significance_level)

    def build_causal_graph(self,
                           cwe_monthly_counts: Dict[str, np.ndarray],
                           min_obs: int = 24) -> CausalGraph:
        return self._discovery.discover_causal_graph(cwe_monthly_counts, min_obs)

    def find_root_causes(self,
                         cwe_monthly_counts: Dict[str, np.ndarray],
                         top_n: int = 10
                         ) -> List[Tuple[str, float, List[str]]]:
        """识别最具因果影响力的根因漏洞类型。"""
        return self._discovery.identify_root_causes(cwe_monthly_counts, top_n)

    def analyze_temporal_evolution(self,
                                    cwe_monthly_counts: Dict[str, np.ndarray],
                                    window_size: int = 36,
                                    step_size: int = 12
                                    ) -> List[Dict[str, Any]]:
        """滑动窗口分析因果关系的时间演化。"""
        return self._discovery.sliding_window_analysis(
            cwe_monthly_counts, window_size, step_size)

    def test_causal_pair(self,
                         x_series: np.ndarray,
                         y_series: np.ndarray,
                         source_name: str = "X",
                         target_name: str = "Y") -> CausalEdge:
        """测试一对CWE类型间的Granger因果关系。"""
        edge = self._tester.test_pair(x_series, y_series)
        edge.source_cwe = source_name
        edge.target_cwe = target_name
        return edge
