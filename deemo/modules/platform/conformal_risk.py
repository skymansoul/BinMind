"""
共形风险预测 -- 为传播图风险评分提供有限样本有效的预测区间.

问题:
  RiskScorer 输出点估计风险值(0-1),但无不确定性量化.
  安全决策者需要知道"这个0.7的风险值有多可靠？"
  传统置信区间依赖分布假设(正态性),在非对称风险分布下失效.

方案:
  Split-conformal prediction.
  1. 将历史风险观测分为训练集和校准集
  2. 在训练集上拟合 RiskScorer
  3. 在校准集上计算非一致性得分(残差绝对值)
  4. 对新节点,预测区间 = [ŷ - q_{1-alpha}, ŷ + q_{1-alpha}]
     其中 q_{1-alpha} 为校准残差的 (1-alpha) 分位数

  有限样本保证:若训练/校准/测试数据满足可交换性,
  则 P(Y_test ∈ interval) ≥ 1-alpha.

创新点:
  对传播图拓扑特征条件分层----节点按层类型和入度分桶,每桶独立校准.
  避免全局分位数在异构节点间的不适当覆盖(firmware节点和smart_contract
  节点的风险分布完全不同,强制共享分位数会导致区间过宽或覆盖不足).

ref: Vovk, Gammerman, Shafer "Algorithmic Learning in a Random World".
ref: Lei et al. "Distribution-Free Predictive Inference for Regression" --
     split-conformal 的理论保证.
"""

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from .propagation_graph import PlatformLayer, PropagationGraph, VulnNode


@dataclass
class ConformalInterval:
    """共形预测区间."""
    point_estimate: float
    lower: float
    upper: float
    confidence_level: float       # 1 - alpha
    calibration_size: int
    bucket: str = ""


class StratifiedConformalCalibrator:
    """分层共形校准器 -- 按节点拓扑特征分桶,每桶独立校准残差分位数.

    桶划分依据:平台层类型 + 入度分位数(低/中/高).
    分层防止全局分位数在异构节点间的不适当覆盖.
    """

    def __init__(self, alpha: float = 0.10):
        self._alpha = alpha
        self._bucket_quantiles: Dict[str, float] = {}     # bucket -> q_{1-alpha}
        self._bucket_sizes: Dict[str, int] = {}
        self._fitted = False

    def _bucket_key(self, layer: PlatformLayer, indegree: int,
                    total_nodes: int) -> str:
        """生成桶标识.入度按三分位数分低/中/高三类."""
        if total_nodes <= 3:
            indegree_tier = "mid"
        elif indegree <= 1:
            indegree_tier = "low"
        elif indegree >= 5:
            indegree_tier = "high"
        else:
            indegree_tier = "mid"
        return f"{layer.name}_{indegree_tier}"

    def calibrate(self, calibration_graphs: List[PropagationGraph],
                  risk_scorer_fn: Callable[[PropagationGraph], Dict[str, float]]
                  ) -> Dict[str, Any]:
        """在校准集上计算每桶的残差分位数.

        risk_scorer_fn: PropagationGraph -> {node_id: risk_score}
        返回校准统计:{total_calibration_nodes, bucket_count, ...}
        """
        bucket_residuals: Dict[str, List[float]] = defaultdict(list)

        for graph in calibration_graphs:
            scores = risk_scorer_fn(graph)
            n = graph.node_count

            for nid, node in graph._nodes.items():
                predicted = scores.get(nid, node.severity)
                # 以 severity 作为伪真值(专家标注不可得时的代理)
                actual = node.severity
                residual = abs(predicted - actual)

                indegree = len(graph._rev_adj.get(nid, []))
                bucket = self._bucket_key(node.layer, indegree, n)
                bucket_residuals[bucket].append(residual)

        for bucket, residuals in bucket_residuals.items():
            sorted_r = sorted(residuals)
            # (1-alpha) 分位数:取 ceil((1-alpha)*(n+1))/n 位置
            idx = math.ceil((1.0 - self._alpha) * (len(sorted_r) + 1)) - 1
            idx = max(0, min(idx, len(sorted_r) - 1))
            self._bucket_quantiles[bucket] = sorted_r[idx]
            self._bucket_sizes[bucket] = len(sorted_r)

        self._fitted = True
        return {
            "total_calibration_nodes": sum(self._bucket_sizes.values()),
            "bucket_count": len(self._bucket_quantiles),
            "mean_bucket_size": round(
                sum(self._bucket_sizes.values()) / max(len(self._bucket_sizes), 1), 1
            ),
        }

    def predict_interval(self, node_id: str, point_estimate: float,
                         layer: PlatformLayer, indegree: int,
                         total_nodes: int) -> ConformalInterval:
        """为单个节点生成共形预测区间."""
        if not self._fitted:
            return ConformalInterval(
                point_estimate=point_estimate, lower=point_estimate,
                upper=point_estimate, confidence_level=0.0,
                calibration_size=0,
            )

        bucket = self._bucket_key(layer, indegree, total_nodes)
        q_val = self._bucket_quantiles.get(bucket, 0.3)  # 未校准桶默认±0.3

        return ConformalInterval(
            point_estimate=point_estimate,
            lower=max(0.0, point_estimate - q_val),
            upper=min(1.0, point_estimate + q_val),
            confidence_level=1.0 - self._alpha,
            calibration_size=self._bucket_sizes.get(bucket, 0),
            bucket=bucket,
        )

    @property
    def is_fitted(self) -> bool:
        return self._fitted


class ConformalRiskAnalyzer:
    """共形风险分析器 -- 端到端的共形预测管线.

    用法::

        calibrator = StratifiedConformalCalibrator(alpha=0.10)
        analyzer = ConformalRiskAnalyzer(calibrator)

        # 校准
        stats = analyzer.calibrate(historical_graphs, my_scorer_fn)

        # 预测
        intervals = analyzer.predict_intervals(new_graph, my_scorer_fn)
        for nid, interval in intervals.items():
            print(f"{nid}: {interval.point_estimate:.3f} [{interval.lower:.3f}, {interval.upper:.3f}]")
    """

    def __init__(self, calibrator: StratifiedConformalCalibrator):
        self._calibrator = calibrator

    def calibrate(self, calibration_graphs: List[PropagationGraph],
                  risk_scorer_fn: Callable[[PropagationGraph], Dict[str, float]]
                  ) -> Dict[str, Any]:
        """校准共形预测器."""
        return self._calibrator.calibrate(calibration_graphs, risk_scorer_fn)

    def predict_intervals(self, graph: PropagationGraph,
                          risk_scorer_fn: Callable[[PropagationGraph], Dict[str, float]]
                          ) -> Dict[str, ConformalInterval]:
        """为传播图中所有节点生成共形预测区间.

        返回 {node_id: ConformalInterval}.
        """
        scores = risk_scorer_fn(graph)
        n = graph.node_count
        intervals: Dict[str, ConformalInterval] = {}

        for nid, node in graph._nodes.items():
            point = scores.get(nid, node.severity)
            indeg = len(graph._rev_adj.get(nid, []))
            interval = self._calibrator.predict_interval(
                nid, point, node.layer, indeg, n,
            )
            intervals[nid] = interval

        return intervals

    def coverage_report(self, graph: PropagationGraph,
                        risk_scorer_fn: Callable[[PropagationGraph], Dict[str, float]],
                        true_risks: Dict[str, float],
                        ) -> Dict[str, Any]:
        """计算共形区间的实际覆盖率----用于模型验证.

        true_risks: 专家标注的真实风险值(或更高精度的估计值).
        """
        intervals = self.predict_intervals(graph, risk_scorer_fn)
        covered = 0
        total = 0
        widths = []
        bucket_coverage: Dict[str, List[bool]] = defaultdict(list)

        for nid, interval in intervals.items():
            true_val = true_risks.get(nid)
            if true_val is None:
                continue
            total += 1
            if interval.lower <= true_val <= interval.upper:
                covered += 1
            widths.append(interval.upper - interval.lower)
            bucket_coverage[interval.bucket].append(
                interval.lower <= true_val <= interval.upper
            )

        bucket_stats = {}
        for bucket, cov_list in bucket_coverage.items():
            bucket_stats[bucket] = {
                "coverage": round(sum(cov_list) / len(cov_list), 4),
                "n": len(cov_list),
            }

        return {
            "overall_coverage": round(covered / max(total, 1), 4),
            "total_nodes_evaluated": total,
            "mean_interval_width": round(sum(widths) / max(len(widths), 1), 4),
            "by_bucket": bucket_stats,
        }
