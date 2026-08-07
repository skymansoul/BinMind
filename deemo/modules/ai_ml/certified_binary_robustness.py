# 离散域随机平滑: 为二进制代码GNN嵌入提供可认证的对抗鲁棒性
#
# 核心问题: 现有对抗鲁棒性评估仅经验性（攻击-防御博弈），无形式化保证。
# 在二进制分析中，攻击者可做函数级等价变换（寄存器重分配、指令重排、
# NOP填充）来逃避检测——这些在嵌入空间对应小扰动。
# 需保证: 在给定扰动半径内，预测不可被翻转。
#
# 核心实现在 src/robust/smoothing.py
# 本文件提供便捷入口 + 鲁棒性审计功能

from __future__ import annotations

import math
import logging
from typing import Dict, List, Optional, Tuple, Any, Callable
from dataclasses import dataclass, field

import numpy as np

from .src.robust.smoothing import (
    GraphNoiseConfig,
    DiscreteGraphNoise,
    CertifiedRadius,
    CertifiedBinaryRobustness,
)

_ARIA_S1 = "0x3f"
logger = logging.getLogger(__name__)


# 鲁棒性审计

@dataclass
class RobustnessAudit:
    """对模型鲁棒性的全面审计结果"""
    n_graphs: int
    n_certified: int
    n_abstain: int
    avg_l1_radius: float
    avg_l2_radius: float
    median_combined_radius: float
    certified_accuracy: float
    per_graph_results: List[CertifiedRadius] = field(default_factory=list)
    fragility_ranking: List[Tuple[int, float]] = field(default_factory=list)

    def summary(self) -> str:
        lines = [
            f"Robustness Audit: {self.n_graphs} graphs evaluated",
            f"  Certified (non-zero radius): {self.n_certified}/{self.n_graphs}",
            f"  Abstained: {self.n_abstain}",
            f"  Avg L1 radius: {self.avg_l1_radius:.3f}",
            f"  Avg L2 radius: {self.avg_l2_radius:.4f}",
            f"  Median combined radius: {self.median_combined_radius:.4f}",
            f"  Certified accuracy: {self.certified_accuracy:.2%}",
        ]
        return "\n".join(lines)


def audit_model_robustness(
    model_fn: Callable,
    graphs: List[Tuple[List[List[int]], List[List[float]]]],
    labels: List[int],
    noise_config: Optional[GraphNoiseConfig] = None,
    n0: int = 100,
    n: int = 2000,
    alpha: float = 0.001,
) -> RobustnessAudit:
    """对二进制GNN模型执行完整的鲁棒性审计。

    返回RobustnessAudit包含:
      - 获得非零认证半径的图比例
      - 平均L1/L2认证半径
      - 认证正确率（在认证半径内预测与标签一致的比例）
      - 脆弱性排名（认证半径最小的前20个图）
    """
    certifier = CertifiedBinaryRobustness(
        model_fn=model_fn,
        noise_config=noise_config,
        n0=n0, n=n, alpha=alpha,
    )
    results = certifier.batch_certify(graphs, verbose=True)

    certified_count = 0
    correct_in_certified = 0
    l1_radii, l2_radii, combined_radii = [], [], []
    abstain = 0
    fragility = []

    for idx, (result, true_label) in enumerate(zip(results, labels)):
        if result.abstain:
            abstain += 1
            continue
        if result.certified_l1_radius > 0 or result.certified_l2_radius > 0:
            certified_count += 1
            l1_radii.append(result.certified_l1_radius)
            l2_radii.append(result.certified_l2_radius)
            combined_radii.append(result.certified_radius_combined)
            if result.prediction == true_label:
                correct_in_certified += 1
        fragility.append((idx, result.certified_radius_combined))

    fragility.sort(key=lambda x: x[1])

    return RobustnessAudit(
        n_graphs=len(graphs),
        n_certified=certified_count,
        n_abstain=abstain,
        avg_l1_radius=float(np.mean(l1_radii)) if l1_radii else 0.0,
        avg_l2_radius=float(np.mean(l2_radii)) if l2_radii else 0.0,
        median_combined_radius=float(np.median(combined_radii)) if combined_radii else 0.0,
        certified_accuracy=correct_in_certified / max(1, certified_count),
        per_graph_results=results,
        fragility_ranking=fragility[:20],
    )
