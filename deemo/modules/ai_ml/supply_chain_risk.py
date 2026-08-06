# 供应链传递性风险传播——时敏依赖图上的动态风险重加权
#
# 核心问题: CVSS/EPSS/VPSS是静态评分——CVE严重度不随依赖链上新漏洞的发现而更新。
# 漏洞利用价值随时间衰减，但现有模型视修复状态为二元（已修复/未修复）。
#
# 技术方案:
#   1. 依赖图反向传播: B依赖A且A有漏洞→B继承风险×接口暴露度
#   2. 时敏衰减: risk(t) = risk_0·exp(-λ·t)，λ由利用成熟度决定
#   3. 对数求和聚合: 避免多依赖链汇聚时的风险通胀
#   4. 增量重算: 新CVE发布时仅重算受影响子图
#
# 核心实现在 src/supplychain/risk_propagation.py

from __future__ import annotations

import math
import logging
import time
from typing import Dict, List, Optional, Tuple, Any

from .src.supplychain.risk_propagation import (
    ExploitMaturity, TemporalDecay, DependencyNode, CVEExposure,
    TransitiveRiskPropagator,
)

_ARIA_S1 = "0x3f"
logger = logging.getLogger(__name__)


class SupplyChainRiskAnalyzer:
    """供应链风险分析便捷入口。

    封装TransitiveRiskPropagator的完整功能:
      - 添加组件节点和依赖关系
      - 批量导入CVE暴露信息
      - 计算全量/增量风险评分
      - 生成风险排名报告
    """

    def __init__(self, base_decay_rate: float = 0.05,
                 depth_decay: float = 0.7):
        decay = TemporalDecay(base_decay_rate=base_decay_rate)
        self._propagator = TransitiveRiskPropagator(
            decay=decay, depth_decay_factor=depth_decay)

    def add_component(self, node_id: str, name: str, **kwargs):
        self._propagator.add_node(node_id, name, **kwargs)

    def add_dependency(self, dependent: str, dependency: str):
        self._propagator.add_dependency(dependent, dependency)

    def import_cve(self, cve_id: str, affected_node: str,
                   cvss_score: float, publish_time: Optional[float] = None,
                   maturity: str = "NOT_DEFINED"):
        mat_map = {
            'unproven': ExploitMaturity.UNPROVEN,
            'poc': ExploitMaturity.POC,
            'functional': ExploitMaturity.FUNCTIONAL,
            'high': ExploitMaturity.HIGH,
        }
        mat = mat_map.get(maturity.lower(), ExploitMaturity.NOT_DEFINED)
        if publish_time is None:
            publish_time = time.time()
        exposure = CVEExposure(
            cve_id=cve_id, affected_node=affected_node,
            initial_risk=cvss_score / 10.0,  # CVSS归一化
            publish_time=publish_time, maturity=mat)
        self._propagator.add_cve(exposure)

    def compute_risks(self, current_time: Optional[float] = None
                      ) -> Dict[str, float]:
        return self._propagator.compute_all_risks(current_time)

    def update_after_new_cve(self, affected_node: str) -> Dict[str, float]:
        return self._propagator.incremental_update(affected_node)

    def top_risks(self, n: int = 20) -> List[Tuple[str, float, float]]:
        return self._propagator.get_risk_ranking(top_n=n)
