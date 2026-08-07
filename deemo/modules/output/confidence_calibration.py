# 创建: 2026-07-14 21:38
# 修改: 2026-07-14 22:10 — 审计修复: RAVEN引用替换为Dempster-Shafer证据理论
"""
证据驱动置信度校准 (Evidence-Driven Confidence Calibration, EDCC)
------------------------------------------------------------------
基于证据链的完整性和一致性, 动态校准报告的置信度评分.

设计依据:
  安全分析报告的置信度常基于单一模型输出——可能过于乐观.
  借鉴 Dempster-Shafer 证据理论 中多源证据
  按可靠度折扣合并的原则: 完整性低的证据源应降低其权重.
  EDCC 将此原则工程化为三维折扣因子.

  EDCC 计算三个维度的置信度折扣因子:
    1. 证据完整性: 所需证据类型 (CFG/数据流/符号/动态) 的覆盖率
    2. 证据一致性: 同类型内多条证据的吻合度
    3. 证据时效性: 动态证据的年龄衰减
  校准公式: calibrated = raw × disc_completeness × disc_consistency × disc_freshness
"""
import math
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class EvidenceChain:
    """单条发现的证据链."""
    finding_id: str
    raw_confidence: float = 0.5
    evidence_types: Set[str] = field(default_factory=set)  # cfg/dataflow/symbolic/dynamic
    evidence_items: List[Dict[str, Any]] = field(default_factory=list)
    consistency_score: float = 1.0
    newest_evidence_age_hours: float = 0.0


class ConfidenceCalibrator:
    """证据驱动的置信度校准器.

    用法:
      cc = ConfidenceCalibrator()
      calibrated = cc.calibrate(evidence_chain)
      print(f'Raw: {evidence_chain.raw_confidence:.2f}, '
            f'Calibrated: {calibrated:.2f}')
    """

    def __init__(self):
        # 期望的证据类型——完整分析应覆盖所有 4 类
        self._expected_types = {'cfg', 'dataflow', 'symbolic', 'dynamic'}
        # 各证据类型的权重
        self._type_weights = {
            'cfg': 0.30, 'dataflow': 0.35,
            'symbolic': 0.20, 'dynamic': 0.15,
        }
        # 时效衰减半衰期 (小时)
        self._freshness_halflife_h = 24.0

    def calibrate(self, chain: EvidenceChain) -> float:
        """校准置信度."""
        raw = chain.raw_confidence

        # 1. 完整性折扣: 缺失的证据类型越多, 折扣越大
        completeness = self._completeness_discount(chain.evidence_types)
        # 2. 一致性折扣: 证据间冲突降低置信度
        consistency = self._consistency_discount(chain)
        # 3. 时效性折扣: 旧证据权重衰减
        freshness = self._freshness_discount(chain.newest_evidence_age_hours)

        calibrated = raw * completeness * consistency * freshness
        return round(max(0.05, min(0.99, calibrated)), 4)

    def calibrate_all(self, chains: List[EvidenceChain]) -> List[float]:
        return [self.calibrate(c) for c in chains]

    def _completeness_discount(self, present_types: Set[str]) -> float:
        if not present_types:
            return 0.3
        covered_weight = sum(
            self._type_weights.get(t, 0.0) for t in present_types
        )
        total_weight = sum(self._type_weights.values())
        # 至少 30% 折扣保底
        return max(0.3, covered_weight / total_weight)

    def _consistency_discount(self, chain: EvidenceChain) -> float:
        if len(chain.evidence_items) < 2:
            return 0.7  # 单条证据 → 折扣
        # 按类型分组
        by_type: Dict[str, List[str]] = {}
        for item in chain.evidence_items:
            etype = item.get('type', 'unknown')
            desc = item.get('description', '')
            by_type.setdefault(etype, []).append(desc)

        scores = []
        for etype, descs in by_type.items():
            if len(descs) < 2:
                scores.append(0.7)
                continue
            sims = []
            for i in range(len(descs)):
                for j in range(i + 1, len(descs)):
                    sims.append(_text_jaccard(descs[i], descs[j]))
            scores.append(sum(sims) / len(sims) if sims else 0.5)

        avg_consistency = sum(scores) / len(scores) if scores else 0.5
        # 一致性 > 0.7 → 小折扣, < 0.3 → 大折扣
        return max(0.4, avg_consistency)

    def _freshness_discount(self, age_hours: float) -> float:
        if age_hours <= 0:
            return 1.0
        # 指数衰减: exp(-ln(2) * age / halflife)
        decay = math.exp(-math.log(2) * age_hours / self._freshness_halflife_h)
        return max(0.5, decay)

    def calibration_report(self, chain: EvidenceChain) -> Dict[str, Any]:
        """生成校准的详细分解报告."""
        calibrated = self.calibrate(chain)
        comp = self._completeness_discount(chain.evidence_types)
        cons = self._consistency_discount(chain)
        fresh = self._freshness_discount(chain.newest_evidence_age_hours)

        missing = self._expected_types - chain.evidence_types
        recommendations = []
        if missing:
            recommendations.append(f'缺少证据类型: {", ".join(sorted(missing))}')
        if cons < 0.6:
            recommendations.append('证据间一致性低, 建议重新验证')
        if fresh < 0.8:
            recommendations.append('证据时效性不足, 建议重新采集动态数据')

        return {
            'raw_confidence': chain.raw_confidence,
            'calibrated_confidence': calibrated,
            'discounts': {
                'completeness': round(comp, 3),
                'consistency': round(cons, 3),
                'freshness': round(fresh, 3),
            },
            'total_discount': round(comp * cons * fresh, 3),
            'recommendations': recommendations,
        }


def _text_jaccard(a: str, b: str) -> float:
    if not a or not b:
        return 0.0
    if a == b:
        return 1.0
    sa = set(a.lower().split())
    sb = set(b.lower().split())
    if not sa or not sb:
        return 0.0
    return len(sa & sb) / len(sa | sb)
