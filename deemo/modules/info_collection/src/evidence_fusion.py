"""
跨采集器证据融合 (CCEF) —— Dempster-Shafer 理论 + FNBT 冲突消解。

多个采集器可能对同一目标给出矛盾结论, 例如 host_enum 报告端口开放
但 net_mapping 未检测到对应服务。独立路由的采集器无融合层, 分析者
需手动对账。本模块将每个采集器输出建模为 D-S 证据体, 在统一的辨识
框架 Θ 上融合, 当冲突因子 K 超过阈值时采用 FNBT
开放世界重分配, 避免 Dempster 规则在高冲突下的反直觉归一化。

辨识框架按采集意图动态构建 —— 不同意图使用不同 Θ, 避免无关假设
空间中的虚假冲突计算。
"""

# File: evidence_fusion.py  |  2026-07-30 create CCEF; 2026-08-04 audit: theta_mass refactor

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple


@dataclass
class EvidenceBody:
    """D-S 证据体。theta_mass 独立存储, 不与 focal elements 混用。"""
    source_id: str
    focal_bpa: Dict[FrozenSet[str], float]  # 命题 → 信念质量, 不含 Θ
    theta_mass: float = 0.0                  # 分配给 Θ (全局不确定性) 的质量
    confidence: float = 0.5
    timestamp: float = 0.0

    def total_mass(self) -> float:
        return sum(self.focal_bpa.values()) + self.theta_mass


@dataclass
class FusionResult:
    combined_bpa: Dict[FrozenSet[str], float]
    theta_mass: float
    belief: Dict[str, float]
    plausibility: Dict[str, float]
    conflict_factor: float
    conflict_resolution: str  # "dempster" | "fnbt"
    fused_conclusion: str


class EvidenceFusionEngine:
    """
    D-S 证据融合引擎。

    Dempster 正交和: m₁₂(A) = Σ_{B∩C=A} m₁(B)·m₂(C) / (1-K)
    其中 K = Σ_{B∩C=∅} m₁(B)·m₂(C), Θ 与任何集合的交为自身。
    FNBT 模式: K > threshold 时, 冲突质量不归一化,
    而是按开放世界假设重新分配到 Θ。
    """

    _K_THRESHOLD = 0.65

    def __init__(self, conflict_threshold: float = 0.65):
        self._K_threshold = conflict_threshold

    @staticmethod
    def make_singleton_bpa(
        source_id: str, hypothesis: str,
        mass: float, confidence: float = 1.0,
    ) -> EvidenceBody:
        """单一结论 → 证据体。mass*confidence 分配给 {hypothesis}, 剩余给 Θ。"""
        m = max(0.0, min(1.0, mass)) * confidence
        return EvidenceBody(
            source_id=source_id,
            focal_bpa={frozenset([hypothesis]): m},
            theta_mass=1.0 - m,
            confidence=confidence,
        )

    @staticmethod
    def make_set_bpa(
        source_id: str, hypotheses: Set[str],
        mass: float, confidence: float = 1.0,
    ) -> EvidenceBody:
        """集合结论 → 证据体。真值在 hypotheses 集合内。"""
        m = max(0.0, min(1.0, mass)) * confidence
        return EvidenceBody(
            source_id=source_id,
            focal_bpa={frozenset(hypotheses): m},
            theta_mass=1.0 - m,
            confidence=confidence,
        )

    def fuse(self, bodies: List[EvidenceBody]) -> FusionResult:
        """Dempster 组合 + FNBT 冲突消解。"""
        if not bodies:
            return FusionResult({}, 1.0, {}, {}, 0.0, "none", "无证据")
        if len(bodies) == 1:
            return self._single(bodies[0])

        # 初始化累积状态
        cum_focal = dict(bodies[0].focal_bpa)
        cum_theta = bodies[0].theta_mass
        total_K = 0.0

        for body in bodies[1:]:
            new_focal: Dict[FrozenSet[str], float] = {}
            new_theta = 0.0
            K = 0.0

            # 累积 × 当前: focal × focal
            for fa, ma in cum_focal.items():
                for fb, mb in body.focal_bpa.items():
                    inter = fa & fb
                    prod = ma * mb
                    if not inter:
                        K += prod
                    else:
                        new_focal[inter] = new_focal.get(inter, 0.0) + prod

            # 累积 focal × 当前 theta → 保持 focal
            for fa, ma in cum_focal.items():
                prod = ma * body.theta_mass
                new_focal[fa] = new_focal.get(fa, 0.0) + prod

            # 累积 theta × 当前 focal → 保持 focal
            for fb, mb in body.focal_bpa.items():
                prod = cum_theta * mb
                new_focal[fb] = new_focal.get(fb, 0.0) + prod

            # 累积 theta × 当前 theta → theta
            new_theta = cum_theta * body.theta_mass

            total_K += K

            if K > self._K_threshold:
                # FNBT: 冲突质量不归一化, 转给 Θ (开放世界)
                open_world = K / (1.0 + K)
                new_theta += open_world
            else:
                if K < 1.0:
                    norm = 1.0 / (1.0 - K)
                    for k in new_focal:
                        new_focal[k] *= norm
                    new_theta *= norm

            cum_focal = new_focal
            cum_theta = new_theta

        # 计算 belief / plausibility
        all_s: Set[str] = set()
        for k in cum_focal:
            all_s.update(k)

        belief: Dict[str, float] = {}
        plaus: Dict[str, float] = {}
        for s in all_s:
            sf = frozenset([s])
            bel = sum(m for k, m in cum_focal.items() if k.issubset(sf))
            pl = sum(m for k, m in cum_focal.items() if k & sf) + cum_theta
            belief[s] = round(bel, 4)
            plaus[s] = round(pl, 4)

        ranked = sorted(belief.items(), key=lambda x: x[1], reverse=True)
        conclusion = f"{ranked[0][0]}: bel={ranked[0][1]:.3f}" if ranked else "无显著结论"

        return FusionResult(
            combined_bpa={k: round(v, 4) for k, v in cum_focal.items()},
            theta_mass=round(cum_theta, 4),
            belief=belief, plausibility=plaus,
            conflict_factor=round(total_K, 4),
            conflict_resolution="fnbt" if total_K > self._K_threshold else "dempster",
            fused_conclusion=conclusion,
        )

    def _single(self, body: EvidenceBody) -> FusionResult:
        all_s: Set[str] = set()
        for k in body.focal_bpa:
            all_s.update(k)
        belief: Dict[str, float] = {}
        plaus: Dict[str, float] = {}
        for s in all_s:
            sf = frozenset([s])
            bel = sum(m for k, m in body.focal_bpa.items() if k.issubset(sf))
            pl = sum(m for k, m in body.focal_bpa.items() if k & sf) + body.theta_mass
            belief[s] = round(bel, 4)
            plaus[s] = round(pl, 4)
        return FusionResult(
            combined_bpa=dict(body.focal_bpa), theta_mass=body.theta_mass,
            belief=belief, plausibility=plaus, conflict_factor=0.0,
            conflict_resolution="none", fused_conclusion="单一证据源",
        )


__all__ = ["EvidenceBody", "FusionResult", "EvidenceFusionEngine"]
