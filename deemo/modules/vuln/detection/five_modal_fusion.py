"""
五模态证据融合——扩展MultiModalVulnFuser至五模态(static+dynamic+LLM+fuzzing+symbex)。

理论依据:
  FuseBinRepr: 文本-图交叉注意力+三任务训练，
  40.8% MRR提升。五模态融合借鉴其跨模态对齐策略。

动机:
  现有MultiModalVulnFuser支持6种模态但fuzzing和symbex未实现:
  - fuzzing: 覆盖率增长曲线、崩溃发现、种子多样性
  - symbex: 路径约束满足性、可达性分析、输入构造
  此模块扩展为完整五模态融合(static+dynamic+LLM+fuzzing+symbex)，
  并提供证据冲突检测与自适应权重调整。

与现有实现差异:
  现有融合固定权重(static=0.30, cve=0.25, llm=0.20, graph=0.10, exploit=0.08, dynamic=0.07)。
  五模态融合引入:
  1. fuzzing模态(权重0.10): 覆盖率信号直接反映代码可达性
  2. symbex模态(权重0.12): 约束求解提供更强的可达性保证
  3. 自适应权重: 根据证据冲突程度动态调整各模态权重

模块位置: vuln/detection/five_modal_fusion.py
"""

import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import logging

_log = logging.getLogger(__name__)


# ============================================================================
# 证据类型定义
# ============================================================================

@dataclass
class ModalEvidence:
    """
    模态证据——单一分析模态的输出。

    扩展字段（相较原MultiModalVulnFuser）:
      - reachability_confidence: 该模态确认的可达性置信度
      - coverage_detail: 覆盖率详细信息（fuzzing/symbex专属）
    """
    source: str              # static | dynamic | llm | fuzzing | symbex
    score: float             # 该模态漏洞评分 [0, 1]
    confidence: float        # 该模态自身置信度 [0, 1]
    weight: float = 0.0      # 融合权重（可为自适应）
    metadata: Dict = field(default_factory=dict)
    reachability_confidence: float = 0.0
    coverage_detail: Dict = field(default_factory=dict)


@dataclass
class FusionResult:
    """融合结果——五模态证据综合输出"""
    final_score: float
    severity_label: str          # CRITICAL/HIGH/MEDIUM/LOW/INFO
    confidence: float
    modalities: List[ModalEvidence]
    fusion_method: str           # weighted_avg | sugeno | adaptive
    evidence_count: int
    evidence_conflicts: List[Dict]  # 冲突详情
    modality_weights_used: Dict[str, float]
    recommendation: str = ""


# ============================================================================
# 五模态默认权重
# ============================================================================

# 权重设计基准:
#   FuseBinRepr 消融实验: 文本与结构特征0.7:0.3最优。
#   扩展至五模态后，LLM+static为核心模态(0.55)，fuzzing+symbex提供
#   互补可达性与约束信息(0.22)，dynamic提供运行时验证(0.10)。
_FIVE_MODAL_WEIGHTS = {
    "static":   0.28,   # 静态分析（危险函数、数据流）
    "dynamic":  0.10,   # 动态沙箱（运行时行为）
    "llm":      0.27,   # LLM语义分析
    "fuzzing":  0.15,   # 模糊测试（覆盖率、崩溃）
    "symbex":   0.20,   # 符号执行（约束求解、可达性）
}


# ============================================================================
# 五模态融合器
# ============================================================================

class FiveModalFuser:
    """
    五模态证据融合器——扩展MultiModalVulnFuser至完整五模态。

    模态说明:
      static:   传统静态分析（危险函数评分、数据流路径）
      dynamic:  动态沙箱执行（API调用序列、行为指纹）
      llm:      LLM语义漏洞检测（ANVIL异常评分）
      fuzzing:  覆盖率引导模糊测试（边覆盖率、崩溃发现）
      symbex:   符号执行（约束求解、输入构造、路径可达性）

    融合方法:
      - weighted_avg: 加权平均（权重×置信度×分数）
      - sugeno: Sugeno模糊积分
      - adaptive: 自适应权重——根据证据冲突程度动态调权

    自适应权重原理:
      多模态评分高度不一致(discord > 0.3)时，降低冲突模态权重，
      提高一致模态权重。避免证据高度冲突时产生虚假高置信度。
    """

    def __init__(
        self,
        fusion_method: str = "adaptive",
        custom_weights: Optional[Dict[str, float]] = None,
    ):
        if fusion_method not in ("weighted_avg", "sugeno", "adaptive"):
            raise ValueError(f"不支持的融合方法: {fusion_method}")
        self._method = fusion_method
        self._weights = custom_weights or dict(_FIVE_MODAL_WEIGHTS)

    def fuse(self, evidences: List[ModalEvidence]) -> FusionResult:
        """融合多模态证据——主入口"""
        if not evidences:
            return FusionResult(
                final_score=0.0, severity_label="INFO", confidence=0.0,
                modalities=[], fusion_method=self._method,
                evidence_count=0, evidence_conflicts=[],
                modality_weights_used={},
                recommendation="无可用证据",
            )

        # 冲突检测——在所有方法之前运行
        conflicts = _detect_conflicts(evidences)

        if self._method == "weighted_avg":
            return self._fuse_weighted(evidences, conflicts)
        elif self._method == "sugeno":
            return self._fuse_sugeno(evidences, conflicts)
        else:
            return self._fuse_adaptive(evidences, conflicts)

    def _fuse_weighted(
        self, evidences: List[ModalEvidence], conflicts: List[Dict]
    ) -> FusionResult:
        """加权平均融合"""
        total_weight = 0.0
        weighted_sum = 0.0

        for ev in evidences:
            w = self._weights.get(ev.source, 0.1)
            total_weight += w * ev.confidence
            weighted_sum += w * ev.confidence * ev.score

        if total_weight == 0:
            return FusionResult(
                final_score=0.0, severity_label="INFO", confidence=0.0,
                modalities=evidences, fusion_method="weighted_avg",
                evidence_count=len(evidences), evidence_conflicts=conflicts,
                modality_weights_used=self._weights,
                recommendation="所有模态置信度为 0",
            )

        score = weighted_sum / total_weight
        avg_conf = total_weight / sum(self._weights.get(e.source, 0.1) for e in evidences)
        label = _score_to_label(score)

        return FusionResult(
            final_score=round(score, 4),
            severity_label=label,
            confidence=round(avg_conf, 4),
            modalities=evidences,
            fusion_method="weighted_avg",
            evidence_count=len(evidences),
            evidence_conflicts=conflicts,
            modality_weights_used=self._weights,
            recommendation=_generate_recommendation(label, score, conflicts),
        )

    def _fuse_sugeno(
        self, evidences: List[ModalEvidence], conflicts: List[Dict]
    ) -> FusionResult:
        """Sugeno模糊积分融合"""
        if len(evidences) == 1:
            return self._fuse_weighted(evidences, conflicts)

        sorted_ev = sorted(evidences, key=lambda e: e.score)

        # 计算模糊测度g(A_i)——以权重作为测度
        weights = [self._weights.get(e.source, 0.1) for e in sorted_ev]
        total_w = sum(weights)
        if total_w == 0:
            return FusionResult(
                final_score=0.0, severity_label="INFO", confidence=0.0,
                modalities=evidences, fusion_method="sugeno",
                evidence_count=len(evidences), evidence_conflicts=conflicts,
                modality_weights_used=self._weights,
                recommendation="权重总和为 0",
            )

        # Sugeno积分: max(min(h(x_i), g(A_i)))
        running_sum = 0.0
        max_val = 0.0
        for i, ev in enumerate(sorted_ev):
            running_sum += weights[i]
            g_i = running_sum / total_w
            val = min(ev.score, g_i)
            if val > max_val:
                max_val = val

        label = _score_to_label(max_val)
        avg_conf = sum(e.confidence for e in evidences) / len(evidences)

        return FusionResult(
            final_score=round(max_val, 4),
            severity_label=label,
            confidence=round(avg_conf, 4),
            modalities=evidences,
            fusion_method="sugeno",
            evidence_count=len(evidences),
            evidence_conflicts=conflicts,
            modality_weights_used=self._weights,
            recommendation=_generate_recommendation(label, max_val, conflicts),
        )

    def _fuse_adaptive(
        self, evidences: List[ModalEvidence], conflicts: List[Dict]
    ) -> FusionResult:
        """
        自适应权重融合——根据证据冲突动态调权。

        策略:
          1. 计算证据discord分数（平均绝对偏差）
          2. discord > 0.3时: 识别离群模态（与中位数差>0.2），
             将其权重减半，其余模态按比例重分配
          3. 使用调整后权重进行加权平均融合

        证据高度冲突时避免虚假高置信度。
        """
        adaptive_weights = dict(self._weights)
        scores = [e.score for e in evidences]

        if len(scores) >= 3:
            discord = _compute_discord(scores)
            if discord > 0.3:
                median = sorted(scores)[len(scores) // 2]
                for ev in evidences:
                    if abs(ev.score - median) > 0.2:
                        # 离群模态权重减半
                        old_w = adaptive_weights.get(ev.source, 0.1)
                        adaptive_weights[ev.source] = old_w * 0.5

                # 重归一化
                total = sum(adaptive_weights.values())
                if total > 0:
                    for k in adaptive_weights:
                        adaptive_weights[k] /= total

        # 加权平均
        total_weight = 0.0
        weighted_sum = 0.0
        for ev in evidences:
            w = adaptive_weights.get(ev.source, 0.1)
            total_weight += w * ev.confidence
            weighted_sum += w * ev.confidence * ev.score

        if total_weight == 0:
            return FusionResult(
                final_score=0.0, severity_label="INFO", confidence=0.0,
                modalities=evidences, fusion_method="adaptive",
                evidence_count=len(evidences), evidence_conflicts=conflicts,
                modality_weights_used=adaptive_weights,
                recommendation="所有模态置信度为 0",
            )

        score = weighted_sum / total_weight
        avg_conf = total_weight / sum(adaptive_weights.get(e.source, 0.1) for e in evidences)
        label = _score_to_label(score)

        return FusionResult(
            final_score=round(score, 4),
            severity_label=label,
            confidence=round(avg_conf, 4),
            modalities=evidences,
            fusion_method="adaptive",
            evidence_count=len(evidences),
            evidence_conflicts=conflicts,
            modality_weights_used=adaptive_weights,
            recommendation=_generate_recommendation(label, score, conflicts),
        )


# ============================================================================
# 辅助函数
# ============================================================================

def _score_to_label(score: float) -> str:
    if score >= 0.85:
        return "CRITICAL"
    if score >= 0.65:
        return "HIGH"
    if score >= 0.40:
        return "MEDIUM"
    if score >= 0.15:
        return "LOW"
    return "INFO"


def _compute_discord(scores: List[float]) -> float:
    """计算证据discord——平均绝对偏差×2.5（与现有多模态模块一致）"""
    if len(scores) < 2:
        return 0.0
    avg = sum(scores) / len(scores)
    mad = sum(abs(s - avg) for s in scores) / len(scores)
    return min(1.0, mad * 2.5)


def _detect_conflicts(evidences: List[ModalEvidence]) -> List[Dict]:
    """检测模态间证据冲突"""
    conflicts = []
    scores = [e.score for e in evidences]
    if len(scores) < 2:
        return conflicts

    discord = _compute_discord(scores)
    if discord > 0.3:
        high_score_sources = [
            e.source for e in evidences if e.score > 0.7
        ]
        low_score_sources = [
            e.source for e in evidences if e.score < 0.3
        ]
        if high_score_sources and low_score_sources:
            conflicts.append({
                "type": "high_low_divergence",
                "high_modalities": high_score_sources,
                "low_modalities": low_score_sources,
                "discord": round(discord, 3),
                "detail": "部分模态的评分高度不一致",
            })

    return conflicts


def _generate_recommendation(
    label: str, score: float, conflicts: List[Dict]
) -> str:
    """根据融合结果产出操作建议"""
    if conflicts:
        return (
            f"证据存在冲突 ({label}, score={score:.2f})。"
            f"建议对冲突模态进行人工审查后重新评估。"
        )
    if label in ("CRITICAL", "HIGH"):
        return f"检测到高风险漏洞 ({label}, score={score:.2f})。建议优先修复并验证。"
    if label == "MEDIUM":
        return f"检测到中等风险 ({label}, score={score:.2f})。建议在下一迭代修复。"
    return f"风险较低 ({label}, score={score:.2f})。可延后处理或标记为信息。"


# ============================================================================
# 便捷函数
# ============================================================================

def make_evidence(
    source: str,
    score: float,
    confidence: float,
    reachability: float = 0.0,
    **metadata,
) -> ModalEvidence:
    """创建模态证据——与现有多模态模块接口兼容"""
    return ModalEvidence(
        source=source,
        score=min(1.0, max(0.0, score)),
        confidence=min(1.0, max(0.0, confidence)),
        weight=_FIVE_MODAL_WEIGHTS.get(source, 0.1),
        metadata=metadata,
        reachability_confidence=reachability,
    )


def fuse_five_modals(
    static_score: float = 0.0, static_conf: float = 0.0,
    dynamic_score: float = 0.0, dynamic_conf: float = 0.0,
    llm_score: float = 0.0, llm_conf: float = 0.0,
    fuzzing_score: float = 0.0, fuzzing_conf: float = 0.0,
    symbex_score: float = 0.0, symbex_conf: float = 0.0,
    method: str = "adaptive",
) -> FusionResult:
    """便捷函数: 五模态融合——单行调用"""
    evidences = []
    if static_conf > 0:
        evidences.append(make_evidence("static", static_score, static_conf))
    if dynamic_conf > 0:
        evidences.append(make_evidence("dynamic", dynamic_score, dynamic_conf))
    if llm_conf > 0:
        evidences.append(make_evidence("llm", llm_score, llm_conf))
    if fuzzing_conf > 0:
        evidences.append(make_evidence("fuzzing", fuzzing_score, fuzzing_conf))
    if symbex_conf > 0:
        evidences.append(make_evidence("symbex", symbex_score, symbex_conf))
    return FiveModalFuser(fusion_method=method).fuse(evidences)


__all__ = [
    "ModalEvidence",
    "FusionResult",
    "FiveModalFuser",
    "make_evidence",
    "fuse_five_modals",
    "_FIVE_MODAL_WEIGHTS",
]
