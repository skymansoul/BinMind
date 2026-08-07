"""
时序因果意图链重建 (TCICR)。

SIFT-D 检测漂移, 本模块重建攻击叙事。从分类器输出的意图序列中
推断最可能的杀伤链路径, 识别缺失阶段, 预测下一动作。

与 MDP-MCTS 的差异:
MDP-MCTS 从 CTI 非结构化文本中推断攻击链, 属于 NLP 语义解析。
本模块从已分类的结构化意图序列中重建 —— 输入是分类器输出流,
而非原始 CTI 报告。适用场景不同: 本模块用于实时交互式分析会话。

算法: 加权维特比解码 — 将意图序列映射到杀伤链阶段序列,
使用转移概率矩阵 + 意图→阶段混淆矩阵联合优化。
"""

# File: causal_chain.py  |  2026-07-30 create TCICR; 2026-08-04 audit: compress tables

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from .intent_route import IntentCategory


class KillChainPhase:
    """杀伤链阶段, 与 llm_intent_infer.py 中的定义一致但语义更细。"""
    RECON = "侦察"
    WEAPONIZATION = "武器化"
    DELIVERY = "投递"
    EXPLOITATION = "利用"
    INSTALLATION = "安装"
    PERSISTENCE = "持久化"
    C2 = "命令与控制"
    EXFILTRATION = "数据窃取"
    IMPACT = "影响"
    UNKNOWN = "未知"

    @classmethod
    def all_phases(cls) -> List[str]:
        return [
            cls.RECON, cls.WEAPONIZATION, cls.DELIVERY,
            cls.EXPLOITATION, cls.INSTALLATION, cls.PERSISTENCE,
            cls.C2, cls.EXFILTRATION, cls.IMPACT,
        ]


# 意图类别 → 杀伤链阶段的发射概率矩阵
# P(phase | intent): 给定意图类别, 最可能对应的杀伤链阶段
# 非对称设计: 一个意图类别可对应多个阶段, 反映真实世界中
# 同一类工具在不同阶段的使用 (如文件操作在安装阶段和外传阶段都出现)

_INTENT_TO_PHASE: Dict[IntentCategory, Dict[str, float]] = {
    IntentCategory.STATIC_COLLECTION: {KillChainPhase.RECON: 0.70, KillChainPhase.DELIVERY: 0.10, KillChainPhase.UNKNOWN: 0.20},
    IntentCategory.DYNAMIC_INTERACTION: {KillChainPhase.EXPLOITATION: 0.50, KillChainPhase.INSTALLATION: 0.20, KillChainPhase.IMPACT: 0.15, KillChainPhase.UNKNOWN: 0.15},
    IntentCategory.INTEL_CORRELATION: {KillChainPhase.RECON: 0.35, KillChainPhase.WEAPONIZATION: 0.25, KillChainPhase.DELIVERY: 0.15, KillChainPhase.UNKNOWN: 0.25},
    IntentCategory.FILE_ANALYSIS: {KillChainPhase.WEAPONIZATION: 0.40, KillChainPhase.DELIVERY: 0.30, KillChainPhase.INSTALLATION: 0.10, KillChainPhase.UNKNOWN: 0.20},
    IntentCategory.UNKNOWN: {KillChainPhase.UNKNOWN: 1.0},
}

# 杀伤链阶段转移概率: P(next_phase | current_phase)
# 沿 Lockheed Martin 的顺序推进, 但允许跳跃和回溯。
_PHASE_TRANSITIONS: Dict[str, Dict[str, float]] = {
    KillChainPhase.RECON: {KillChainPhase.WEAPONIZATION: 0.45, KillChainPhase.DELIVERY: 0.25, KillChainPhase.RECON: 0.20, KillChainPhase.UNKNOWN: 0.10},
    KillChainPhase.WEAPONIZATION: {KillChainPhase.DELIVERY: 0.55, KillChainPhase.WEAPONIZATION: 0.25, KillChainPhase.EXPLOITATION: 0.10, KillChainPhase.UNKNOWN: 0.10},
    KillChainPhase.DELIVERY: {KillChainPhase.EXPLOITATION: 0.50, KillChainPhase.INSTALLATION: 0.25, KillChainPhase.DELIVERY: 0.10, KillChainPhase.UNKNOWN: 0.15},
    KillChainPhase.EXPLOITATION: {KillChainPhase.INSTALLATION: 0.40, KillChainPhase.PERSISTENCE: 0.20, KillChainPhase.C2: 0.15, KillChainPhase.EXPLOITATION: 0.15, KillChainPhase.UNKNOWN: 0.10},
    KillChainPhase.INSTALLATION: {KillChainPhase.PERSISTENCE: 0.35, KillChainPhase.C2: 0.30, KillChainPhase.EXPLOITATION: 0.15, KillChainPhase.UNKNOWN: 0.20},
    KillChainPhase.PERSISTENCE: {KillChainPhase.C2: 0.40, KillChainPhase.PERSISTENCE: 0.25, KillChainPhase.EXFILTRATION: 0.15, KillChainPhase.UNKNOWN: 0.20},
    KillChainPhase.C2: {KillChainPhase.EXFILTRATION: 0.35, KillChainPhase.IMPACT: 0.25, KillChainPhase.C2: 0.25, KillChainPhase.UNKNOWN: 0.15},
    KillChainPhase.EXFILTRATION: {KillChainPhase.IMPACT: 0.40, KillChainPhase.EXFILTRATION: 0.30, KillChainPhase.C2: 0.20, KillChainPhase.UNKNOWN: 0.10},
    KillChainPhase.IMPACT: {KillChainPhase.IMPACT: 0.50, KillChainPhase.EXFILTRATION: 0.15, KillChainPhase.UNKNOWN: 0.35},
}


@dataclass
class ChainLink:
    """攻击链的一环。"""
    position: int
    intent_category: IntentCategory
    inferred_phase: str
    confidence: float
    evidence: str  # 原始请求摘要
    is_gap: bool = False  # 是否为推断的缺失阶段


@dataclass
class CausalChainReport:
    """因果链重建报告。"""
    links: List[ChainLink]
    most_likely_path: List[str]          # 最可能的阶段序列
    missing_phases: List[str]             # 缺失的杀伤链阶段
    predicted_next_phase: Optional[str]   # 预测的下一个阶段
    overall_coherence: float              # 链的连贯性评分 [0,1]
    alternative_paths: List[List[str]]    # 2-3 个备选路径


class CausalChainReconstructor:
    """
    因果链重建器。

    输入: 按时间排序的意图分类结果列表
    输出: 包含最可能杀伤链路径、缺失阶段、下一阶段预测的报告

    算法: 加权维特比 — 在每个时间步, 取发射概率和转移概率的乘积
    最大值作为当前阶段的最优指派。不同于标准 HMM,
    观测 (意图类别) 与隐状态 (杀伤链阶段) 之间存在一对多映射,
    需要使用意图→阶段的概率矩阵而非确定性映射。
    """

    def __init__(self):
        self._intent_to_phase = _INTENT_TO_PHASE
        self._transitions = _PHASE_TRANSITIONS

    def reconstruct(
        self,
        intent_sequence: List[Tuple[IntentCategory, float, str]],
        # 每项: (类别, 置信度, 请求摘要)
    ) -> CausalChainReport:
        """
        从意图序列重建因果链。

        intent_sequence 应为按时间排序的列表。
        最少需要 2 条意图才能做有意义的链重建。
        """
        if len(intent_sequence) < 2:
            return self._single_link_report(intent_sequence)

        phases = KillChainPhase.all_phases()
        n = len(intent_sequence)

        # 维特比矩阵: dp[t][p] = 到时间步 t 以阶段 p 结尾的最优对数概率
        dp: List[Dict[str, float]] = [{} for _ in range(n)]
        backpointer: List[Dict[str, Optional[str]]] = [{} for _ in range(n)]

        # 初始化 t=0
        cat0, conf0, _ = intent_sequence[0]
        emission0 = self._intent_to_phase.get(cat0, {KillChainPhase.UNKNOWN: 1.0})
        for phase in phases:
            emit_prob = emission0.get(phase, 0.01) * conf0
            dp[0][phase] = math.log(max(1e-10, emit_prob))
            backpointer[0][phase] = None

        # 递推
        for t in range(1, n):
            cat, conf, _ = intent_sequence[t]
            emission = self._intent_to_phase.get(cat, {KillChainPhase.UNKNOWN: 1.0})
            for phase in phases:
                emit_prob = emission.get(phase, 0.01) * conf
                best_prev_logp = float("-inf")
                best_prev = None
                for prev_phase in phases:
                    trans_prob = self._transitions.get(prev_phase, {}).get(phase, 0.05)
                    candidate = dp[t - 1][prev_phase] + math.log(max(1e-10, trans_prob))
                    if candidate > best_prev_logp:
                        best_prev_logp = candidate
                        best_prev = prev_phase
                dp[t][phase] = best_prev_logp + math.log(max(1e-10, emit_prob))
                backpointer[t][phase] = best_prev

        # 回溯: 找到最优路径
        best_final = max(phases, key=lambda p: dp[-1][p])
        path: List[str] = [best_final]
        for t in range(n - 1, 0, -1):
            prev = backpointer[t][path[0]]
            if prev is None:
                prev = KillChainPhase.UNKNOWN
            path.insert(0, prev)

        # 构建 ChainLink 列表
        links: List[ChainLink] = []
        for i, (cat, conf, evidence) in enumerate(intent_sequence):
            links.append(ChainLink(
                position=i,
                intent_category=cat,
                inferred_phase=path[i],
                confidence=conf,
                evidence=evidence[:80],
            ))

        # 识别缺失阶段
        observed_phases = set(path)
        missing = [p for p in KillChainPhase.all_phases()
                    if p not in observed_phases and p != KillChainPhase.UNKNOWN]

        # 预测下一阶段
        current = path[-1]
        next_trans = self._transitions.get(current, {})
        predicted = max(next_trans, key=next_trans.get) if next_trans else None
        if predicted == KillChainPhase.UNKNOWN:
            # 找次优的非 UNKNOWN 预测
            sorted_trans = sorted(
                [(p, v) for p, v in next_trans.items() if p != KillChainPhase.UNKNOWN],
                key=lambda x: x[1], reverse=True,
            )
            predicted = sorted_trans[0][0] if sorted_trans else None

        # 连贯性评分
        coherence = self._compute_coherence(path)

        # 备选路径 (top-2 以外的维特比候选)
        alternatives = self._alternative_paths(dp, phases, 2)

        return CausalChainReport(
            links=links,
            most_likely_path=path,
            missing_phases=missing,
            predicted_next_phase=predicted,
            overall_coherence=coherence,
            alternative_paths=alternatives,
        )

    def _single_link_report(
        self, intent_sequence: List[Tuple[IntentCategory, float, str]]
    ) -> CausalChainReport:
        """单条意图的特例处理。"""
        if not intent_sequence:
            return CausalChainReport(
                links=[], most_likely_path=[], missing_phases=[],
                predicted_next_phase=None, overall_coherence=0.0,
                alternative_paths=[],
            )
        cat, conf, evidence = intent_sequence[0]
        emission = self._intent_to_phase.get(cat, {KillChainPhase.UNKNOWN: 1.0})
        best_phase = max(emission, key=emission.get)
        return CausalChainReport(
            links=[ChainLink(position=0, intent_category=cat,
                    inferred_phase=best_phase, confidence=conf,
                    evidence=evidence[:80])],
            most_likely_path=[best_phase],
            missing_phases=[p for p in KillChainPhase.all_phases()
                            if p != best_phase],
            predicted_next_phase=None,
            overall_coherence=0.5,
            alternative_paths=[],
        )

    def _compute_coherence(self, path: List[str]) -> float:
        """计算链的连贯性: 相邻阶段的平均转移概率。"""
        if len(path) < 2:
            return 0.5
        probs: List[float] = []
        for i in range(len(path) - 1):
            trans = self._transitions.get(path[i], {})
            probs.append(trans.get(path[i + 1], 0.05))
        return sum(probs) / len(probs)

    def _alternative_paths(
        self, dp: List[Dict[str, float]], phases: List[str], count: int
    ) -> List[List[str]]:
        """从维特比矩阵中提取次优路径。"""
        n = len(dp)
        if n == 0:
            return []
        alternatives: List[List[str]] = []
        # 在最后一步选择非最优的阶段作为备选终点
        best_final = max(phases, key=lambda p: dp[-1][p])
        sorted_finals = sorted(phases, key=lambda p: dp[-1][p], reverse=True)
        for alt_final in sorted_finals[1:count + 1]:
            alt_path: List[str] = [alt_final]
            # 简化: 从备选终点向前贪心回溯
            for t in range(n - 1, 0, -1):
                best_prev = max(phases, key=lambda p: dp[t - 1].get(p, float("-inf")))
                alt_path.insert(0, best_prev)
            alternatives.append(alt_path)
        return alternatives


__all__ = [
    "KillChainPhase",
    "ChainLink",
    "CausalChainReport",
    "CausalChainReconstructor",
]
