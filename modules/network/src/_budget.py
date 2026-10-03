"""状态感知协议 Fuzzer — 预算规划逻辑。

将预算分配从 StateAwareFuzzer 类中提取为独立函数，
降低主类复杂度。提供两套分配策略:
1. 基于转移熵的标准分配 (EXPLORE 均匀 + EXPLOIT 按熵加权)
2. 谱制导分配 (用状态机谱漏洞得分替代均匀分配)

谱先验不替代在线反馈，仅影响初始预算分布。
fuzzing过程中reward反馈持续更新bandit后验;
谱先验在warmup阶段后权重衰减至零。
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from ._types import FuzzPhase, FuzzingPlan, ProtocolState, StateTransition


def plan_budget_core(
    transitions: Dict[Tuple[str, str], StateTransition],
    phase: FuzzPhase,
    exploration_ratio: float,
    total_sessions: int,
) -> FuzzingPlan:
    """按转移熵分配 fuzz 预算到各状态的转移边。"""
    transitions_plan: List[Tuple[str, str, int]] = []

    if phase == FuzzPhase.EXPLORE:
        # 探索模式: 均匀分配，优先未访问边
        unvisited = [
            (k, t) for k, t in transitions.items()
            if not t.has_been_visited
        ]
        if unvisited:
            per_edge = max(1, total_sessions // len(unvisited))
            for (src, tgt), _ in unvisited:
                transitions_plan.append((src, tgt, per_edge))
        exp_ratio = 1.0
    else:
        # 利用模式: 按转移熵分配
        total_entropy = sum(t.transfer_entropy for t in transitions.values())
        if total_entropy <= 0:
            total_entropy = 1.0

        sorted_trans = sorted(
            transitions.items(),
            key=lambda x: x[1].transfer_entropy * (1 if not x[1].has_been_visited else 0.3),
            reverse=True,
        )

        remaining = total_sessions
        for (src, tgt), t in sorted_trans:
            if remaining <= 0:
                break
            # 高转移熵 + 未访问 = 高分配权重
            weight = t.transfer_entropy / total_entropy
            if not t.has_been_visited:
                weight *= 2.0  # 未访问边权重翻倍
            alloc = max(1, int(total_sessions * weight))
            alloc = min(alloc, remaining)
            transitions_plan.append((src, tgt, alloc))
            remaining -= alloc

        exp_ratio = exploration_ratio

    return FuzzingPlan(
        transitions_to_fuzz=transitions_plan,
        exploration_ratio=exp_ratio,
        sessions_planned=total_sessions,
    )


def plan_budget_spectral(
    states: Dict[str, ProtocolState],
    transitions: Dict[Tuple[str, str], StateTransition],
    spectral_allocator,
    exploration_ratio: float,
    total_sessions: int,
    fallback_fn,  # 回退到标准分配的函数
) -> Tuple[FuzzingPlan, Dict[str, float]]:
    """谱制导预算规划: 用状态机谱漏洞得分替代均匀分配。

    返回 (FuzzingPlan, spectral_state_scores)。
    spectral_state_scores 供 MAB 变异算子选择时参考。
    若谱分析器不可用或状态数不足，回退到标准分配。
    """
    if spectral_allocator is None or len(states) < 3:
        return fallback_fn(total_sessions), {}

    # 构建谱分析输入
    state_ids = list(states.keys())
    trans_pairs = [(t.source, t.target) for t in transitions.values()]
    weights = {(t.source, t.target): t.transfer_entropy
               for t in transitions.values()}

    try:
        from .spectral_vulnerability import analyze_state_machine_vulnerability
        report = analyze_state_machine_vulnerability(
            state_ids, trans_pairs, weights, total_sessions)
    except ImportError:
        return fallback_fn(total_sessions), {}

    # 提取状态得分
    spectral_state_scores = {
        sv.state_id: sv.vulnerability_score
        for sv in report.state_scores
    }

    transitions_plan: List[Tuple[str, str, int]] = []
    remaining = total_sessions

    # 按谱得分加权分配: 高漏洞面状态获得更多fuzz预算
    score_sum = sum(
        max(spectral_state_scores.get(
            t.source, spectral_state_scores.get(t.target, 0.1)),
            0.05)
        for t in transitions.values()
    ) or 1.0

    sorted_trans = sorted(
        transitions.items(),
        key=lambda x: max(
            spectral_state_scores.get(x[1].source, 0.1),
            spectral_state_scores.get(x[1].target, 0.1)),
        reverse=True,
    )

    for (src, tgt), t in sorted_trans:
        if remaining <= 0:
            break
        state_score = max(
            spectral_state_scores.get(src, 0.1),
            spectral_state_scores.get(tgt, 0.1),
            0.05)
        alloc = max(1, int(total_sessions * state_score / score_sum))
        alloc = min(alloc, remaining)
        if not t.has_been_visited:
            alloc = max(alloc, 2)  # 未访问边最低2次尝试
        transitions_plan.append((src, tgt, alloc))
        remaining -= alloc

    plan = FuzzingPlan(
        transitions_to_fuzz=transitions_plan,
        exploration_ratio=exploration_ratio,
        sessions_planned=total_sessions,
    )
    return plan, spectral_state_scores
