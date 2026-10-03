"""状态感知协议 Fuzzer — 核心类。

基于因果状态机的转移制导报文生成。
消费 temporal_causal_inference 推断的状态机，生成覆盖未访问转移的
报文序列，并优先选择高转移熵（= 高不确定性）的边进行探索。

自主探索模式: 当状态机尚无足够的转移边 (sparse phase) 时，切换到"探索模式"——
随机采样未访问的 (source_state, target_state) 对来指导报文生成，
而非依赖转移熵排序。转移边数达到 min_edges 后自动切换到"利用模式"。

- AFLNet: 首个基于状态的网络协议 fuzzer，
  本项目在其基础上增加了转移熵制导和自适应探索/利用切换。
- 因果状态机推断方法论: 基于转移熵
  与置换检验，
  从被动报文序列推断状态转移关系。
"""

from __future__ import annotations

import random
from collections import deque
from typing import Any, Dict, List, Optional, Set, Tuple

from ._types import FuzzPhase, FuzzingPlan, ProtocolState, StateTransition
from ._budget import plan_budget_core, plan_budget_spectral

class StateAwareFuzzer:
    """状态感知协议 Fuzzer。

    消费因果推断得到的状态机，按转移熵制导生成报文序列，
    支持自适应探索/利用切换、谱制导预算分配、MAB变异算子选择。
    """

    def __init__(self, min_edges_for_exploit: int = 20,
                 default_exploration_ratio: float = 0.3,
                 mab_selector=None,   # 可选: HierarchicalBanditManager实例
                 spectral_allocator=None):  # 可选: SpectralBudgetAllocator实例
        self._states: Dict[str, ProtocolState] = {}
        self._transitions: Dict[Tuple[str, str], StateTransition] = {}
        self._phase: FuzzPhase = FuzzPhase.EXPLORE
        self._min_edges_for_exploit = min_edges_for_exploit
        self._exploration_ratio = default_exploration_ratio
        self._current_state: str = ""
        # 历史记录
        self._visit_history: deque[str] = deque(maxlen=50)
        self._total_sessions: int = 0
        self._unique_crashes: int = 0
        # 2026-08 集成专利创新: MAB变异算子选择 + 谱制导预算
        self._mab_selector = mab_selector
        self._spectral_allocator = spectral_allocator
        self._spectral_state_scores: Dict[str, float] = {}

# 状态机加载
    def load_state_machine(self,
                            states: List[ProtocolState],
                            transitions: List[StateTransition]):
        """加载因果推断得到的状态机。"""
        self._states = {s.state_id: s for s in states}
        self._transitions = {}
        for t in transitions:
            key = (t.source, t.target)
            self._transitions[key] = t

        # 确定初始状态
        initial = [s for s in states if s.is_initial]
        if initial:
            self._current_state = initial[0].state_id

        # 判断阶段
        self._update_phase()

    def _update_phase(self):
        edge_count = len(self._transitions)
        if edge_count >= self._min_edges_for_exploit:
            self._phase = FuzzPhase.EXPLOIT
        else:
            self._phase = FuzzPhase.EXPLORE

    @property
    def phase(self) -> FuzzPhase:
        return self._phase

# 预算规划
    def plan_budget(self, total_sessions: int = 1000) -> FuzzingPlan:
        """按转移熵分配 fuzz 预算到各状态的转移边。"""
        return plan_budget_core(
            self._transitions, self._phase,
            self._exploration_ratio, total_sessions)

    def plan_budget_with_spectral_guidance(self,
                                            total_sessions: int = 1000
                                            ) -> FuzzingPlan:
        """谱制导预算规划: 用状态机谱漏洞得分替代均匀分配。"""
        plan, scores = plan_budget_spectral(
            self._states, self._transitions,
            self._spectral_allocator, self._exploration_ratio,
            total_sessions, self.plan_budget)
        self._spectral_state_scores = scores
        return plan

# 消息生成
    def next_message(self) -> Optional[str]:
        """生成下一条要发送的消息类型——基于当前状态和转移熵排序。"""
        if not self._current_state:
            return None

        # 从当前状态出发的所有转移
        outgoing = [
            ((s, t), trans) for (s, t), trans in self._transitions.items()
            if s == self._current_state
        ]

        if not outgoing:
            # 死胡同: 选择任意状态跳转
            return self._random_explore()

        if self._phase == FuzzPhase.EXPLORE:
            # 优先未访问
            unvisited = [(k, t) for k, t in outgoing if not t.has_been_visited]
            if unvisited:
                chosen = random.choice(unvisited)
                return chosen[1].trigger_msg_type
            return random.choice(outgoing)[1].trigger_msg_type
        else:
            # 按转移熵加权采样
            total_te = sum(t.transfer_entropy for _, t in outgoing)
            if total_te <= 0:
                return random.choice(outgoing)[1].trigger_msg_type

            r = random.random() * total_te
            cumulative = 0.0
            for (_, tgt), t in outgoing:
                cumulative += t.transfer_entropy
                if r <= cumulative:
                    return t.trigger_msg_type
            return outgoing[-1][1].trigger_msg_type

    def _random_explore(self) -> Optional[str]:
        """随机探索: 从所有转移中随机选择一条。"""
        if not self._transitions:
            return None
        chosen = random.choice(list(self._transitions.values()))
        return chosen.trigger_msg_type

# 反馈报告
    def report_transition_result(self,
                                   msg_type: str,
                                   success: bool,
                                   crashed: bool = False,
                                   new_state: Optional[str] = None):
        """报告一次消息发送的结果——用于更新状态转移统计和当前状态。"""
        self._total_sessions += 1
        self._visit_history.append(msg_type)

        if new_state:
            self._current_state = new_state

        # 更新转移统计
        for key, trans in self._transitions.items():
            if trans.trigger_msg_type == msg_type:
                trans.has_been_visited = True
                trans.visit_count += 1
                if crashed:
                    trans.crash_count += 1
                    self._unique_crashes += 1
                break

        # 检查是否需要从 EXPLORE 切到 EXPLOIT
        visited_count = sum(1 for t in self._transitions.values() if t.has_been_visited)
        if visited_count >= self._min_edges_for_exploit and self._phase == FuzzPhase.EXPLORE:
            self._phase = FuzzPhase.EXPLOIT

# 状态覆盖统计
    def coverage_stats(self) -> Dict[str, Any]:
        """返回当前的状态覆盖统计。"""
        total = len(self._transitions)
        visited = sum(1 for t in self._transitions.values() if t.has_been_visited)
        crashed = sum(1 for t in self._transitions.values() if t.crash_count > 0)
        return {
            "total_states": len(self._states),
            "total_transitions": total,
            "visited_transitions": visited,
            "coverage_ratio": round(visited / max(total, 1), 3),
            "transitions_with_crashes": crashed,
            "unique_crashes": self._unique_crashes,
            "total_sessions": self._total_sessions,
            "phase": self._phase.name,
        }

# 自适应预热
    def add_transition(self, src: str, tgt: str, msg_type: str,
                        transfer_entropy: float = 0.5, p_value: float = 0.01):
        """在线添加一条新学习到的转移 (自适应状态机扩展)。"""
        key = (src, tgt)
        if key not in self._transitions:
            self._transitions[key] = StateTransition(
                source=src, target=tgt,
                trigger_msg_type=msg_type,
                transfer_entropy=transfer_entropy,
                p_value=p_value,
            )
        # 确保源状态存在
        if src not in self._states:
            self._states[src] = ProtocolState(state_id=src, name=f"state_{src}")
        if tgt not in self._states:
            self._states[tgt] = ProtocolState(state_id=tgt, name=f"state_{tgt}")
        self._update_phase()

# MAB变异算子选择
    def select_mutation_operator(self) -> Optional[int]:
        """从MAB选择器获取当前状态下最优变异算子。

        先决条件: fuzzer初始化时传入了mab_selector。
        未提供时返回None，调用方使用默认变异策略。
        """
        if self._mab_selector is None:
            return None
        if not self._current_state:
            return None
        # 确保bandit中注册了当前状态
        state = self._states.get(self._current_state)
        msg_types = state.msg_types if state else set()
        self._mab_selector.register_state(self._current_state, msg_types)
        return self._mab_selector.select_operator(self._current_state)

# 差分反馈更新
    def report_differential_feedback(self,
                                      msg_type: str,
                                      reward: float,
                                      mutation_op: Optional[int] = None,
                                      new_state: Optional[str] = None):
        """将差分预言机奖励反馈给MAB选择器。

        reward ∈ [0,1]: 来自differential_reward_from_verdict的合成奖励。
        mutation_op: 产生此奖励的变异算子(用于更新对应臂)。
        """
        if self._mab_selector is not None:
            if mutation_op is not None and self._current_state:
                self._mab_selector.update(
                    self._current_state, mutation_op, reward)
        # 同时更新转移统计
        self.report_transition_result(
            msg_type, success=(reward > 0.1),
            crashed=(reward > 0.7), new_state=new_state)

    def reset(self):
        self._states.clear()
        self._transitions.clear()
        self._phase = FuzzPhase.EXPLORE
        self._current_state = ""
        self._visit_history.clear()
        self._total_sessions = 0
        self._unique_crashes = 0
        self._spectral_state_scores.clear()
