"""状态感知协议 Fuzzer — 基于因果状态机的转移制导报文生成。

修改记录:
2025-07-17 19:10 - 增加稀有转移加权: 少见的转移获得更高采样优先级
2025-07-20 14:33 - 引入 entropy_budget: 按转移熵分配 fuzz 预算到各状态
2025-07-25 09:18 - 新增 adaptive_warmup: 状态机尚稀疏时切换为探索模式

与 temporal_causal_inference.py 的关系:
- temporal_causal_inference: 从被动抓包中推断协议状态机和转移熵
- state_aware_fuzzer (本模块): 消费推断出的状态机，生成覆盖未访问转移的
  报文序列，并优先选择高转移熵（= 高不确定性）的边进行探索。

自主探索模式: 当状态机尚无足够的转移边 (sparse phase) 时，切换到"探索模式"——
随机采样未访问的 (source_state, target_state) 对来指导报文生成，
而非依赖转移熵排序。转移边数达到 min_edges 后自动切换到"利用模式"。

参考:
- SPIREFuzz (Chen et al., IEEE TIFS 2025): 使用扩散模型从真实流量中学习
  报文格式与状态转移关系，本项目以轻量转移熵排序替代扩散模型，
  适合快速部署和在线场景。
- RSAFL (Zhang et al., Computer & Security 2026): 从运行时内存快照中推断
  实现级协议状态机 (IPSM)，本项目使用因果推断替代内存分析，
  二者正交——可组合使用以获得更完整的状态覆盖。
- AFLNet (Pham et al., ICST 2020): 首个基于状态的网络协议 fuzzer，
  本项目在其基础上增加了转移熵制导和自适应探索/利用切换。
"""

from __future__ import annotations

import math
import random
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class ProtocolState:
    """协议状态——通过因果分析推断出的一个状态节点。"""
    state_id: str
    name: str = ""
    msg_types: Set[str] = field(default_factory=set)    # 此状态下的合法消息类型
    is_initial: bool = False
    is_terminal: bool = False


@dataclass
class StateTransition:
    """状态转移边——带转移熵评分。"""
    source: str              # source state_id
    target: str              # target state_id
    trigger_msg_type: str    # 触发转移的消息类型
    transfer_entropy: float  # 因果强度 (0~1, 来自 temporal_causal_inference)
    p_value: float = 1.0     # 统计显著性
    has_been_visited: bool = False
    visit_count: int = 0
    crash_count: int = 0     # 此转移导致崩溃的次数


@dataclass
class FuzzBudget:
    """每个状态的 fuzz 预算——按转移熵分配。"""
    state_id: str
    total_transitions: int
    visited_transitions: int
    entropy_sum: float       # 该状态所有转移的转移熵之和
    allocated_budget: int    # 分配的 fuzz 次数
    remaining: int


@dataclass
class FuzzingPlan:
    """一次 fuzzing 会话的计划——按预算分配要探索的转移。"""
    transitions_to_fuzz: List[Tuple[str, str, int]]  # (src, tgt, count)
    exploration_ratio: float   # 探索 vs 利用的比例
    sessions_planned: int


class FuzzPhase(Enum):
    EXPLORE = auto()   # 状态机稀疏阶段：随机探索
    EXPLOIT = auto()   # 状态机稠密阶段：按转移熵利用


class StateAwareFuzzer:
    """状态感知协议 Fuzzer。

    用法:
        fuzzer = StateAwareFuzzer()
        fuzzer.load_state_machine(states, transitions)
        plan = fuzzer.plan_budget(total_sessions=1000)
        for session in plan:
            msg = fuzzer.next_message()
            result = send_and_receive(msg)
            fuzzer.report_transition_result(msg_type, result)
    """

    def __init__(self, min_edges_for_exploit: int = 20,
                 default_exploration_ratio: float = 0.3):
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

    # ── 状态机加载 ───────────────────────────────────────────
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

    # ── 预算规划 ─────────────────────────────────────────────
    def plan_budget(self, total_sessions: int = 1000) -> FuzzingPlan:
        """按转移熵分配 fuzz 预算到各状态的转移边。"""
        transitions_plan: List[Tuple[str, str, int]] = []

        if self._phase == FuzzPhase.EXPLORE:
            # 探索模式: 均匀分配，优先未访问边
            unvisited = [
                (k, t) for k, t in self._transitions.items()
                if not t.has_been_visited
            ]
            if unvisited:
                per_edge = max(1, total_sessions // len(unvisited))
                for (src, tgt), _ in unvisited:
                    transitions_plan.append((src, tgt, per_edge))
            exp_ratio = 1.0
        else:
            # 利用模式: 按转移熵分配
            total_entropy = sum(t.transfer_entropy for t in self._transitions.values())
            if total_entropy <= 0:
                total_entropy = 1.0

            sorted_trans = sorted(
                self._transitions.items(),
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

            exp_ratio = self._exploration_ratio

        return FuzzingPlan(
            transitions_to_fuzz=transitions_plan,
            exploration_ratio=exp_ratio,
            sessions_planned=total_sessions,
        )

    # ── 消息生成 ─────────────────────────────────────────────
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

    # ── 反馈报告 ─────────────────────────────────────────────
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

    # ── 状态覆盖统计 ─────────────────────────────────────────
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

    # ── 自适应预热 ───────────────────────────────────────────
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

    def reset(self):
        self._states.clear()
        self._transitions.clear()
        self._phase = FuzzPhase.EXPLORE
        self._current_state = ""
        self._visit_history.clear()
        self._total_sessions = 0
        self._unique_crashes = 0
