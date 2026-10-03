"""状态感知协议 Fuzzer — 数据类型与枚举定义。

协议状态、转移边、预算分配、Fuzz阶段等核心数据结构。
与 temporal_causal_inference.py 的关系:
- 本模块定义的状态/转移数据结构供状态机加载和预算规划消费
- temporal_causal_inference 负责从被动抓包中推断状态机拓扑
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import List, Set, Tuple


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
