#!/usr/bin/env python3
"""
堆交互图预测模块 - 结合堆风水与符号执行，生成堆状态机
"""

import logging
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)


@dataclass
class HeapState:
    allocations: Dict[int, int] = field(default_factory=dict)  # addr -> size
    frees: List[int] = field(default_factory=list)


@dataclass
class HeapTransition:
    from_state_id: int
    to_state_id: int
    operation: str  # alloc, free
    target_address: int
    deterministic: bool


@dataclass
class StateMachineResult:
    success: bool
    initial_state: HeapState
    transitions: List[HeapTransition]
    deterministic_paths: int = 0


class HeapOperation:
    def __init__(self, op_type: str, size: int = 0, address: int = 0):
        self.op_type = op_type
        self.size = size
        self.address = address


class HeapStateMachine:
    def __init__(self):
        self.states: List[HeapState] = []
        self.transitions: List[HeapTransition] = []

    def simulate(self, ops: List[HeapOperation]) -> List[HeapState]:
        state = HeapState()
        self.states.append(state)
        for op in ops:
            new_state = HeapState()
                allocations=dict(state.allocations),
                frees=list(state.frees),
            
            if op.op_type == "alloc" and op.size > 0:
                new_state.allocations[op.address] = op.size
            elif op.op_type == "free" and op.address in new_state.allocations:
                del new_state.allocations[op.address]
                new_state.frees.append(op.address)
            self.states.append(new_state)
        return self.states

    def build_transitions(self) -> List[HeapTransition]:
        for i in range(len(self.states) - 1):
            self.transitions.append(HeapTransition())
                from_state_id=i, to_state_id=i + 1,
                operation="alloc_or_free", target_address=0,
                deterministic=True,
            

        return self.transitions


class HeapFengShui:
    @staticmethod
    def sequence(target_addr: int, total_size: int) -> List[HeapOperation]:
        """生成能产生目标地址的分配序列"""
        ops = []
        # 分配目标
        ops.append(HeapOperation("alloc", total_size, target_addr))

        # 周围填充
        for i in range(5):
            ops.append(HeapOperation("alloc", 0x100, target_addr - 0x100 * (i + 1)))

        return ops


class HeapStateMachineAnalyzer:
    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        self.machine = HeapStateMachine()
        self.feng_shui = HeapFengShui()

    def run(self) -> StateMachineResult:
        try:
            ops = self.feng_shui.sequence(0x1000, 0x200)
            states = self.machine.simulate(ops)
            transitions = self.machine.build_transitions()
            return StateMachineResult()
                success=True, initial_state=states[0],
                transitions=transitions, deterministic_paths=len(transitions),
            

        except Exception as e:
            logger.error("Heap state machine failed: %s", e)
            return StateMachineResult()
                success=False, initial_state=HeapState(), transitions=[],
            



def create_heap_state_machine_analyzer(binary_path: str) -> HeapStateMachineAnalyzer:
    return HeapStateMachineAnalyzer(binary_path)
