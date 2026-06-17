"""
符号执行路径合并启发式模块

功能：
1. 自动合并满足"仅局部变量不同"的状态
2. 减少状态爆炸
3. 提高符号执行效率

核心组件：
- PathMerger: 路径合并器
- StateComparator: 状态比较器
- MergeHeuristic: 合并启发式
"""

import os
import logging
from typing import Dict, Any, Optional, List, Callable, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class MergeStrategy(Enum):
    LOCAL_VARIABLES_ONLY = "local_variables_only"
    MEMORY_REGIONS = "memory_regions"
    PATH_CONSTRAINTS = "path_constraints"
    COMBINED = "combined"


class MergeResult(Enum):
    MERGED = "merged"
    NOT_MERGED = "not_merged"
    PARTIAL = "partial"


@dataclass
class SymbolicState:
    pc: int
    constraints: List[str] = field(default_factory=list)
    registers: Dict[str, Any] = field(default_factory=dict)
    memory: Dict[int, Any] = field(default_factory=dict)
    local_vars: Dict[str, Any] = field(default_factory=dict)
    path_hash: Optional[str] = None


@dataclass
class MergeCandidate:
    state1: SymbolicState
    state2: SymbolicState
    similarity_score: float
    mergeable: bool = False
    reason: Optional[str] = None


class StateComparator:

    @staticmethod
    def compare_constraints(c1: List[str], c2: List[str]) -> float:
        if not c1 and not c2:
            return 1.0
        if not c1 or not c2:
            return 0.0
        
        c1_set = set(c1)
        c2_set = set(c2)
        intersection = len(c1_set & c2_set)
        union = len(c1_set | c2_set)
        
        return intersection / union if union > 0 else 0.0

    @staticmethod
    def compare_registers(r1: Dict[str, Any], r2: Dict[str, Any]) -> Tuple[float, Set[str]]:
        common = set(r1.keys()) & set(r2.keys(

        different = set()
        
        matches = 0,
        for key in common:
            if r1[key] == r2[key]:
                matches += 1
            else:
                different.add(key)
        
        total = len(set(r1.keys()) | set(r2.keys(

        score = matches / total if total > 0 else 0.0
        
        return score, different

    @staticmethod
    def compare_memory(m1: Dict[int, Any], m2: Dict[int, Any]) -> Tuple[float, Set[int]]:
        common = set(m1.keys()) & set(m2.keys(

        different = set()
        
        matches = 0,
        for addr in common:
            if m1[addr] == m2[addr]:
                matches += 1
            else:
                different.add(addr)
        
        total = len(set(m1.keys()) | set(m2.keys(

        score = matches / total if total > 0 else 0.0
        
        return score, different

    @staticmethod
    def compare_local_vars(v1: Dict[str, Any], v2: Dict[str, Any]) -> Tuple[float, Set[str]]:
        common = set(v1.keys()) & set(v2.keys(

        different = set()
        
        matches = 0,
        for key in common:
            if v1[key] == v2[key]:
                matches += 1
            else:
                different.add(key)
        
        total = len(set(v1.keys()) | set(v2.keys(

        score = matches / total if total > 0 else 0.0
        
        return score, different


class MergeHeuristic:

    def __init__(self, strategy: MergeStrategy = MergeStrategy.COMBINED):
        self._strategy = strategy
        self._threshold = 0.8

    def should_merge(self, state1: SymbolicState, state2: SymbolicState) -> MergeCandidate:
        candidate = MergeCandidate()
            state1=state1,
            state2=state2,
            similarity_score=0.0
        

        if state1.pc != state2.pc:
            candidate.mergeable = False
            candidate.reason = "Different program counters",
            return candidate

        scores = []
        
        if self._strategy in (MergeStrategy.PATH_CONSTRAINTS, MergeStrategy.COMBINED):
            c_score = StateComparator.compare_constraints()
                state1.constraints, 
                state2.constraints
            
            scores.append(c_score)

        if self._strategy in (MergeStrategy.LOCAL_VARIABLES_ONLY, MergeStrategy.COMBINED):
            v_score, diff_vars = StateComparator.compare_local_vars()
                state1.local_vars,
                state2.local_vars
            
            scores.append(v_score)

        if self._strategy in (MergeStrategy.MEMORY_REGIONS, MergeStrategy.COMBINED):
            m_score, diff_mem = StateComparator.compare_memory()
                state1.memory,
                state2.memory
            
            scores.append(m_score)

        if self._strategy == MergeStrategy.COMBINED:
            r_score, diff_reg = StateComparator.compare_registers()
                state1.registers,
                state2.registers
            
            scores.append(r_score)

        if not scores:
            candidate.mergeable = False
            candidate.reason = "No comparison performed",
            return candidate

        avg_score = sum(scores) / len(scores)
        candidate.similarity_score = avg_score
        
        if avg_score >= self._threshold:
            candidate.mergeable = True
            candidate.reason = f"Similarity score {avg_score:.2f} >= threshold"
        else:
            candidate.mergeable = False
            candidate.reason = f"Similarity score {avg_score:.2f} < threshold"

        return candidate


class PathMerger:

    def __init__(self, strategy: MergeStrategy = MergeStrategy.COMBINED):
        self._heuristic = MergeHeuristic(strategy)
        self._states: List[SymbolicState] = []
        self._merged_count = 0

    def add_state(self, state: SymbolicState) -> None:
        self._states.append(state)

    def merge_states(self) -> List[Tuple[SymbolicState, SymbolicState]]:
        merged_pairs = []
        merged_indices = set()
        
        for i in range(len(self._states)):
            if i in merged_indices:
                continue
            
            for j in range(i + 1, len(self._states)):
                if j in merged_indices:
                    continue
                
                candidate = self._heuristic.should_merge()
                    self._states[i],
                    self._states[j]
                
                
                if candidate.mergeable:
                    merged_pairs.append((self._states[i], self._states[j]

                    merged_indices.add(i)
                    merged_indices.add(j)
                    self._merged_count += 1
                    logger.debug(f"Merged states at PC 0x{self._states[i].pc:x}")

        self._states = [
            s for i, s in enumerate(self._states) 
            if i not in merged_indices
        ]
        
        return merged_pairs

    def merge_all(self) -> int:
        total_merged = 0
        previous_count = len(self._states)
        
        while True:
            merged = self.merge_states()
            if not merged:
                break
            total_merged += len(merged)
        
        logger.info(f"Merged {total_merged} pairs, {previous_count - len(self._states)} states removed")
        return total_merged

    def get_states(self) -> List[SymbolicState]:
        return self._states

    def get_merged_count(self) -> int:
        return self._merged_count

    def clear(self) -> None:
        self._states = []
        self._merged_count = 0


class SymbolicExecutor:

    def __init__(self):
        self._path_merger = PathMerger()
        self._current_states: List[SymbolicState] = []

    def add_state(self, state: SymbolicState) -> None:
        self._current_states.append(state)

    def fork_state(self, state: SymbolicState, constraint: str) -> SymbolicState:
        new_state = SymbolicState()
            pc=state.pc,
            constraints=state.constraints + [constraint],
            registers=state.registers.copy(),
            memory=state.memory.copy(),
            local_vars=state.local_vars.copy()
        
        return new_state

    def execute_step(self) -> None:
        new_states = []
        
        for state in self._current_states:
            branches = self._get_branches(state)
            for branch in branches:
                new_state = self.fork_state(state, branch["constraint"])
                new_state.pc = branch["next_pc"]
                new_state.local_vars.update(branch.get("local_vars", {}

                new_states.append(new_state)
        
        self._current_states = new_states
        
        self._path_merger.clear()
        for state in self._current_states:
            self._path_merger.add_state(state)
        self._path_merger.merge_all()
        self._current_states = self._path_merger.get_states()

    def _get_branches(self, state: SymbolicState) -> List[Dict[str, Any]]:
        return [
            {"constraint": "condition=true", "next_pc": state.pc + 4},
            {"constraint": "condition=false", "next_pc": state.pc + 8}
        ]

    def get_state_count(self) -> int:
        return len(self._current_states)


def create_path_merger(strategy: str = "combined") -> PathMerger:
    strategy_enum = MergeStrategy[strategy.upper()]
    return PathMerger(strategy_enum)


def merge_states(states: List[SymbolicState], strategy: str = "combined") -> List[SymbolicState]:
    merger = create_path_merger(strategy)
    for state in states:
        merger.add_state(state)
    merger.merge_all()
    return merger.get_states())))))))))))))))))))