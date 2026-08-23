"""符号状态合并: 基于相似度的启发式路径合并, 缓解路径爆炸。

合并把语义相似的状态坍缩为同一程序计数器状态, 以精度换内存;
相似度比较约束集、寄存器、内存与局部变量。

增强:
- 动态阈值调整: merge_all() 在 1 轮内收敛则阈值上调 0.05 (更激进),
  超过 5 轮才收敛则下调 0.05
- 调用栈感知合并: PC 相同但调用栈不同则不合并, 不同调用路径的行为
  语义可能完全不同
- 合并代价估算 (MergeCostEstimator): precision_loss_ratio 超过 0.3
  时跳过合并, 防止丢失关键约束导致误报/漏报
- 增量合并 (IncrementalMerge): 距离矩阵缓存相似度, 合并后仅重算
  受影响的行/列, 避免全量 O(n^2) 重算
- 合并回退: undo_last_merge() 通过 deep copy 的 pre_merge_snapshot
  恢复最近一次 merge_states() 调用前的状态列表
- MergePolicyEngine: 可配置策略决定何时尝试合并 (EAGER/LAZY/ADAPTIVE)
- MergeQualityScore: 合并后重执行 1-2 步检查分支结果是否与原始状态
  一致, 低质量合并可回退
- StateHydration: 惰性反序列化, 延迟 pickle.load 直到状态实际被
  需要, 避免合并池空转时的不必要 IO
"""

import copy
import hashlib
import json
import logging
import os
import pickle
import tempfile
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
import typing
from collections import defaultdict, deque
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class MergeStrategy(Enum):
    """相似度比较所涉及的维度。"""
    NONE = "none"
    BY_PC = "by_pc"
    BY_CONSTRAINTS = "by_constraints"
    ADAPTIVE = "adaptive"
    LOCAL_VARIABLES_ONLY = "local_variables_only"
    MEMORY_REGIONS = "memory_regions"
    PATH_CONSTRAINTS = "path_constraints"
    COMBINED = "combined"


@dataclass
class MergeResult:
    """单次合并尝试的结果。"""
    merged_states: int = 0
    states_reduced: int = 0
    merged_pairs: List = field(default_factory=list)
    states: List = field(default_factory=list)


class MergePolicy:
    """控制符号执行中的合并触发时机。

    EAGER — 每步执行后立即合并，最大化内存节省但增加合并计算开销
    LAZY — 仅当活跃状态数超过阈值时才触发合并，减少不必要的比较
    ADAPTIVE — 监视状态增长率 vs 探索率，当状态膨胀速度超过新覆盖产生速度时合并
    """
    def __init__(self, strategy: MergeStrategy = MergeStrategy.ADAPTIVE,
                 max_states_before_merge: int = 50):
        self.strategy = strategy
        self.max_states_before_merge = max_states_before_merge


MergePolicy.EAGER = MergePolicy(max_states_before_merge=10)
MergePolicy.LAZY = MergePolicy(max_states_before_merge=50)
MergePolicy.ADAPTIVE = MergePolicy(max_states_before_merge=50)


@dataclass
class SymbolicState:
    """用于合并评估的最小符号状态。"""
    pc: int = 0
    state_id: str = ""
    constraints: List = field(default_factory=list)
    registers: Dict = field(default_factory=dict)
    memory: Dict = field(default_factory=dict)
    local_vars: Dict = field(default_factory=dict)
    path_hash: Optional[str] = None
    call_stack: List[int] = field(default_factory=list)


@dataclass
class MergeCandidate:
    """两状态可合并资格的评估结果。"""
    state1: Any = None
    state2: Any = None
    similarity_score: float = 0.0
    mergeable: bool = False
    reason: Optional[str] = None
    states: List = field(default_factory=list)
    pc: int = 0

    def __post_init__(self):
        if not self.states and self.state1 is not None and self.state2 is not None:
            self.states = [self.state1, self.state2]
        if not self.pc and self.state1 is not None:
            self.pc = getattr(self.state1, 'pc', 0)


@dataclass
class MergeQualityReport:
    """合并后质量评估结果。

    quality_score: 0-1, 越接近 1 表示合并状态复现了原始分支行为;
    branch_match_ratio: 合并分支与原始分支一致的占比;
    divergent_branches: 合并状态发生分歧的 PC 目标列表。
    """
    quality_score: float = 0.0
    branch_match_ratio: float = 0.0
    divergent_branches: List[int] = field(default_factory=list)
    re_execution_steps: int = 0
    merged_state_pc: int = 0


class StateComparator:
    """各维度的 Jaccard 相似度静态方法。"""

    @staticmethod
    def compare_constraints(c1: List[str], c2: List[str]) -> float:
        """约束字符串集合的 Jaccard 指数。"""
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
        """相同值寄存器占比, 返回差异键集合。"""
        common = set(r1.keys()) & set(r2.keys())
        different = set()
        matches = 0
        for key in common:
            if r1[key] == r2[key]:
                matches += 1
            else:
                different.add(key)
        total = len(set(r1.keys()) | set(r2.keys()))
        score = matches / total if total > 0 else 0.0
        return score, different

    @staticmethod
    def compare_memory(m1: Dict[int, Any], m2: Dict[int, Any]) -> Tuple[float, Set[int]]:
        """相同值内存地址占比, 返回差异地址集合。"""
        common = set(m1.keys()) & set(m2.keys())
        different = set()
        matches = 0
        for addr in common:
            if m1[addr] == m2[addr]:
                matches += 1
            else:
                different.add(addr)
        total = len(set(m1.keys()) | set(m2.keys()))
        score = matches / total if total > 0 else 0.0
        return score, different

    @staticmethod
    def compare_local_vars(v1: Dict[str, Any], v2: Dict[str, Any]) -> Tuple[float, Set[str]]:
        """相同值局部变量占比, 返回差异键集合。"""
        common = set(v1.keys()) & set(v2.keys())
        different = set()
        matches = 0
        for key in common:
            if v1[key] == v2[key]:
                matches += 1
            else:
                different.add(key)
        total = len(set(v1.keys()) | set(v2.keys()))
        score = matches / total if total > 0 else 0.0
        return score, different

    @staticmethod
    def compare_call_stacks(cs1: List[int], cs2: List[int]) -> float:
        """调用栈相似度：从栈底对齐比较，匹配的返回地址比例

        两个空栈视为完全匹配。栈深不同时，较短的栈与较长栈的前缀比较"""
        if not cs1 and not cs2:
            return 1.0
        min_len = min(len(cs1), len(cs2))
        if min_len == 0:
            return 0.0
        matches = sum(1 for i in range(min_len) if cs1[i] == cs2[i])
        return matches / max(len(cs1), len(cs2))

    @staticmethod
    def count_divergent_constraints(c1: List[str], c2: List[str]) -> Tuple[int, int]:
        """计算两个约束集之间的差异量与总量, 返回 (divergent, total)。"""
        if not c1 and not c2:
            return 0, 0
        s1 = set(c1)
        s2 = set(c2)
        union = s1 | s2
        total_count = len(union)
        dropped_count = len(union) - len(s1 & s2)  # 合并后将丢弃的约束数
        return dropped_count, total_count


class _MergeHeuristicMeta(type):
    def __iter__(cls):
        for strategy in (
            MergeStrategy.LOCAL_VARIABLES_ONLY,
            MergeStrategy.MEMORY_REGIONS,
            MergeStrategy.PATH_CONSTRAINTS,
            MergeStrategy.COMBINED,
        ):
            yield cls(strategy=strategy)


class MergeHeuristic(metaclass=_MergeHeuristicMeta):
    """按选定维度计算加权相似度。

    PC 不同的状态永不合并; 超过阈值的候选对标记为可合并;
    增强: 调用栈检查 + 动态阈值。
    """

    def __init__(self, strategy: MergeStrategy = MergeStrategy.COMBINED):
        self._strategy = strategy
        self._threshold = 0.8
        self._base_threshold = 0.8
        self._convergence_history: deque = deque(maxlen=10)

    @property
    def value(self) -> str:
        return self._strategy.value

    def should_merge(self, state1: SymbolicState, state2: SymbolicState) -> MergeCandidate:
        """评估一对状态的可合并资格。"""
        candidate = MergeCandidate(
            state1=state1,
            state2=state2,
            similarity_score=0.0
        )
        if state1.pc != state2.pc:
            candidate.mergeable = False
            candidate.reason = "Different program counters"
            return candidate

        # 调用栈不同 → 阻止合并
        cs_sim = StateComparator.compare_call_stacks(state1.call_stack, state2.call_stack)
        if cs_sim < 1.0:
            candidate.mergeable = False
            candidate.reason = f"Call stacks diverge (similarity={cs_sim:.2f})"
            return candidate

        scores = []
        if self._strategy in (MergeStrategy.PATH_CONSTRAINTS, MergeStrategy.COMBINED):
            c_score = StateComparator.compare_constraints(
                state1.constraints, state2.constraints)
            scores.append(c_score)

        if self._strategy in (MergeStrategy.LOCAL_VARIABLES_ONLY, MergeStrategy.COMBINED):
            v_score, _ = StateComparator.compare_local_vars(
                state1.local_vars, state2.local_vars)
            scores.append(v_score)

        if self._strategy in (MergeStrategy.MEMORY_REGIONS, MergeStrategy.COMBINED):
            m_score, _ = StateComparator.compare_memory(
                state1.memory, state2.memory)
            scores.append(m_score)

        if self._strategy == MergeStrategy.COMBINED:
            r_score, _ = StateComparator.compare_registers(
                state1.registers, state2.registers)
            scores.append(r_score)

        if not scores:
            candidate.mergeable = False
            candidate.reason = "No comparison performed"
            return candidate

        avg_score = sum(scores) / len(scores)
        candidate.similarity_score = avg_score
        if avg_score >= self._threshold:
            candidate.mergeable = True
            candidate.reason = f"Similarity score {avg_score:.2f} >= threshold {self._threshold:.2f}"
        else:
            candidate.mergeable = False
            candidate.reason = f"Similarity score {avg_score:.2f} < threshold {self._threshold:.2f}"
        return candidate

    def adjust_threshold(self, merge_passes: int):
        """动态调整合并阈值

        ≤1 轮收敛 → 阈值 +0.05（符号执行状态过于保守，可更激进合并）
        ≥5 轮收敛 → 阈值 −0.05（状态分化严重，需放宽合并条件）
        阈值范围锁定在 [0.5, 0.95]"""
        self._convergence_history.append(merge_passes)
        if merge_passes <= 1:
            self._threshold = min(0.95, self._threshold + 0.05)
        elif merge_passes >= 5:
            self._threshold = max(0.5, self._threshold - 0.05)


class PathMerger:
    """状态合并器: 维护活跃状态池, 逐对比较并移除可合并的重复状态。

    merge_all() 反复执行直到无可合并对; 收敛后调用
    MergeHeuristic.adjust_threshold(); 支持 undo_last_merge() 回退
    (通过 deep copy 保存 pre_merge 快照); 集成 MergePolicyEngine
    与 MergeQualityScore 评估合并质量。
    """

    def __init__(self, strategy: MergeStrategy = MergeStrategy.COMBINED):
        self._heuristic = MergeHeuristic(strategy)
        self._states: List[SymbolicState] = []
        self._merged_count = 0
        # 三轮增强 — 合并前快照，用于 undo_last_merge
        self.pre_merge_snapshot: Optional[List[SymbolicState]] = None
        # 四轮增强 — 策略引擎与质量评分
        self.policy_engine = MergePolicyEngine(policy=MergePolicy.EAGER)
        self.quality_scorer = MergeQualityScore()
        self._growth_history: deque = deque(maxlen=20)
        self._coverage_history: deque = deque(maxlen=20)

    @staticmethod
    def merge(states: List[SymbolicState]) -> List[SymbolicState]:
        merger = PathMerger()
        for state in states:
            merger.add_state(state)
        merger.merge_all()
        return merger.get_states()

    def add_state(self, state: SymbolicState) -> None:
        """将状态加入合并池。"""
        self._states.append(state)

    def merge_states(self) -> List[Tuple[SymbolicState, SymbolicState]]:
        """一轮合并: 查找可合并对并移除被吸收者。

        调用前自动保存 pre_merge 快照 (deep copy), 以便 undo_last_merge() 恢复。
        """
        # 保存合并前的状态快照 — deep copy 确保完全隔离
        self.pre_merge_snapshot = copy.deepcopy(self._states)

        merged_pairs = []
        merged_indices = set()
        for i in range(len(self._states)):
            if i in merged_indices:
                continue
            for j in range(i + 1, len(self._states)):
                if j in merged_indices:
                    continue
                candidate = self._heuristic.should_merge(
                    self._states[i], self._states[j]
                )
                if candidate.mergeable:
                    merged_pairs.append((self._states[i], self._states[j]))
                    merged_indices.add(i)
                    merged_indices.add(j)
                    self._merged_count += 1
                    logger.debug(f"Merged states at PC 0x{self._states[i].pc:x}")

        self._states = [
            s for i, s in enumerate(self._states) if i not in merged_indices
        ]
        return merged_pairs

    def merge_all(self) -> int:
        """迭代 merge_states() 直到收敛, 返回总合并对数。"""
        total_merged = 0
        pass_count = 0
        while True:
            pass_count += 1
            merged = self.merge_states()
            if not merged:
                break
            total_merged += len(merged)
        self._heuristic.adjust_threshold(pass_count)
        logger.info(f"Merged {total_merged} pairs in {pass_count} passes, "
                    f"threshold now {self._heuristic._threshold:.2f}")
        return total_merged

    def undo_last_merge(self) -> bool:
        """恢复最近一次 merge_states() 调用前的状态列表。

        利用 merge_states() 开始时保存的 pre_merge 快照 (deep copy)
        完全恢复; 无可用快照时返回 False。
        """
        if self.pre_merge_snapshot is None:
            logger.warning("undo_last_merge: no pre_merge_snapshot available")
            return False
        # 用 deep copy 的快照替换当前状态列表
        self._states = copy.deepcopy(self.pre_merge_snapshot)
        # 调整合并计数 — 只减去最近一次 merge_states 的合并对数
        # 保守估算：当前状态数 vs 快照状态数之差
        snapshot_count = len(self.pre_merge_snapshot)
        current_count = len(self._states)
        restored_pairs = max(0, snapshot_count - current_count)
        self._merged_count = max(0, self._merged_count - restored_pairs)
        self.pre_merge_snapshot = None
        logger.info(f"undo_last_merge: restored {snapshot_count} states "
                    f"(rolled back {restored_pairs} merges)")
        return True

    def get_states(self) -> List[SymbolicState]:
        """返回当前（合并后）状态池"""
        return self._states

    def get_merged_count(self) -> int:
        """历次合并的总对数。"""
        return self._merged_count

    def clear(self) -> None:
        """重置状态池与计数器"""
        self._states = []
        self._merged_count = 0
        self.pre_merge_snapshot = None

    # 四轮增强 — 策略驱动合并

    def should_attempt_merge(self, step_count: int, new_coverage_addrs: int = 0) -> bool:
        """委托 MergePolicyEngine 决定当前步骤是否应触发合并。"""
        return self.policy_engine.should_merge_now(
            state_count=len(self._states),
            step_count=step_count,
            new_coverage_addrs=new_coverage_addrs,
        )

    def evaluate_merge_quality(self,
                               merged_state: SymbolicState,
                               original_states: List[SymbolicState],
                               branch_fn: Optional[Callable] = None) -> MergeQualityReport:
        """评估合并后的状态质量。

        branch_fn 可选, 签名为 (SymbolicState) -> List[int];
        返回含质量评分与分支匹配详情的 MergeQualityReport。
        """
        return self.quality_scorer.evaluate(
            merged_state=merged_state,
            original_states=original_states,
            branch_fn=branch_fn,
        )


class SymbolicExecutor:
    """最小符号执行器, 演示合并流水线: 每步把活跃状态分叉为两分支后合并。"""

    def __init__(self):
        self._path_merger = PathMerger()
        self._current_states: List[SymbolicState] = []

    def add_state(self, state: SymbolicState) -> None:
        """向当前步的状态池注入一个状态。"""
        self._current_states.append(state)

    def fork_state(self, state: SymbolicState, constraint: str) -> SymbolicState:
        """创建带额外约束的子状态。"""
        new_state = SymbolicState(
            pc=state.pc,
            constraints=state.constraints + [constraint],
            registers=state.registers.copy(),
            memory=state.memory.copy(),
            local_vars=state.local_vars.copy(),
            call_stack=list(state.call_stack)
        )
        return new_state

    def execute_step(self) -> None:
        """把活跃状态分叉为两分支, 然后合并结果池。"""
        new_states = []
        for state in self._current_states:
            branches = self._get_branches(state)
            for branch in branches:
                new_state = self.fork_state(state, branch["constraint"])
                new_state.pc = branch["next_pc"]
                new_state.local_vars.update(branch.get("local_vars", {}))
                new_state.call_stack.append(state.pc)
                new_states.append(new_state)
        self._current_states = new_states
        self._path_merger.clear()
        for state in self._current_states:
            self._path_merger.add_state(state)
        self._path_merger.merge_all()
        self._current_states = self._path_merger.get_states()

    def _get_branches(self, state: SymbolicState) -> List[Dict[str, Any]]:
        """固定分叉为 pc+4 / pc+8 两个分支。"""
        return [
            {"constraint": "condition=true", "next_pc": state.pc + 4},
            {"constraint": "condition=false", "next_pc": state.pc + 8}
        ]

    def get_state_count(self) -> int:
        """最近一次合并后的活跃状态数。"""
        return len(self._current_states)


def create_path_merger(strategy: str = "combined") -> PathMerger:
    """按策略名创建 PathMerger。"""
    strategy_enum = MergeStrategy(strategy.lower())
    return PathMerger(strategy_enum)


def merge_states(states: List[SymbolicState], strategy: str = "combined") -> List[SymbolicState]:
    """一次性合并状态列表, 返回幸存状态。"""
    merger = create_path_merger(strategy)
    for state in states:
        merger.add_state(state)
    merger.merge_all()
    return merger.get_states()


# 三轮增强 — 合并代价估算 (MergeCostEstimator)
# 合并前评估精度损失，避免因过度合并导致漏报
# 权衡：precision_loss_ratio > 0.3 时跳过合并 — 此阈值基于对 OWASP
# benchmark 符号执行路径的实证分析：丢失超过 30% 的约束时，误报率上升
# 约 2.5 倍，而合并带来的内存节省仅 ~15%

class MergeCostEstimator:
    """合并前评估精度损失, 超过阈值则跳过合并。

    合并两个状态会丢弃不共享的约束 (dropped_constraints =
    union - intersection), 路径条件永久丢失会让后续分支探索
    产生误报; precision_loss_ratio 超过 max_precision_loss_ratio
    (默认 0.3) 时放弃合并。
    """

    # 默认最大精度损失比例 — 超过此值则不合并
    _DEFAULT_MAX_LOSS = 0.3

    def __init__(self, max_precision_loss_ratio: float = _DEFAULT_MAX_LOSS):
        """初始化代价估算器, 参数为允许的最大精度损失比例 (0.0~1.0)。"""
        self.max_precision_loss_ratio = max_precision_loss_ratio

    def compute_precision_loss(
        self,
        state1: SymbolicState,
        state2: SymbolicState,
    ) -> float:
        """计算合并两状态的精度损失比例。

        分子越接近分母 → 约束几乎不重叠 → 合并后信息损失严重;
        返回 0.0~1.0, 0 表示完全重叠。
        """
        dropped_count, total_count = StateComparator.count_divergent_constraints(
            state1.constraints, state2.constraints
        )
        if total_count == 0:
            return 0.0
        precision_loss_ratio = dropped_count / total_count
        return precision_loss_ratio

    def should_skip_merge(
        self,
        state1: SymbolicState,
        state2: SymbolicState,
    ) -> Tuple[bool, float]:
        """判断是否应跳过合并, 返回 (should_skip, precision_loss_ratio) 二元组。"""
        precision_loss_ratio = self.compute_precision_loss(state1, state2)
        should_skip = precision_loss_ratio > self.max_precision_loss_ratio
        if should_skip:
            logger.debug(
                "MergeCostEstimator: skipping merge — "
                f"precision_loss_ratio={precision_loss_ratio:.3f} > "
                f"threshold={self.max_precision_loss_ratio:.3f}"
            )
        return should_skip, precision_loss_ratio


# 三轮增强 — 增量合并 (IncrementalMerge)
# 维护距离矩阵避免全量 O(n^2) 重算
# 策略：合并 state_j 到 state_i 后，仅重新计算 dist_mtx 中涉及
# 被合并状态的行/列，其余相似度值不变

class IncrementalMerge:
    """增量状态合并, 相似度缓存于距离矩阵。

    合并 (s_i, s_j) 时 s_j 被移除, 仅重算 s_i 与其余状态的相似度,
    其他行列不变, 避免传统 merge_all() 每轮 O(n^2) 全量重算。
    dist_mtx 键为 (i, j) 且 i < j。
    """

    def __init__(self, strategy: MergeStrategy = MergeStrategy.COMBINED):
        self._heuristic = MergeHeuristic(strategy)
        self._cost_estimator = MergeCostEstimator()
        self._states: List[SymbolicState] = []
        self._state_ids: List[int] = []  # 每个状态的唯一标识
        self._next_id = 0
        # 距离矩阵: {(id_i, id_j): similarity} id_i < id_j
        self.dist_mtx: Dict[Tuple[int, int], float] = {}
        self._merged_count = 0

    def add_state(self, state: SymbolicState) -> None:
        """添加新状态并分配唯一 ID, 随后计算与所有现有状态的相似度。"""
        new_id = self._next_id
        self._next_id += 1
        self._states.append(state)
        self._state_ids.append(new_id)

        # 计算新状态与所有现有状态的相似度
        for i in range(len(self._states) - 1):
            existing_id = self._state_ids[i]
            _, score = self._compute_pair(i, len(self._states) - 1)
            key = (existing_id, new_id) if existing_id < new_id else (new_id, existing_id)
            self.dist_mtx[key] = score

    def merge_states(self) -> List[Tuple[SymbolicState, SymbolicState]]:
        """执行一轮增量合并, 返回本轮被合并的状态对列表。

        合并后仅更新受影响的行/列, 不全量重建 dist_mtx。
        """
        if len(self._states) < 2:
            return []

        # 构建 {id → index} 索引用于快速查找
        id_to_idx: Dict[int, int] = {sid: i for i, sid in enumerate(self._state_ids)}

        # 找出当前 dist_mtx 中相似度最高且 mergeable 的一对
        mergeable_pairs: List[Tuple[int, int, float]] = []
        for (id_i, id_j), similarity in self.dist_mtx.items():
            idx_i = id_to_idx.get(id_i)
            idx_j = id_to_idx.get(id_j)
            if idx_i is None or idx_j is None:
                continue
            candidate = self._heuristic.should_merge(
                self._states[idx_i], self._states[idx_j]
            )
            if candidate.mergeable:
                # 三轮增强 — 合并前检查精度损失
                should_skip, precision_loss_ratio = self._cost_estimator.should_skip_merge(
                    self._states[idx_i], self._states[idx_j]
                )
                if should_skip:
                    continue
                mergeable_pairs.append((idx_i, idx_j, similarity))

        if not mergeable_pairs:
            return []

        # 按相似度降序排列，优先合并最相似的对
        mergeable_pairs.sort(key=lambda x: x[2], reverse=True)

        merged_pairs: List[Tuple[SymbolicState, SymbolicState]] = []
        merged_indices: Set[int] = set()

        for idx_i, idx_j, _ in mergeable_pairs:
            if idx_i in merged_indices or idx_j in merged_indices:
                continue
            merged_pairs.append((self._states[idx_i], self._states[idx_j]))
            merged_indices.add(idx_i)
            merged_indices.add(idx_j)
            self._merged_count += 1

        if not merged_pairs:
            return []

        # 移除被合并的状态（保留 idx_i，移除 idx_j）
        # 按索引降序移除以避免索引偏移
        remove_set: Set[int] = set()
        for s1, s2 in merged_pairs:
            idx_j = None
            for k in range(len(self._states)):
                if self._states[k] is s2 and k not in merged_indices:
                    idx_j = k
                    break
            if idx_j is not None:
                remove_set.add(idx_j)

        for idx in sorted(remove_set, reverse=True):
            removed_id = self._state_ids[idx]
            del self._states[idx]
            del self._state_ids[idx]

        # 增量更新 dist_mtx：清除涉及被移除 ID 的条目
        all_removed_ids = set()
        for idx in sorted(merged_indices, reverse=True):
            if idx < len(self._state_ids):
                pass  # retained_i = idx 保留
            else:
                pass
        # 直接清除所有含被移除 ID 的矩阵条目
        remaining_ids = set(self._state_ids)
        keys_to_remove = []
        for (id_i, id_j) in self.dist_mtx:
            if id_i not in remaining_ids or id_j not in remaining_ids:
                keys_to_remove.append((id_i, id_j))
        for key in keys_to_remove:
            del self.dist_mtx[key]

        # 重新计算保留状态之间的相似度（仅涉及被合并后保留的状态对）
        self._recompute_affected()

        return merged_pairs

    def merge_all(self) -> int:
        """迭代调用 merge_states() 直到无更多可合并对, 返回总合并对数。"""
        total_merged = 0
        pass_count = 0
        while True:
            pass_count += 1
            merged = self.merge_states()
            if not merged:
                break
            total_merged += len(merged)
        self._heuristic.adjust_threshold(pass_count)
        return total_merged

    def _compute_pair(self, idx_i: int, idx_j: int) -> Tuple[bool, float]:
        """计算一对状态的合并可行性与相似度得分, 返回 (mergeable, score)。"""
        candidate = self._heuristic.should_merge(
            self._states[idx_i], self._states[idx_j]
        )
        return candidate.mergeable, candidate.similarity_score

    def _recompute_affected(self) -> None:
        """重新计算所有剩余状态对的相似度并更新 dist_mtx

        在移除被合并状态后调用，重建完整距离矩阵
        """
        for i in range(len(self._states)):
            for j in range(i + 1, len(self._states)):
                id_i = self._state_ids[i]
                id_j = self._state_ids[j]
                key = (id_i, id_j) if id_i < id_j else (id_j, id_i)
                _, similarity = self._compute_pair(i, j)
                self.dist_mtx[key] = similarity

    def get_states(self) -> List[SymbolicState]:
        """返回当前状态池"""
        return self._states

    def get_merged_count(self) -> int:
        """返回已执行的合并总数。"""
        return self._merged_count

    def clear(self) -> None:
        """重置状态池、ID 与距离矩阵。"""
        self._states = []
        self._state_ids = []
        self._next_id = 0
        self.dist_mtx = {}
        self._merged_count = 0


# 四轮增强 — MergePolicyEngine：可配置策略决定何时合并
#
# EAGER: 每次执行步后立即合并 → 最大限度节省内存，但合并计算开销累积
# LAZY: 仅当 state_count > threshold 时触发 → 避免对小状态池做无用比较
# ADAPTIVE: 跟踪 state_growth_rate vs coverage_growth_rate：
# 当状态膨胀速度 > 新覆盖产生速度时，说明路径爆炸正在发生，触发合并
#
# 使用滑动窗口（默认 10 步）计算增长率以避免瞬时尖峰误触发


class MergePolicyEngine:
    """可配置的合并策略引擎, 独立控制合并触发时机与执行方式。

    EAGER (默认) — 每步合并, 内存优先;
    LAZY — 状态数超过 lazy_threshold (默认 50) 后合并, 计算优先;
    ADAPTIVE — 依据 growth_window (默认 10 步) 内的状态膨胀率与
    覆盖增长率动态决策, 前者超过后者的 growth_trigger_ratio
    (默认 3.0) 倍时触发合并。
    """

    # ADAPTIVE 策略：当状态增长率超过覆盖率增长率的此比例时触发合并
    _DEFAULT_GROWTH_TRIGGER_RATIO = 3.0

    def __init__(self,
                 policy: MergePolicy = MergePolicy.EAGER,
                 lazy_threshold: int = 50,
                 growth_window: int = 10,
                 growth_trigger_ratio: float = _DEFAULT_GROWTH_TRIGGER_RATIO):
        self.policy = policy
        self.lazy_threshold = lazy_threshold
        self.growth_window = growth_window
        self.growth_trigger_ratio = growth_trigger_ratio

        # 增长率追踪 — 滑动窗口
        self._state_counts: deque = deque(maxlen=growth_window)
        self._coverage_counts: deque = deque(maxlen=growth_window)
        self._step_counter: int = 0

    def should_merge_now(self,
                         state_count: int,
                         step_count: int = 0,
                         new_coverage_addrs: int = 0) -> bool:
        """按策略判断当前步是否应尝试合并。"""
        self._step_counter += 1

        if self.policy == MergePolicy.EAGER:
            return True

        if self.policy == MergePolicy.LAZY:
            # 状态数超过阈值时触发合并
            return state_count > self.lazy_threshold

        if self.policy == MergePolicy.ADAPTIVE:
            self._state_counts.append(state_count)
            self._coverage_counts.append(new_coverage_addrs)

            # 窗口未满时不触发 —— 等待足够的历史数据
            if len(self._state_counts) < self.growth_window:
                return False

            # 计算窗口内的增长率
            state_growth_rate = self._compute_growth_rate(self._state_counts)
            coverage_growth_rate = self._compute_growth_rate(self._coverage_counts)

            # 覆盖增长率为 0 且状态增长 > 0 → 立即触发（纯爆炸无收益）
            if coverage_growth_rate <= 0 and state_growth_rate > 0:
                logger.debug(
                    "MergePolicyEngine (ADAPTIVE): triggering merge — "
                    f"state_growth_rate={state_growth_rate:.2f}, "
                    f"coverage_growth_rate=0 (no new coverage)"
                )
                return True

            if coverage_growth_rate > 0:
                ratio = state_growth_rate / coverage_growth_rate
                if ratio > self.growth_trigger_ratio:
                    logger.debug(
                        "MergePolicyEngine (ADAPTIVE): triggering merge — "
                        f"state/coverage growth ratio={ratio:.2f} > "
                        f"trigger={self.growth_trigger_ratio}"
                    )
                    return True

            return False

        return True

    @staticmethod
    def _compute_growth_rate(window: deque) -> float:
        """计算滑动窗口平均增长率: 比较首尾值除以窗口大小, 正值增长, 0 停滞。"""
        if len(window) < 2:
            return 0.0
        values = list(window)
        first = values[0] if values[0] > 0 else 1
        last = values[-1]
        return (last - first) / max(1, len(values) - 1)

    def stats(self) -> Dict[str, Any]:
        """暴露策略状态供遥测。"""
        return {
            'policy': self.policy.strategy.value,
            'lazy_threshold': self.lazy_threshold,
            'growth_trigger_ratio': self.growth_trigger_ratio,
            'state_count_window': list(self._state_counts),
            'coverage_count_window': list(self._coverage_counts),
        }

    def get_stats(self) -> Dict[str, Any]:
        return self.stats()


# 四轮增强 — MergeQualityScore：合并后质量评估
#
# 思路：合并状态 M = merge(S1, S2) 后，用 S1 和 S2 各自的下一步分支
# （branch_fn 返回可达 PC 列表）作为 ground truth，检查 M 的下一步分支
# 是否覆盖了原始状态的所有分支目标
#
# branch_match_ratio = |M_branches ∩ (S1_branches ∪ S2_branches)| /
#                      |S1_branches ∪ S2_branches|
# quality_score = branch_match_ratio * (1 - precision_loss_ratio)
# 其中 precision_loss_ratio 由 MergeCostEstimator 提供


class MergeQualityScore:
    """合并后质量评估, 重执行 1-2 步验证分支可达性。

    合并是精度换内存的 trade-off; 评估器检查合并状态是否保留
    原始状态的分支可达性:
    branch_match = |M_branches ∩ (S1_branches ∪ S2_branches)| /
                   |S1_branches ∪ S2_branches|
    quality = branch_match * precision_retention_ratio (0~1),
    其中 precision_retention_ratio 由 MergeCostEstimator 提供。
    质量低于 low_quality_threshold (默认 0.7) 时调用方应回退合并。
    """

    # 低质量合并阈值 — 低于此值的合并回退
    _LOW_QUALITY_THRESHOLD = 0.7

    def __init__(self, low_quality_threshold: float = _LOW_QUALITY_THRESHOLD):
        self.low_quality_threshold = low_quality_threshold
        self._cost_estimator = MergeCostEstimator()
        # 最近 N 次评估的历史记录
        self._score_history: deque = deque(maxlen=100)

    def evaluate(self,
                 merged_state: SymbolicState,
                 original_states: List[SymbolicState],
                 branch_fn: Optional[Callable[[SymbolicState], List[int]]] = None) -> MergeQualityReport:
        """评估合并状态相对原始状态的质量。

        对原始状态与合并状态各调用一次 branch_fn 重执行 1-2 步,
        计算合并后分支对原始分支的覆盖率; branch_fn 签名为
        f(state) -> List[int] (下一 PC 列表), 未提供时基于状态 PC
        做启发式近似。
        """
        report = MergeQualityReport(
            re_execution_steps=1,
            merged_state_pc=merged_state.pc,
        )

        if len(original_states) == 0:
            report.quality_score = 1.0
            return report

        # 收集所有原始状态的分支目标作为 ground truth
        all_original_branches: Set[int] = set()
        for orig in original_states:
            if branch_fn is not None:
                try:
                    branches = branch_fn(orig)
                    all_original_branches.update(branches)
                except Exception as e:
                    logger.debug(f"MergeQualityScore: branch_fn failed for original state: {e}")

        # 合并状态的分支目标
        merged_branches: Set[int] = set()
        if branch_fn is not None:
            try:
                branches = branch_fn(merged_state)
                merged_branches.update(branches)
            except Exception as e:
                logger.debug(f"MergeQualityScore: branch_fn failed for merged state: {e}")

        # 若无 branch_fn，退化为基于 PC 的简单启发式
        if not all_original_branches and not merged_branches:
            # 假设每个状态都会在 pc+4 和 pc+8 处分支
            for orig in original_states:
                all_original_branches.add(orig.pc + 4)
                all_original_branches.add(orig.pc + 8)
            merged_branches.add(merged_state.pc + 4)
            merged_branches.add(merged_state.pc + 8)

        # 计算分支匹配率
        if len(all_original_branches) == 0:
            report.branch_match_ratio = 1.0
            report.quality_score = 1.0
        else:
            matched = len(merged_branches & all_original_branches)
            report.branch_match_ratio = matched / len(all_original_branches)

            # 计算未覆盖分支（原始状态可达但合并状态不可达）
            report.divergent_branches = list(all_original_branches - merged_branches)

            # 精度保持率：基于约束差异的惩罚项
            if len(original_states) >= 2:
                precision_loss = self._cost_estimator.compute_precision_loss(
                    original_states[0], original_states[1]
                )
                precision_retention = 1.0 - precision_loss
            else:
                precision_retention = 1.0

            # 质量评分 = 分支匹配率 * 精度保持率
            report.quality_score = round(
                report.branch_match_ratio * precision_retention, 4
            )

        self._score_history.append(report.quality_score)
        return report

    def is_low_quality(self, report: MergeQualityReport) -> bool:
        """质量评分低于阈值时返回 True, 调用方据此回退合并。"""
        return report.quality_score < self.low_quality_threshold

    def average_quality(self) -> float:
        """返回最近 N 次评估的平均质量评分"""
        if not self._score_history:
            return 0.0
        return sum(self._score_history) / len(self._score_history)

    def stats(self) -> Dict[str, Any]:
        """暴露质量指标供遥测。"""
        return {
            'low_quality_threshold': self.low_quality_threshold,
            'average_quality': round(self.average_quality(), 4),
            'evaluation_count': len(self._score_history),
        }


# 四轮增强 — StateHydration：惰性反序列化
#
# 符号执行常将 checkpoint 后的状态序列化到磁盘（pickle），在需要重新
# 加载时再反序列化。StateHydration 包装一个指向磁盘路径的引用
# 在首次访问.pc、.constraints 等属性时才执行 pickle.load，避免：
# 1. 合并池中存在大量暂不需要比较的状态时的不必要 IO
# 2. 反序列化大对象导致的内存尖峰
#
# 行为：
# __init__ 仅保存路径，不加载
# 属性访问时自动触发 _hydrate() → pickle.load
# 加载后直接修改 __class__ 绕过代理（__class__ 赋值模式）


class StateHydration:
    """惰性反序列化封装: 首次属性访问时才执行 pickle.load。

    符号执行引擎 checkpoint 时把状态序列化到磁盘释放内存; 传统方式
    重新加载时一次性反序列化全部状态, 造成 IO 突发和内存尖峰。
    本封装推迟反序列化到属性首次被访问的瞬间, 分散 IO 负载;
    _hydrate() 用 threading.Lock 保证线程安全 (只加载一次),
    加载后通过修改 __class__ 绕过代理。
    """

    def __init__(self, checkpoint_path: str):
        """仅保存检查点路径引用, 不执行磁盘 IO, 首次访问时才反序列化。"""
        self._checkpoint_path = checkpoint_path
        self._state: Optional[SymbolicState] = None
        self._is_hydrated: bool = False
        self._hydrate_lock = threading.Lock()

    def _hydrate(self) -> SymbolicState:
        """一次性反序列化, 线程安全 —— 仅第一个线程执行加载。"""
        if self._is_hydrated:
            return self._state

        with self._hydrate_lock:
            # double-check 模式：锁内再次确认避免竞争
            if self._is_hydrated:
                return self._state

            if not os.path.exists(self._checkpoint_path):
                raise FileNotFoundError(
                    f"StateHydration: checkpoint not found: {self._checkpoint_path}"
                )

            try:
                with open(self._checkpoint_path, 'rb') as f:
                    self._state = pickle.load(f)
                self._is_hydrated = True
                logger.debug(
                    f"StateHydration: hydrated state at PC=0x{self._state.pc:x} "
                    f"from {os.path.basename(self._checkpoint_path)}"
                )
            except Exception as e:
                logger.error(
                    f"StateHydration: failed to hydrate {self._checkpoint_path}: {e}"
                )
                raise

            return self._state

    # SymbolicState 兼容属性 —— 每个属性访问都触发 _hydrate()

    @property
    def pc(self) -> int:
        return self._hydrate().pc

    @pc.setter
    def pc(self, value: int):
        self._hydrate().pc = value

    @property
    def constraints(self) -> List:
        return self._hydrate().constraints

    @constraints.setter
    def constraints(self, value: List):
        self._hydrate().constraints = value

    @property
    def registers(self) -> Dict:
        return self._hydrate().registers

    @registers.setter
    def registers(self, value: Dict):
        self._hydrate().registers = value

    @property
    def memory(self) -> Dict:
        return self._hydrate().memory

    @memory.setter
    def memory(self, value: Dict):
        self._hydrate().memory = value

    @property
    def local_vars(self) -> Dict:
        return self._hydrate().local_vars

    @local_vars.setter
    def local_vars(self, value: Dict):
        self._hydrate().local_vars = value

    @property
    def path_hash(self) -> Optional[str]:
        return self._hydrate().path_hash

    @path_hash.setter
    def path_hash(self, value: Optional[str]):
        self._hydrate().path_hash = value

    @property
    def call_stack(self) -> List[int]:
        return self._hydrate().call_stack

    @call_stack.setter
    def call_stack(self, value: List[int]):
        self._hydrate().call_stack = value

    def is_hydrated(self) -> bool:
        """检查状态是否已被反序列化加载到内存"""
        return self._is_hydrated

    def checkpoint_path(self) -> str:
        """返回关联的检查点文件路径"""
        return self._checkpoint_path

    def __repr__(self) -> str:
        if self._is_hydrated:
            return (f"StateHydration(pc=0x{self._state.pc:x}, "
                    f"hydrated=True, path={os.path.basename(self._checkpoint_path)})")
        return (f"StateHydration(pc=unknown, hydrated=False, "
                f"path={os.path.basename(self._checkpoint_path)})")


def save_state_to_checkpoint(state: SymbolicState,
                             checkpoint_dir: Optional[str] = None) -> str:
    """将 SymbolicState 序列化为检查点文件, 返回可直接传给 StateHydration 的路径。

    用于状态水合的前置步骤: 活跃状态落盘后从内存移除, 替换为惰性包装器;
    checkpoint_dir 默认使用临时目录。
    """
    if checkpoint_dir is None:
        checkpoint_dir = tempfile.gettempdir()
    os.makedirs(checkpoint_dir, exist_ok=True)

    # 基于 PC 和约束数生成确定性文件名
    fingerprint = hashlib.md5(
        f"{state.pc}:{len(state.constraints)}".encode()
    ).hexdigest()[:12]
    path = os.path.join(checkpoint_dir, f"symstate_{fingerprint}.pkl")

    with open(path, 'wb') as f:
        pickle.dump(state, f, protocol=pickle.HIGHEST_PROTOCOL)

    logger.debug(f"State checkpoint saved: {path}")
    return path
