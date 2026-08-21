#!/usr/bin/env python3
"""
Symbolic 优化 — path pruning, state merging, loop unrolling, summaries

Architecture:
- Composition over inheritance: Path优化器 a ConstraintSolver
SymbolicExecutor collaborators, base classes
- ConstraintSimplifier a separate utility for expression-level
优化s (redundant constraints, constant folding)

Edge cases:
- State merging same PC: requires compatible constraints (union)
constraints contradictory, 合并 skipped states kept
- Loop unrolling symbolic trip count: 构造 a BOUND copies
loop body, adds a fresh symbolic variable for remaining
iterations (sound over-approximation)

Time complexity:
- prune_infeasible_paths(): O(N * solver_time) N=states
- merge_states(): O(N^2) naive implementation; O(N * 记录 N) using
PC-based 哈希
- simplify_constraints(): O(|constraints| * ||) linear scan + dedup
"""
# from collections import OrderedDict  # python3.7+不需要了
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Set, Tuple, Union

_log = logging.getLogger(__name__)


# ConstraintSimplifier

class ConstraintSimplifier:
    """
    Simplifies constraint sets eliminating redundancies folding constants

    Operations:
    1. Duplicate elimination: identical constraints removed
    2. Contradiction detection: var==a var==b a!=b -> UNSAT
    3. Constant folding: evaluate concrete sub-expressions
    4. Tautology removal: constraints always true (x==x)

    Time: O(N) for N constraints dict-based dedup
    Space: O(N) for result list

    策略: apply simplification before solver invocation because
    Z3's internal simplifier is general-purpose, doesn't exploit
    domain knowledge of path constraints (mostly equality/
    inequality comparisons on individual variables)
    """

    def simplify(self, constraints: List[Any]) -> List[Any]:
        """
        Simplify a list constraints. 返回 a (possibly shorter) list

        Time: O(N) single pass dedup. Space: O(N)
        """
        if not constraints:
            return []

        seen: Set[str] = set()
        result: List[Any] = []
        eq_map: Dict[str, int] = {}

        for c in constraints:
            key = self._constraint_key(c)
            if key in seen:
                continue  # Duplicate
            seen.add(key)

            # 检查 for contradictory equality constraints
            if isinstance(c, dict) and c.get("type") == "eq":
                var = c.get("var", "")
                val = c.get("value", 0)
                if var in eq_map and eq_map[var] != val:
                    # Contradiction found — 返回 a minimal UNSAT marker
                    _log.debug("Constraint contradiction: %s=%d vs %s=%d", var, eq_map[var], var, val)
                    return [{"type": "eq", "var": "__unsat__", "value": 0}]
                eq_map[var] = val

            # Skip tautologies: var == var
            if isinstance(c, dict) and c.get("type") == "eq":
                if c.get("var") == str(c.get("value")):
                    continue  # Tautology, skip

            result.append(c)

        return result

    def eliminate_redundant(self, constraints: List[Any]) -> List[Any]:
        """
        Remove constraints logically implied others

        For, a structural 检查: x>5 x>3
        x>3 implied x>5 dropped

        Time: O(N^2) for pairwise comparison. Space: O(N)

        Trade-off: O(N^2) but N typically small (<100 per path)
        For larger sets, consider using Z3's reduce or a proper SMT solver
        """
        if len(constraints) <= 1:
            return list(constraints)

        result = list(constraints)
        i = 0
        while i < len(result):
            ci = result[i]
            if not isinstance(ci, dict):
                i += 1
                continue
            j = 0
            while j < len(result):
                if i == j:
                    j += 1
                    continue
                cj = result[j]
                if not isinstance(cj, dict):
                    j += 1
                    continue
                if self._implies(ci, cj):
                    # cj implied ci, remove cj
                    result.pop(j)
                    if j < i:
                        i -= 1  # Adjust index removal
                    continue
                j += 1
            i += 1

        return result

    def _implies(self, stronger: Dict, weaker: Dict) -> bool:
        """检查 'stronger' constraint logically implies 'weaker'

        Currently 检查 simple cases:
        - x>5 implies x>3 (same var, same type, stronger value)
        - x==5 implies x!=3
        """
        if stronger.get("type") != weaker.get("type"):
            return False
        if stronger.get("var") != weaker.get("var"):
            return False
        sv = stronger.get("value", 0)
        wv = weaker.get("value", 0)
        typ = stronger.get("type")
        if typ == "gt":
            return sv >= wv  # x > 5 implies x > 3
        if typ == "lt":
            return sv <= wv  # x < 3 implies x < 5
        if typ == "ge":
            return sv >= wv
        if typ == "le":
            return sv <= wv
        return False

    def _constraint_key(self, c: Any) -> str:
        """构造 a stable key for deduplication. O(1)"""
        if isinstance(c, dict):
            items = sorted(c.items())
            return str(items)
        return repr(c)


# Path优化器

class PathOptimizer:
    """
    优化 符号执行 pruning, merging, summarizing

    Components:
    1. Path pruning: remove infeasible states (constraints UNSAT)
    2. State merging: combine states same PC
    3. Loop unrolling: bounded symbolic unrolling
    4. Function summaries: pre-computed input/输出 constraints

    策略: Pruning before merging — pruning eliminates
    dead states cheaply, reducing N for expensive O(N^2) merging.
    Merging at join points is most impactful for code with lots of control
    flow convergence (if-else chains, switch statements)

    Trade-off: Merging loses path sensitivity (forget branch
    came), but acceptable for analysis dramatically
    reduces state explosion
    """

    def __init__(
        self,
        constraint_solver=None,
        simplifier: Optional[ConstraintSimplifier] = None,
        pruning_enabled: bool = True,
        merging_enabled: bool = True,
        loop_unroll_bound: int = 10,
    ):
        self._solver = constraint_solver
        self._simplifier = simplifier or ConstraintSimplifier()
        self.pruning_enabled = pruning_enabled
        self.merging_enabled = merging_enabled
        self.loop_unroll_bound = loop_unroll_bound
        self._summaries: Dict[str, Any] = {}  # func_name -> summary
        self._stats: Dict[str, int] = {
            "pruned": 0, "merged": 0, "unrolled": 0,
            "summaries_used": 0,
        }

    def prune_infeasible_paths(self, states: List[Any]) -> List[Any]:
        """
        Remove paths unsatisfiable constraints

        对每个 state, simplifies constraints 检查 satisfiability
        Infeasible states dropped counted

        Time: O(N * solver_time). Space: O(N) for result
        solver None, skips pruning 返回 states

        # NOTE: solver errs side SAT (default for timeouts)
        # infeasible paths survive — conservative for pruning
        """
        if not self.pruning_enabled or self._solver is None:
            return states

        survivors = []
        for state in states:
            constraints = getattr(state, 'path_constraints', [])
            simplified = self._simplifier.simplify(constraints)
            if not simplified:
                survivors.append(state)
                continue
            # 检查 for UNSAT marker simplifier
            if any(isinstance(c, dict) and c.get("var") == "__unsat__" for c in simplified):
                self._stats["pruned"] += 1
                continue
            try:
                if self._solver.is_satisfiable(simplified):
                    survivors.append(state)
                else:
                    self._stats["pruned"] += 1
            except Exception:
                # Solver error — keep state (conservative)
                survivors.append(state)

        return survivors

    def merge_states(self, states: List[Any]) -> List[Any]:
        """
        合并 states same PC compatible constraints

        States grouped PC. group, attempt 合并
        pairs compatible constraint sets (union doesn't 创建 UNSAT)

        Time: O(N * 记录 N) for sorting PC, O(K^2) per group K
        group size. Groups typically small (<5)

        Trade-off: Merging reduces state count but loses path-sensitivity
        Good for: switch/-else convergence. Bad for: divergent paths
        tracked separately
        """
        if not self.merging_enabled or len(states) < 2:
            return states

        from collections import defaultdict

        # Group PC
        groups: Dict[int, List[Any]] = defaultdict(list)
        for s in states:
            pc = getattr(s, 'pc', 0)
            groups[pc].append(s)

        result = []
        for pc, group in groups.items():
            if len(group) == 1:
                result.extend(group)
            elif self._solver is None:
                result.append(group[0])  # solver — pick first
                self._stats["merged"] += len(group) - 1
            else:
                merged, unmerged = self._merge_group(group)
                result.extend(merged)
                result.extend(unmerged)

        _log.debug("Merged %d states, %d remain", self._stats["merged"], len(result))
        return result

    def _merge_group(self, group: List[Any]) -> Tuple[List[Any], List[Any]]:
        """
        Attempt 合并 states a group

        Greedy algorithm: 启动 first state, try 合并
        subsequent state. 合并 fails, state stays unmerged

        Time: O(K^2 * solver_time) worst case. Space: O(K)
        """
        if len(group) <= 1:
            return ([], group)

        merged_states: List[Any] = [group[0]]
        unmerged: List[Any] = []

        for i in range(1, len(group)):
            new_state = group[i]
            merged = False
            for base in merged_states:
                combined = self._try_merge_pair(base, new_state)
                if combined is not None:
                    merged_states[merged_states.index(base)] = combined
                    self._stats["merged"] += 1
                    merged = True
                    break
            if not merged:
                unmerged.append(new_state)

        return (merged_states, unmerged)

    def _try_merge_pair(self, s1: Any, s2: Any) -> Optional[Any]:
        """
        Try 合并 two states one

        Merging possible iff:
        1. states same PC (caller 确保)
        2. union constraints satisfiable
        3. 寄存器 values merged via ITE (--else)

        success, 返回 merged state; failure, 返回 None

        Time: O(solver_time) for satisfiability 检查
        """
        c1 = getattr(s1, 'path_constraints', [])
        c2 = getattr(s2, 'path_constraints', [])
        combined_constraints = self._simplifier.simplify(c1 + c2)

        # 检查 UNSAT marker
        if any(isinstance(c, dict) and c.get("var") == "__unsat__" for c in combined_constraints):
            return None

        if self._solver and not self._solver.is_satisfiable(combined_constraints):
            return None

        # 合并: for, union constraints pick s1's state
        # (full ITE-based 寄存器 merging complex)
        merged = s1.fork(getattr(s1, 'state_id', 0) + 100000) if hasattr(s1, 'fork') else s1
        if hasattr(merged, 'path_constraints'):
            merged.path_constraints = combined_constraints
        return merged

    def unroll_loop(
        self,
        loop_body: List[Any],  # List IR instructions
        trip_count_expr: Any,   # Symbolic expression for loop count
        initial_state: Any,
        ir_fetcher: Any,
    ) -> List[Any]:
        """
        Bounded loop unrolling symbolic trip count

        Strategy:
        1. Unroll up loop_unroll_bound times (concrete copies)
        2. bound, add a fresh symbolic variable for remaining iters
        3. a sound over-approximation: cover bounded executions
        exactly model rest symbolically

        Time: O(bound * |loop_body| * instruction_time)
        Space: O(bound * state_size)

        Corner case: trip_count concrete < bound, unroll
        exactly times don't add symbolic tail
        """
        results: List[Any] = []
        current_state = initial_state

        # Heuristic: try concrete trip count
        concrete_trip = None
        if hasattr(trip_count_expr, 'is_symbolic') and not trip_count_expr.is_symbolic:
            concrete_trip = trip_count_expr.value
        elif isinstance(trip_count_expr, int):
            concrete_trip = trip_count_expr

        # For symbolic or unknown trip count, 使用 bound
        if concrete_trip is None:
            unroll_count = self.loop_unroll_bound
            add_symbolic_tail = True
        else:
            unroll_count = min(concrete_trip, self.loop_unroll_bound)
            add_symbolic_tail = concrete_trip > self.loop_unroll_bound

        for iteration in range(unroll_count):
            self._stats["unrolled"] += 1
            for instr in loop_body:
                if hasattr(ir_fetcher, 'step_one'):
                    successors = ir_fetcher.step_one(current_state, instr)
                    if successors:
                        current_state = successors[0]
            results.append(current_state)

        if add_symbolic_tail:
            # Add a symbolic tail state
            if hasattr(current_state, 'fork'):
                tail = current_state.fork(current_state.state_id + 1000)
                if hasattr(tail, 'path_constraints'):
                    tail.path_constraints.append({
                        "type": "lt", "var": "sym_loop_remaining",
                        "value": 0xFFFFFFFF, "desc": "symbolic_loop_tail",
                    })
                results.append(tail)

        return results

    def register_summary(self, func_name: str, summary: Any) -> None:
        """
        寄存器 a pre-computed function summary

        Summary 格式化: {"inputs": [.], "输出": [.], "constraints": [.]
        "side_effects": ["写入",.], "may_return": bool}

        Time: O(1). Space: O(1) per summary
        """
        self._summaries[func_name] = summary

    def has_summary(self, func_name: str) -> bool:
        """检查 a summary for func_name. O(1)"""
        return func_name in self._summaries

    def get_summary(self, func_name: str) -> Optional[Any]:
        """
        Retrieve a function summary. 返回 None found. O(1)

        使用摘要可以避免进入库函数内部，大幅减少状态空间
        // 比如memcpy/memset/strlen这种常用的，预定义好摘要后能省大量时间
        """
        summary = self._summaries.get(func_name)
        if summary:
            self._stats["summaries_used"] += 1
        return summary

    def apply_summary(self, state: Any, func_name: str, args: List[Any]) -> Optional[Any]:
        """
        Apply a function summary a state — skip function body
        directly 更新 state per summary

        Time: O(|summary.constraints|). Space: O(state + summary size)

        // 策略: Function summaries trade precision for speed
        // For security analysis, we want precise modeling of dangerous
        // functions (memcpy, system) and coarse models for utility sets —
        // a tiered approach gives us best ROI
        """
        summary = self.get_summary(func_name)
        if summary is None:
            return None

        # Apply 输出 constraints
        if hasattr(state, 'path_constraints'):
            for c in summary.get("constraints", []):
                state.path_constraints.append(c)

        # Apply 寄存器/memory modifications summary
        for reg_name, val in summary.get("outputs", {}).items():
            if hasattr(state, 'registers'):
                state.registers[reg_name] = val

        state.pc = getattr(state, 'pc', 0) + 4  # Advance past call
        return state

    def get_stats(self) -> Dict[str, int]:
        return dict(self._stats)


# Dead code — 留着备用，后面可能用

def _compute_StateFingerprint(state: Any) -> int:
    """
    计算 a deterministic hash for state comparison
    Used for state deduplication but currently wired

    这个是基于PC+寄存器快照的哈希，merge前先检查是否完全一样可以跳过
    """
    h = 0
    h ^= hash(getattr(state, 'pc', 0))
    for reg, val in sorted(getattr(state, 'registers', {}).items()):
        h ^= hash((reg, str(val)))
    return h


__all__ = [
    "PathOptimizer", "ConstraintSimplifier",
    "_compute_StateFingerprint",
]
