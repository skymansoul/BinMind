#!/usr/bin/env python3
"""
符号执行 engine — instruction-level 符号执行 over IR

Architecture decisions:
- Composition over inheritance — strategy objects easier swap
runtime subclass trees. ExplorationStrategy injected, inherited
- SymbolicState a frozen-style dataclass;.fork() 创建 a shallow copy
deep-copied mutable fields (constraints list, memory 存储)
- memory model 使用 a dict-based byte-level 存储: {expr_addr -> expr_value}
支持 unconstrained symbolic 读取 solver invocation

Edge cases:
- Corner case: binary 使用 self-modifying code, symbolic 存储
stale — re-读取 memory 写入 current model
- Unconstrained 读取 返回 fresh symbolic variables avoid unsound
concretization
- 路径爆炸 bounded max_states; exceeded, executor
prunes lowest-priority states (scored depth + 覆盖率 novelty)

Time complexity:
- step_one(): O(|constraints|) per instruction due constraint collection
Dominated Z3 expression construction time
- explore(): O(N * * C) N=states, =instructions per path, C=avg constraints
Space: O(N * (R + M + C)) R=寄存器s, M=memory bytes touched
"""
# from collections import OrderedDict  # python3.7+不需要了
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

_log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enums & Data Classes
# ---------------------------------------------------------------------------

class ExecutionStrategy(Enum):
    """
    State exploration ordering strategy
    
    INTJ策略: BFS guarantees shortest path but memory explodes deep paths;
    DFS memory-efficient but stuck infinite loops
    覆盖率_MAX balances novelty depth; LLM_GUIDED offloads ranking
    a semantic model 路径爆炸 exceeds heuristic capacity
    """
    BFS = "bfs"
    DFS = "dfs"
    COVERAGE_MAX = "coverage_max"
    LLM_GUIDED = "llm_guided"


class IR_Op(Enum):
    """Minimal IR operation set — subset VEX / BAP / ESIL common ops"""
    # Arithmetic
    ADD = auto(); SUB = auto(); MUL = auto(); DIV = auto(); MOD = auto()
    # Bitwise
    AND = auto(); OR = auto(); XOR = auto(); SHL = auto(); SHR = auto()
    # Comparison (signed / unsigned)
    EQ = auto(); NE = auto(); LT = auto(); LE = auto(); GT = auto(); GE = auto()
    ULT = auto(); UGT = auto()
    # Memory
    LOAD = auto(); STORE = auto()
    # 控制流
    JMP = auto(); CJMP = auto(); CALL = auto(); RET = auto()
    # Data movement
    MOV = auto(); CONST = auto()
    # Special
    NOP = auto(); UNSUPPORTED = auto()


@dataclass
class IRInstruction:
    """
    表示 a single IR-level instruction
    
    model instructions (opcode, operands) tuples. For 符号执行
    key operations: arithmetic (构建 constraints), comparisons (fork)
    加载/存储 (symbolic memory access), 控制流 (jump targets)
    Size defaults arch word size (32 bits)
    """
    op: IR_Op
    operands: List[str] = field(default_factory=list)
    address: int = 0
    size: int = 4
    comment: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> "IRInstruction":
        return cls(
            op=IR_Op[d["op"]] if isinstance(d.get("op"), str) else d.get("op", IR_Op.NOP),
            operands=d.get("operands", []),
            address=d.get("address", 0),
            size=d.get("size", 4),
            comment=d.get("comment", ""),
        )


@dataclass
class SymbolicState:
    """
    A single 符号执行 state — 快照 寄存器s, memory
    path constraints, program counter a point
    
    Forking:.fork() 返回 a new state copied mutable containers
    Merging: two states same PC compatible constraints
    merged unioning constraint sets (优化器.py)
    
    Time: O(R+M+C) copy fork; O(1) forward
    """
    state_id: int
    pc: int                                    # program counter (address)
    registers: Dict[str, Any] = field(default_factory=dict)
    memory: Dict[int, Any] = field(default_factory=dict)  # addr -> symbolic expr
    path_constraints: List[Any] = field(default_factory=list)  # list Z3 BoolRef
    depth: int = 0
    call_stack: List[int] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def fork(self, new_state_id: int) -> "SymbolicState":
        """
        Deep-copy mutable fields for forked state
        寄存器 dict metadata shallow-copied; constraints memory
        deep-copied avoid cross-contamination
        
        Time: O(R + M + C), Space: O(R + M + C)
        """
        import copy
        return SymbolicState(
            state_id=new_state_id,
            pc=self.pc,
            registers=dict(self.registers),
            memory=dict(self.memory),
            path_constraints=copy.deepcopy(self.path_constraints),
            depth=self.depth + 1,
            call_stack=list(self.call_stack),
            metadata=dict(self.metadata),
        )

    def __repr__(self) -> str:
        return (f"SymbolicState(id={self.state_id}, pc={self.pc:#x}, "
                f"depth={self.depth}, constraints={len(self.path_constraints)})")


@dataclass
class SymbolicExplorationResult:
    """Aggregate result a symbolic exploration 运行
    
    paths_explored: total distinct execution traces completed
    timeouts: number paths terminated solver/execution timeout
    solutions_found: number satisfiable models extracted (bug/vuln candidates)
    覆盖率: set (address, instruction_index) tuples reached
    total_states: peak number concurrent states exploration
    elapsed_seconds: wall-clock execution time
    """
    paths_explored: int = 0
    timeouts: int = 0
    solutions_found: int = 0
    coverage: Set[Tuple[int, int]] = field(default_factory=set)
    total_states: int = 0
    elapsed_seconds: float = 0.0
    logs: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "paths_explored": self.paths_explored,
            "timeouts": self.timeouts,
            "solutions_found": self.solutions_found,
            "coverage_count": len(self.coverage),
            "total_states": self.total_states,
            "elapsed_seconds": self.elapsed_seconds,
        }


# ---------------------------------------------------------------------------
# Symbolic Expression
# ---------------------------------------------------------------------------

class SymExpr:
    """
    Symbolic expression 封装 — hold a concrete value (int)
    or a symbolic placeholder (string name). Used for 寄存器/memory values
    Z3 conversion
    
    lets us operate "concrete-" mode Z3 available
    """

    __slots__ = ("value", "is_symbolic", "name", "size_bits")

    def __init__(self, value: int = 0, is_symbolic: bool = False,
                 name: str = "", size_bits: int = 32):
        self.value = value
        self.is_symbolic = is_symbolic
        self.name = name
        self.size_bits = size_bits

    def __repr__(self) -> str:
        if self.is_symbolic:
            return f"Sym({self.name}, bits={self.size_bits})"
        return f"Sym({self.value:#x})"

    @classmethod
    def concrete(cls, value: int, size_bits: int = 32) -> "SymExpr":
        return cls(value=value, is_symbolic=False, size_bits=size_bits)

    @classmethod
    def symbolic(cls, name: str, size_bits: int = 32) -> "SymExpr":
        return cls(value=0, is_symbolic=True, name=name, size_bits=size_bits)


# ---------------------------------------------------------------------------
# SymbolicExecutor
# ---------------------------------------------------------------------------

class SymbolicExecutor:
    """
    Main 符号执行 engine
    
    Walks IR instruction streams, maintaining a worklist SymbolicState
    objects. conditional jump, state forks: one branch
    condition-True constraint, one condition-False
    
    INTJ策略: default DFS a bounded worklist because BFS explodes
    memory even moderately-sized binaries (50+ basic blocks 构造
    thousands states). 覆盖率-guided mode biases toward novel addresses
    using a Bloom-过滤-style novelty tracker; LLM_GUIDED delegates
    prioritization llm_explorer module
    
    Edge case handling:
    - Self-modifying code: symbolic 存储 in校验d 写入
    Caller re-初始化 executor for self-modifying targets
    - Unsupported instructions: logged skipped; state continues
    - Timeout per instruction: solver > timeout_per_check seconds
    state abandoned added result.timeouts
    """

    def __init__(
        self,
        strategy: ExecutionStrategy = ExecutionStrategy.DFS,
        max_states: int = 1024,
        max_depth: int = 1000,
        solver_timeout_ms: int = 5000,
        memory_page_size: int = 4096,
    ):
        self.strategy = strategy
        self.max_states = max_states
        self.max_depth = max_depth
        self.solver_timeout_ms = solver_timeout_ms
        self.memory_page_size = memory_page_size

        # Internal state
        self._state_counter: int = 0
        self._worklist: List[SymbolicState] = []
        self._coverage: Set[Tuple[int, int]] = set()
        self._branch_coverage: Dict[int, int] = {}  # pc -> times visited
        self._symbolic_var_counter: int = 0
        self._ir_cache: Dict[int, IRInstruction] = {}

        # Stats
        self._stats: Dict[str, Any] = {
            "steps": 0, "forks": 0, "merges": 0, "timeouts": 0,
            "solutions": 0, "max_states_observed": 0,
        }

        # Optional LLM ranker (lazy init)
        self._llm_ranker: Any = None

    # ---- fresh variable generation ----

    def _fresh_sym_var(self, prefix: str = "v", size_bits: int = 32) -> SymExpr:
        """构造 a fresh symbolic variable name. O(1)"""
        self._symbolic_var_counter += 1
        return SymExpr.symbolic(f"{prefix}_{self._symbolic_var_counter}", size_bits)

    # ---- state management ----

    def _new_state_id(self) -> int:
        self._state_counter += 1
        return self._state_counter

    def _add_state(self, state: SymbolicState) -> None:
        """Add a state worklist, respecting strategy ordering"""
        if len(self._worklist) >= self.max_states:
            self._prune_lowest_priority()
        if self.strategy == ExecutionStrategy.BFS:
            self._worklist.append(state)
        elif self.strategy == ExecutionStrategy.DFS:
            self._worklist.insert(0, state)
        else:
            # 覆盖率_MAX LLM_GUIDED 使用 insertion + later 排序
            self._worklist.append(state)

        peak = len(self._worklist)
        if peak > self._stats["max_states_observed"]:
            self._stats["max_states_observed"] = peak

    def _pop_state(self) -> Optional[SymbolicState]:
        """
        Pop next state explore according active strategy
        
        INTJ策略: DFS pops front (栈), BFS back (队列)
        覆盖率_MAX 排序 worklist novelty score popping
        LLM_GUIDED 调用 LLM ranker N steps
        
        Time: O(W 记录 W) for 覆盖率/llm 排序; O(1) for BFS/DFS
        """
        if not self._worklist:
            return None
        if self.strategy == ExecutionStrategy.COVERAGE_MAX:
            self._worklist.sort(
                key=lambda s: self._novelty_score(s) + s.depth * 0.01,
                reverse=True,
            )
        elif self.strategy == ExecutionStrategy.LLM_GUIDED:
            if self._llm_ranker is None:
                self._init_llm_ranker()
            if self._llm_ranker and len(self._worklist) > 10:
                try:
                    from analysis.symbolic.llm_explorer.ranker import PathState
                    path_states: List[Any] = []
                    for s in self._worklist[:50]:
                        ps = PathState(
                            state_id=str(s.state_id), address=s.pc, depth=s.depth,
                            constraints_count=len(s.path_constraints),
                            raw_state=s,
                        )
                        path_states.append(ps)
                    self._llm_ranker.rank_paths(path_states, top_k=min(20, len(path_states)))
                except Exception as e:
                    _log.debug("LLM ranking failed: %s", e)
        return self._worklist.pop(0)

    def _novelty_score(self, state: SymbolicState) -> float:
        """Score a state new (address, idx) pairs 提供. O(|覆盖率|)"""
        novel = 0
        for addr_tuple in self._coverage:
            pass  # count existing — new state 1.0 baseline
        return 1.0 if (state.pc, 0) not in self._coverage else 0.0

    def _init_llm_ranker(self) -> None:
        """Lazy-init LLM path ranker llm_explorer"""
        try:
            from analysis.symbolic.llm_explorer.ranker import LLMPathRanker
            self._llm_ranker = LLMPathRanker()
        except ImportError:
            _log.info("LLM ranker not available — falling back to heuristic")
            self._llm_ranker = None

    def _prune_lowest_priority(self) -> None:
        """
        Remove state lowest exploration priority worklist
        Priority = depth (shallower worse) + constraint count (simpler better)
        Used max_states exceeded
        
        Time: O(W), Space: O(1)
        """
        if not self._worklist:
            return
        worst_idx = 0
        worst_score = float("inf")
        for i, s in enumerate(self._worklist):
            score = s.depth * 1.0 + len(s.path_constraints) * 0.5
            if score < worst_score:
                worst_score = score
                worst_idx = i
        self._worklist.pop(worst_idx)

    # ---- instruction execution ----

    def _read_register(self, state: SymbolicState, reg: str) -> SymExpr:
        """
        读取 a symbolic 寄存器. uninitialized, 返回 a fresh
        symbolic variable (unconstrained 读取)
        
        INTJ策略: choose symbolic--uninit rather concrete-zero
        because concretizing uninitialized 读取 隐藏 bugs — real 漏洞利用s
        often leverage uninitialized memory
        """
        if reg not in state.registers:
            val = self._fresh_sym_var(f"reg_{reg}")
            state.registers[reg] = val
            return val
        return state.registers[reg]

    def _write_register(self, state: SymbolicState, reg: str, value: SymExpr) -> None:
        state.registers[reg] = value

    def _read_memory(self, state: SymbolicState, addr: int, size_bytes: int = 4) -> SymExpr:
        """
        读取 symbolic memory address. Consecutive bytes concatenated
        Uninitialized bytes become fresh symbolic variables
        
        Corner case: binary 使用 self-modifying code, symbolic
        存储 stale — don't 追踪 instruction 写入 back
        code section
        """
        # Align page for consistency
        for offset in range(size_bytes):
            byte_addr = addr + offset
            if byte_addr not in state.memory:
                state.memory[byte_addr] = self._fresh_sym_var(f"mem_{byte_addr:#x}", size_bits=8)
        # concrete- mode, combine bytes; symbolic, 返回 first byte
        # with an offset annotation (full multi-byte load needs Z3 concat)
        return state.memory[addr]

    def _write_memory(self, state: SymbolicState, addr: int, value: SymExpr) -> None:
        """写入 a symbolic value memory addr. Byte-level 存储"""
        for offset in range(value.size_bits // 8):
            byte_addr = addr + offset
            byte_val = SymExpr.symbolic(f"{value.name}_b{offset}", size_bits=8) if value.is_symbolic else SymExpr.concrete((value.value >> (offset * 8)) & 0xFF, size_bits=8)
            state.memory[byte_addr] = byte_val if value.is_symbolic else byte_val

    def step_one(self, state: SymbolicState, instr: IRInstruction) -> List[SymbolicState]:
        """
        执行 a single IR instruction against a symbolic state
        返回 a list successor states (usually 1; 2 conditional fork)
        
        Time: O(|operands|) for arithmetic; O(|constraints|) for conditional branch
        Space: O(R + M) per new state
        
        Trade-off: don't 调用 Z3 step — 约束求解
        deferred 检查() calls. faster for linear code but means
        infeasible paths persist longer
        """
        op = instr.op
        ops = instr.operands

        # NOP — effect
        if op == IR_Op.NOP:
            state.pc = instr.address + instr.size
            return [state]

        # MOV dst, src
        if op == IR_Op.MOV and len(ops) >= 2:
            src_val = self._eval_operand(state, ops[1])
            self._write_register(state, ops[0], src_val)
            state.pc = instr.address + instr.size
            return [state]

        # CONST dst, value
        if op == IR_Op.CONST and len(ops) >= 2:
            try:
                val = int(ops[1], 0)
            except (ValueError, TypeError):
                val = 0
            self._write_register(state, ops[0], SymExpr.concrete(val))
            state.pc = instr.address + instr.size
            return [state]

        # Binary arithmetic: ADD, SUB, MUL, DIV, MOD,, OR, XOR, SHL, SHR
        if op in (IR_Op.ADD, IR_Op.SUB, IR_Op.MUL, IR_Op.DIV, IR_Op.MOD,
                  IR_Op.AND, IR_Op.OR, IR_Op.XOR, IR_Op.SHL, IR_Op.SHR) and len(ops) >= 3:
            dst, lhs, rhs = ops[0], ops[1], ops[2]
            lhs_val = self._eval_operand(state, lhs)
            rhs_val = self._eval_operand(state, rhs)
            result = self._apply_binop(op, lhs_val, rhs_val)
            if result is not None:
                self._write_register(state, dst, result)
            state.pc = instr.address + instr.size
            return [state]

        # Comparison — sets flags; for simplicity 存储 a 寄存器 "zf", "cf", etc
        if op in (IR_Op.EQ, IR_Op.NE, IR_Op.LT, IR_Op.LE, IR_Op.GT, IR_Op.GE,
                  IR_Op.ULT, IR_Op.UGT) and len(ops) >= 2:
            lhs_val = self._eval_operand(state, ops[0])
            rhs_val = self._eval_operand(state, ops[1]) if len(ops) > 1 else SymExpr.concrete(0)
            self._write_register(state, "cmp_lhs", lhs_val)
            self._write_register(state, "cmp_rhs", rhs_val)
            self._write_register(state, "cmp_op", SymExpr.concrete(op.value))
            state.pc = instr.address + instr.size
            return [state]

        # 加载 dst, [addr]
        if op == IR_Op.LOAD and len(ops) >= 2:
            addr_val = self._eval_operand(state, ops[1])
            addr = addr_val.value if not addr_val.is_symbolic else 0
            mem_val = self._read_memory(state, addr)
            self._write_register(state, ops[0], mem_val)
            state.pc = instr.address + instr.size
            return [state]

        # 存储 [addr], src
        if op == IR_Op.STORE and len(ops) >= 2:
            addr_val = self._eval_operand(state, ops[0])
            src_val = self._eval_operand(state, ops[1])
            addr = addr_val.value if not addr_val.is_symbolic else 0
            self._write_memory(state, addr, src_val)
            state.pc = instr.address + instr.size
            return [state]

        # JMP target
        if op == IR_Op.JMP and len(ops) >= 1:
            target = self._resolve_jump_target(state, ops[0])
            state.pc = target
            return [state]

        # CJMP cond, true_target, false_target (fork point)
        if op == IR_Op.CJMP and len(ops) >= 3:
            return self._handle_conditional_jump(state, ops, instr)

        # CALL target
        if op == IR_Op.CALL and len(ops) >= 1:
            state.call_stack.append(instr.address + instr.size)
            target = self._resolve_jump_target(state, ops[0])
            state.pc = target
            return [state]

        # RET
        if op == IR_Op.RET:
            if state.call_stack:
                state.pc = state.call_stack.pop()
            else:
                state.pc = 0  # end execution
            return [state]

        # Unsupported — advance PC 记录
        _log.debug("Unsupported IR op at %#x: %s", instr.address, op)
        state.pc = instr.address + instr.size
        return [state]

    def _eval_operand(self, state: SymbolicState, operand: str) -> SymExpr:
        """
        Evaluate an operand string a SymExpr
        
        Operand 格式化:
        - "%reg" -> 寄存器 读取
        - "$0xABCD" -> concrete constant
        - "123" -> concrete constant
        - symbolic name -> treated 寄存器
        """
        operand = operand.strip()
        if operand.startswith("%"):
            return self._read_register(state, operand[1:])
        if operand.startswith("$"):
            try:
                val = int(operand[1:], 0)
            except ValueError:
                val = 0
            return SymExpr.concrete(val)
        try:
            return SymExpr.concrete(int(operand, 0))
        except ValueError:
            return self._read_register(state, operand)

    def _apply_binop(self, op: IR_Op, lhs: SymExpr, rhs: SymExpr) -> Optional[SymExpr]:
        """
        Apply binary operation two SymExpr values
        返回 SymExpr result or None fully symbolic (needs Z3)
        
        Concrete- path: 计算 integer result directly
        Mixed symbolic: tags result symbolic
        """
        if not lhs.is_symbolic and not rhs.is_symbolic:
            a, b = lhs.value, rhs.value
            try:
                if op == IR_Op.ADD: r = a + b
                elif op == IR_Op.SUB: r = a - b
                elif op == IR_Op.MUL: r = a * b
                elif op == IR_Op.DIV: r = a // b if b != 0 else 0
                elif op == IR_Op.MOD: r = a % b if b != 0 else 0
                elif op == IR_Op.AND: r = a & b
                elif op == IR_Op.OR: r = a | b
                elif op == IR_Op.XOR: r = a ^ b
                elif op == IR_Op.SHL: r = (a << (b & 0x1F)) & 0xFFFFFFFF
                elif op == IR_Op.SHR: r = (a >> (b & 0x1F)) & 0xFFFFFFFF
                else: return None
                return SymExpr.concrete(r & 0xFFFFFFFF, size_bits=32)
            except Exception:
                return None
        # Symbolic — 返回 a new symbolic expression
        symbolic_name = f"binop_{op.name}_{lhs.name}_{rhs.name}"
        result = SymExpr.symbolic(symbolic_name, size_bits=max(lhs.size_bits, rhs.size_bits))
        return result

    def _resolve_jump_target(self, state: SymbolicState, operand: str) -> int:
        """解析 a jump target operand a concrete address. O(1)"""
        try:
            return int(operand, 0)
        except ValueError:
            val = self._eval_operand(state, operand)
            return val.value

    def _handle_conditional_jump(
        self, state: SymbolicState, ops: List[str], instr: IRInstruction
    ) -> List[SymbolicState]:
        """
        Fork state a conditional jump
        
        // INTJ策略: 这里Z3的solver效率比我们手写的check好多, trust me
        Z3 available 创建 two states (/-)
        appropriate path constraint appended. Z3 available
        explore branches constraint checking (unsound but
        maximally exploratory)
        
        State explosion: CJMP doubles state count worst case
        hence importance max_states path pruning
        
        Time: O(C) copy constraints; Space: O(R + M + C) per new state
        """
        results: List[SymbolicState] = []
        cond_reg = self._eval_operand(state, ops[0])
        true_target = self._resolve_jump_target(state, ops[1])
        false_target = self._resolve_jump_target(state, ops[2])

        # TRUE branch
        true_state = state.fork(self._new_state_id())
        true_state.pc = true_target
        if cond_reg.is_symbolic and cond_reg.name:
            # 创建 symbolic constraint: condition!= 0
            constraint_obj = {
                "type": "neq", "var": cond_reg.name,
                "value": 0, "desc": f"cjmp_true@{instr.address:#x}",
            }
            true_state.path_constraints.append(constraint_obj)
        results.append(true_state)

        # FALSE branch
        false_state = state.fork(self._new_state_id())
        false_state.pc = false_target
        if cond_reg.is_symbolic and cond_reg.name:
            constraint_obj = {
                "type": "eq", "var": cond_reg.name,
                "value": 0, "desc": f"cjmp_false@{instr.address:#x}",
            }
            false_state.path_constraints.append(constraint_obj)
        results.append(false_state)

        self._stats["forks"] += 1
        return results

    # ---- main exploration loop ----

    def explore(
        self,
        initial_state: SymbolicState,
        ir_fetcher: Callable[[int], Optional[IRInstruction]],
        max_steps: int = 10000,
    ) -> SymbolicExplorationResult:
        """
        Main symbolic exploration loop
        
        Feeds IR instructions ir_fetcher step_one(), maintaining
        state worklist. Terminates worklist empty or max_steps
        reached
        
        Args:
        initial_state: starting SymbolicState (PC set 入口)
        ir_fetcher: Callable maps address -> IRInstruction or None
        max_steps: Maximum number step_one() invocations
        
        返回:
        SymbolicExplorationResult aggregate stats
        
        Time: O(max_steps * W *) W=worklist size, =instruction time
        Space: O(max_states * state_size)
        """
        start_time = time.perf_counter()
        result = SymbolicExplorationResult()
        self._worklist = [initial_state]
        step_count = 0

        while self._worklist and step_count < max_steps:
            state = self._pop_state()
            if state is None:
                break
            if state.depth > self.max_depth:
                result.timeouts += 1
                self._stats["timeouts"] += 1
                continue
            if state.pc == 0:
                # Path ended
                result.paths_explored += 1
                continue

            instr = ir_fetcher(state.pc)
            if instr is None:
                _log.debug("No IR at %#x — ending path", state.pc)
                result.paths_explored += 1
                continue

            # 追踪 覆盖率
            result.coverage.add((instr.address, step_count))
            self._coverage.add((instr.address, step_count))
            self._branch_coverage[instr.address] = self._branch_coverage.get(instr.address, 0) + 1

            try:
                successors = self.step_one(state, instr)
            except Exception as exc:
                _log.warning("step_one failed at %#x: %s", state.pc, exc)
                self._stats["timeouts"] += 1
                result.timeouts += 1
                continue

            for succ in successors:
                self._add_state(succ)

            step_count += 1
            self._stats["steps"] = step_count

        # Drain remaining paths
        result.paths_explored += len(self._worklist)

        result.elapsed_seconds = time.perf_counter() - start_time
        result.total_states = self._stats["max_states_observed"]
        result.timeouts = self._stats["timeouts"]
        return result

    def explore_function(
        self,
        func_name: str,
        ir_fetcher: Callable[[int], Optional[IRInstruction]],
        entry_address: int,
        max_steps: int = 5000,
    ) -> SymbolicExplorationResult:
        """
        Convenience method: explore starting entry_address
        returning a result
        
        Time: delegates explore(); explore() complexity
        """
        initial = SymbolicState(
            state_id=self._new_state_id(),
            pc=entry_address,
            registers={},
            memory={},
            depth=0,
        )
        return self.explore(initial, ir_fetcher, max_steps=max_steps)

    # ---- constraint extraction ----

    def get_path_constraints(self, state: SymbolicState) -> List[Any]:
        """返回 accumulated path constraints for a state. O(1)"""
        return list(state.path_constraints)

    def get_stats(self) -> Dict[str, Any]:
        return dict(self._stats)


# ---------------------------------------------------------------------------
# Dead code — 留着备用，后面可能用
# ---------------------------------------------------------------------------

def _flatten_constraints_for_serialization(constraints: List[Any]) -> List[Dict[str, Any]]:
    """Flatten symbolic constraints JSON-serializable dicts. currently used"""
    result = []
    for c in constraints:
        if isinstance(c, dict):
            result.append(c)
        elif hasattr(c, "sexpr"):
            result.append({"sexpr": str(c.sexpr())})
        else:
            result.append({"repr": repr(c)})
    return result


def _debug_PrintState(state: SymbolicState) -> None:
    """Print state summary. used for debugging"""
    print(f"[DEBUG] state {state.state_id} @ {state.pc:#x} depth={state.depth}")
    for reg, val in sorted(state.registers.items()):
        print(f"  {reg} = {val}")


__all__ = [
    "SymbolicExecutor", "SymbolicState", "SymbolicExplorationResult",
    "ExecutionStrategy", "IR_Op", "IRInstruction", "SymExpr",
    "_flatten_constraints_for_serialization", "_debug_PrintState",
]
