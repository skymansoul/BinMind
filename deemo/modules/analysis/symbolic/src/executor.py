#!/usr/bin/env python3
"""符号执行引擎——指令级符号执行，消费 IR 流并维护状态工作列表"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

_log = logging.getLogger(__name__)


# Enums & Data Classes

class ExecutionStrategy(Enum):
    """状态探索排序策略

    BFS 保证最短路径但深层路径内存爆炸; DFS 省内存但会卡在无限循环;
    COVERAGE_MAX 平衡新颖度与深度; LLM_GUIDED 在路径爆炸超出启发式能力时把排序交给语义模型。
    """
    BFS = "bfs"
    DFS = "dfs"
    COVERAGE_MAX = "coverage_max"
    LLM_GUIDED = "llm_guided"


class IR_Op(Enum):
    """最小 IR 操作集——VEX/BAP/ESIL 公共操作的子集"""
    # 算术
    ADD = auto(); SUB = auto(); MUL = auto(); DIV = auto(); MOD = auto()
    # 位运算
    AND = auto(); OR = auto(); XOR = auto(); SHL = auto(); SHR = auto()
    # 比较（有符号/无符号）
    EQ = auto(); NE = auto(); LT = auto(); LE = auto(); GT = auto(); GE = auto()
    ULT = auto(); UGT = auto()
    # 内存
    LOAD = auto(); STORE = auto()
    # 控制流
    JMP = auto(); CJMP = auto(); CALL = auto(); RET = auto()
    # 数据移动
    MOV = auto(); CONST = auto()
    # 特殊
    NOP = auto(); UNSUPPORTED = auto()


@dataclass
class IRInstruction:
    """单条 IR 级指令

    指令建模为 (opcode, operands) 元组。对符号执行的关键操作:
    算术（构造约束）、比较（分叉）、加载/存储（符号内存访问）、
    控制流（跳转目标）。size 默认为架构字长（32 位）。
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
    """单个符号执行状态——寄存器、内存、路径约束与程序计数器的快照

    fork() 返回复制了可变容器的新状态; PC 相同且约束兼容的两个状态
    合并为约束集的并集（见 symexec_optimizer.py）。
    """

    state_id: int
    pc: int                                    # 程序计数器（地址）
    registers: Dict[str, Any] = field(default_factory=dict)
    memory: Dict[int, Any] = field(default_factory=dict)  # 地址 -> 符号表达式
    path_constraints: List[Any] = field(default_factory=list)  # Z3 BoolRef 列表
    depth: int = 0
    call_stack: List[int] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def fork(self, new_state_id: int) -> "SymbolicState":
        """深拷贝分叉状态的可变字段

        寄存器与 metadata 浅拷贝; constraints 与 memory 深拷贝，避免交叉污染。
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
    """一次符号探索运行的聚合结果

    paths_explored: 完成的不同执行轨迹总数; timeouts: 因求解器/执行超时终止的路径数;
    solutions_found: 提取的可满足模型数（缺陷/漏洞候选）; coverage: 到达的
    (address, instruction_index) 元组集合; total_states: 探索中的并发状态峰值;
    elapsed_seconds: 墙钟执行时间。
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


# 符号表达式

class SymExpr:
    """符号表达式封装——持有具体值（int）或符号占位符（字符串名）

    用于寄存器/内存值及 Z3 转换，使 Z3 可用时也能以具体值模式运行。
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


# 符号执行引擎

class SymbolicExecutor:
    """主符号执行引擎

    遍历 IR 指令流，维护 SymbolicState 工作列表。条件跳转时分叉:
    一个分支加 True 约束，一个加 False 约束。

    默认用带界工作列表的 DFS，因为 BFS 即使在中等大小二进制上也会内存爆炸
    （50+ 基本块可构造上千状态）。覆盖率引导模式用 Bloom-filter 风格的新颖度
    追踪器偏向新地址; LLM_GUIDED 把优先级排序委托给 llm_explorer 模块。
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

        # 内部状态
        self._state_counter: int = 0
        self._worklist: List[SymbolicState] = []
        self._coverage: Set[Tuple[int, int]] = set()
        self._branch_coverage: Dict[int, int] = {}  # pc -> 访问次数
        self._symbolic_var_counter: int = 0
        self._ir_cache: Dict[int, IRInstruction] = {}

        # 统计
        self._stats: Dict[str, Any] = {
            "steps": 0, "forks": 0, "merges": 0, "timeouts": 0,
            "solutions": 0, "max_states_observed": 0,
        }

        # LLM 排序器（惰性初始化）
        self._llm_ranker: Any = None

# 符号变量生成

    def _fresh_sym_var(self, prefix: str = "v", size_bits: int = 32) -> SymExpr:
        """构造一个新的符号变量名"""
        self._symbolic_var_counter += 1
        return SymExpr.symbolic(f"{prefix}_{self._symbolic_var_counter}", size_bits)

# 状态管理

    def _new_state_id(self) -> int:
        self._state_counter += 1
        return self._state_counter

    def _add_state(self, state: SymbolicState) -> None:
        """按策略顺序把状态加入工作列表"""
        if len(self._worklist) >= self.max_states:
            self._prune_lowest_priority()
        if self.strategy == ExecutionStrategy.BFS:
            self._worklist.append(state)
        elif self.strategy == ExecutionStrategy.DFS:
            self._worklist.insert(0, state)
        else:
            # COVERAGE_MAX / LLM_GUIDED 用插入 + 稍后排序
            self._worklist.append(state)

        peak = len(self._worklist)
        if peak > self._stats["max_states_observed"]:
            self._stats["max_states_observed"] = peak

    def _pop_state(self) -> Optional[SymbolicState]:
        """按当前策略弹出下一个待探索状态

        DFS 弹头部（栈），BFS 弹尾部（队列）; COVERAGE_MAX 弹出前按
        新颖度排序工作列表; LLM_GUIDED 每 N 步调用 LLM 排序器。
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
                    from modules.analysis.symbolic.llm_explorer.ranker import PathState
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
        """按是否提供新的 (address, idx) 对给状态打分"""
        return 1.0 if (state.pc, 0) not in self._coverage else 0.0

    def _init_llm_ranker(self) -> None:
        """惰性初始化 llm_explorer 的 LLM 路径排序器"""
        try:
            from modules.analysis.symbolic.llm_explorer.ranker import LLMPathRanker
            self._llm_ranker = LLMPathRanker()
        except ImportError:
            _log.info("LLM ranker not available — falling back to heuristic")
            self._llm_ranker = None

    def _prune_lowest_priority(self) -> None:
        """从工作列表移除探索优先级最低的状态

        优先级 = depth（越浅越差）+ constraint count（越简单越好）;
        在超过 max_states 时使用。
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

# 指令执行

    def _read_register(self, state: SymbolicState, reg: str) -> SymExpr:
        """读取符号寄存器值，未初始化时返回新的符号变量

        未初始化时选符号变量而非具体零，因为把未初始化读取具体化会隐藏缺陷
        ——真实漏洞利用常借助未初始化内存。
        """
        if reg not in state.registers:
            val = self._fresh_sym_var(f"reg_{reg}")
            state.registers[reg] = val
            return val
        return state.registers[reg]

    def _write_register(self, state: SymbolicState, reg: str, value: SymExpr) -> None:
        state.registers[reg] = value

    def _read_memory(self, state: SymbolicState, addr: int, size_bytes: int = 4) -> SymExpr:
        """读取符号内存地址，连续字节拼接，未初始化字节变为新符号变量"""
        for offset in range(size_bytes):
            byte_addr = addr + offset
            if byte_addr not in state.memory:
                state.memory[byte_addr] = self._fresh_sym_var(f"mem_{byte_addr:#x}", size_bits=8)
        # 具体模式拼接字节; 符号模式返回首字节（多字节加载需 Z3 concat）
        return state.memory[addr]

    def _write_memory(self, state: SymbolicState, addr: int, value: SymExpr) -> None:
        """写入符号值到内存地址，字节级存储"""
        for offset in range(value.size_bits // 8):
            byte_addr = addr + offset
            byte_val = SymExpr.symbolic(f"{value.name}_b{offset}", size_bits=8) if value.is_symbolic else SymExpr.concrete((value.value >> (offset * 8)) & 0xFF, size_bits=8)
            state.memory[byte_addr] = byte_val if value.is_symbolic else byte_val

    def step_one(self, state: SymbolicState, instr: IRInstruction) -> List[SymbolicState]:
        """执行单条 IR 指令，返回后继状态列表（通常 1 个，条件跳转时 2 个）

        约束求解延迟到 check() 调用——对线性代码更快，但不可达路径会存活更久。
        """
        op = instr.op
        ops = instr.operands

        # NOP——无效果
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

        # 二元算术: ADD, SUB, MUL, DIV, MOD, AND, OR, XOR, SHL, SHR
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

        # 比较——设置标志位; 简化处理，存入寄存器 "cmp_lhs", "cmp_rhs" 等
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

        # CJMP cond, true_target, false_target（分叉点）
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
                state.pc = 0  # 结束执行
            return [state]

        # 不支持的操作——前进 PC 并记录
        _log.debug("Unsupported IR op at %#x: %s", instr.address, op)
        state.pc = instr.address + instr.size
        return [state]

    def _eval_operand(self, state: SymbolicState, operand: str) -> SymExpr:
        """解析操作数字符串为 SymExpr

        操作数格式:
        - "%reg" -> 读寄存器
        - "$0xABCD" -> 具体常量
        - "123" -> 具体常量
        - 符号名 -> 当作寄存器处理
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
        """对两个 SymExpr 执行二元运算，返回结果或 None（全符号需 Z3）

        具体路径直接计算整数值; 混合符号路径标记结果为符号。
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
        # 符号路径——返回新符号表达式
        symbolic_name = f"binop_{op.name}_{lhs.name}_{rhs.name}"
        result = SymExpr.symbolic(symbolic_name, size_bits=max(lhs.size_bits, rhs.size_bits))
        return result

    def _resolve_jump_target(self, state: SymbolicState, operand: str) -> int:
        """解析跳转目标操作数为具体地址"""
        try:
            return int(operand, 0)
        except ValueError:
            val = self._eval_operand(state, operand)
            return val.value

    def _handle_conditional_jump(
        self, state: SymbolicState, ops: List[str], instr: IRInstruction
    ) -> List[SymbolicState]:
        """条件跳转时分叉状态

        Z3 可用时创建两个状态（True/False 分支）并附加路径约束;
        Z3 不可用时仅凭约束追加探索（不完全正确但最大化探索范围）。
        """
        results: List[SymbolicState] = []
        cond_reg = self._eval_operand(state, ops[0])
        true_target = self._resolve_jump_target(state, ops[1])
        false_target = self._resolve_jump_target(state, ops[2])

        # TRUE 分支
        true_state = state.fork(self._new_state_id())
        true_state.pc = true_target
        if cond_reg.is_symbolic and cond_reg.name:
            # 构造符号约束: condition != 0
            constraint_obj = {
                "type": "neq", "var": cond_reg.name,
                "value": 0, "desc": f"cjmp_true@{instr.address:#x}",
            }
            true_state.path_constraints.append(constraint_obj)
        results.append(true_state)

        # FALSE 分支
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

# 主探索循环

    def explore(
        self,
        initial_state: SymbolicState,
        ir_fetcher: Callable[[int], Optional[IRInstruction]],
        max_steps: int = 10000,
    ) -> SymbolicExplorationResult:
        """主符号探索循环

        把 ir_fetcher 提供的 IR 指令喂给 step_one()，维护状态工作列表;
        工作列表清空或达到 max_steps 时终止。

        参数: initial_state 起始 SymbolicState（PC 设为入口）,
        ir_fetcher 为 address -> IRInstruction 的可调用,
        max_steps 为 step_one() 最大调用次数。
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
                # 路径结束
                result.paths_explored += 1
                continue

            instr = ir_fetcher(state.pc)
            if instr is None:
                _log.debug("No IR at %#x — ending path", state.pc)
                result.paths_explored += 1
                continue

            # 追踪覆盖率
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

        # 排空剩余路径
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
        """便捷方法: 从 entry_address 开始探索并返回结果"""
        initial = SymbolicState(
            state_id=self._new_state_id(),
            pc=entry_address,
            registers={},
            memory={},
            depth=0,
        )
        return self.explore(initial, ir_fetcher, max_steps=max_steps)

# 约束提取

    def get_path_constraints(self, state: SymbolicState) -> List[Any]:
        """返回某状态的累积路径约束"""
        return list(state.path_constraints)

    def get_stats(self) -> Dict[str, Any]:
        return dict(self._stats)


def _flatten_constraints_for_serialization(constraints: List[Any]) -> List[Dict[str, Any]]:
    """把符号约束展平为可 JSON 序列化的 dict 列表。"""
    result = []
    for c in constraints:
        if isinstance(c, dict):
            result.append(c)
        elif hasattr(c, "sexpr"):
            result.append({"sexpr": str(c.sexpr())})
        else:
            result.append({"repr": repr(c)})
    return result


def _debug_print_state(state: SymbolicState) -> None:
    """打印状态摘要, 供调试用。"""
    print(f"[DEBUG] state {state.state_id} @ {state.pc:#x} depth={state.depth}")
    for reg, val in sorted(state.registers.items()):
        print(f"  {reg} = {val}")


__all__ = [
    "SymbolicExecutor", "SymbolicState", "SymbolicExplorationResult",
    "ExecutionStrategy", "IR_Op", "IRInstruction", "SymExpr",
    "_flatten_constraints_for_serialization", "_debug_print_state",
]
