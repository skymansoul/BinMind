#!/usr/bin/env python3
"""
Shared 工具集 for 符号执行 module

Functions:
- 格式化 conversion: smtlib <-> Z3 expressions
- Constraint parsing various input 格式化
- State 序列化/反序列化 for 检查点ing
- 覆盖率 computation: path 覆盖率, branch 覆盖率
- Error hierarchy: custom 异常s for well-defined 错误处理

Design:
- 序列化 使用 JSON-serializable intermediate 格式化 (dicts/lists)
decouple Z3's internal representation
- 覆盖率 computation 使用 set-based tracking for O(1) lookup

Time complexity:
- 覆盖率 functions: O(|reached|) for set operations
- 序列化: O(|state size|) linear state components
"""
# from collections import OrderedDict  # python3.7+不需要了
from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, List, Optional, Set, Tuple

_log = logging.getLogger(__name__)


# Error hierarchy

class SymbolicError(Exception):
    """Base 异常 for 符号执行 errors
    
    module-specific 异常s inherit 允许
    single-except catching integration layer
    """
    pass


class SolverTimeout(SymbolicError):
    """约束求解 exceeded time budget
    
    caller treat UNSAT (conservative) or
    重试 an increased timeout
    """
    pass


class PathExplosionError(SymbolicError):
    """State count exceeded max_states, indicating 路径爆炸
    
    Indicates target binary too branches for exhaustive
    符号执行. Consider using heuristic pruning or LLM-guided
    exploration
    """
    def __init__(self, state_count: int, max_states: int):
        super().__init__(f"Path explosion: {state_count} states exceeds limit {max_states}")
        self.state_count = state_count
        self.max_states = max_states


class UnsupportedInstructionError(SymbolicError):
    """Encountered an instruction cannot symbolically executed
    
    executor skip instruction continue
    next one (graceful degradation)
    """
    def __init__(self, address: int, opcode: str = ""):
        msg = f"Unsupported instruction at {address:#x}"
        if opcode:
            msg += f" (opcode: {opcode})"
        super().__init__(msg)
        self.address = address
        self.opcode = opcode


class StateSerializationError(SymbolicError):
    """Failed 序列化 or 反序列化 a SymbolicState"""
    pass


# 格式化 conversion

def smtlib_to_z3(smtlib_str: str) -> Optional[Any]:
    """
    解析 an SMT-LIB2 string 返回 a Z3 expression
    
    使用 Z3's parse_smt2_string available, otherwise 返回 a dict
    representation for concrete- mode
    
    Time: O(|string|) for parsing. Space: O(|ast|)
    
    # NOTE: Z3's SMT-LIB 解析器 picky exact 格式化
    # string 启动 a valid SMT-LIB command like (assert.)
    """
    if not smtlib_str.strip():
        return None
    try:
        import z3
        # Wrap a well-formed SMT-LIB2 script
        ctx = z3.Context()
        if not smtlib_str.strip().startswith("(assert"):
            smtlib_str = f"(assert {smtlib_str})"
        parsed = z3.parse_smt2_string(smtlib_str, ctx=ctx)
        # parsed a list BoolRef
        if parsed:
            return parsed[0]
        return None
    except ImportError:
        _log.debug("Z3 not available for SMT-LIB parsing")
        return {"smtlib": smtlib_str, "parsed": False}
    except Exception as e:
        _log.warning("Failed to parse SMT-LIB: %s", e)
        return None


def z3_to_smtlib(expr: Any) -> str:
    """
    转换 a Z3 expression SMT-LIB2 string 格式化
    
    Useful for interoperability external solvers for
    日志/debugging constraint sets
    
    Time: O(|expr|). Space: O(|输出 string|)
    
    Edge case: Z3 available, 返回 repr(expr)
    """
    try:
        if hasattr(expr, 'sexpr'):
            return str(expr.sexpr())
        return str(expr)
    except Exception as e:
        _log.warning("z3_to_smtlib failed: %s", e)
        return repr(expr)


# Constraint parsing

def parse_constraints(raw: Any) -> List[Dict[str, Any]]:
    """
    解析 constraints various input 格式化 a uniform dict 格式化
    
    Supported inputs:
    - JSON string (list dicts)
    - Python list dicts
    - Single dict (auto-wrapped list)
    - SMT-LIB2 string (via smtlib_to_z3, decomposed)
    
    Time: O(|input|) for parsing. Space: O(|result|)
    
    返回:
    List constraint dicts keys: type, var, value, desc (optional)
    
    Edge cases:
    - Empty input 返回 empty list
    - Malformed JSON 返回 empty list warning
    """
    if raw is None:
        return []

    # a list dicts
    if isinstance(raw, list):
        result = []
        for item in raw:
            if isinstance(item, dict):
                result.append(item)
            elif isinstance(item, str):
                result.append({"type": "raw", "smtlib": item})
        return result

    # Single dict
    if isinstance(raw, dict):
        return [raw]

    # JSON string
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, list):
                return parse_constraints(parsed)
            if isinstance(parsed, dict):
                return [parsed]
        except json.JSONDecodeError:
            pass
        # Try SMT-LIB
        if raw.strip().startswith("(assert") or raw.strip().startswith("("):
            z3_expr = smtlib_to_z3(raw)
            if z3_expr is not None:
                return [{"type": "z3_expr", "expr": z3_expr, "smtlib": raw}]
        _log.warning("Could not parse constraint string: %s", raw[:100])

    return []


# State 序列化

def serialize_state(state: Any) -> Dict[str, Any]:
    """
    序列化 a SymbolicState a JSON-compatible dict
    
    used for 检查点ing (保存/恢复 execution state)
    分布式 符号执行 (发送 state worker)
    debugging (inspect state a 快照)
    
    Time: O(R + M + C) linear state components
    Space: O(serialized size)
    
    格式化:
    {
    "state_id": int
    "pc": int
    "寄存器s": {"reg_name": {"value": int, "symbolic": bool, "name": str},.}
    "memory": {addr: {.},.}
    "constraints": [.]
    "depth": int
    "call_栈": [int,.]
    "metadata": {.}
    }
    """
    try:
        result: Dict[str, Any] = {
            "state_id": getattr(state, "state_id", 0),
            "pc": getattr(state, "pc", 0),
            "registers": {},
            "memory": {},
            "constraints": [],
            "depth": getattr(state, "depth", 0),
            "call_stack": list(getattr(state, "call_stack", [])),
            "metadata": dict(getattr(state, "metadata", {})),
        }

        # 序列化 寄存器s
        registers = getattr(state, "registers", {})
        for reg_name, val in registers.items():
            result["registers"][reg_name] = _serialize_symexpr(val)

        # 序列化 memory
        memory = getattr(state, "memory", {})
        for addr, val in memory.items():
            result["memory"][str(addr)] = _serialize_symexpr(val)

        # 序列化 constraints
        constraints = getattr(state, "path_constraints", [])
        for c in constraints:
            if isinstance(c, dict):
                result["constraints"].append(c)
            elif hasattr(c, "sexpr"):
                result["constraints"].append({"sexpr": str(c.sexpr())})
            else:
                result["constraints"].append({"repr": repr(c)})

        return result
    except Exception as e:
        raise StateSerializationError(f"Serialization failed: {e}")


def deserialize_state(data: Dict[str, Any]) -> Any:
    """
    反序列化 a dict back a SymbolicState
    
    Time: O(|data|) linear dict size. Space: O(state size)
    
    Raises State序列化Error malformed input
    
    # NOTE: 创建 a minimal object (使用 SimpleNamespace)
    # avoid importing SymbolicState directly. caller
    # 转换 a full SymbolicState needed
    """
    try:
        from types import SimpleNamespace
        from analysis.symbolic.src.executor import SymbolicState

        state = SymbolicState(
            state_id=data.get("state_id", 0),
            pc=data.get("pc", 0),
            depth=data.get("depth", 0),
            call_stack=list(data.get("call_stack", [])),
            metadata=dict(data.get("metadata", {})),
        )

        # 反序列化 寄存器s
        for reg_name, val_dict in data.get("registers", {}).items():
            state.registers[reg_name] = _deserialize_symexpr(val_dict)

        # 反序列化 memory
        for addr_str, val_dict in data.get("memory", {}).items():
            addr = int(addr_str)
            state.memory[addr] = _deserialize_symexpr(val_dict)

        # Constraints preserved dicts
        state.path_constraints = list(data.get("constraints", []))

        return state
    except Exception as e:
        raise StateSerializationError(f"Deserialization failed: {e}")


def _serialize_symexpr(val: Any) -> Dict[str, Any]:
    """序列化 a SymExpr or similar object a dict. O(1)"""
    if hasattr(val, "is_symbolic"):
        is_sym = val.is_symbolic
        return {
            "value": val.value,
            "symbolic": is_sym,
            "name": val.name if is_sym else "",
            "size_bits": getattr(val, "size_bits", 32),
        }
    if isinstance(val, dict):
        return val
    # 回退: treat int
    try:
        return {"value": int(val), "symbolic": False, "name": ""}
    except (ValueError, TypeError):
        return {"value": 0, "symbolic": False, "name": str(val)[:64]}


def _deserialize_symexpr(data: Dict[str, Any]) -> Any:
    """反序列化 a SymExpr dict back a SymExpr. O(1)"""
    from analysis.symbolic.src.executor import SymExpr
    is_sym = data.get("symbolic", False)
    name = data.get("name", "")
    value = data.get("value", 0)
    size = data.get("size_bits", 32)
    if is_sym and name:
        return SymExpr.symbolic(name, size_bits=size)
    return SymExpr.concrete(value, size_bits=size)


# 覆盖率 computation

def compute_path_coverage(
    reached: Set[Tuple[int, int]],
    total_basic_blocks: int,
) -> float:
    """
    计算 path 覆盖率 ratio unique (address, step) pairs reached
    
    Args:
    reached: Set (address, instruction_idx) tuples visited
    total_basic_blocks: Total number basic blocks target
    
    返回:
    Float 0.0 1.0 representing 覆盖率 ratio
    
    Time: O(|reached|). Space: O(1)
    
    Edge case: total_basic_blocks 0, 返回 0.0
    """
    if total_basic_blocks <= 0:
        return 0.0
    # 计算 unique addresses (steps)
    unique_addrs = set(addr for addr, _ in reached)
    return min(1.0, len(unique_addrs) / total_basic_blocks)


def compute_branch_coverage(
    branch_counts: Dict[int, int],
    total_branches: int,
    min_hits_per_branch: int = 1,
) -> float:
    """
    计算 branch 覆盖率 ratio branches visited least once
    
    Args:
    branch_counts: Dict mapping branch address visit count
    total_branches: Total number branch instructions target
    min_hits_per_branch: Minimum visits count covered (default 1)
    
    返回:
    Float 0.0 1.0
    
    Time: O(|branch_counts|). Space: O(1)
    
    // BFS guarantees shortest path but memory explodes deep paths;
    // DFS memory-efficient reaches deep branches faster
    // 覆盖率-guided strategies sit — bias toward
    // novel branches but miss deep, isolated code paths
    """
    if total_branches <= 0:
        return 0.0
    covered = sum(1 for count in branch_counts.values() if count >= min_hits_per_branch)
    return min(1.0, covered / total_branches)


# Dead code — 留着备用，后面可能用

def _validate_symbolic_smt(smtlib_str: str) -> bool:
    """
    校验 SMT-LIB2 syntax invoking Z3. currently wired
    
    用正则粗略校验SMT-LIB格式，免得传无效字符串到Z3导致crash
    """
    smtlib_str = smtlib_str.strip()
    if not smtlib_str:
        return False
    # 启动 '('
    if not smtlib_str.startswith("("):
        return False
    # Balanced parentheses 检查
    depth = 0
    for ch in smtlib_str:
        if ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
        if depth < 0:
            return False
    return depth == 0


def _InspectCoverageReport(coverage: Set[Tuple[int, int]]) -> str:
    """构造 a human-readable 覆盖率 summary. main flow"""
    unique_addrs = sorted(set(addr for addr, _ in coverage))
    lines = [f"Coverage report: {len(unique_addrs)} unique addresses"]
    for addr in unique_addrs[:20]:
        steps = sum(1 for a, _ in coverage if a == addr)
        lines.append(f"  {addr:#010x}: hit {steps} times")
    if len(unique_addrs) > 20:
        lines.append(f"  ... and {len(unique_addrs) - 20} more")
    return "\n".join(lines)


__all__ = [
    # Error hierarchy
    "SymbolicError", "SolverTimeout", "PathExplosionError",
    "UnsupportedInstructionError", "StateSerializationError",
    # 格式化 conversion
    "smtlib_to_z3", "z3_to_smtlib",
    # Constraint parsing
    "parse_constraints",
    # State 序列化
    "serialize_state", "deserialize_state",
    # 覆盖率
    "compute_path_coverage", "compute_branch_coverage",
]
