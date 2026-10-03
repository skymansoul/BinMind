#!/usr/bin/env python3
"""
符号执行模块的共享工具集。

功能:
- 格式转换: smtlib <-> Z3 表达式
- 多种输入格式的约束解析
- 状态序列化/反序列化, 用于检查点
- 覆盖率计算: 路径覆盖率、分支覆盖率
- 错误层级: 自定义异常, 用于明确的错误处理

设计:
- 序列化使用 JSON 可序列化的中间格式 (dicts/lists),
  与 Z3 内部表示解耦
- 覆盖率计算用集合追踪, O(1) 查找

时间复杂度:
- 覆盖率函数: O(|reached|) 集合操作
- 序列化: O(|state size|), 随状态组件线性增长
"""
# from collections import OrderedDict  # python3.7+不需要了
from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, List, Optional, Set, Tuple

_log = logging.getLogger(__name__)


# 错误层次结构

class SymbolicError(Exception):
    """符号执行错误的基类异常。

    模块专属异常继承它, 集成层可以单 except 捕获。
    """
    pass


class SolverTimeout(SymbolicError):
    """约束求解超出时间预算。

    调用方可按不可解处理 (保守) 或加大超时重试。
    """
    pass


class PathExplosionError(SymbolicError):
    """状态数超过 max_states, 指示路径爆炸。

    说明目标二进制分支过多, 无法穷尽符号执行;
    可考虑启发式剪枝或 LLM 引导探索。
    """
    def __init__(self, state_count: int, max_states: int):
        super().__init__(f"Path explosion: {state_count} states exceeds limit {max_states}")
        self.state_count = state_count
        self.max_states = max_states


class UnsupportedInstructionError(SymbolicError):
    """遇到无法符号执行的指令。

    executor 跳过该指令继续下一条 (优雅降级)。
    """
    def __init__(self, address: int, opcode: str = ""):
        msg = f"Unsupported instruction at {address:#x}"
        if opcode:
            msg += f" (opcode: {opcode})"
        super().__init__(msg)
        self.address = address
        self.opcode = opcode


class StateSerializationError(SymbolicError):
    """SymbolicState 序列化或反序列化失败。"""
    pass


# 格式转换

def smtlib_to_z3(smtlib_str: str) -> Optional[Any]:
    """
    解析 SMT-LIB2 字符串, 返回 Z3 表达式。

    Z3 可用时用 parse_smt2_string, 否则返回供具体值模式使用的
    dict 表示。

    # 注意: Z3 的 SMT-LIB 解析器对格式严格,
    # 字符串必须以 (assert ...) 之类的合法命令开头
    """
    if not smtlib_str.strip():
        return None
    try:
        import z3
        # 裸表达式 (如 "(= x 5)") 包成 (assert ...);
        # declare-const/set-logic 等命令开头的完整脚本原样解析
        stripped = smtlib_str.strip()
        if stripped.startswith("(") and not stripped.startswith("(assert"):
            _CMD_PREFIXES = ("(declare-", "(set-", "(define-", "(push",
                             "(pop", "(check-sat", "(get-", "(exit", "(echo")
            if not stripped.startswith(_CMD_PREFIXES):
                smtlib_str = f"(assert {stripped})"
            else:
                smtlib_str = stripped
        elif not stripped.startswith("("):
            smtlib_str = f"(assert {stripped})"
        ctx = z3.Context()
        parsed = z3.parse_smt2_string(smtlib_str, ctx=ctx)
        # parsed 是 BoolRef 列表，取第一个
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
    把 Z3 表达式转为 SMT-LIB2 字符串格式。

    用于与外部求解器互操作、约束集日志/调试。

    边界情况: Z3 不可用时返回 repr(expr)。
    """
    try:
        if hasattr(expr, 'sexpr'):
            return str(expr.sexpr())
        return str(expr)
    except Exception as e:
        _log.warning("z3_to_smtlib failed: %s", e)
        return repr(expr)


# 约束解析

def parse_constraints(raw: Any) -> List[Dict[str, Any]]:
    """
    把各种输入格式的约束解析为统一的 dict 格式列表。

    支持的输入: JSON 字符串 (dict 列表)、Python dict 列表、
    单个 dict (自动包装)、SMT-LIB2 字符串 (经 smtlib_to_z3
    分解)。约束 dict 键含 type、var、value、desc (可选)。

    边界情况: 空输入返回空列表; 畸形 JSON 返回空列表并警告。
    """
    if raw is None:
        return []

    # dict 列表
    if isinstance(raw, list):
        result = []
        for item in raw:
            if isinstance(item, dict):
                result.append(item)
            elif isinstance(item, str):
                result.append({"type": "raw", "smtlib": item})
        return result

    # 单个 dict
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
        # 尝试 SMT-LIB
        if raw.strip().startswith("(assert") or raw.strip().startswith("("):
            z3_expr = smtlib_to_z3(raw)
            if z3_expr is not None:
                return [{"type": "z3_expr", "expr": z3_expr, "smtlib": raw}]
        _log.warning("Could not parse constraint string: %s", raw[:100])

    return []


# State 序列化

def serialize_state(state: Any) -> Dict[str, Any]:
    """
    把 SymbolicState 序列化为 JSON 兼容的 dict。

    用于检查点 (保存/恢复执行状态)、分布式符号执行
    (发送状态到 worker) 与调试 (把状态检视为快照)。

    格式: {"state_id": int, "pc": int,
    "registers": {"reg_name": {"value": int, "symbolic": bool,
    "name": str}, ...}, "memory": {addr: {...}, ...},
    "constraints": [...], "depth": int, "call_stack": [int, ...],
    "metadata": {...}}。
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

        # 序列化寄存器
        registers = getattr(state, "registers", {})
        for reg_name, val in registers.items():
            result["registers"][reg_name] = _serialize_symexpr(val)

        # 序列化内存
        memory = getattr(state, "memory", {})
        for addr, val in memory.items():
            result["memory"][str(addr)] = _serialize_symexpr(val)

        # 序列化约束
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
    把 dict 反序列化回 SymbolicState。

    输入畸形时抛 StateSerializationError; 反序列化直接构造
    SymbolicState 实例。
    """
    try:
        from types import SimpleNamespace
        from modules.analysis.symbolic.src.executor import SymbolicState

        state = SymbolicState(
            state_id=data.get("state_id", 0),
            pc=data.get("pc", 0),
            depth=data.get("depth", 0),
            call_stack=list(data.get("call_stack", [])),
            metadata=dict(data.get("metadata", {})),
        )

        # 反序列化寄存器
        for reg_name, val_dict in data.get("registers", {}).items():
            state.registers[reg_name] = _deserialize_symexpr(val_dict)

        # 反序列化内存
        for addr_str, val_dict in data.get("memory", {}).items():
            addr = int(addr_str)
            state.memory[addr] = _deserialize_symexpr(val_dict)

        # 保留 dict 格式的约束
        state.path_constraints = list(data.get("constraints", []))

        return state
    except Exception as e:
        raise StateSerializationError(f"Deserialization failed: {e}")


def _serialize_symexpr(val: Any) -> Dict[str, Any]:
    """把 SymExpr 或类似对象序列化为 dict, O(1)。"""
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
    # 回退: 尝试当作整数处理
    try:
        return {"value": int(val), "symbolic": False, "name": ""}
    except (ValueError, TypeError):
        return {"value": 0, "symbolic": False, "name": str(val)[:64]}


def _deserialize_symexpr(data: Dict[str, Any]) -> Any:
    """把 SymExpr dict 反序列化回 SymExpr, O(1)。"""
    from modules.analysis.symbolic.src.executor import SymExpr
    is_sym = data.get("symbolic", False)
    name = data.get("name", "")
    value = data.get("value", 0)
    size = data.get("size_bits", 32)
    if is_sym and name:
        return SymExpr.symbolic(name, size_bits=size)
    return SymExpr.concrete(value, size_bits=size)


# 覆盖率计算

def compute_path_coverage(
    reached: Set[Tuple[int, int]],
    total_basic_blocks: int,
) -> float:
    """
    计算路径覆盖率: 到达的唯一 (address, step) 对比例。

    reached 为访问过的 (address, instruction_idx) 元组集合;
    total_basic_blocks 为目标的基本块总数; 返回 0.0-1.0,
    总块数为 0 时返回 0.0。
    """
    if total_basic_blocks <= 0:
        return 0.0
    # 计算唯一地址（忽略步号）
    unique_addrs = set(addr for addr, _ in reached)
    return min(1.0, len(unique_addrs) / total_basic_blocks)


def compute_branch_coverage(
    branch_counts: Dict[int, int],
    total_branches: int,
    min_hits_per_branch: int = 1,
) -> float:
    """
    计算分支覆盖率: 至少访问 min_hits_per_branch 次的分支比例。

    branch_counts 为分支地址→访问次数的映射, total_branches 为
    目标中的分支指令总数; 返回 0.0-1.0。
    """
    if total_branches <= 0:
        return 0.0
    covered = sum(1 for count in branch_counts.values() if count >= min_hits_per_branch)
    return min(1.0, covered / total_branches)


def _validate_symbolic_smt(smtlib_str: str) -> bool:
    """粗略校验 SMT-LIB 格式, 避免把无效字符串传给 Z3 导致崩溃。"""
    smtlib_str = smtlib_str.strip()
    if not smtlib_str:
        return False
    # 必须以 '(' 开头
    if not smtlib_str.startswith("("):
        return False
    # 括号配对检查
    depth = 0
    for ch in smtlib_str:
        if ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
        if depth < 0:
            return False
    return depth == 0


def _coverage_report_text(coverage: Set[Tuple[int, int]]) -> str:
    """构造人类可读的覆盖率摘要。"""
    unique_addrs = sorted(set(addr for addr, _ in coverage))
    lines = [f"Coverage report: {len(unique_addrs)} unique addresses"]
    for addr in unique_addrs[:20]:
        steps = sum(1 for a, _ in coverage if a == addr)
        lines.append(f"  {addr:#010x}: hit {steps} times")
    if len(unique_addrs) > 20:
        lines.append(f"  ... and {len(unique_addrs) - 20} more")
    return "\n".join(lines)


__all__ = [
# 错误层级
    "SymbolicError", "SolverTimeout", "PathExplosionError",
    "UnsupportedInstructionError", "StateSerializationError",
    # 格式转换
    "smtlib_to_z3", "z3_to_smtlib",
# 约束解析
    "parse_constraints",
    # State 序列化
    "serialize_state", "deserialize_state",
    # 覆盖率
    "compute_path_coverage", "compute_branch_coverage",
]
