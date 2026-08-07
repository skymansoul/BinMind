#!/usr/bin/env python3
"""
约束求解器 — Z3-based 约束求解 graceful 回退

Architecture:
- Composition over inheritance: ConstraintSolver wraps a Z3 context
inheriting. 隔离 Z3-specific code
concrete- 回退 trivially swappable
- Z3ExpressionBuilder a separate builder class for constructing
Z3 AST nodes IR operations. 处理 BitVector theory
(QF_BV) appropriate for 二进制分析

Edge cases:
- Solver timeout: a call solver.检查() exceeds timeout_ms
返回 UNSAT (safe under-approximation — avoid reporting
a false positive)
- Memory limit: large constraint sets OOM Z3; catch
gracefully degrade
- Mixed concrete/symbolic expressions: automatically lifted BV

Time complexity:
- solve(): O(|constraints| * BV_size) for conversion + Z3 solver time
(exponential worst-case for BV theory, typically polynomial for QF_BV)
- is_satisfiable(): same solve() but model extraction
- simplify(): O(|expr|) Z3 internal simplification pass
- model_to_dict(): O(|variables|) iteration over model
"""
# from collections import OrderedDict  # python3.7+不需要了
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

_log = logging.getLogger(__name__)

# Error hierarchy

class SymbolicError(Exception):
    """Base error for 符号执行 operations"""
    pass


class SolverTimeout(SymbolicError):
    """Raised 约束求解 exceeds time budget"""
    pass


class SolverNotFound(SymbolicError):
    """Raised Z3 installed an operation requires"""
    pass


# Z3 可用性 检查

_HAS_Z3: Optional[bool] = None


def has_z3() -> bool:
    """检查 Z3 available.缓存s result. O(1) first call"""
    global _HAS_Z3
    if _HAS_Z3 is None:
        try:
            import z3  # noqa: F401
            _HAS_Z3 = True
        except ImportError:
            _HAS_Z3 = False
    return _HAS_Z3


# Z3ExpressionBuilder

class Z3ExpressionBuilder:
    """
    构建 Z3 expressions IR operations symbolic expressions
    
    支持 BitVector theory (QF_BV) for 二进制分析. expressions
    built BitVec specified width (default 32 bits)
    
    INTJ策略: 使用 BitVec rather Int theory because:
    1. Binary operations naturally bit-vector arithmetic
    2. Overflow semantics match CPU behavior (wrapping)
    3. QF_BV solvers efficient for domain LIA
    
    Trade-off: BitVec solves slower for purely arithmetic constraints
    but models hardware faithfully (wrapping, shifts, sign extension)
    """

    def __init__(self, default_bits: int = 32):
        self.default_bits = default_bits
        self._z3 = None
        if has_z3():
            import z3
            self._z3 = z3

    @property
    def z3(self):
        if self._z3 is None:
            raise SolverNotFound("Z3 is not installed. Use concrete-only mode.")
        return self._z3

    def make_bv(self, name: str, bits: int = 0) -> Any:
        """创建 a fresh BitVec variable. O(1)
        
        Args:
        name: Variable name (Z3-safe identifier)
        bits: Bit width (defaults self.default_bits)
        """
        if bits <= 0:
            bits = self.default_bits
        return self.z3.BitVec(name, bits)

    def make_const(self, value: int, bits: int = 0) -> Any:
        """创建 a BitVec constant. O(1)"""
        if bits <= 0:
            bits = self.default_bits
        return self.z3.BitVecVal(value, bits)

# Arithmetic

    def bv_add(self, lhs: Any, rhs: Any) -> Any: return lhs + rhs
    def bv_sub(self, lhs: Any, rhs: Any) -> Any: return lhs - rhs
    def bv_mul(self, lhs: Any, rhs: Any) -> Any: return lhs * rhs

    def bv_div(self, lhs: Any, rhs: Any) -> Any:
        """Unsigned division. O(BV_size) Z3"""
        return self.z3.UDiv(lhs, rhs)

    def bv_sdiv(self, lhs: Any, rhs: Any) -> Any:
        """Signed division"""
        return lhs / rhs

    def bv_mod(self, lhs: Any, rhs: Any) -> Any:
        """Unsigned modulo"""
        return self.z3.URem(lhs, rhs)

    def bv_smod(self, lhs: Any, rhs: Any) -> Any:
        """Signed modulo"""
        return lhs % rhs

# Bitwise

    def bv_and(self, lhs: Any, rhs: Any) -> Any: return lhs & rhs
    def bv_or(self, lhs: Any, rhs: Any) -> Any: return lhs | rhs
    def bv_xor(self, lhs: Any, rhs: Any) -> Any: return lhs ^ rhs
    def bv_shl(self, lhs: Any, rhs: Any) -> Any: return lhs << rhs

    def bv_shr(self, lhs: Any, rhs: Any) -> Any:
        """Logical (unsigned) right shift"""
        return self.z3.LShR(lhs, rhs)

    def bv_ashr(self, lhs: Any, rhs: Any) -> Any:
        """Arithmetic (signed) right shift"""
        return lhs >> rhs

# Comparisons

    def bv_eq(self, lhs: Any, rhs: Any) -> Any: return lhs == rhs
    def bv_ne(self, lhs: Any, rhs: Any) -> Any: return lhs != rhs

    def bv_ult(self, lhs: Any, rhs: Any) -> Any:
        """Unsigned less"""
        return self.z3.ULT(lhs, rhs)

    def bv_ugt(self, lhs: Any, rhs: Any) -> Any:
        """Unsigned greater"""
        return self.z3.UGT(lhs, rhs)

    def bv_ule(self, lhs: Any, rhs: Any) -> Any:
        """Unsigned less or equal"""
        return self.z3.ULE(lhs, rhs)

    def bv_uge(self, lhs: Any, rhs: Any) -> Any:
        """Unsigned greater or equal"""
        return self.z3.UGE(lhs, rhs)

    def bv_slt(self, lhs: Any, rhs: Any) -> Any: return lhs < rhs
    def bv_sgt(self, lhs: Any, rhs: Any) -> Any: return lhs > rhs
    def bv_sle(self, lhs: Any, rhs: Any) -> Any: return lhs <= rhs
    def bv_sge(self, lhs: Any, rhs: Any) -> Any: return lhs >= rhs

# Memory (Array Theory)

    def make_memory_array(self, name: str, addr_bits: int = 32, data_bits: int = 8) -> Any:
        """
        创建 an Array for symbolic memory modeling
        Array(address_bitvec, data_bitvec) for byte-level memory
        
        // INTJ策略: Array theory precise ITE-chains for memory
        // but Z3's array solver slower large numbers 存储
        // For small functions (<100 存储), array fine
        // For larger ones, consider concretizing "cold" memory pages
        """
        addr_sort = self.z3.BitVecSort(addr_bits)
        data_sort = self.z3.BitVecSort(data_bits)
        return self.z3.Array(name, addr_sort, data_sort)

    def array_select(self, arr: Any, idx: Any) -> Any:
        """读取 array: arr[idx]. O(1) Z3 term construction"""
        return self.z3.Select(arr, idx)

    def array_store(self, arr: Any, idx: Any, val: Any) -> Any:
        """写入 array: 存储(arr, idx, val). 创建 new SSA array. O(1)"""
        return self.z3.Store(arr, idx, val)

# Utility

    def bool_to_bv(self, cond: Any) -> Any:
        """转换 a Bool BitVec(1): (cond, 1, 0). O(1)"""
        return self.z3.If(cond, self.make_const(1, 1), self.make_const(0, 1))

    def bv_to_bool(self, bv: Any) -> Any:
        """转换 BitVec(1) Bool: bv == 1. O(1)"""
        return bv == self.make_const(1, bv.size() if hasattr(bv, 'size') else 1)

    def concat(self, hi: Any, lo: Any) -> Any:
        """Concatenate two BitVecs: Concat(hi, lo). O(1)"""
        return self.z3.Concat(hi, lo)

    def extract(self, bv: Any, high: int, low: int) -> Any:
        """提取 bits [high:low] BitVec. O(1)"""
        return self.z3.Extract(high, low, bv)


# ConstraintSolver

class ConstraintSolver:
    """
    约束求解器 Z3 backend concrete- 回退
    
    Design:
    - Z3 available, 使用 z3.Solver() 配置urable timeout
    - Z3 available, falls back concrete- mode
    constraints dictionary-based simple integer comparisons
    supported. 允许 unit tests basic workflows Z3
    
    INTJ策略: Timeout handling 使用 a background-thread approach because
    z3.Solver.set("timeout", N) works for SAT calls, for
    model enumeration. wrap entire 检查() a timer
    
    Trade-off: Concrete- mode sound but incomplete — cannot
    solve for symbolic variables. 's useful for testing for
    targets values analysis time
    """

    def __init__(self, timeout_ms: int = 5000, memory_mb: int = 256):
        self.timeout_ms = timeout_ms
        self.memory_mb = memory_mb
        self._z3_solver: Any = None
        self._builder: Optional[Z3ExpressionBuilder] = None
        self._stats: Dict[str, int] = {"solves": 0, "timeouts": 0, "sat": 0, "unsat": 0}

    @property
    def builder(self) -> Z3ExpressionBuilder:
        if self._builder is None:
            self._builder = Z3ExpressionBuilder()
        return self._builder

    def _get_solver(self) -> Any:
        """Lazy-init Z3 solver 配置ured timeout/memory. O(1)"""
        if self._z3_solver is None:
            if not has_z3():
                raise SolverNotFound("Z3 is not installed. Cannot create solver.")
            import z3  # noqa: F811
            self._z3_solver = z3.Solver()
            self._z3_solver.set("timeout", self.timeout_ms)
            if hasattr(self._z3_solver, 'set') and self.memory_mb:
                try:
                    self._z3_solver.set("max_memory", self.memory_mb)
                except Exception:
                    pass  # Z3 versions don't 支持 max_memory
        return self._z3_solver

    def solve(self, constraints: List[Any], target_var: str) -> Optional[int]:
        """
        Solve constraints for a concrete value target_var
        
        Args:
        constraints: List constraint dicts or Z3 BoolRefs
        target_var: Name variable solve for
        
        返回:
        Concrete integer value satisfiable, None otherwise
        
        Time: O(|constraints| + solver_time). Space: O(|constraints| * BV_size)
        
        # 2025-10-17: 这个workaround估计后面版本修复了就能删
        # Z3 versions 返回 negative values for unsigned BV — mask
        """
        if not has_z3():
            return self._solve_concrete_only(constraints, target_var)

        try:
            solver = self._get_solver()
            solver.reset()
            z3_exprs = self._constraints_to_z3(constraints)
            for expr in z3_exprs:
                solver.add(expr)
            self._stats["solves"] += 1

            result = solver.check()
            if str(result) == "sat":
                self._stats["sat"] += 1
                model = solver.model()
                return self._extract_var_value(model, target_var)
            else:
                self._stats["unsat"] += 1
                return None

        except SolverTimeout:
            self._stats["timeouts"] += 1
            _log.warning("Solver timeout for target_var=%s", target_var)
            return None
        except Exception as e:
            _log.error("Solver error: %s", e)
            return None

    def is_satisfiable(self, constraints: List[Any]) -> bool:
        """
        检查 a set constraints satisfiable
        
        core predicate used path pruning: a path's
        constraints UNSAT, path infeasible pruned
        
        Time: O(|constraints| + solver_time). Space: O(|constraints| * BV_size)
        
        Edge case: empty constraint list trivially SAT
        """
        if not constraints:
            return True
        if not has_z3():
            return self._is_satisfiable_concrete(constraints)

        try:
            solver = self._get_solver()
            solver.reset()
            z3_exprs = self._constraints_to_z3(constraints)
            for expr in z3_exprs:
                solver.add(expr)
            self._stats["solves"] += 1

            result = solver.check()
            return str(result) == "sat"

        except SolverTimeout:
            self._stats["timeouts"] += 1
            return True  # Safe over-approximation: assume satisfiable
        except Exception as e:
            _log.error("Solver error in is_satisfiable: %s", e)
            return True  # Safe over-approximation

    def simplify(self, expr: Any) -> Any:
        """
        Simplify a Z3 expression using Z3's built- simplifier
        
        // NOTE: Z3's simplify() heuristic-; doesn't guarantee
        // minimal form but usually good enough for 90% cases
        
        Time: O(|expr|) Z3 simplify pass
        """
        if not has_z3():
            return expr  # -op concrete mode
        import z3  # noqa: F811
        try:
            return z3.simplify(expr)
        except Exception:
            return expr

    def model_to_dict(self, z3_model: Any) -> Dict[str, Any]:
        """
        提取 variable bindings a Z3 model a plain dict
        
        Args:
        z3_model: A z3.ModelRef solver.model()
        
        返回:
        Dict mapping variable names integer values
        
        Time: O(|variables|). Space: O(|variables|)
        """
        result: Dict[str, Any] = {}
        if z3_model is None:
            return result
        try:
            for decl in z3_model.decls():
                name = decl.name()
                val = z3_model[decl]
                try:
                    if hasattr(val, 'as_long'):
                        result[name] = val.as_long()
                    elif hasattr(val, 'as_string'):
                        result[name] = val.as_string()
                    else:
                        result[name] = str(val)
                except Exception:
                    result[name] = str(val)
        except Exception as e:
            _log.warning("model_to_dict failed: %s", e)
        return result

    def _extract_var_value(self, model: Any, var_name: str) -> Optional[int]:
        """提取 a single variable's value a Z3 model. O(|decls|)"""
        try:
            for decl in model.decls():
                if decl.name() == var_name:
                    val = model[decl]
                    if hasattr(val, 'as_long'):
                        raw = val.as_long()
                        # Mask 32-bit for consistency
                        return raw & 0xFFFFFFFF
                    return None
        except Exception:
            pass
        return None

    def _constraints_to_z3(self, constraints: List[Any]) -> List[Any]:
        """
        转换 a list constraint dicts or Z3 expressions Z3 BoolRefs
        
        Constraint dict 格式化: {"type": "eq"|"neq"|"lt"|"gt"|""|"or"
        "var": str, "value": int,.}
        
        Time: O(|constraints|). conversion O(1)
        """
        import z3  # noqa: F811
        bld = self.builder
        result = []
        for c in constraints:
            if hasattr(c, 'decl'):
                # a Z3 expression
                result.append(c)
            elif isinstance(c, dict):
                z3_expr = self._dict_to_z3(bld, c)
                if z3_expr is not None:
                    result.append(z3_expr)
        return result

    def _dict_to_z3(self, bld: Z3ExpressionBuilder, c: Dict[str, Any]) -> Optional[Any]:
        """转换 a constraint dict a Z3 BoolRef. O(1)"""
        typ = c.get("type", "")
        var_name = c.get("var", "")
        value = c.get("value", 0)

        var_bv = bld.make_bv(var_name)
        val_bv = bld.make_const(value)

        if typ == "eq":
            return var_bv == val_bv
        elif typ == "neq":
            return var_bv != val_bv
        elif typ == "lt":
            return bld.bv_ult(var_bv, val_bv)
        elif typ == "gt":
            return bld.bv_ugt(var_bv, val_bv)
        elif typ == "le":
            return bld.bv_ule(var_bv, val_bv)
        elif typ == "ge":
            return bld.bv_uge(var_bv, val_bv)
        elif typ == "and":
            children = c.get("children", [])
            z3_children = [self._dict_to_z3(bld, ch) for ch in children]
            z3_children = [x for x in z3_children if x is not None]
            if z3_children:
                return z3.And(*z3_children)
            return None
        elif typ == "or":
            children = c.get("children", [])
            z3_children = [self._dict_to_z3(bld, ch) for ch in children]
            z3_children = [x for x in z3_children if x is not None]
            if z3_children:
                return z3.Or(*z3_children)
            return None
        return None

# Concrete- 回退

    def _solve_concrete_only(self, constraints: List[Any], target_var: str) -> Optional[int]:
        """
        Solve constraints concrete- mode (Z3)
        
        支持 simple eq/neq integer values
        返回 value constraints consistent, else None
        
        // a severely limited subset — for full symbolic solving
        // install Z3: pip install z3-solver
        """
        target_val = None
        for c in constraints:
            if not isinstance(c, dict):
                continue
            if c.get("var") == target_var:
                if c.get("type") == "eq":
                    candidate = c.get("value")
                    if target_val is not None and target_val != candidate:
                        return None  # Contradiction
                    target_val = candidate
                elif c.get("type") == "neq":
                    candidate = c.get("value")
                    if target_val == candidate:
                        return None  # Contradiction
        return target_val

    def _is_satisfiable_concrete(self, constraints: List[Any]) -> bool:
        """
        检查 satisfiability concrete- mode
        返回 True contradictions found
        
        Time: O(N^2) for checking pairs
        """
        eq_map: Dict[str, int] = {}
        neq_map: Dict[str, Set[int]] = {}
        for c in constraints:
            if not isinstance(c, dict):
                continue
            var = c.get("var", "")
            val = c.get("value", 0)
            if c.get("type") == "eq":
                if var in eq_map and eq_map[var] != val:
                    return False
                eq_map[var] = val
            elif c.get("type") == "neq":
                if var not in neq_map:
                    neq_map[var] = set()
                neq_map[var].add(val)
        for var, val in eq_map.items():
            if var in neq_map and val in neq_map[var]:
                return False
        return True

    def get_stats(self) -> Dict[str, int]:
        return dict(self._stats)


# Dead code — 留着备用，后面可能用

def _symbolic_SimplifyExpression(expr_tree: dict) -> dict:
    """Simplify a symbolic expression AST using local rules. Never
    
    an attempt Z3-independent simplification integrated
    Z3's simplify(). Kept 回退 for offline mode
    """
    if not isinstance(expr_tree, dict):
        return expr_tree
    typ = expr_tree.get("type", "")
    # Constant folding: const op const
    if typ in ("add", "sub", "mul") and "left" in expr_tree and "right" in expr_tree:
        left = expr_tree["left"]
        right = expr_tree["right"]
        if isinstance(left, (int, float)) and isinstance(right, (int, float)):
            if typ == "add": return {"type": "const", "value": left + right}
            if typ == "sub": return {"type": "const", "value": left - right}
            if typ == "mul": return {"type": "const", "value": left * right}
    return expr_tree


__all__ = [
    "ConstraintSolver", "Z3ExpressionBuilder",
    "SymbolicError", "SolverTimeout", "SolverNotFound",
    "has_z3",
    "_symbolic_SimplifyExpression",
]
