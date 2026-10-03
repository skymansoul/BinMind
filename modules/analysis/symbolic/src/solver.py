#!/usr/bin/env python3
"""
约束求解器 — 基于 Z3, 带优雅降级的具体值回退。

架构:
- 组合优于继承: ConstraintSolver 包装 Z3 上下文而非继承,
  隔离 Z3 相关代码, 具体值回退可平凡替换
- Z3ExpressionBuilder 是独立的构造器类, 把 IR 操作构造成
  Z3 AST 节点, 使用适合二进制分析的 BitVector 理论 (QF_BV)

边界情况:
- 求解器超时: 调用超过 timeout_ms 时返回不可解 (安全下近似,
  避免报出假阳性)
- 内存限制: 大规模约束集导致 Z3 OOM 时捕获并优雅降级
- 混合具体/符号表达式: 自动提升为 BV

时间复杂度:
- solve(): O(|constraints| * BV_size) 转换 + Z3 求解时间
  (BV 理论最坏指数, QF_BV 通常多项式)
- is_satisfiable(): 同 solve() 但不提取模型
- simplify(): O(|expr|) Z3 内部化简
- model_to_dict(): O(|variables|) 遍历模型
"""
# from collections import OrderedDict  # python3.7+不需要了
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

_log = logging.getLogger(__name__)

# 错误层级

class SymbolicError(Exception):
    """符号执行操作的基类异常。"""
    pass


class SolverTimeout(SymbolicError):
    """约束求解超出时间预算时抛出。"""
    pass


class SolverNotFound(SymbolicError):
    """Z3 未安装但操作需要它时抛出。"""
    pass


# Z3 可用性 检查

_HAS_Z3: Optional[bool] = None


def has_z3() -> bool:
    """检查 Z3 是否可用, 结果缓存, 首次调用后 O(1)。"""
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
    把 IR 操作与符号表达式构造成 Z3 表达式。

    使用适合二进制分析的 BitVector 理论 (QF_BV), 表达式按指定
    位宽构造 (默认 32 位)。

    设计策略: 用 BitVec 而非 Int 理论, 因为:
    1. 二进制操作天然是位向量算术
    2. 溢出语义与 CPU 行为一致 (回绕)
    3. QF_BV 求解器在本领域比 LIA 高效

    权衡: 纯算术约束上 BitVec 求解更慢, 但忠实建模硬件行为
    (回绕、移位、符号扩展)。
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
        """创建新的 BitVec 变量, bits 默认取 default_bits。"""
        if bits <= 0:
            bits = self.default_bits
        return self.z3.BitVec(name, bits)

    def make_const(self, value: int, bits: int = 0) -> Any:
        """创建 BitVec 常量。"""
        if bits <= 0:
            bits = self.default_bits
        return self.z3.BitVecVal(value, bits)

# 算术运算

    def bv_add(self, lhs: Any, rhs: Any) -> Any: return lhs + rhs
    def bv_sub(self, lhs: Any, rhs: Any) -> Any: return lhs - rhs
    def bv_mul(self, lhs: Any, rhs: Any) -> Any: return lhs * rhs

    def bv_div(self, lhs: Any, rhs: Any) -> Any:
        """无符号除法。"""
        return self.z3.UDiv(lhs, rhs)

    def bv_sdiv(self, lhs: Any, rhs: Any) -> Any:
        """有符号除法。"""
        return lhs / rhs

    def bv_mod(self, lhs: Any, rhs: Any) -> Any:
        """无符号取模。"""
        return self.z3.URem(lhs, rhs)

    def bv_smod(self, lhs: Any, rhs: Any) -> Any:
        """有符号取模。"""
        return lhs % rhs

# 位运算

    def bv_and(self, lhs: Any, rhs: Any) -> Any: return lhs & rhs
    def bv_or(self, lhs: Any, rhs: Any) -> Any: return lhs | rhs
    def bv_xor(self, lhs: Any, rhs: Any) -> Any: return lhs ^ rhs
    def bv_shl(self, lhs: Any, rhs: Any) -> Any: return lhs << rhs

    def bv_shr(self, lhs: Any, rhs: Any) -> Any:
        """逻辑右移 (无符号)。"""
        return self.z3.LShR(lhs, rhs)

    def bv_ashr(self, lhs: Any, rhs: Any) -> Any:
        """算术右移 (有符号)。"""
        return lhs >> rhs

# 比较运算

    def bv_eq(self, lhs: Any, rhs: Any) -> Any: return lhs == rhs
    def bv_ne(self, lhs: Any, rhs: Any) -> Any: return lhs != rhs

    def bv_ult(self, lhs: Any, rhs: Any) -> Any:
        """无符号小于。"""
        return self.z3.ULT(lhs, rhs)

    def bv_ugt(self, lhs: Any, rhs: Any) -> Any:
        """无符号大于。"""
        return self.z3.UGT(lhs, rhs)

    def bv_ule(self, lhs: Any, rhs: Any) -> Any:
        """无符号小于等于。"""
        return self.z3.ULE(lhs, rhs)

    def bv_uge(self, lhs: Any, rhs: Any) -> Any:
        """无符号大于等于。"""
        return self.z3.UGE(lhs, rhs)

    def bv_slt(self, lhs: Any, rhs: Any) -> Any: return lhs < rhs
    def bv_sgt(self, lhs: Any, rhs: Any) -> Any: return lhs > rhs
    def bv_sle(self, lhs: Any, rhs: Any) -> Any: return lhs <= rhs
    def bv_sge(self, lhs: Any, rhs: Any) -> Any: return lhs >= rhs

# 内存建模（Array 理论）

    def make_memory_array(self, name: str, addr_bits: int = 32, data_bits: int = 8) -> Any:
        """
        创建符号内存建模用的 Array: Array(address_bitvec, data_bitvec),
        字节级内存。

        # 设计策略: Array 理论比 ITE 链更精确
        # 但 Z3 的数组求解器在大规模存储操作下更慢
        # 小函数 (<100 次存储) 用 array 即可
        # 更大规模时考虑把"冷"内存页具体化
        """
        addr_sort = self.z3.BitVecSort(addr_bits)
        data_sort = self.z3.BitVecSort(data_bits)
        return self.z3.Array(name, addr_sort, data_sort)

    def array_select(self, arr: Any, idx: Any) -> Any:
        """读数组: arr[idx], O(1) Z3 项构造。"""
        return self.z3.Select(arr, idx)

    def array_store(self, arr: Any, idx: Any, val: Any) -> Any:
        """写数组: Store(arr, idx, val), 创建新的 SSA 数组, O(1)。"""
        return self.z3.Store(arr, idx, val)

# 工具方法

    def bool_to_bv(self, cond: Any) -> Any:
        """把 Bool 转为 BitVec(1): If(cond, 1, 0)。"""
        return self.z3.If(cond, self.make_const(1, 1), self.make_const(0, 1))

    def bv_to_bool(self, bv: Any) -> Any:
        """把 BitVec(1) 转为 Bool: bv == 1。"""
        return bv == self.make_const(1, bv.size() if hasattr(bv, 'size') else 1)

    def concat(self, hi: Any, lo: Any) -> Any:
        """拼接两个 BitVec: Concat(hi, lo)。"""
        return self.z3.Concat(hi, lo)

    def extract(self, bv: Any, high: int, low: int) -> Any:
        """提取 BitVec 的 [high:low] 位。"""
        return self.z3.Extract(high, low, bv)


# ConstraintSolver

class ConstraintSolver:
    """
    带 Z3 后端与具体值回退的约束求解器。

    设计:
    - Z3 可用时使用带可配置超时的 z3.Solver()
    - Z3 不可用时回退到具体值模式, 支持基于字典的简单整数
      比较约束, 使单元测试能在无 Z3 环境下跑通基本流程

    超时处理: z3.Solver.set("timeout", N) 对 SAT 调用生效,
    超时结果按不可解处理 (安全下近似)。

    权衡: 具体值模式 sound 但不完整 — 无法求解符号变量,
    适合测试与目标值在分析期已知的场景。
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
        """惰性初始化带超时/内存配置的 Z3 solver。"""
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
                    pass  # 部分 Z3 版本不支持 max_memory
        return self._z3_solver

    def solve(self, constraints: List[Any], target_var: str) -> Optional[int]:
        """
        求解约束, 得到 target_var 的具体值。

        constraints 为约束字典列表或 Z3 BoolRef; 可满足时返回
        具体整数值, 否则返回 None。

        # Z3 旧版 workaround: 无符号 BV 会返回负值，提取时取模掩码
        # 后续版本修复后可删
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
        检查约束集是否可满足。

        用于路径剪枝的核心谓词: 某路径的约束 UNSAT 则该路径
        不可行, 应被剪除。边界情况: 空约束列表平凡可满足。
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
            return True  # 安全过近似: 假设可满足
        except Exception as e:
            _log.error("Solver error in is_satisfiable: %s", e)
            return True  # 安全过近似

    def simplify(self, expr: Any) -> Any:
        """
        用 Z3 内置化简器化简表达式。

        # 注意: Z3 的 simplify() 是启发式的，不保证最简形式
        # 但通常对大多数场景足够
        """
        if not has_z3():
            return expr  # 无 Z3 时的具体值模式
        import z3  # noqa: F811
        try:
            return z3.simplify(expr)
        except Exception:
            return expr

    def model_to_dict(self, z3_model: Any) -> Dict[str, Any]:
        """把 Z3 模型的变量绑定提取为普通字典, 键为变量名。"""
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
        """从 Z3 模型提取单个变量的值, 无匹配时返回 None。"""
        try:
            for decl in model.decls():
                if decl.name() == var_name:
                    val = model[decl]
                    if hasattr(val, 'as_long'):
                        raw = val.as_long()
                        # 32 位掩码保持一致性
                        return raw & 0xFFFFFFFF
                    return None
        except Exception:
            pass
        return None

    def _constraints_to_z3(self, constraints: List[Any]) -> List[Any]:
        """
        把约束字典列表或 Z3 表达式转为 Z3 BoolRef 列表。

        约束字典格式: {"type": "eq"|"neq"|"lt"|"gt"|"le"|"ge"|"and"|"or",
        "var": str, "value": int, ...}, 转换单条 O(1)。
        """
        import z3  # noqa: F811
        bld = self.builder
        result = []
        for c in constraints:
            if hasattr(c, 'decl'):
                # Z3 表达式直接使用
                result.append(c)
            elif isinstance(c, dict):
                z3_expr = self._dict_to_z3(bld, c)
                if z3_expr is not None:
                    result.append(z3_expr)
        return result

    def _dict_to_z3(self, bld: Z3ExpressionBuilder, c: Dict[str, Any]) -> Optional[Any]:
        """把约束字典转为 Z3 BoolRef, O(1)。"""
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
                return bld.z3.And(*z3_children)
            return None
        elif typ == "or":
            children = c.get("children", [])
            z3_children = [self._dict_to_z3(bld, ch) for ch in children]
            z3_children = [x for x in z3_children if x is not None]
            if z3_children:
                return bld.z3.Or(*z3_children)
            return None
        return None

# 具体值回退

    def _solve_concrete_only(self, constraints: List[Any], target_var: str) -> Optional[int]:
        """
        具体值模式求解 (无 Z3)。

        仅支持简单的 eq/neq 整数值; 约束一致时返回该值,
        否则返回 None。

        # 这是严重受限的子集 — 完整符号求解请安装 Z3:
        # pip install z3-solver
        """
        target_val = None
        for c in constraints:
            if not isinstance(c, dict):
                continue
            if c.get("var") == target_var:
                if c.get("type") == "eq":
                    candidate = c.get("value")
                    if target_val is not None and target_val != candidate:
                        return None  # 矛盾
                    target_val = candidate
                elif c.get("type") == "neq":
                    candidate = c.get("value")
                    if target_val == candidate:
                        return None  # 矛盾
        return target_val

    def _is_satisfiable_concrete(self, constraints: List[Any]) -> bool:
        """具体值模式的可满足性检查, 发现矛盾返回 False。"""
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


def simplify_expression_ast(expr_tree: dict) -> dict:
    """用局部规则化简符号表达式 AST。

    与 Z3 无关的化简, 作为离线模式下的回退; 目前支持
    const op const 的常量折叠。
    """
    if not isinstance(expr_tree, dict):
        return expr_tree
    typ = expr_tree.get("type", "")
    # 常量折叠: const op const
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
    "simplify_expression_ast",
]
