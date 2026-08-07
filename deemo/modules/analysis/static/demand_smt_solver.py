"""按需SMT约束求解器 (Demand-Driven SMT Constraint Solver) — DDSSC核心模块.

核心决策:
  符号关联分析无法判定的告警("unknown"), 需要更强的分析能力.
  本模块在告警点构建路径约束 + 尺寸不等式, 通过Z3求解器验证
  溢出路径的可行性. 若路径不可达 → 误报; 若可达 → 确认溢出.

创建: 2026-07-24
"""

import logging
from typing import Dict, List, Optional, Tuple

from .sym_size_correlator import SymExpr
from .value_range import ValueRange
from .path_condition import PathConstraint, CondOp, JCC_TO_COND
from ._smt_path_collector import (PathConstraintCollector, _W32_TO_W64,
                                    _HAS_Z3, _SOLVER_TIMEOUT_MS)

try:
    from z3 import (BitVec, BitVecVal, Solver, sat, unsat, UGT,
                     ULT, UGE, ULE, And, BoolVal, simplify)
except ImportError:
    pass

logger = logging.getLogger(__name__)


class DemandDrivenSMTSolver:
    """按需SMT约束求解器.

    对符号关联分析无法判定的告警, 构建约束并求解.
    """

    def __init__(self):
        self._collector = PathConstraintCollector()
        self._z3_available = _HAS_Z3
        self._solve_count = 0
        self._unsat_count = 0
        self._sat_count = 0
        self._timeout_count = 0

    @property
    def z3_available(self) -> bool:
        return self._z3_available

    def verify_overflow(self, instructions: List[dict],
                        write_addr: int,
                        alloc_size_expr: Optional[SymExpr],
                        write_size_expr: Optional[SymExpr],
                        alloc_vr: Optional[ValueRange],
                        write_vr: Optional[ValueRange],
                        known_constants: Dict[str, int] = None
                        ) -> Tuple[str, str]:
        """验证溢出路径的可达性.

        返回: (判定类别, 判定依据)
        """
        self._solve_count += 1
        constants = known_constants or {}

        path_constraints = self._collector.collect(
            instructions, write_addr, constants)

        if not self._z3_available:
            size_reg = write_size_expr.var if write_size_expr else ""
            return self._degraded_check(
                alloc_vr, write_vr, path_constraints, size_reg)

        try:
            result = self._z3_solve(path_constraints,
                                    alloc_size_expr, write_size_expr,
                                    alloc_vr, write_vr)
            return result
        except Exception as e:
            logger.debug("Z3求解异常: %s, 退化为保守策略", e)
            return ("unknown", "smt_error")

    def _z3_solve(self, path_constraints: List[PathConstraint],
                  alloc_expr: Optional[SymExpr],
                  write_expr: Optional[SymExpr],
                  alloc_vr: Optional[ValueRange],
                  write_vr: Optional[ValueRange]) -> Tuple[str, str]:
        """Z3求解: 将alloc/write符号表达式编码为共享变量的约束."""
        bv_width = 64
        solver = Solver()
        solver.set("timeout", _SOLVER_TIMEOUT_MS)

        var_name = None
        if alloc_expr and alloc_expr.var:
            var_name = alloc_expr.var
        elif write_expr and write_expr.var:
            var_name = write_expr.var

        if var_name is None:
            if alloc_expr is None or write_expr is None:
                return ("unknown", "missing_expr")
            a_c = alloc_expr.const
            w_c = write_expr.const
            if w_c > a_c:
                self._sat_count += 1
                return ("confirmed", "const_overflow")
            self._unsat_count += 1
            return ("false_positive", "const_safe")

        param_bv = BitVec(var_name, bv_width)

        reg_to_param = {
            "rcx": "param_0", "rdx": "param_1",
            "r8": "param_2", "r9": "param_3",
        }

        if alloc_expr and alloc_expr.var == var_name:
            alloc_z3 = alloc_expr.coeff * param_bv + \
                BitVecVal(alloc_expr.const, bv_width)
        elif alloc_expr and alloc_expr.is_const():
            alloc_z3 = BitVecVal(alloc_expr.const, bv_width)
        else:
            return ("unknown", "no_shared_var_alloc")

        if write_expr and write_expr.var == var_name:
            write_z3 = write_expr.coeff * param_bv + \
                BitVecVal(write_expr.const, bv_width)
        elif write_expr and write_expr.is_const():
            write_z3 = BitVecVal(write_expr.const, bv_width)
        else:
            return ("unknown", "no_shared_var_write")

        overflow_cond = UGT(write_z3, alloc_z3)

        path_conds = []
        for pc in path_constraints:
            pc_reg = pc.reg
            mapped = reg_to_param.get(pc_reg)
            if mapped == var_name:
                bv = param_bv
            elif mapped:
                bv = BitVec(mapped, bv_width)
            elif "[" not in pc_reg and "qword" not in pc_reg and "dword" not in pc_reg:
                bv = BitVec(pc_reg, bv_width)
            else:
                continue
            val_bv = BitVecVal(pc.value, bv_width)
            cond = self._z3_cond(pc.op, bv, val_bv)
            if cond is not None:
                path_conds.append(cond)

        range_conds = []
        if alloc_vr and not alloc_vr.is_bottom:
            if alloc_expr and alloc_expr.var == var_name:
                range_conds.append(UGE(param_bv, BitVecVal(alloc_vr.lo, bv_width)))
                range_conds.append(ULE(param_bv, BitVecVal(alloc_vr.hi, bv_width)))
        if write_vr and not write_vr.is_bottom:
            if write_expr and write_expr.var == var_name:
                range_conds.append(UGE(param_bv, BitVecVal(write_vr.lo, bv_width)))
                range_conds.append(ULE(param_bv, BitVecVal(write_vr.hi, bv_width)))

        all_conds = path_conds + range_conds + [overflow_cond]
        if all_conds:
            solver.add(And(*all_conds))

        check_result = solver.check()
        if check_result == sat:
            self._sat_count += 1
            return ("confirmed", "smt_sat")
        elif check_result == unsat:
            self._unsat_count += 1
            return ("false_positive", "smt_unsat")
        else:
            self._timeout_count += 1
            return ("unknown", "smt_timeout")

    @staticmethod
    def _z3_cond(op: CondOp, lhs, rhs):
        """将CondOp转换为Z3约束."""
        mapping = {
            CondOp.EQ: lambda a, b: a == b,
            CondOp.NE: lambda a, b: a != b,
            CondOp.LT: ULT, CondOp.LE: ULE,
            CondOp.GT: UGT, CondOp.GE: UGE,
            CondOp.BELOW: ULT, CondOp.BELOW_EQ: ULE,
            CondOp.ABOVE: UGT, CondOp.ABOVE_EQ: UGE,
        }
        fn = mapping.get(op)
        if fn is None:
            return None
        return fn(lhs, rhs)

    def _degraded_check(self, alloc_vr: Optional[ValueRange],
                        write_vr: Optional[ValueRange],
                        path_constraints: List[PathConstraint] = None,
                        size_reg: str = "") -> Tuple[str, str]:
        """退化方案: 无Z3时用路径约束窄化区间推理."""
        if alloc_vr is None or write_vr is None:
            return ("unknown", "degraded_no_range")
        if alloc_vr.is_bottom or write_vr.is_bottom:
            return ("unknown", "degraded_bottom")

        alloc_lo, alloc_hi = alloc_vr.lo, alloc_vr.hi
        write_lo, write_hi = write_vr.lo, write_vr.hi

        if path_constraints and size_reg:
            norm = self._norm_reg_static(size_reg)
            for pc in path_constraints:
                if "[" in pc.reg or "qword" in pc.reg or "dword" in pc.reg:
                    continue
                if pc.reg == norm:
                    write_lo, write_hi = pc.narrow(write_lo, write_hi)

        if write_hi <= alloc_lo:
            return ("false_positive", "degraded_range_safe")
        if write_lo > alloc_hi:
            return ("confirmed", "degraded_range_overflow")
        return ("unknown", "degraded_overlap")

    @staticmethod
    def _norm_reg_static(reg: str) -> str:
        r = reg.strip().lower().lstrip("%").replace("$", "")
        return _W32_TO_W64.get(r, r)

    @property
    def stats(self) -> dict:
        return {
            "total_solves": self._solve_count,
            "sat": self._sat_count,
            "unsat": self._unsat_count,
            "timeout_or_error": self._timeout_count,
            "z3_available": self._z3_available,
        }


__all__ = ["DemandDrivenSMTSolver", "PathConstraintCollector"]
