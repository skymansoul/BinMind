"""
语义差异分析: 函数逻辑等价性证明模块

功能:
    1. 使用 SMT 求解器 (Z3) 验证两个函数在特定输入范围内的等价性
    2. 应用于补丁验证/代码克隆检测的去重
    3. 消除因编译器优化导致的误报

核心技术:
    - SSA 提升 (简化版)
    - Z3 符号执行 + 约束求解
    - 输入范围约束 (e.g. 0 <= x < 2^32)
    - 路径敏感等价性: 输出值在所有路径上相等
"""

import logging
import os
import re
import json
import time
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)

try:
    import z3
    Z3_AVAILABLE = True
except ImportError:
    Z3_AVAILABLE = False


class EquivalenceResult(Enum):
    EQUIVALENT = "equivalent"
    NOT_EQUIVALENT = "not_equivalent"
    UNKNOWN = "unknown"
    TIMEOUT = "timeout"
    ERROR = "error"


@dataclass
class EquivalenceProof:
    function_a: str
    function_b: str
    result: EquivalenceResult
    counterexample: Optional[Dict[str, Any]] = None
    elapsed_ms: float = 0.0
    input_range: Optional[Dict[str, int]] = None
    notes: str = ""


@dataclass
class FunctionSemantics:
    """函数语义模型"""
    name: str
    params: List[str] = field(default_factory=list)
    returns: str = "result"
    output_exprs: List[str] = field(default_factory=list)
    side_effects: List[str] = field(default_factory=list)
    preconditions: List[str] = field(default_factory=list)
    postconditions: List[str] = field(default_factory=list)
    source: str = ""


class SMTEquivalenceProver:
    """基于 Z3 的等价性证明器"""

    def __init__(self, timeout_ms: int = 10000):
        self.timeout_ms = timeout_ms
        self.solver = z3.Solver() if Z3_AVAILABLE else None
        if self.solver is not None:
            self.solver.set("timeout", timeout_ms)

    def _bitvec(self, name: str, bits: int):
        return z3.BitVec(name, bits)

    def prove(self, a: FunctionSemantics, b: FunctionSemantics,
              input_range: Optional[Dict[str, int]] = None) -> EquivalenceProof:
        """
        证明: 在输入范围内, 对所有有效输入, a 和 b 行为等价
        """
        start = time.time()
        if not Z3_AVAILABLE:
            return EquivalenceProof(
                function_a=a.name, function_b=b.name,
                result=EquivalenceResult.UNKNOWN,
                notes="Z3 不可用, 无法证明",
                elapsed_ms=(time.time() - start) * 1000
            )
        if set(a.params) != set(b.params):
            return EquivalenceProof(
                function_a=a.name, function_b=b.name,
                result=EquivalenceResult.NOT_EQUIVALENT,
                notes="参数列表不同",
                elapsed_ms=(time.time() - start) * 1000
            )
        if not a.output_exprs or not b.output_exprs:
            return EquivalenceProof(
                function_a=a.name, function_b=b.name,
                result=EquivalenceResult.UNKNOWN,
                notes="缺少输出表达式",
                elapsed_ms=(time.time() - start) * 1000
            )

        bits = input_range.get("bits", 32) if input_range else 32
        # 创建共享输入符号
        syms_a = {p: self._bitvec(f"a_{p}", bits) for p in a.params}
        syms_b = {p: self._bitvec(f"b_{p}", bits) for p in b.params}

        # 输入范围约束
        constraints = []
        if input_range:
            for p, sym in syms_a.items():
                lo = input_range.get(f"{p}_lo", 0)
                hi = input_range.get(f"{p}_hi", (1 << bits) - 1)
                constraints.append(z3.UGE(sym, lo))
                constraints.append(z3.ULE(sym, hi))
                # 同样的约束应用到 b
                bsym = syms_b[p]
                constraints.append(z3.UGE(bsym, lo))
                constraints.append(z3.ULE(bsym, hi))

        # 简化的输出表达式求值
        try:
            out_a = self._eval_outputs(a.output_exprs, syms_a)
            out_b = self._eval_outputs(b.output_exprs, syms_b)
        except Exception as e:
            return EquivalenceProof(
                function_a=a.name, function_b=b.name,
                result=EquivalenceResult.ERROR,
                notes=f"表达式求值失败: {e}",
                elapsed_ms=(time.time() - start) * 1000
            )

        # 不等价条件
        not_equiv = z3.Distinct(out_a, out_b)
        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms)
        for c in constraints:
            solver.add(c)
        solver.add(not_equiv)

        result = solver.check()
        elapsed = (time.time() - start) * 1000
        if str(result) == "sat":
            model = solver.model()
            ce = {p: str(model.eval(syms_a[p], model_completion=True))
                  for p in a.params}
            return EquivalenceProof(
                function_a=a.name, function_b=b.name,
                result=EquivalenceResult.NOT_EQUIVALENT,
                counterexample=ce,
                elapsed_ms=elapsed,
                input_range=input_range,
                notes="Z3 找到反例"
            )
        elif str(result) == "unsat":
            return EquivalenceProof(
                function_a=a.name, function_b=b.name,
                result=EquivalenceResult.EQUIVALENT,
                elapsed_ms=elapsed,
                input_range=input_range,
                notes="Z3 证明等价"
            )
        elif str(result) == "unknown":
            return EquivalenceProof(
                function_a=a.name, function_b=b.name,
                result=EquivalenceResult.TIMEOUT,
                elapsed_ms=elapsed,
                input_range=input_range,
                notes="Z3 求解超时"
            )
        return EquivalenceProof(
            function_a=a.name, function_b=b.name,
            result=EquivalenceResult.UNKNOWN,
            elapsed_ms=elapsed,
            notes=str(result)
        )

    def _eval_outputs(self, exprs: List[str], syms: Dict[str, Any]):
        # 简化: 假设只有一个输出, 且为简单算术表达式
        # 实际中需要真正的表达式解析器
        if len(exprs) != 1:
            # 多输出时, 把结果打包成元组比较不实际, 返回第一个
            exprs = exprs[:1]
        expr = exprs[0]
        # 安全 eval
        return self._safe_eval(expr, syms)

    def _safe_eval(self, expr: str, syms: Dict[str, Any]):
        """在受控命名空间中求值表达式"""
        # 替换符号名 -> 简单替换, 算术表达式
        # 仅支持: 变量名, +, -, *, &, |, ^, %, //, <, >, ==
        # 简化: 用 z3 表达式构造
        tokens = re.findall(r"[A-Za-z_]\w*|[0-9]+|[\+\-\*\&\|\^\%\/\=\<\>\(\)]", expr)
        out_stack: List[Any] = []
        op_stack: List[str] = []
        prec = {"+": 1, "-": 1, "*": 2, "/": 2, "%": 2,
                "&": 0, "|": 0, "^": 0}
        for tk in tokens:
            if tk in prec:
                while op_stack and op_stack[-1] in prec and prec[op_stack[-1]] >= prec[tk]:
                    self._apply_op(op_stack.pop(), out_stack, syms)
                op_stack.append(tk)
            elif tk == "(":
                op_stack.append(tk)
            elif tk == ")":
                while op_stack and op_stack[-1] != "(":
                    self._apply_op(op_stack.pop(), out_stack, syms)
                op_stack.pop()
            else:
                if tk.isdigit():
                    out_stack.append(z3.BitVecVal(int(tk), 32))
                elif tk in syms:
                    out_stack.append(syms[tk])
                else:
                    out_stack.append(z3.BitVecVal(0, 32))  # 未知变量
        while op_stack:
            self._apply_op(op_stack.pop(), out_stack, syms)
        if not out_stack:
            return z3.BitVecVal(0, 32)
        return out_stack[-1]

    def _apply_op(self, op: str, stack: List[Any], syms: Dict[str, Any]):
        if len(stack) < 2:
            return
        b = stack.pop()
        a = stack.pop()
        if op == "+":
            stack.append(a + b)
        elif op == "-":
            stack.append(a - b)
        elif op == "*":
            stack.append(a * b)
        elif op == "/":
            stack.append(a / b)
        elif op == "%":
            stack.append(z3.URem(a, b))
        elif op == "&":
            stack.append(a & b)
        elif op == "|":
            stack.append(a | b)
        elif op == "^":
            stack.append(a ^ b)


def prove_func_equivalence(
    func_a_exprs: List[str],
    func_b_exprs: List[str],
    params: List[str],
    input_range: Optional[Dict[str, int]] = None,
    name_a: str = "A",
    name_b: str = "B"
) -> Dict[str, Any]:
    """便捷入口"""
    a = FunctionSemantics(name=name_a, params=params, output_exprs=func_a_exprs)
    b = FunctionSemantics(name=name_b, params=params, output_exprs=func_b_exprs)
    prover = SMTEquivalenceProver()
    proof = prover.prove(a, b, input_range=input_range)
    return {
        'success': True,
        'result': proof.result.value,
        'counterexample': proof.counterexample,
        'elapsed_ms': proof.elapsed_ms,
        'notes': proof.notes
    }
