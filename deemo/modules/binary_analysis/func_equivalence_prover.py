import logging
import os
import re
import json
import time
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)

try:
    import z3
    Z3_AVAILABLE = True
except ImportError:
    Z3_AVAILABLE = False


class EquivalenceResult(str, Enum):
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
    counterexample: Optional[Dict] = None
    elapsed_ms: float = 0.0
    input_range: Optional[Dict[str, int]] = None
    notes: str = ""


@dataclass
class FunctionSemantics:
    name: str
    params: List = field(default_factory=list)
    returns: str = "result"
    output_exprs: List = field(default_factory=list)
    side_effects: List = field(default_factory=list)
    preconditions: List = field(default_factory=list)
    postconditions: List = field(default_factory=list)
    source: str = ""

class SMTEquivalenceProver:

    def __init__(self, timeout_ms: int = 10000):
        self.timeout_ms = timeout_ms
        self.solver = z3.Solver() if Z3_AVAILABLE else None
        if self.solver is not None:
            self.solver.set("timeout", timeout_ms)

    def _bitvec(self, name: str, bits: int):
        return z3.BitVec(name, bits)

    def prove(self, a: FunctionSemantics, b: FunctionSemantics,
               input_range: Optional[Dict[str, int]] = None) -> EquivalenceProof:
        start = time.time()
        if not Z3_AVAILABLE:
            return EquivalenceProof(
                function_a=a.name, function_b=b.name,
                result=EquivalenceResult.UNKNOWN,
                notes="Z3 unavailable, cannot prove",
                elapsed_ms=(time.time() - start) * 1000
            )
        if set(a.params) != set(b.params):
            return EquivalenceProof(
                function_a=a.name, function_b=b.name,
                result=EquivalenceResult.NOT_EQUIVALENT,
                notes="Parameter lists differ",
                elapsed_ms=(time.time() - start) * 1000
            )
        if not a.output_exprs or not b.output_exprs:
            return EquivalenceProof(
                function_a=a.name, function_b=b.name,
                result=EquivalenceResult.UNKNOWN,
                notes="Missing output expressions",
                elapsed_ms=(time.time() - start) * 1000
            )

        bits = input_range.get("bits", 32) if input_range else 32
        syms_a = {p: self._bitvec(f"a_{p}", bits) for p in a.params}
        syms_b = {p: self._bitvec(f"b_{p}", bits) for p in b.params}

        constraints = []
        if input_range:
            for p, sym in syms_a.items():
                lo = input_range.get(f"{p}_lo", 0)
                hi = input_range.get(f"{p}_hi", (1 << bits) - 1)
                constraints.append(z3.UGE(sym, lo))
                constraints.append(z3.ULE(sym, hi))
                bsym = syms_b[p]
                constraints.append(z3.UGE(bsym, lo))
                constraints.append(z3.ULE(bsym, hi))

        try:
            out_a = self._eval_outputs(a.output_exprs, syms_a)
            out_b = self._eval_outputs(b.output_exprs, syms_b)
        except Exception as e:
            return EquivalenceProof(
                function_a=a.name, function_b=b.name,
                result=EquivalenceResult.ERROR,
                notes=f"Expression evaluation failed: {e}",
                elapsed_ms=(time.time() - start) * 1000
            )

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
                notes="Z3 found counterexample"
            )
        elif str(result) == "unsat":
            return EquivalenceProof(
                function_a=a.name, function_b=b.name,
                result=EquivalenceResult.EQUIVALENT,
                elapsed_ms=elapsed,
                input_range=input_range,
                notes="Z3 proved equivalence"
            )
        elif str(result) == "unknown":
            return EquivalenceProof(
                function_a=a.name, function_b=b.name,
                result=EquivalenceResult.TIMEOUT,
                elapsed_ms=elapsed,
                input_range=input_range,
                notes="Z3 solver timed out"
            )
        return EquivalenceProof(
            function_a=a.name, function_b=b.name,
            result=EquivalenceResult.UNKNOWN,
            elapsed_ms=elapsed,
            notes=str(result)
        )

    def _eval_outputs(self, exprs: List[str], syms: Dict[str, Any]):
        if len(exprs) != 1:
            exprs = exprs[:1]
        expr = exprs[0]
        return self._safe_eval(expr, syms)

    def _safe_eval(self, expr: str, syms: Dict[str, Any]):
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
                    out_stack.append(z3.BitVecVal(0, 32))
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
