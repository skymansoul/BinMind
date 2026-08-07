# 路径约束收集器.
# 从指令序列中收集到达目标地址的路径约束.
# 创建: 2026-04-23

from typing import Dict, List, Optional, Tuple

from .sym_size_correlator import SymExpr
from .value_range import ValueRange
from .path_condition import PathConstraint, CondOp, JCC_TO_COND

try:
    from z3 import (BitVec, BitVecVal, Solver, sat, unsat, UGT,
                     ULT, UGE, ULE, And, BoolVal, simplify)
    _HAS_Z3 = True
except ImportError:
    _HAS_Z3 = False

_W32_TO_W64 = {
    "eax": "rax", "ebx": "rbx", "ecx": "rcx", "edx": "rdx",
    "esi": "rsi", "edi": "rdi", "r8d": "r8", "r9d": "r9",
}

_STACK_SLOT_TO_REG = {
    "qword ptr [rbp+0x10]": "rcx",
    "qword ptr [rbp+0x18]": "rdx",
    "qword ptr [rbp+0x20]": "r8",
    "qword ptr [rbp+0x28]": "r9",
    "dword ptr [rbp+0x10]": "ecx",
    "dword ptr [rbp+0x18]": "edx",
    "dword ptr [rbp+0x20]": "r8d",
    "dword ptr [rbp+0x28]": "r9d",
}

_MAX_CONSTRAINTS = 50
_SOLVER_TIMEOUT_MS = 2000


class PathConstraintCollector:
    """从指令序列中收集到达目标地址的路径约束."""

    def __init__(self):
        self._constraints: List[PathConstraint] = []

    def collect(self, instructions: List[dict],
                target_addr: int,
                known_constants: Dict[str, int] = None
                ) -> List[PathConstraint]:
        """收集 target_addr 所在函数内、从函数入口到 target_addr 的路径约束."""
        self._constraints = []
        constants = known_constants or {}

        func_start_idx = 0
        for i in range(len(instructions) - 1, -1, -1):
            addr = instructions[i].get("address", 0)
            if addr > target_addr:
                continue
            mnem = instructions[i].get("mnemonic", "").lower()
            if mnem == "ret" and i + 1 < len(instructions):
                next_addr = instructions[i + 1].get("address", 0)
                if next_addr <= target_addr:
                    func_start_idx = i + 1
                    break

        for i in range(func_start_idx, len(instructions)):
            ins = instructions[i]
            addr = ins.get("address", 0)
            if addr >= target_addr:
                break
            mnem = ins.get("mnemonic", "").lower()
            ops = ins.get("operands", [])

            if mnem == "call":
                continue
            if mnem not in ("cmp", "test"):
                continue

            jcc = self._find_next_jcc(instructions, i, target_addr)
            if jcc is None:
                continue

            jcc_ins, jcc_idx, jcc_mnem = jcc
            cond = JCC_TO_COND.get(jcc_mnem)
            if cond is None:
                continue

            reg = self._norm_reg(ops[0]) if ops else ""
            cmp_val = self._parse_imm(ops[1]) if len(ops) >= 2 else None

            if cmp_val is None or not reg:
                continue

            jcc_addr = jcc_ins.get("address", 0)
            target = self._extract_jump_target(jcc_ins)
            fallthrough = self._get_fallthrough(instructions, jcc_idx)

            goes_to_target = None
            if target is not None and target <= target_addr:
                goes_to_target = "taken"
            elif fallthrough and fallthrough <= target_addr:
                goes_to_target = "fallthrough"

            if goes_to_target is None:
                continue

            pc = PathConstraint(reg=reg, op=cond, value=cmp_val,
                                ins_addr=jcc_addr)
            if goes_to_target == "fallthrough":
                pc = pc.negate()

            self._constraints.append(pc)

            if len(self._constraints) >= _MAX_CONSTRAINTS:
                break

        return self._constraints

    @staticmethod
    def _find_next_jcc(instructions: List[dict], cmp_idx: int,
                       target_addr: int) -> Optional[Tuple[dict, int, str]]:
        for j in range(cmp_idx + 1, min(cmp_idx + 5, len(instructions))):
            ins = instructions[j]
            if ins.get("address", 0) >= target_addr:
                break
            mnem = ins.get("mnemonic", "").lower()
            if mnem in JCC_TO_COND:
                return (ins, j, mnem)
        return None

    @staticmethod
    def _get_fallthrough(instructions: List[dict], jcc_idx: int) -> int:
        if jcc_idx + 1 < len(instructions):
            return instructions[jcc_idx + 1].get("address", 0)
        return 0

    @staticmethod
    def _norm_reg(reg: str) -> str:
        r = reg.strip().lower().lstrip("%").replace("$", "").split("#")[0].strip()
        if r in _STACK_SLOT_TO_REG:
            mapped = _STACK_SLOT_TO_REG[r]
            return _W32_TO_W64.get(mapped, mapped)
        return _W32_TO_W64.get(r, r)

    @staticmethod
    def _parse_imm(op: str) -> Optional[int]:
        s = op.strip().lower().replace("$", "").split("#")[0].strip()
        try:
            if s.startswith("0x"):
                return int(s, 16)
            if s.isdigit() or (s.startswith("-") and s[1:].isdigit()):
                return int(s)
        except ValueError:
            pass
        return None

    @staticmethod
    def _extract_jump_target(ins: dict) -> Optional[int]:
        ops = ins.get("operands", [])
        if not ops:
            return None
        target = ops[0].strip().lower().lstrip("%").replace("$", "")
        target = target.split("<")[0].strip()
        try:
            if target.startswith("0x"):
                return int(target, 16)
            return int(target, 16)
        except ValueError:
            return None
