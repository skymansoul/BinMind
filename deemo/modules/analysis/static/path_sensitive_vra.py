# 路径敏感的值范围分析器 (Path-Sensitive Value Range Analyzer)
#
# 核心决策:
#   标准抽象解释在分支合并点用join丢失路径条件信息.
#   本模块在cmp+jcc分支处提取路径约束, 在危险调用点前
#   检查路径条件是否可将写入大小窄化到安全范围.
#
# 理论依据:
#   选择性路径枚举平衡精度与效率; 分支条件窄化消除系统性误报.
#

from typing import Dict, List, Optional, Tuple

from .value_range import ValueRange
from .value_range_analyzer import ValueRangeAnalyzer
from .path_condition import PathConstraint, CondOp, JCC_TO_COND


# 需要窄化的关键函数: 大小参数经过bounds check后才安全
_CRITICAL_FUNCS = {"malloc", "calloc", "realloc", "memcpy", "memmove",
                   "strncpy", "snprintf", "read", "fread", "recv"}

# 32→64 bit 归一化
_W32_TO_W64 = {
    "eax":"rax","ebx":"rbx","ecx":"rcx","edx":"rdx",
    "esi":"rsi","edi":"rdi","r8d":"r8","r9d":"r9",
    "r10d":"r10","r11d":"r11","r12d":"r12","r13d":"r13",
    "r14d":"r14","r15d":"r15",
}


class PathSensitiveVRA:
    """路径敏感的值范围分析器.

    不枚举全部路径, 而是针对到达危险调用点的单条路径,
    查找该路径上的cmp+jcc分支条件, 应用约束窄化.
    """

    def __init__(self):
        self._known_constants: Dict[str, int] = {}

    def set_constants(self, constants: Dict[str, int]):
        self._known_constants.update(constants)

    def narrow_for_bounds_check(self, instructions: List[dict],
                                 call_addr: int,
                                 size_reg: str) -> Optional[ValueRange]:
        """若到达call_addr的路径上存在bounds check, 返回窄化后的区间.

        典型模式:
          cmp rcx, 256
          ja  .error_handler    ← 溢出路径: 不窄化
          mov rdi, rcx          ← 安全路径: rcx ∈ [0, 256]
          call malloc           ← 分配大小 ∈ [0, 256]

        返回: 窄化后的ValueRange, 或None (无有效bounds check).
        """
        if not instructions:
            return None

        norm_target = self._norm_reg(size_reg)
        branch_points = self._find_branches_before(instructions, call_addr)

        best = None
        for bp in branch_points:
            cmp_ins = instructions[bp["cmp_idx"]]
            jcc_ins = instructions[bp["jcc_idx"]]
            ops = cmp_ins.get("operands", [])

            if len(ops) < 2:
                continue
            cmp_reg = self._norm_reg(ops[0])
            if cmp_reg != norm_target:
                # 也检查: cmp reg, reg → 两个操作数都检查
                cmp_reg2 = self._norm_reg(ops[1])
                if cmp_reg2 != norm_target:
                    continue
                # 交换: 约束在 ops[0] 上
                cmp_val = self._parse_imm(ops[0])
                swapped = True
            else:
                cmp_val = self._parse_imm(ops[1])
                swapped = False

            if cmp_val is None:
                continue

            cond = JCC_TO_COND.get(jcc_ins.get("mnemonic","").lower())
            if cond is None:
                continue

            jcc_addr = jcc_ins.get("address", 0)
            target_addr = self._extract_jump_target(jcc_ins)
            fallthrough = self._get_fallthrough(instructions, bp["jcc_idx"])

            # 确定哪条路径通向 call_addr
            goes_to_call = None
            if target_addr and target_addr <= call_addr:
                goes_to_call = "taken"
            if fallthrough and fallthrough <= call_addr:
                goes_to_call = "fallthrough"
            if goes_to_call is None:
                continue

            # 构建该路径上的约束
            constraint = PathConstraint(
                reg=norm_target if not swapped else self._norm_reg(ops[0]),
                op=cond, value=cmp_val, ins_addr=jcc_addr)

            if goes_to_call == "fallthrough":
                constraint = constraint.negate()  # 未跳转 = 条件为false
            # taken路径: 条件为true, 直接使用

            narrowed = constraint.narrow(0, 2**31 - 1)
            vr = ValueRange(max(narrowed[0], 0), narrowed[1])
            if best is None or vr.span < best.span:
                best = vr

        return best

    def check_safety(self, instructions: List[dict],
                     call_addr: int, size_reg: str,
                     alloc_size: int) -> bool:
        """检查在call_addr处, size_reg的值是否可窄化到 ≤ alloc_size.

        返回 True 表示安全 (被bounds check保护).
        """
        narrowed = self.narrow_for_bounds_check(
            instructions, call_addr, size_reg)
        if narrowed and narrowed.hi <= alloc_size:
            return True
        return False

    def _find_branches_before(self, instructions: List[dict],
                               target_addr: int) -> List[dict]:
        """找到 target_addr 之前的所有 cmp+jcc 分支点."""
        branches = []
        for i, ins in enumerate(instructions):
            if ins.get("address", 0) >= target_addr:
                break
            mnem = ins.get("mnemonic", "").lower()
            if mnem in ("cmp", "test"):
                for j in range(i + 1, min(i + 5, len(instructions))):
                    next_ins = instructions[j]
                    if next_ins.get("mnemonic","").lower() in JCC_TO_COND:
                        branches.append({
                            "cmp_idx": i, "jcc_idx": j,
                            "cmp_addr": ins.get("address", 0),
                            "jcc_addr": next_ins.get("address", 0),
                            "cmp_mnem": mnem,
                            "jcc_mnem": next_ins.get("mnemonic","").lower(),
                            "cmp_ops": ins.get("operands", []),
                        })
                        break
        return branches

    @staticmethod
    def _get_fallthrough(instructions: List[dict], jcc_idx: int) -> int:
        if jcc_idx + 1 < len(instructions):
            return instructions[jcc_idx + 1].get("address", 0)
        return 0

    @staticmethod
    def _norm_reg(reg: str) -> str:
        r = reg.strip().lower().lstrip("%").replace("$", "")
        if "[" in r:
            return r
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
        try:
            if target.startswith("0x"):
                return int(target, 16)
            return int(target)
        except ValueError:
            return None

    def reset(self):
        self._known_constants.clear()


__all__ = ["PathSensitiveVRA"]
