# 路径条件追踪与约束窄化 (Path Condition Tracking & Narrowing)
#
# 核心决策:
# 堆溢出误报的最大单一来源 - 值范围分析在分支合并点用join丢弃
#   路径条件. 例如: cmp rcx,256; ja .error → 安全路径上rcx≤256,
#   但标准抽象解释无法捕获此信息, 将rcx保持为[0, 2^31-1].
#
#   本模块在控制流分支处捕获cmp+jcc条件, 沿每条路径独立传播
#   窄化后的区间. 合并时不再用join, 而是记录路径谓词并在危险点
#   前检查谓词可满足性.
#
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple


class CondOp(Enum):
    """条件运算符, 对应 x86-64 条件跳转."""
    EQ = 1   # je/jz: ==
    NE = 2   # jne/jnz: !=
    LT = 3   # jl/jnge: < (signed)
    LE = 4   # jle/jng: <= (signed)
    GT = 5   # jg/jnle: > (signed)
    GE = 6   # jge/jnl: >= (signed)
    BELOW = 7     # jb/jnae/jc: < (unsigned)
    BELOW_EQ = 8  # jbe/jna: <= (unsigned)
    ABOVE = 9     # ja/jnbe: > (unsigned)
    ABOVE_EQ = 10 # jae/jnb/jnc: >= (unsigned)


# x86-64 条件跳转 → 条件运算符 映射
JCC_TO_COND = {
    "je": CondOp.EQ, "jz": CondOp.EQ,
    "jne": CondOp.NE, "jnz": CondOp.NE,
    "jl": CondOp.LT, "jnge": CondOp.LT,
    "jle": CondOp.LE, "jng": CondOp.LE,
    "jg": CondOp.GT, "jnle": CondOp.GT,
    "jge": CondOp.GE, "jnl": CondOp.GE,
    "jb": CondOp.BELOW, "jnae": CondOp.BELOW, "jc": CondOp.BELOW,
    "jbe": CondOp.BELOW_EQ, "jna": CondOp.BELOW_EQ,
    "ja": CondOp.ABOVE, "jnbe": CondOp.ABOVE,
    "jae": CondOp.ABOVE_EQ, "jnb": CondOp.ABOVE_EQ, "jnc": CondOp.ABOVE_EQ,
}


@dataclass
class PathConstraint:
    """单条路径约束: 寄存器 op 常量/寄存器."""
    reg: str          # 受约束的寄存器名 (归一化后)
    op: CondOp         # 比较运算符
    value: int         # 比较常量 (仅支持 reg op const)
    ins_addr: int      # 产生此约束的指令地址

    def narrow(self, lo: int, hi: int) -> Tuple[int, int]:
        """根据约束窄化区间 [lo, hi], 返回窄化后的 (lo, hi)."""
        v = self.value
        if self.op == CondOp.EQ:
            return (max(lo, v), min(hi, v))
        if self.op == CondOp.NE:
            return (lo, hi)  # != 不能窄化区间
        if self.op == CondOp.LT:
            return (lo, min(hi, v - 1))
        if self.op == CondOp.LE:
            return (lo, min(hi, v))
        if self.op == CondOp.GT:
            return (max(lo, v + 1), hi)
        if self.op == CondOp.GE:
            return (max(lo, v), hi)
        if self.op == CondOp.BELOW:
            return (lo, min(hi, v - 1))
        if self.op == CondOp.BELOW_EQ:
            return (lo, min(hi, v))
        if self.op == CondOp.ABOVE:
            return (max(lo, v + 1), hi)
        if self.op == CondOp.ABOVE_EQ:
            return (max(lo, v), hi)
        return (lo, hi)

    def negate(self) -> "PathConstraint":
        """返回此约束的否定形式."""
        neg_map = {
            CondOp.EQ: CondOp.NE, CondOp.NE: CondOp.EQ,
            CondOp.LT: CondOp.GE, CondOp.LE: CondOp.GT,
            CondOp.GT: CondOp.LE, CondOp.GE: CondOp.LT,
            CondOp.BELOW: CondOp.ABOVE_EQ, CondOp.BELOW_EQ: CondOp.ABOVE,
            CondOp.ABOVE: CondOp.BELOW_EQ, CondOp.ABOVE_EQ: CondOp.BELOW,
        }
        return PathConstraint(
            reg=self.reg, op=neg_map.get(self.op, self.op),
            value=self.value, ins_addr=self.ins_addr)

    def __repr__(self) -> str:
        op_str = {CondOp.EQ: "==", CondOp.NE: "!=", CondOp.LT: "<",
                  CondOp.LE: "<=", CondOp.GT: ">", CondOp.GE: ">=",
                  CondOp.BELOW: "<u", CondOp.BELOW_EQ: "<=u",
                  CondOp.ABOVE: ">u", CondOp.ABOVE_EQ: ">=u"}
        return f"{self.reg}{op_str.get(self.op,'?')}{self.value}"


class PathConditionTracker:
    """路径条件追踪器.

    在控制流分支处提取 cmp+jcc 条件, 沿各路径独立窄化值区间.
    """

    # 32→64 bit 寄存器归一化
    _W32_TO_W64 = {
        "eax":"rax","ebx":"rbx","ecx":"rcx","edx":"rdx",
        "esi":"rsi","edi":"rdi","r8d":"r8","r9d":"r9",
        "r10d":"r10","r11d":"r11","r12d":"r12","r13d":"r13",
        "r14d":"r14","r15d":"r15",
        "ax":"rax","bx":"rbx","cx":"rcx","dx":"rdx",
        "si":"rsi","di":"rdi",
    }

    def __init__(self):
        # 每个地址上的活跃路径约束集: addr → [PathConstraint, ...]
        self._addr_constraints: Dict[int, List[PathConstraint]] = {}
        # 前一条cmp/test的寄存器与比较值
        self._last_cmp_reg: Optional[str] = None
        self._last_cmp_val: Optional[int] = None
        self._last_cmp_addr: int = 0

    def feed_instruction(self, ins: dict):
        """逐指令馈入, 在cmp+jcc对处提取路径条件.

        此方法应在控制流分析循环中调用.
        返回: 若当前指令是条件跳转, 返回 (taken_constraint, fallthrough_constraint);
               否则返回 None.
        """
        mnem = ins.get("mnemonic", "").lower()
        ops = ins.get("operands", [])
        addr = ins.get("address", 0)

        # cmp 指令: 记录比较操作数
        if mnem in ("cmp", "test"):
            if len(ops) >= 2:
                reg = self._norm(ops[0])
                val = self._parse_imm(ops[1])
                if val is not None:
                    self._last_cmp_reg = reg
                    self._last_cmp_val = val
                    self._last_cmp_addr = addr
            return None

        # 条件跳转: 生成两个方向的路径约束
        if mnem in JCC_TO_COND and self._last_cmp_reg and self._last_cmp_val is not None:
            # 只在cmp与jcc之间无其他修改时才提取 (间距≤2指令)
            if addr - self._last_cmp_addr <= 30:
                cond = JCC_TO_COND[mnem]
                constraint = PathConstraint(
                    reg=self._last_cmp_reg, op=cond,
                    value=self._last_cmp_val, ins_addr=addr)
                return (constraint, constraint.negate())
        return None

    def apply_constraints(self, addr: int, lo: int, hi: int,
                          reg: str) -> Tuple[int, int]:
        """在地址addr处, 应用所有活跃的路径约束窄化区间."""
        constraints = self._addr_constraints.get(addr, [])
        norm_reg = self._norm(reg)
        cur_lo, cur_hi = lo, hi
        for c in constraints:
            if c.reg == norm_reg:
                cur_lo, cur_hi = c.narrow(cur_lo, cur_hi)
        return (max(cur_lo, 0), cur_hi)

    def record_constraint_at(self, addr: int, constraint: PathConstraint):
        """在指定地址记录一个活跃路径约束."""
        if addr not in self._addr_constraints:
            self._addr_constraints[addr] = []
        # 去重: 同一寄存器的同类型约束只保留最紧的
        existing = self._addr_constraints[addr]
        for i, c in enumerate(existing):
            if c.reg == constraint.reg and c.op == constraint.op:
                if constraint.op in (CondOp.LE, CondOp.BELOW_EQ,
                                      CondOp.LT, CondOp.BELOW):
                    if constraint.value < c.value:
                        existing[i] = constraint
                elif constraint.op in (CondOp.GE, CondOp.ABOVE_EQ,
                                        CondOp.GT, CondOp.ABOVE):
                    if constraint.value > c.value:
                        existing[i] = constraint
                return
        existing.append(constraint)

    def clear_constraints_at(self, addr: int):
        """清除某地址的路径约束 (用于不可达路径)."""
        self._addr_constraints.pop(addr, None)

    def get_constraints(self, addr: int) -> List[PathConstraint]:
        return list(self._addr_constraints.get(addr, []))

    def has_contradiction(self, addr: int) -> bool:
        """检查约束集是否包含矛盾 (如 rcx≤16 且 rcx>32)."""
        constraints = self._addr_constraints.get(addr, [])
        by_reg: Dict[str, List[PathConstraint]] = {}
        for c in constraints:
            by_reg.setdefault(c.reg, []).append(c)
        for reg, cs in by_reg.items():
            lo_upper = 2**63
            hi_lower = 0
            for c in cs:
                narrowed = c.narrow(0, 2**31 - 1)
                lo_upper = min(lo_upper, narrowed[1])
                hi_lower = max(hi_lower, narrowed[0])
            if hi_lower > lo_upper:
                return True  # 矛盾: 无具体值可同时满足所有约束
        return False

    @classmethod
    def _norm(cls, reg: str) -> str:
        r = reg.strip().lower().lstrip("%").replace("$", "")
        if "[" in r:
            return r
        return cls._W32_TO_W64.get(r, r)

    @staticmethod
    def _parse_imm(op: str) -> Optional[int]:
        s = op.strip().lower().lstrip("%").replace("$", "")
        s = s.split("#")[0].strip()
        try:
            if s.startswith("0x"):
                return int(s, 16)
            if s.isdigit() or (s.startswith("-") and s[1:].isdigit()):
                return int(s)
        except ValueError:
            pass
        return None

    def reset(self):
        self._addr_constraints.clear()
        self._last_cmp_reg = None
        self._last_cmp_val = None
        self._last_cmp_addr = 0


__all__ = ["PathConditionTracker", "PathConstraint", "CondOp",
           "JCC_TO_COND"]
