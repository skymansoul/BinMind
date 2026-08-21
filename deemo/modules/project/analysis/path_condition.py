# 路径条件追踪器: 在线性扫描中维护分支条件以实现路径敏感精度
# 核心创新: 传统的线性扫描对所有分支路径等同对待, 丢失路径信息.
#   本模块追踪cmp+条件跳转的分支语义, 在每条路径上维护一个轻量级的
#   条件集合, 增强值域分析的精度.
#   例: if(size>256) abort(); memcpy(buf, src, size);
#      → 路径条件 size ≤ 256 传播到memcpy, 将写入上界约束为256
#      → 若malloc(256), 则DEFINITE_SAFE (无路径条件时会是POSSIBLE_OVERFLOW)
# 理论来源:
#   Bodik et al. "ABCD: Eliminating Array Bounds Checks on Demand"
#     — 基于条件的约束推导
#   Beyer et al. "CPAchecker: A Tool for Configurable Software Verification"
# — 可配置路径条件分析框架
# 与现有分析的关系: 作为值域分析的精度增强层,
#   只在遇到条件分支时截取条件传递给后续指令,
#   不改变现有的三阶段管道结构
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Set, Tuple, Union

_U64_MAX = 0xFFFFFFFFFFFFFFFF


class ConditionOp(Enum):
    """比较操作符."""
    LT = auto()   # <
    LE = auto()   # ≤
    GT = auto()   # >
    GE = auto()   # ≥
    EQ = auto()   # ==
    NE = auto()   # ≠


@dataclass
class PathCondition:
    """单条路径条件: reg op val (或 reg op other_reg).

    例: edx ≤ 256, eax > 0, ecx == 128
    """
    reg: str                 # 左操作数 (寄存器名)
    op: ConditionOp          # 比较运算符
    value: int = 0           # 右操作数 (立即数时为具体值)
    other_reg: str = ""      # 右操作数 (寄存器时)
    is_active: bool = True   # 当前路径上是否生效


@dataclass
class BranchContext:
    """分支上下文: 记录一条分支路径上的所有条件."""
    conditions: List[PathCondition] = field(default_factory=list)
    branch_addr: int = 0       # 分支指令地址
    taken: bool = True         # True=跳转被执行, False=跳转未执行(继续下一条指令)


class PathConditionTracker:
    """路径条件追踪器.

    在线性扫描中维护当前路径的条件集合.
    核心操作:
      - record_condition: 遇到cmp+条件跳转时记录路径条件
      - apply_to_value_range: 将路径条件约束应用到值域上
      - clear_dead_conditions: 离开分支范围时清除过期条件
    """

    # 条件跳转→比较运算符映射: jl → LT, jle → LE, etc.
    _JUMP_CONDITION_MAP = {
        'jl': (ConditionOp.LT, True),     # 跳转执行 ↔ 条件成立
        'jle': (ConditionOp.LE, True),
        'jg': (ConditionOp.GT, True),
        'jge': (ConditionOp.GE, True),
        'je': (ConditionOp.EQ, True),
        'jz': (ConditionOp.EQ, True),
        'jne': (ConditionOp.NE, True),
        'jnz': (ConditionOp.NE, True),
        'ja': (ConditionOp.GT, True),     # 无符号>
        'jae': (ConditionOp.GE, True),    # 无符号≥
        'jb': (ConditionOp.LT, True),     # 无符号<
        'jbe': (ConditionOp.LE, True),    # 无符号≤
    }

    # 反向条件 (跳转未取 ↔ 条件取反)
    _NEGATED_CONDITION = {
        ConditionOp.LT: ConditionOp.GE,
        ConditionOp.LE: ConditionOp.GT,
        ConditionOp.GT: ConditionOp.LE,
        ConditionOp.GE: ConditionOp.LT,
        ConditionOp.EQ: ConditionOp.NE,
        ConditionOp.NE: ConditionOp.EQ,
    }

    def __init__(self):
        self._active_conditions: List[PathCondition] = []
        self._branch_stack: List[BranchContext] = []  # 分支嵌套栈
        self._last_cmp_reg: str = ""
        self._last_cmp_value: Optional[int] = None
        self._last_cmp_other_reg: str = ""
        self._active_branch_ranges: List[Tuple[int, int]] = []  # 活跃分支的指令范围

# 比较指令记录

    def record_cmp(self, left_reg: str, right_imm: Optional[int],
                   right_reg: str = ""):
        """记录最近的cmp指令: 为后续的条件跳转准备."""
        self._last_cmp_reg = left_reg
        self._last_cmp_value = right_imm
        self._last_cmp_other_reg = right_reg

    def record_test(self, reg: str):
        """记录test指令: test reg, reg → 等价位 cmp reg, 0."""
        self._last_cmp_reg = reg
        self._last_cmp_value = 0
        self._last_cmp_other_reg = ""

# 条件跳转处理

    def record_conditional_jump(self, jump_op: str, jump_target_addr: int,
                                current_addr: int, taken: bool) -> List[PathCondition]:
        """处理条件跳转指令, 生成路径条件.

        返回此分支上下文中的活跃条件列表.
        taken=True: 跳转被采取 (到jump_target)
        taken=False: 跳转未被采取 (继续顺序执行)
        """
        if jump_op not in self._JUMP_CONDITION_MAP:
            return []

        base_op, _ = self._JUMP_CONDITION_MAP[jump_op]
        # 跳转未被采取 → 条件取反
        effective_op = base_op if taken else self._NEGATED_CONDITION.get(base_op)
        if effective_op is None:
            return []

        if not self._last_cmp_reg:
            return []

        cond = PathCondition(
            reg=self._last_cmp_reg,
            op=effective_op,
            value=self._last_cmp_value if self._last_cmp_value is not None else 0,
            other_reg=self._last_cmp_other_reg,
            is_active=True)

        self._active_conditions.append(cond)
        return [cond]

# 值域约束应用

    def constrain_value_bound(self, reg: str, current_umin: int,
                              current_umax: int) -> Tuple[int, int]:
        """将活跃路径条件应用到值域, 缩小范围.

        reg: 被约束的寄存器名
        current_umin/umax: 当前值域的下/上界
        返回 (新umin, 新umax)。
        """
        new_umin, new_umax = current_umin, current_umax

        for cond in self._active_conditions:
            if not cond.is_active:
                continue
            # 仅处理寄存器名匹配的条件
            if cond.reg != reg and not (
                    cond.reg.startswith('e') and reg.startswith('r')
                    and cond.reg[1:] == reg[1:]):
                continue

            val = cond.value
            if cond.op == ConditionOp.LE:
                new_umax = min(new_umax, val)
            elif cond.op == ConditionOp.LT:
                new_umax = min(new_umax, val - 1)
            elif cond.op == ConditionOp.GE:
                new_umin = max(new_umin, val)
            elif cond.op == ConditionOp.GT:
                new_umin = max(new_umin, val + 1)
            elif cond.op == ConditionOp.EQ:
                new_umin = max(new_umin, val)
                new_umax = min(new_umax, val)
            # NE: 不提供精确的数值约束, 跳过

        return (max(new_umin, 0), max(new_umin, new_umax))

    def get_active_bound(self, reg: str) -> Optional[int]:
        """获取路径条件对reg的上界约束 (取最紧的)."""
        best = None
        for cond in self._active_conditions:
            if not cond.is_active:
                continue
            if cond.reg != reg:
                continue
            if cond.op in (ConditionOp.LE, ConditionOp.LT):
                bound = cond.value if cond.op == ConditionOp.LE else cond.value - 1
                if best is None or bound < best:
                    best = bound
        return best

# 分支生命周期管理

    def push_branch(self, branch_addr: int, is_taken: bool,
                    end_addr: int):
        """进入一个分支范围."""
        self._branch_stack.append(BranchContext(
            conditions=list(self._active_conditions),
            branch_addr=branch_addr, taken=is_taken))
        self._active_branch_ranges.append((branch_addr, end_addr))

    def pop_branch(self, fallthrough_addr: int, jump_target: int = -1):
        """离开分支范围: 清除进入分支后新增的条件."""
        if self._branch_stack:
            ctx = self._branch_stack.pop()
            self._active_conditions = ctx.conditions
        if self._active_branch_ranges:
            self._active_branch_ranges.pop()

    def invalidate_at_address(self, addr: int):
        """在地址addr处: 检查是否有分支范围到期, 若到期则清除条件."""
        while self._active_branch_ranges:
            start, end = self._active_branch_ranges[-1]
            if addr > end:
                self.pop_branch(addr, -1)
            else:
                break

# 条件查询

    def is_condition_guaranteed(self, reg: str, op: ConditionOp,
                                val: int) -> bool:
        """检查当前路径是否保证 reg op val 成立."""
        for cond in self._active_conditions:
            if not cond.is_active:
                continue
            if cond.reg != reg:
                continue
            if cond.op == ConditionOp.LE and op == ConditionOp.LE:
                if cond.value <= val:
                    return True  # reg ≤ cond.value ≤ val → reg ≤ val
            elif cond.op == ConditionOp.LT and op == ConditionOp.LE:
                if cond.value <= val + 1:
                    return True
            elif cond.op == op:
                if (cond.op in (ConditionOp.LE, ConditionOp.GE, ConditionOp.EQ)
                        and cond.value == val):
                    return True
        return False

    def any_active_condition(self) -> bool:
        return len(self._active_conditions) > 0

    def active_conditions(self) -> List[PathCondition]:
        return [c for c in self._active_conditions if c.is_active]

    def clear(self):
        self._active_conditions.clear()
        self._branch_stack.clear()
        self._active_branch_ranges.clear()
        self._last_cmp_reg = ""
        self._last_cmp_value = None
        self._last_cmp_other_reg = ""

    def summary(self) -> Dict:
        return {
            'active_conditions': len(self._active_conditions),
            'branch_depth': len(self._branch_stack),
            'branch_ranges': len(self._active_branch_ranges),
        }
