"""
路径约束追踪器 - 累积分支条件并在报告前检查可行性.

原理: 静态分析把所有 CFG 路径视为可行, 在汇聚点合并两分支状态导致过近似
(如 if(x>100) 与 if(x<50) 合并出 "x 可为 30 也可为 200")。本模块记录每条路径的
分支守卫, 在报告堆溢出前检查 "是否存在可行路径使分配大小 < 写入偏移";
若路径约束已隐含偏移必超上限, 则该溢出路径不可行, 可排除。

设计决策 (参照 KLEE 路径条件积累范式):
  - 不做完整 SMT 求解: 完整符号执行对二进制路径爆炸不可行, 只在报告违规时做
    轻量级约束验证 - 不探索路径, 只验证.
  - 约束表示: 线性不等式 a*x + b*y + c >= 0 的有限集合, 对 malloc 大小推断已足够.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Callable
import re
import operator


@dataclass
class LinearConstraint:
    """线性约束: coeffs · vars + constant >= 0 或 == 0.

    例: {x: 1, y: -1} + 0 >= 0 表示 x - y >= 0, 即 x >= y.
    """
    coeffs: Dict[str, int] = field(default_factory=dict)  # var_name → coefficient
    constant: int = 0
    is_equality: bool = False  # True = ==, False = >=

    def negate(self) -> "LinearConstraint":
        """取反: >= 变成 < (即 <= -1)."""
        neg = LinearConstraint(
            coeffs={k: -v for k, v in self.coeffs.items()},
            constant=-self.constant - 1,
            is_equality=False)
        return neg

    def evaluate(self, assignment: Dict[str, int]) -> bool:
        """在给定赋值下检查是否满足."""
        val = self.constant + sum(
            c * assignment.get(v, 0) for v, c in self.coeffs.items())
        if self.is_equality:
            return val == 0
        return val >= 0

    def to_readable(self) -> str:
        parts = []
        for v, c in sorted(self.coeffs.items()):
            if c == 1:
                parts.append(v)
            elif c == -1:
                parts.append(f"-{v}")
            elif c > 0:
                parts.append(f"{c}*{v}")
            else:
                parts.append(f"{c}*{v}")
        expr = " + ".join(parts) if parts else "0"
        expr += f" + {self.constant}"
        if self.is_equality:
            return f"{expr} == 0"
        return f"{expr} >= 0"

    def __hash__(self):
        return hash((
            tuple(sorted(self.coeffs.items())),
            self.constant, self.is_equality))


@dataclass
class PathCondition:
    """一条路径上的约束集合.

    约束集合 {c1, c2, ..., cn} 的合取 —— 所有约束必须同时满足.
    """

    constraints: Tuple[LinearConstraint, ...] = ()
    path_id: int = 0

    def add(self, c: LinearConstraint) -> "PathCondition":
        return PathCondition(
            constraints=self.constraints + (c,),
            path_id=self.path_id)

    def is_trivially_unsat(self) -> bool:
        """快速检查: 是否存在 (x >= k) 和 (x <= k-1) 矛盾对."""
        bounds: Dict[str, Tuple[int, int]] = {}  # var → (min, max)
        for c in self.constraints:
            if c.is_equality:
                continue
            for var, coeff in c.coeffs.items():
                if abs(coeff) != 1 or len(c.coeffs) != 1:
                    continue
                # c: coeff*var + constant >= 0
                if coeff == 1:
                    lo = -c.constant  # var >= -constant
                    prev = bounds.get(var, (-10**9, 10**9))
                    bounds[var] = (max(prev[0], lo), prev[1])
                elif coeff == -1:
                    hi = c.constant  # -var + c >= 0 → var <= constant
                    prev = bounds.get(var, (-10**9, 10**9))
                    bounds[var] = (prev[0], min(prev[1], hi))
        for var, (lo, hi) in bounds.items():
            if lo > hi:
                return True  # 矛盾
        return False

    def evaluate(self, assignment: Dict[str, int]) -> bool:
        return all(c.evaluate(assignment) for c in self.constraints)

    def __repr__(self) -> str:
        return " ∧ ".join(c.to_readable() for c in self.constraints) or "true"


class ConstraintTracker:
    """轻量级路径约束追踪器.

    在分析每条指令时:
      1. 遇到条件分支 (cmp + jcc) 时, 提取比较表达式作为约束
      2. 分支后的指令继承对应的约束
      3. 报告堆溢出前, 检查溢出路径是否与约束一致
    """

    # 条件码 → 比较运算符映射 (AT&T/GAS 语法方向)
    # cmp a, b → 比较 b 与 a
    # jg  (大于跳转)     → b > a  → b - a >= 1
    # jge (大于等于跳转)  → b >= a → b - a >= 0
    # jl  (小于跳转)     → b < a  → a - b >= 1
    # jle (小于等于跳转)  → b <= a → a - b >= 0
    # je  (等于)        → a == b
    # jne (不等于)       → a != b → 不等式的合取 (复杂, 近似为 true)

    _CC_TO_CMP: Dict[str, Callable[[str, str], LinearConstraint]] = {
        "jg":  lambda a, b: LinearConstraint({b: 1, a: -1}, 1),   # b > a
        "ja":  lambda a, b: LinearConstraint({b: 1, a: -1}, 1),   # ja (above, 无符号)
        "jge": lambda a, b: LinearConstraint({b: 1, a: -1}, 0),   # b >= a
        "jae": lambda a, b: LinearConstraint({b: 1, a: -1}, 0),   # jae (above or equal)
        "jl":  lambda a, b: LinearConstraint({a: 1, b: -1}, 1),   # b < a
        "jb":  lambda a, b: LinearConstraint({a: 1, b: -1}, 1),   # jb (below, 无符号)
        "jle": lambda a, b: LinearConstraint({a: 1, b: -1}, 0),   # b <= a
        "jbe": lambda a, b: LinearConstraint({a: 1, b: -1}, 0),   # jbe (below or equal)
        "je":  lambda a, b: LinearConstraint({a: 1, b: -1}, 0, is_equality=True),
        "jz":  lambda a, b: LinearConstraint({a: 1, b: -1}, 0, is_equality=True),
        "jne": lambda a, b: LinearConstraint({}, 0),  # 无法用线性约束表达, 近似为 true
        "jnz": lambda a, b: LinearConstraint({}, 0),
    }

    def __init__(self):
        # 寄存器名 → 标准化变量名 (用于约束中的符号)
        self._reg_renaming: Dict[str, str] = {}
        # 当前路径条件
        self._current_pc: PathCondition = PathCondition()
        # 最后一条 cmp/test 指令的操作数
        self._last_cmp: Optional[Tuple[str, str]] = None
        # 分配的变量追踪: {malloc_site_var → 分配大小变量}
        self._alloc_vars: Dict[str, str] = {}

    def set_renaming(self, renaming: Dict[str, str]) -> None:
        """设置寄存器→变量名的映射."""
        self._reg_renaming = renaming

    def feed_cmp(self, op1: str, op2: str) -> None:
        """记录 cmp/test 的操作数."""
        v1 = self._reg_renaming.get(op1, op1)
        v2 = self._reg_renaming.get(op2, op2)
        self._last_cmp = (v1, v2)

    def feed_jcc(self, cc: str, taken: bool) -> PathCondition:
        """记录条件分支: cc 为条件码, taken 为是否走分支; 返回更新后的路径条件。"""
        if self._last_cmp is None:
            return self._current_pc

        constraint_fn = self._CC_TO_CMP.get(cc)
        if constraint_fn is None:
            return self._current_pc

        a, b = self._last_cmp
        constraint = constraint_fn(a, b)

        if not taken:
            constraint = constraint.negate()

        self._current_pc = self._current_pc.add(constraint)
        self._last_cmp = None
        return self._current_pc

    def feed_assignment(self, dst: str, src_expr: str) -> None:
        """记录赋值: dst = 表达式."""
        # 简化: 若 src 是已命名的变量, dst 继承其名
        src_var = self._reg_renaming.get(src_expr, src_expr)
        self._reg_renaming[dst] = src_var

    def get_path_condition(self) -> PathCondition:
        return self._current_pc

    def fork(self) -> "ConstraintTracker":
        """分叉 — 用于条件分支的两条路径."""
        child = ConstraintTracker()
        child._reg_renaming = dict(self._reg_renaming)
        child._current_pc = self._current_pc
        child._last_cmp = self._last_cmp
        child._alloc_vars = dict(self._alloc_vars)
        return child

    def is_path_feasible(self, alloc_var: str, alloc_size: int,
                         access_offset: int) -> bool:
        """检查是否存在可行路径使得 access_offset < alloc_size。

        核心思想: 若路径约束隐含 access_offset 必大于 alloc_size,
        则该溢出路径不可行, 可排除; 无法排除时保守保留。
        """
        # 构建反约束: access_offset < alloc_size
        # 等价于 alloc_var >= access_offset + 1
        # 若此反约束与当前路径条件一致, 则溢出可行
        safety_constraint = LinearConstraint(
            {alloc_var: 1}, -(access_offset + 1))
        # 检查 safety_constraint 是否与路径条件一致
        # 简化为: 检查路径条件中是否存在 (alloc_var <= k) with k < access_offset
        for c in self._current_pc.constraints:
            if c.is_equality or len(c.coeffs) != 1:
                continue
            for var, coeff in c.coeffs.items():
                if var == alloc_var and coeff == -1:
                    # c: -var + k >= 0 → var <= k
                    if c.constant < access_offset:
                        return False  # 路径保证 var < access_offset, 溢出不可行
        return True  # 无法排除 → 保守保留

    def clear(self) -> None:
        self._reg_renaming.clear()
        self._current_pc = PathCondition()
        self._last_cmp = None
        self._alloc_vars.clear()
