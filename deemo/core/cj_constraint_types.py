"""
约束联结求解器核心数据结构 — GAPSBV-CJ方法的类型定义.

GAPSBV-CJ: Constraint-Joined Path-Sensitive Binary Verification
将堆溢出检测中四类约束统一建模为线性不等式系统, 通过Feasibility
Check和简化Farkas引理判定安全性, 无需SMT求解器.

核心思路: 不再让各维度独立判定SAFE/KEEP, 而是将所有约束收集到
统一的LinearConstraintSystem中, 做联合可行性判定. 当约束系统
证明"写入不可能溢出"时才FILTER, 否则保守保留.

  - Cousot & Cousot, POPL 1977: 抽象解释框架
  - Karr, 1976: 仿射关系分析
  - CAFD/AFD: 值流追踪分配大小
  - SUTURE: 路径约束驱动的二进制验证
  - CSA: 跨域稀疏抽象执行
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

class ConstraintType(Enum):
    """约束来源类型, 影响求解器的信任级别."""
    ALLOC_SIZE = "alloc_size"          # 分配大小约束
    COPY_SIZE = "copy_size"            # 拷贝大小约束
    WRITE_OFFSET = "write_offset"      # 写入偏移约束
    LOOP_BOUND = "loop_bound"          # 循环上界约束
    GUARD_CONDITION = "guard"          # 守卫条件
    AFFINE_RELATION = "affine"         # 仿射关系
    TYPE_BOUND = "type_bound"          # 类型上界
    ALIGNMENT = "alignment"            # 分配器对齐

class SolverVerdict(Enum):
    """求解器判定结果."""
    PROVEN_SAFE = "proven_safe"        # 约束系统证明写入安全
    PROVEN_OVERFLOW = "proven_overflow" # 约束系统确认溢出
    INCONCLUSIVE = "inconclusive"      # 约束不足以判定, 保守保留

@dataclass
class LinearConstraint:
    """线性不等式约束: sum(coef[i]*var[i]) + const OP 0.

    OP ∈ {'<=', '<', '>=', '>', '=='}
    常量约束退化为 const OP 0.
    """
    coefficients: dict[str, float]     # 变量名到系数的映射
    constant: float                    # 常数项
    operator: str                      # '<=', '<', '>=', '>', '=='
    source: ConstraintType             # 约束来源
    confidence: float = 1.0            # 约束可信度 [0,1]
    description: str = ""              # 人类可读描述

    def is_constant_only(self) -> bool:
        """约束是否仅含常量项(无变量), 即可直接求值."""
        return not self.coefficients or all(
            v == 0 for v in self.coefficients.values())

@dataclass
class ConstraintSystem:
    """线性约束系统 — 收集同一(alloc, write)对的所有约束."""
    constraints: list[LinearConstraint] = field(default_factory=list)
    alloc_var: str = ""                # 分配大小变量名
    alloc_size: int = 0                # 已知分配大小常量 (0=未知)
    copy_var: str = ""                 # 拷贝大小变量名
    copy_size: int = 0                 # 已知拷贝大小常量
    offset_var: str = ""               # 写入偏移变量名
    offset_val: int = 0                # 已知写入偏移常量
    loop_var: str = ""                 # 循环索引变量名
    loop_bound: int = -1               # 循环上界
    mnemonic: str = ""                 # 写入操作类型(store/memcpy/strcpy等)
    store_size: int = 0                # store操作的写入字节数(非copy操作)

    def add(self, c: LinearConstraint) -> None:
        self.constraints.append(c)

    @property
    def var_names(self) -> set[str]:
        """系统中出现的所有变量名."""
        names: set[str] = set()
        if self.alloc_var:
            names.add(self.alloc_var)
        if self.copy_var:
            names.add(self.copy_var)
        if self.offset_var:
            names.add(self.offset_var)
        if self.loop_var:
            names.add(self.loop_var)
        for c in self.constraints:
            names.update(c.coefficients.keys())
        return names

@dataclass
class SolverResult:
    """约束联结求解器的输出."""
    verdict: SolverVerdict = SolverVerdict.INCONCLUSIVE
    reason: str = ""
    constraints_collected: int = 0
    constraints_used: int = 0
    confidence_delta: float = 0.0      # 置信度调整量
    proof_chain: list[str] = field(default_factory=list)

__all__ = [
    'ConstraintType', 'SolverVerdict',
    'LinearConstraint', 'ConstraintSystem', 'SolverResult',
]
