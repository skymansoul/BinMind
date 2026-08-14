"""约束累加器 — 在值流图上做仿射约束推理.
提取线性约束 (x=y, x=c, x=y+z, x=y*c) 证明或推翻堆写入安全;
沿值流路径累积约束, 证 write_offset<alloc_size 则判安全(滤FP), 证反则判不安全, 否则不确定. 参考 Crab-LLVM."""

from dataclasses import dataclass, field
from enum import Enum
import re
from typing import Dict, List, Optional, Set, Tuple

from core.vfg_builder import (
    ValueFlowGraph, VFGNode, VFGEdge, NodeKind,
)

class ConstraintKind(Enum):
    EQ = "eq"           # x = y
    EQ_CONST = "eq_c"   # x = c
    ADD = "add"         # x = y + z
    SUB = "sub"         # x = y - z
    MUL_CONST = "mul_c" # x = y * c
    LE = "le"           # x <= c
    GE = "ge"           # x >= c

@dataclass
class LinearConstraint:
    """线性约束: var = coeff_a * var_a + coeff_b * var_b + constant."""
    var: str
    coeff_a: float = 0.0
    var_a: str = ''
    coeff_b: float = 0.0
    var_b: str = ''
    constant: int = 0
    kind: ConstraintKind = ConstraintKind.EQ

    @classmethod
    def eq(cls, var: str, other_var: str) -> 'LinearConstraint':
        return cls(var=var, coeff_a=1.0, var_a=other_var, kind=ConstraintKind.EQ)

    @classmethod
    def eq_const(cls, var: str, value: int) -> 'LinearConstraint':
        return cls(var=var, constant=value, kind=ConstraintKind.EQ_CONST)

    @classmethod
    def add(cls, var: str, a: str, b: str) -> 'LinearConstraint':
        return cls(var=var, coeff_a=1.0, var_a=a, coeff_b=1.0, var_b=b,
                   kind=ConstraintKind.ADD)

    @classmethod
    def sub(cls, var: str, a: str, b: str) -> 'LinearConstraint':
        return cls(var=var, coeff_a=1.0, var_a=a, coeff_b=-1.0, var_b=b,
                   kind=ConstraintKind.SUB)

    @classmethod
    def mul_const(cls, var: str, base: str, factor: int) -> 'LinearConstraint':
        return cls(var=var, coeff_a=float(factor), var_a=base,
                   kind=ConstraintKind.MUL_CONST)

    def evaluate_with(self, bindings: Dict[str, int]) -> Optional[int]:
        """在给定变量绑定下计算值。返回None若存在未绑定变量。"""
        val = self.constant
        if self.var_a:
            if self.var_a not in bindings:
                return None
            val += int(self.coeff_a * bindings[self.var_a])
        if self.var_b:
            if self.var_b not in bindings:
                return None
            val += int(self.coeff_b * bindings[self.var_b])
        return val

@dataclass
class ConstraintSet:
    """一组线性约束, 对应一个值流路径。"""
    constraints: List[LinearConstraint] = field(default_factory=list)
    source_node: Optional[VFGNode] = None   # 分配点
    sink_node: Optional[VFGNode] = None     # 写入点

    def can_prove_safe(self) -> Optional[bool]:
        """试图证明 write_offset < alloc_size。返回 None 表示不确定。"""
        # 提取分配大小和写入偏移的约束并尝试比较
        # 将由 ConstraintAccumulator 的子类方法处理
        return None

class ConstraintAccumulator:
    """从值流图中提取并推理线性约束。

    对于每一对 (alloc_site, write_site):
    1. 从 alloc_site 反向追踪到"根源"变量 (函数参数/常量/循环边界)
    2. 从 write_site 同样反向追踪
    3. 如果两者共享同一个根源变量, 构建两个表达式并比较

    例:
      alloc_site:  p = malloc(n)      → alloc_size = n
      write_site:  store(p + n - 4)   → write_offset = n - 4
      共享根源: n
      → 约束: alloc_size = n, write_offset = n - 4
      → 证明: write_offset < alloc_size (因为 n-4 < n 对于 n > 0)
      → 判定: SAFE (这是FP, 需要滤除)

    保守原则: 只在能*证明*安全时才滤除。无法证明时保留 (宁可误报, 不漏报)。
    """

    def __init__(self):
        self._constraints: Dict[str, List[LinearConstraint]] = {}
        self._const_values: Dict[str, int] = {}
        self._eq_classes: Dict[str, str] = {}  # 变量 → 等价类代表元

    def accumulate(self, g: ValueFlowGraph):
        """从值流图提取所有约束。"""
        self._constraints.clear()
        self._const_values.clear()
        self._eq_classes.clear()

        for node in g.nodes:
            if node.kind == NodeKind.CONSTANT and node.value is not None:
                self._const_values[node.name] = node.value
                self._add_constraint(LinearConstraint.eq_const(node.name, node.value))

            elif node.kind == NodeKind.EXPRESSION and node.call_info:
                a, op, b = node.call_info
                # 尝试解析 a 或 b 为常量
                const_b = self._try_int(b)
                const_a = self._try_int(a)

                if op == '+' and const_a is not None:
                    self._add_constraint(LinearConstraint.eq_const(
                        node.name, const_a + (self._const_values.get(b, 0) if const_a == 0 else 0)))
                elif op == '+' and const_b is not None:
                    self._add_constraint(LinearConstraint.eq_const(
                        node.name, self._const_values.get(a, 0) + const_b))
                elif op == '+' and const_a is None and const_b is None:
                    self._add_constraint(LinearConstraint.add(node.name, a, b))
                elif op == '-' and const_b is not None:
                    self._add_constraint(LinearConstraint.sub(node.name, a, str(const_b)))
                    self._add_constraint(LinearConstraint(
                        var=node.name, coeff_a=1.0, var_a=a, constant=-const_b,
                        kind=ConstraintKind.SUB))
                elif op == '*' and const_b is not None:
                    self._add_constraint(LinearConstraint.mul_const(node.name, a, const_b))
                elif op == '*' and const_a is not None:
                    self._add_constraint(LinearConstraint.mul_const(node.name, b, const_a))

            elif node.kind == NodeKind.LOOP_BOUND and node.value is not None:
                self._add_constraint(LinearConstraint(
                    var=node.name, constant=node.value, kind=ConstraintKind.LE))

        # 传递闭包: 合并等价类直到不动点
        self._propagate_eq_classes()

    def _add_constraint(self, c: LinearConstraint):
        self._constraints.setdefault(c.var, []).append(c)
        # 更新等价类
        if c.kind == ConstraintKind.EQ_CONST and c.constant > 0:
            self._const_values[c.var] = c.constant
        elif c.kind == ConstraintKind.EQ and c.coeff_a == 1.0 and c.var_a:
            rep = self._find_root(c.var)
            rep_a = self._find_root(c.var_a)
            if rep != rep_a:
                self._eq_classes[rep] = rep_a
                # 传播常数值
                if rep in self._const_values:
                    self._const_values[rep_a] = self._const_values[rep]

    def _propagate_eq_classes(self):
        """迭代传播等价类和常量值直到不动点。最多迭代20次 (变量数上界)。"""
        changed = True
        iters = 0
        while changed and iters < 20:
            changed = False
            iters += 1
            # 传播常量到等价类代表元
            for var, val in list(self._const_values.items()):
                root = self._find_root(var)
                if root not in self._const_values:
                    self._const_values[root] = val
                    changed = True
            # 通过表达式计算新常量值
            for var, constraints in self._constraints.items():
                if var in self._const_values:
                    continue
                for c in constraints:
                    val = self._evaluate_constraint(c)
                    if val is not None:
                        self._const_values[var] = val
                        self._constraints[var].append(
                            LinearConstraint.eq_const(var, val))
                        changed = True
                        break

    def _find_root(self, var: str) -> str:
        """并查集找等价类的根。"""
        path = []
        while var in self._eq_classes:
            path.append(var)
            var = self._eq_classes[var]
        for p in path:
            self._eq_classes[p] = var
        return var

    def _evaluate_constraint(self, c: LinearConstraint) -> Optional[int]:
        """尝试在已知常量绑定下求值约束。"""
        bindings = dict(self._const_values)
        # 也加入等价类
        for var, root in self._eq_classes.items():
            if root in self._const_values and var not in bindings:
                bindings[var] = self._const_values[root]
        return c.evaluate_with(bindings)

    def get_value(self, var: str) -> Optional[int]:
        """获取变量的已知常量值 (若存在)。"""
        root = self._find_root(var)
        if root in self._const_values:
            return self._const_values[root]
        return self._const_values.get(var)

    def get_expression(self, var: str) -> List[LinearConstraint]:
        """获取变量的约束表达式列表。"""
        return self._constraints.get(var, [])

    def compare_expressions(self, expr_a: str, expr_b: str) -> Optional[bool]:
        """比较两个表达式的值关系: expr_a < expr_b 是否可证明？"""
        val_a = self.get_value(expr_a)
        val_b = self.get_value(expr_b)
        if val_a is not None and val_b is not None:
            return val_a < val_b
        return None

    @staticmethod
    def _try_int(s: str) -> Optional[int]:
        try:
            s = s.strip()
            if s.startswith('0x') or s.startswith('0X'):
                return int(s, 16)
            return int(s)
        except (ValueError, TypeError):
            return None

def prove_heap_write_safety(
    alloc_size_var: str,
    write_offset_expr: str,
    accumulator: ConstraintAccumulator,
) -> Optional[bool]:
    """证明堆写入安全/不安全。

    参数:
      alloc_size_var: 分配大小对应的变量名
      write_offset_expr: 写入偏移表达式 (字符串)
      accumulator: 已构建的约束累加器

    返回:
      True:  可证明安全 (写入偏移 < 分配大小) → 滤除的FP
      False: 可证明不安全 (写入偏移 ≥ 分配大小) → 保留的真阳性
      None:  无法确定 → 保留, 交给下游处理
    """
    alloc_val = accumulator.get_value(alloc_size_var)

    # 尝试从写入表达式解析常量
    try:
        write_val = int(write_offset_expr.strip(), 0) if write_offset_expr.strip() else 0
    except (ValueError, TypeError):
        write_val = accumulator.get_value(write_offset_expr)

    if alloc_val is not None and write_val is not None:
        return write_val < alloc_val

    return None
