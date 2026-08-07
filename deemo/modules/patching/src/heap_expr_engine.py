# 堆溢出表达式引擎 — Expr数据结构与常量折叠
"""轻量级符号表达式引擎 — Expr树与算术运算符(ADD/SUB/MUL),
支持区间评估(eval_min/eval_max)、常量折叠、溢出比较。

不进行全符号执行, 仅支持 TAINT + const / TAINT - const / TAINT * const。
"""

from enum import Enum, auto
from dataclasses import dataclass
from typing import Optional


class ExprKind(Enum):
    CONST = auto()    # 常量
    TAINT = auto()    # 污点源(外部输入, 值未知)
    ADD = auto()      # expr + const
    SUB = auto()      # expr - const
    MUL = auto()      # expr * const

    def __str__(self):
        return self.name


@dataclass
class Expr:
    """轻量级符号表达式。只支持常量+taint的加减乘。"""
    kind: ExprKind
    value: int = 0           # CONST的值, 或ADD/SUB/MUL的操作数
    child: Optional['Expr'] = None  # ADD/SUB/MUL的子表达式
    taint_label: str = ""    # TAINT的来源描述
    cap_value: int = 0       # cmova/g/ge约束上限 (0=无约束)
    floor_value: int = 0     # cmovl/le/b/be约束下限 (0=无约束)

    def eval_min(self) -> int:
        """表达式的最小可能值。TAINT最小=0。floor_value可提高下界。"""
        if self.kind == ExprKind.CONST:
            return self.value
        if self.kind == ExprKind.TAINT:
            raw = 0
        else:
            child_min = self.child.eval_min() if self.child else 0
            if self.kind == ExprKind.ADD:
                raw = child_min + self.value
            elif self.kind == ExprKind.SUB:
                raw = max(0, child_min - self.value)
            elif self.kind == ExprKind.MUL:
                raw = child_min * self.value
            else:
                raw = 0
        # floor_value提高下界: max(raw, floor_value)
        if self.floor_value > raw:
            return self.floor_value
        return raw

    def eval_max(self) -> int:
        """表达式的最大可能值。TAINT最大=SIZE_MAX。cmova约束可降低上界。"""
        if self.kind == ExprKind.CONST:
            return self.value
        if self.kind == ExprKind.TAINT:
            raw = 0x7FFFFFFF
        else:
            child_max = self.child.eval_max() if self.child else 0
            if self.kind == ExprKind.ADD:
                raw = min(0x7FFFFFFF, child_max + self.value)
            elif self.kind == ExprKind.SUB:
                raw = child_max  # 减法不增加上界
            elif self.kind == ExprKind.MUL:
                raw = min(0x7FFFFFFF, child_max * self.value)
            else:
                raw = 0
        # cmova约束上界: min(raw, cap_value)
        if self.cap_value > 0 and self.cap_value < raw:
            return self.cap_value
        return raw

    def to_str(self) -> str:
        if self.kind == ExprKind.CONST:
            return str(self.value)
        if self.kind == ExprKind.TAINT:
            return f"TAINT[{self.taint_label}]"
        op = {ExprKind.ADD: '+', ExprKind.SUB: '-', ExprKind.MUL: '*'}[self.kind]
        child_s = self.child.to_str() if self.child else '?'
        return f"({child_s} {op} {self.value})"

    def has_taint(self) -> bool:
        if self.kind == ExprKind.TAINT:
            return True
        if self.child:
            return self.child.has_taint()
        return False

    def get_taint_root(self) -> Optional['Expr']:
        """获取表达式树的TAINT根节点。"""
        if self.kind == ExprKind.TAINT:
            return self
        if self.child:
            return self.child.get_taint_root()
        return None


def const_expr(v: int) -> Expr:
    return Expr(kind=ExprKind.CONST, value=v)


def taint_expr(label: str = "") -> Expr:
    return Expr(kind=ExprKind.TAINT, taint_label=label)


def add_expr(child: Expr, v: int) -> Expr:
    """child + v, 折叠常量。"""
    if child.kind == ExprKind.CONST:
        return const_expr(child.value + v)
    if v == 0:
        return child
    # 折叠 (e + a) + b → e + (a+b)
    if child.kind == ExprKind.ADD:
        return Expr(kind=ExprKind.ADD, value=child.value + v, child=child.child)
    if child.kind == ExprKind.SUB:
        # (e - a) + b → e + (b - a) 或 e - (a - b)
        net = v - child.value
        if net >= 0:
            return Expr(kind=ExprKind.ADD, value=net, child=child.child)
        else:
            return Expr(kind=ExprKind.SUB, value=-net, child=child.child)
    return Expr(kind=ExprKind.ADD, value=v, child=child)


def sub_expr(child: Expr, v: int) -> Expr:
    """child - v, 折叠常量。"""
    if child.kind == ExprKind.CONST:
        return const_expr(max(0, child.value - v))
    if v == 0:
        return child
    if child.kind == ExprKind.ADD:
        # (e + a) - b → e + (a - b) 或 e - (b - a)
        net = child.value - v
        if net >= 0:
            return Expr(kind=ExprKind.ADD, value=net, child=child.child)
        else:
            return Expr(kind=ExprKind.SUB, value=-net, child=child.child)
    if child.kind == ExprKind.SUB:
        # (e - a) - b → e - (a+b)
        return Expr(kind=ExprKind.SUB, value=child.value + v, child=child.child)
    return Expr(kind=ExprKind.SUB, value=v, child=child)


def mul_expr(child: Expr, v: int) -> Expr:
    """child * v。"""
    if child.kind == ExprKind.CONST:
        return const_expr(child.value * v)
    if v == 0:
        return const_expr(0)
    if v == 1:
        return child
    return Expr(kind=ExprKind.MUL, value=v, child=child)


def compare_for_overflow(alloc: Expr, write: Expr) -> int:
    """比较alloc和write表达式。若write恒大于alloc, 返回最小溢出字节数。

    返回 0 表示无法确定溢出 (可能等值, 或无共享taint源)。
    """
    alloc_root = alloc.get_taint_root()
    write_root = write.get_taint_root()
    if alloc_root is None or write_root is None:
        # 至少一个无taint → 常量比较
        if alloc.kind == ExprKind.CONST and write.kind == ExprKind.CONST:
            return max(0, write.value - alloc.value)
        return 0

    # 共享taint根: write_min > alloc_max → 确定溢出
    w_min = write.eval_min()
    a_max = alloc.eval_max()
    if w_min > a_max:
        return w_min - a_max

    # 结构比较: 相同taint + 不同常量偏移
    if alloc_root.taint_label == write_root.taint_label:
        a_const = _extract_const_offset(alloc)
        w_const = _extract_const_offset(write)
        if w_const > a_const:
            return w_const - a_const

    return 0


def _extract_const_offset(expr: Expr) -> int:
    """提取表达式相对于TAINT根的常量偏移。TAINT + K → K。"""
    if expr.kind == ExprKind.TAINT:
        return 0
    if expr.kind == ExprKind.CONST:
        return expr.value
    if expr.child:
        child_off = _extract_const_offset(expr.child)
        if expr.kind == ExprKind.ADD:
            return child_off + expr.value
        if expr.kind == ExprKind.SUB:
            return child_off - expr.value
        if expr.kind == ExprKind.MUL:
            return child_off * expr.value
    return 0
