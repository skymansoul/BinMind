"""
符号尺寸关联分析 (Symbolic Size Correlation Analysis) — DDSSC核心模块.

核心决策:
  堆溢出误报的最大来源: malloc(N) 与 memcpy(ptr, src, M) 中
  N 和 M 为同一变量或等价表达式时, 区间分析因宽化产生重叠区间,
  导致"可能溢出"告警. 本模块通过符号化追踪分配参数与写入参数的
  数据流来源, 判定两者是否等价, 从而消除此类误报.

方法:
  1. 为每个寄存器/栈槽构建 def-use 链上的符号表达式
  2. malloc 的 size 参数 → 符号变量 S_alloc
  3. memcpy 的 len 参数 → 符号表达式 E_write
  4. 若 E_write 可化简为 S_alloc 的线性函数且系数为1常数项为0 → 安全
  5. 若 E_write = S_alloc + k (k>0) → 确定溢出 k 字节

理论依据:
  符号执行消除抽象解释的模糊区间; 路径约束窄化消除系统性误报.

创建: 2024-12-03
"""

from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field


@dataclass
class SymExpr:
    """线性符号表达式: a*var + b, 或纯常量 b."""
    var: Optional[str] = None  # 符号变量名, None=纯常量
    coeff: int = 1             # 变量系数
    const: int = 0             # 常数项

    def is_const(self) -> bool:
        return self.var is None

    def is_identity(self) -> bool:
        """是否为 var*1 + 0, 即自身."""
        return self.var is not None and self.coeff == 1 and self.const == 0

    def add_const(self, c: int) -> "SymExpr":
        return SymExpr(self.var, self.coeff, self.const + c)

    def scale(self, k: int) -> "SymExpr":
        if k == 0:
            return SymExpr(None, 0, 0)
        return SymExpr(self.var, self.coeff * k, self.const * k)

    def __repr__(self) -> str:
        if self.var is None:
            return str(self.const)
        parts = []
        if self.coeff != 0:
            if self.coeff == 1:
                parts.append(self.var)
            else:
                parts.append(f"{self.coeff}*{self.var}")
        if self.const != 0:
            parts.append(str(self.const))
        return " + ".join(parts) if parts else "0"


class SymbolicSizeTracker:
    """符号尺寸追踪器.

    在指令分析过程中维护每个寄存器/栈槽的符号表达式,
    用于判定分配参数与写入参数的等价性.
    """

    def __init__(self):
        self._exprs: Dict[str, SymExpr] = {}
        self._stack_exprs: Dict[str, SymExpr] = {}
        # 分配点 → 尺寸符号变量名
        self._alloc_syms: Dict[int, str] = {}
        self._sym_counter: int = 0

    def new_alloc_symbol(self, alloc_addr: int, size_reg: str) -> str:
        """为分配点创建符号变量, 返回变量名."""
        sym = f"S_alloc_{self._sym_counter}"
        self._sym_counter += 1
        self._alloc_syms[alloc_addr] = sym
        expr = self._exprs.get(size_reg, SymExpr(var=sym))
        if expr.is_const():
            self._exprs[sym] = expr
        else:
            self._exprs[sym] = SymExpr(var=sym)
        return sym

    def get_alloc_sym(self, alloc_addr: int) -> Optional[str]:
        return self._alloc_syms.get(alloc_addr)

    def set_expr(self, reg: str, expr: SymExpr):
        self._exprs[reg] = expr

    def get_expr(self, reg: str) -> Optional[SymExpr]:
        return self._exprs.get(reg)

    def set_stack_expr(self, slot: str, expr: SymExpr):
        self._stack_exprs[slot] = expr

    def get_stack_expr(self, slot: str) -> Optional[SymExpr]:
        return self._stack_exprs.get(slot)

    def clear(self, reg: str):
        self._exprs.pop(reg, None)

    def reset(self):
        self._exprs.clear()
        self._stack_exprs.clear()
        self._alloc_syms.clear()
        self._sym_counter = 0


def correlate_sizes(
    alloc_expr: Optional[SymExpr],
    write_expr: Optional[SymExpr],
) -> Tuple[str, int]:
    """判定分配尺寸与写入尺寸的符号关系.

    返回: (判定类别, 溢出字节数)
      ("safe_equal", 0)      — 两者完全等价, 安全
      ("safe_dominates", 0)  — 分配尺寸 ≥ 写入尺寸(符号证明), 安全
      ("overflow", n)        — 写入 > 分配, 溢出 n 字节
      ("unknown", 0)         — 无法判定, 需更高层分析
    """
    if alloc_expr is None or write_expr is None:
        return ("unknown", 0)

    # 两者均为常量
    if alloc_expr.is_const() and write_expr.is_const():
        a, w = alloc_expr.const, write_expr.const
        if w <= a:
            return ("safe_dominates", 0)
        return ("overflow", w - a)

    # 同一符号变量
    if (alloc_expr.var is not None and
            alloc_expr.var == write_expr.var):
        # 系数不同时: write = w_coeff*var + w_const, alloc = a_coeff*var + a_const
        # 溢出条件: w_coeff*var + w_const > a_coeff*var + a_const
        # 即 (w_coeff - a_coeff)*var > (a_const - w_const)
        w_c, a_c = write_expr.coeff, alloc_expr.coeff
        w_k, a_k = write_expr.const, alloc_expr.const
        if w_c == a_c:
            # 系数相同: 比较常数项
            diff = w_k - a_k
            if diff <= 0:
                return ("safe_equal", 0)
            return ("overflow", diff)
        elif w_c > a_c and w_k >= a_k:
            # write系数更大且常数项不更小: 对所有var>0必然溢出
            return ("overflow", 0)
        elif w_c < a_c and w_k <= a_k:
            # write系数更小且常数项不更大: 对所有var>0安全
            return ("safe_dominates", 0)
        else:
            # 系数不同但方向不确定: 需更高层分析
            return ("unknown", 0)

    # 分配为常量, 写入为变量: 无法静态判定
    if alloc_expr.is_const() and not write_expr.is_const():
        return ("unknown", 0)

    # 分配为变量, 写入为常量
    if not alloc_expr.is_const() and write_expr.is_const():
        if write_expr.const <= 0:
            return ("safe_dominates", 0)
        return ("unknown", 0)

    # 不同符号变量: 无法判定
    return ("unknown", 0)


__all__ = ["SymExpr", "SymbolicSizeTracker", "correlate_sizes"]
