"""共享数据模型 — 分配点/写点/守卫/结论的类型定义。

模型只承载结构，判定逻辑在 coupling_check 与 fp_filter 中。
"""


from dataclasses import dataclass, field
from typing import List, Optional

from .expr_ast import Expr


@dataclass
class AllocSite:
    var: str                 # 分配返回值变量
    size_expr: Expr          # 分配大小符号表达式
    kind: str                # malloc / calloc / realloc / ...
    func: str                # 所在函数
    pos: int = 0
    const_size: int = 0      # size_expr 为常量时的值; 0=非纯常量
    is_dynamic: bool = True

    def describe(self) -> str:
        return f'{self.kind}({self.func}@{self.pos})'


@dataclass
class WriteSite:
    dst_var: str             # 写入目标变量(原始)
    kind: str                # memcpy/strcpy/strncpy/sprintf/memset/read/
                             # array_write/field_write/ptr_write/unknown
    extent_expr: Optional[Expr]   # 总写入字节数表达式; None=未知
    index_expr: Optional[Expr]    # 数组写时的下标表达式
    elem_size: int = 1            # 数组写元素字节数
    src_expr: Optional[Expr] = None  # 拷贝类调用的源参数
    alias_base: str = ''          # 解析到的分配变量
    alias_offset: int = 0         # 别名偏移(字节)
    field_name: str = ''          # 字段写时的字段名
    func: str = ''
    pos: int = 0
    desc: str = ''
    stmt: object = None           # 语句引用, 用于守卫查找


@dataclass
class GuardConstraint:
    op: str                  # < <= > >= == !=
    lhs: Expr
    rhs: Expr
    pos: int = 0


@dataclass
class Finding:
    func: str
    alloc_var: str
    alloc_expr: str
    alloc_site: AllocSite
    write: WriteSite
    size_expr_str: str
    extent_expr_str: str
    verdict: str                 # verdict.OVERFLOW 等
    confidence: float
    fp_reasons: List[str] = field(default_factory=list)
    overflow_bytes: int = 0
    description: str = ''
    pos: int = 0
