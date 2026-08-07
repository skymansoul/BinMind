"""
过程间仿射关系数据类型 — 函数摘要/跨函数关系的 dataclass 定义.

"""


from dataclasses import dataclass, field
from typing import Dict, List, Set

from analysis.affine_expr import AffineExpr, OverfRelation


@dataclass
class FuncAllocSummary:
    """函数内堆分配的摘要 — 记录分配变量和大小表达式."""
    alloc_var: str = ""
    size_expr: AffineExpr = field(default_factory=AffineExpr)
    alloc_func: str = "malloc"
    is_returned: bool = False
    line_no: int = 0


@dataclass
class FuncWriteSummary:
    """函数内堆写入的摘要 — 记录写入目标和大小表达式."""
    target_var: str = ""
    write_expr: AffineExpr = field(default_factory=AffineExpr)
    write_type: str = "memcpy"
    offset_val: int = 0
    line_no: int = 0


@dataclass
class FunctionSummary:
    """函数摘要 — 该函数内的所有 alloc/write 操作的仿射签名."""
    func_name: str = ""
    params: List[str] = field(default_factory=list)
    return_var: str = ""
    allocs: List[FuncAllocSummary] = field(default_factory=list)
    writes: List[FuncWriteSummary] = field(default_factory=list)
    param_exprs: Dict[str, AffineExpr] = field(default_factory=dict)


@dataclass
class CrossFuncRelation:
    """跨函数 alloc-write 关系 — 在调用点实例化后的结果."""
    caller_func: str = ""
    callee_alloc: FuncAllocSummary = field(default_factory=FuncAllocSummary)
    callee_write: FuncWriteSummary = field(default_factory=FuncWriteSummary)
    instantiated_alloc: AffineExpr = field(default_factory=AffineExpr)
    instantiated_write: AffineExpr = field(default_factory=AffineExpr)
    diff: AffineExpr = field(default_factory=AffineExpr)
    shared_vars: Set[str] = field(default_factory=set)
    verdict: str = "UNKNOWN"


__all__ = [
    'FuncAllocSummary', 'FuncWriteSummary', 'FunctionSummary',
    'CrossFuncRelation',
]
