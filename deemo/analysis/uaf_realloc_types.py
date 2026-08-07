"""
UAF Realloc追踪器 — 类型定义.
"""


from dataclasses import dataclass, field
from enum import Enum
from typing import Set


class ReallocVerdict(Enum):
    """Realloc 相关判定."""
    SAFE = "SAFE"
    DANGLE_ALIAS = "DANGLE"
    DOUBLE_FREE = "DBL_FREE"
    REALLOC_ZERO = "RZERO_FREE"
    LEAK_ON_FAILURE = "LEAK"
    UNKNOWN = "UNKNOWN"


@dataclass
class ReallocSite:
    """单个 realloc 调用点."""
    line_no: int
    target_var: str
    arg_var: str
    new_size: str
    old_aliases: Set[str] = field(default_factory=set)
    is_zero_size: bool = False
    is_self_assign: bool = False
    verdict: ReallocVerdict = ReallocVerdict.UNKNOWN


@dataclass
class DanglingAlias:
    """悬空别名 — realloc 后仍被使用的旧指针别名."""
    alias_var: str
    realloc_line: int
    use_line: int
    realloc_target: str
    risk: str = "HIGH"


__all__ = ['ReallocVerdict', 'ReallocSite', 'DanglingAlias']
