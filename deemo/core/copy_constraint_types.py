"""
Copy约束验证数据类型 — SizeVarOrigin / CopyVerifyResult dataclass 定义.

"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class SizeVarOrigin:
    """size 变量的值来源追踪结果."""
    var_name: str = ''
    is_constant: bool = False
    constant_value: int = 0
    is_external_input: bool = False
    input_source: str = ''
    derived_vars: list[str] = field(default_factory=list)
    guard_constraints: list[str] = field(default_factory=list)
    has_upper_bound: bool = False
    upper_bound: int = 0


@dataclass
class CopyVerifyResult:
    """copy操作的约束验证结果."""
    verdict: str = 'UNCERTAIN'
    confidence_adjust: float = 0.0
    reason: str = ''
    alloc_origin: Optional[SizeVarOrigin] = None
    copy_origin: Optional[SizeVarOrigin] = None
    guard_found: bool = False
    guard_detail: str = ''


__all__ = ['SizeVarOrigin', 'CopyVerifyResult']
