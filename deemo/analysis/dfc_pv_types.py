"""DFC-PV 类型定义 — Double-free Causal-chain Pattern Verifier 共用类型.

AOI (Allocation Object Identity) 区分同一变量在不同时刻指向的不同分配对象,
解决变量名相同但底层分配已变更导致的误判.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Set, Dict, Tuple


class DfcVerdict(Enum):
    VULN = "VULN"
    SAFE = "SAFE"
    UNCERTAIN = "UNCERTAIN"


@dataclass
class AllocSite:
    """malloc/calloc/realloc 调用点, 创建新 AOI."""
    line: int
    var: str
    func: str = ""
    size_expr: str = ""


@dataclass
class FreeSite:
    """free() 调用点."""
    line: int
    var_expr: str        # 原始表达式: p, g->name, arr[0], *pp
    base_var: str        # 基础变量: p, name, arr, pp
    func: str = ""


@dataclass
class AliasEdge:
    """别名图有向边: target 在 line 行成为 source 的别名."""
    source: str
    target: str
    line: int
    kind: str = "assign"  # assign | field | array | arith | memcpy | global | param


@dataclass
class NullAssign:
    """NULL 赋值记录."""
    line: int
    var: str
    conditional: bool = False  # 是否在条件分支内


@dataclass
class ReallocSite:
    """重新分配: 变量被赋值为新的 malloc/calloc/realloc 返回值."""
    line: int
    var: str
    func: str = ""


@dataclass
class DfcResult:
    """DFC-PV 判定结果."""
    verdict: DfcVerdict
    first_free_line: int = 0
    second_free_line: int = 0
    var_name: str = ""
    alias_chain: str = ""
    confidence: float = 0.0
    reason: str = ""
    pattern: str = ""  # direct | cross_func | loop | wrapper | alias_chain | field_alias


__all__ = ['DfcVerdict', 'AllocSite', 'FreeSite', 'AliasEdge',
           'NullAssign', 'ReallocSite', 'DfcResult']
