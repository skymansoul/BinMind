"""
UAF路径敏感时序验证 — 类型定义.

PtrState: 指针生命周期状态 (ALLOCATED/FREED/NULLIFIED/UNKNOWN)
TemporalVerdict: 时序验证判定 (SAFE/UAF/DOUBLE_FREE/UNCERTAIN)
TemporalResult: 单次时序验证结果
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple


class PtrState(Enum):
    """指针生命周期状态."""
    UNKNOWN = "UNKNOWN"
    ALLOCATED = "ALLOCATED"
    FREED = "FREED"
    NULLIFIED = "NULLIFIED"


class TemporalVerdict(Enum):
    """时序验证判定."""
    SAFE = "SAFE"
    UAF = "UAF"
    DOUBLE_FREE = "DOUBLE_FREE"
    UNCERTAIN = "UNCERTAIN"


@dataclass
class TemporalResult:
    """单次时序验证结果."""
    verdict: TemporalVerdict = TemporalVerdict.UNCERTAIN
    ptr_var: str = ""
    free_line: int = 0
    use_line: int = 0
    safe_paths: int = 0
    uaf_paths: int = 0
    total_paths: int = 0
    reason: str = ""


def _has_nullify_between(line: str, var: str,
                         free_col: int, use_col: int) -> bool:
    """同行内free和use之间是否有NULL赋值或realloc安全模式."""
    import re
    between = line[free_col:use_col]
    if re.search(rf'\b{re.escape(var)}\s*=\s*(?:NULL|0|nullptr|nil)\b',
                 between, re.IGNORECASE):
        return True
    if re.search(rf'\b{re.escape(var)}\s*=\s*(?:\([^)]*\)\s*)?'
                 rf'(?:malloc|calloc|realloc)\s*\(', between, re.IGNORECASE):
        return True
    return False


__all__ = ['PtrState', 'TemporalVerdict', 'TemporalResult',
           '_has_nullify_between']
