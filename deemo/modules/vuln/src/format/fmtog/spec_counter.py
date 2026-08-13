"""格式说明符解析 — 计数与类型分类.

值型说明符 (d/i/u/x/o/c/f/e/g) 消耗一个整型/浮点实参; 引用型
(%s/%p/%n) 消耗一个指针实参; %% 不消耗. %n 单独计数 (写内存语义).
解析失败时保守: 视为消耗 1 实参.
"""

import re
from dataclasses import dataclass, field
from typing import List, Optional

_SPEC_RE = re.compile(r'%[-+ #0]*\d*(?:\.\d+)?(?:hh|h|ll|l|j|z|t|L)?'
                      r'([diuoxXfFeEgGaAcspn%])')
_VALUE_SPECS = set('diuoxXfFeEgGaA')
_PTR_SPECS = set('spn')


@dataclass
class SpecCount:
    value_args: int = 0      # 值型实参数
    ptr_args: int = 0        # 引用型实参数 (%s/%p/%n)
    n_count: int = 0         # %n 出现次数
    total: int = 0
    raw: List[str] = field(default_factory=list)


def count_specs(fmt: str) -> SpecCount:
    """解析格式串, 统计各类说明符."""
    sc = SpecCount()
    for m in _SPEC_RE.finditer(fmt):
        conv = m.group(1)
        if conv == '%':
            continue
        sc.raw.append(m.group(0))
        sc.total += 1
        if conv == 'n':
            sc.n_count += 1
            sc.ptr_args += 1
        elif conv in _PTR_SPECS:
            sc.ptr_args += 1
        else:
            sc.value_args += 1
    return sc


def required_args(fmt: str) -> int:
    return count_specs(fmt).total
