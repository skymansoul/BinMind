# coding: utf-8
#
"""
区间抽象域-轻量级抽象解释基础设施。

抽象域: 区间抽象（Box Domain），O(n×k²)。
仅处理安全敏感操作(memcpy/strcpy等)的缓冲区语义，其余回退TOP。
"""

import re
import math
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional

_log = logging.getLogger(__name__)


class AbstractValue:
    """区间抽象值-变量的可能取值区间[min, max]。

    BOTTOM: 不可达(lo>hi); TOP: 任意值(±inf)
    """

    def __init__(self, lo: float = float('-inf'),
                  hi: float = float('inf')):
        self.lo = lo
        self.hi = hi

    @property
    def is_bottom(self) -> bool:
        return self.lo > self.hi

    @property
    def is_top(self) -> bool:
        return self.lo == float('-inf') and self.hi == float('inf')

    def join(self, other: 'AbstractValue') -> 'AbstractValue':
        return AbstractValue(min(self.lo, other.lo), max(self.hi, other.hi))

    def widen(self, other: 'AbstractValue') -> 'AbstractValue':
        lo = float('-inf') if other.lo < self.lo else self.lo
        hi = float('inf') if other.hi > self.hi else self.hi
        return AbstractValue(lo, hi)

    def contains(self, val: float) -> bool:
        return self.lo <= val <= self.hi

    def __repr__(self):
        return f"[{self.lo}, {self.hi}]"


@dataclass
class AbstractState:
    """抽象程序状态-变量名→AbstractValue映射"""
    variables: Dict[str, AbstractValue] = field(default_factory=dict)
    path_condition: str = ""

    def copy(self) -> 'AbstractState':
        return AbstractState(
            variables={k: AbstractValue(v.lo, v.hi) for k, v in self.variables.items()},
            path_condition=self.path_condition)


class AbstractInterpreter:
    """区间抽象解释器-对C代码片段执行区间抽象域语义分析。

    支持: 赋值/条件精化/敏感函数调用(memcpy等)
    限制: 无指针解引用/循环用加宽/跨函数回退TOP
    """

    _MEMORY_OPS = {'memcpy', 'strcpy', 'strncpy', 'strcat', 'strncat',
                   'sprintf', 'snprintf', 'memmove', 'memset', 'read', 'recv'}
    _BUFFER_HINTS = {'buf', 'buffer', 'dst', 'dest', 'src', 'data', 'out', 'in'}

    def interpret_sequence(self, lines: List[str],
                            initial_state: AbstractState = None
                            ) -> AbstractState:
        """对代码行序列执行抽象解释-逐行更新区间状态"""
        state = initial_state.copy() if initial_state else AbstractState()
        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith('//') or stripped.startswith('/*'):
                continue
            self._step(stripped, state)
        return state

    def _step(self, line: str, state: AbstractState):
        """单行抽象语义"""
        m = re.match(r'(\w+)\s*=\s*(.+);', line)
        if m:
            val = self._eval(m.group(2).strip(), state)
            if val is not None:
                state.variables[m.group(1)] = val
            return

        m = re.match(r'if\s*\((.+)\)', line)
        if m:
            self._refine(m.group(1), state)
            return

        m = re.match(r'(\w+)\s*\((.*)\);', line)
        if m:
            self._model_call(m.group(1), m.group(2), state)

    def _eval(self, expr: str, state: AbstractState) -> Optional[AbstractValue]:
        """表达式求值-常量/变量/二元运算的区间抽象"""
        expr = expr.strip().rstrip(';')
        try:
            v = float(expr)
            return AbstractValue(v, v)
        except ValueError:
            pass
        if expr in state.variables:
            return state.variables[expr]
        for op in ('+', '-', '*'):
            parts = expr.split(f' {op} ')
            if len(parts) == 2:
                a = self._eval(parts[0], state)
                b = self._eval(parts[1], state)
                if a is not None and b is not None:
                    if op == '+':
                        return AbstractValue(a.lo + b.lo, a.hi + b.hi)
                    elif op == '-':
                        return AbstractValue(a.lo - b.hi, a.hi - b.lo)
                    else:
                        p = [a.lo * b.lo, a.lo * b.hi, a.hi * b.lo, a.hi * b.hi]
                        return AbstractValue(min(p), max(p))
                break
        if '(' in expr:
            return AbstractValue()
        return None

    def _refine(self, cond: str, state: AbstractState):
        """条件精化-保守区间收缩"""
        for op in ('>=', '<=', '>', '<', '=='):
            parts = cond.split(op)
            if len(parts) != 2:
                continue
            lhs = parts[0].strip()
            rhs = self._eval(parts[1].strip(), state)
            if lhs not in state.variables or rhs is None:
                continue
            cur = state.variables[lhs]
            if op == '>=':
                state.variables[lhs] = AbstractValue(max(cur.lo, rhs.lo), cur.hi)
            elif op == '<=':
                state.variables[lhs] = AbstractValue(cur.lo, min(cur.hi, rhs.hi))
            elif op == '>':
                state.variables[lhs] = AbstractValue(max(cur.lo, rhs.lo + 1e-10), cur.hi)
            elif op == '<':
                state.variables[lhs] = AbstractValue(cur.lo, min(cur.hi, rhs.hi - 1e-10))
            break

    def _model_call(self, func: str, args_str: str, state: AbstractState):
        """敏感函数调用建模-缓冲区写入的抽象效果"""
        args = [a.strip() for a in args_str.split(',')]
        if func in self._MEMORY_OPS and len(args) >= 2:
            dst = args[0]
            if dst in state.variables:
                # 写入效果: dst区间保守扩展
                cur = state.variables[dst]
                if len(args) >= 3:
                    sz = self._eval(args[2], state)
                    if sz is not None and not sz.is_top:
                        state.variables[dst] = AbstractValue(cur.lo, max(cur.hi, sz.hi))
        elif func in ('malloc', 'calloc', 'realloc') and args:
            sz = self._eval(args[0], state)
            if sz is not None and sz.lo >= 0:
                state.variables['ret'] = AbstractValue(0, float('inf'))


__all__ = [
    "AbstractValue",
    "AbstractState",
    "AbstractInterpreter",
]
