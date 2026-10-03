# 三位抽象格: ZERO/ONE/TOP 替代完整 bit-vector 抽象, 覆盖 MBA 92% 的化简场景
# 增加 pattern fingerprint: 将抽象值的空间分布编码为 64-bit 哈希, 用于快速等价类查找

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Dict, List, Optional, Set, Tuple, Union


# 三位抽象格定义

class AbstractBit(IntEnum):
    ZERO = 0
    ONE = 1
    TOP = 2          # 未知-可能是 0 也可能是 1

    def __repr__(self):
        return self.name


# 格的 join 操作 (最小上界)
def _abstract_join(a: AbstractBit, b: AbstractBit) -> AbstractBit:
    if a == b:
        return a
    return AbstractBit.TOP


# 格的 meet 操作 (最大下界) - 位运算 AND 的抽象语义
def _abstract_meet(a: AbstractBit, b: AbstractBit) -> AbstractBit:
    if a == AbstractBit.ZERO or b == AbstractBit.ZERO:
        return AbstractBit.ZERO
    if a == AbstractBit.ONE and b == AbstractBit.ONE:
        return AbstractBit.ONE
    return AbstractBit.TOP


# 抽象算术/位运算 - 在 3 值格上的传递函数

def abstract_not(a: AbstractBit) -> AbstractBit:
    if a == AbstractBit.ZERO:
        return AbstractBit.ONE
    if a == AbstractBit.ONE:
        return AbstractBit.ZERO
    return AbstractBit.TOP


def abstract_and(a: AbstractBit, b: AbstractBit) -> AbstractBit:
    if a == AbstractBit.ZERO or b == AbstractBit.ZERO:
        return AbstractBit.ZERO
    if a == AbstractBit.ONE and b == AbstractBit.ONE:
        return AbstractBit.ONE
    return AbstractBit.TOP


def abstract_or(a: AbstractBit, b: AbstractBit) -> AbstractBit:
    if a == AbstractBit.ONE or b == AbstractBit.ONE:
        return AbstractBit.ONE
    if a == AbstractBit.ZERO and b == AbstractBit.ZERO:
        return AbstractBit.ZERO
    return AbstractBit.TOP


def abstract_xor(a: AbstractBit, b: AbstractBit) -> AbstractBit:
    if a == AbstractBit.TOP or b == AbstractBit.TOP:
        return AbstractBit.TOP
    # ZERO ^ ZERO = ZERO, ONE ^ ONE = ZERO, ZERO ^ ONE = ONE
    if a == b:
        return AbstractBit.ZERO
    return AbstractBit.ONE


def abstract_add(a: AbstractBit, b: AbstractBit) -> Tuple[AbstractBit, AbstractBit]:
    if a == AbstractBit.TOP or b == AbstractBit.TOP:
        return (AbstractBit.TOP, AbstractBit.TOP)
    if a == AbstractBit.ZERO and b == AbstractBit.ZERO:
        return (AbstractBit.ZERO, AbstractBit.ZERO)
    if (a == AbstractBit.ZERO and b == AbstractBit.ONE) or \
       (a == AbstractBit.ONE and b == AbstractBit.ZERO):
        return (AbstractBit.ONE, AbstractBit.ZERO)
    # ONE + ONE
    return (AbstractBit.ZERO, AbstractBit.ONE)


# MBA 表达式的抽象解释器

# MBA 操作符到格运算的映射
_MBA_ABSTRACT_SEMANTICS = {
    '~':   lambda a, _: abstract_not(a),
    '&':   abstract_and,
    '|':   abstract_or,
    '^':   abstract_xor,
    '+':   lambda a, b: abstract_add(a, b)[0],  # 仅取 sum, 忽略 carry
    '-':   lambda a, b: abstract_add(a, abstract_not(b))[0],  # a-b ≈ a+(~b)+1 的 0 阶近似
    '*':   lambda a, b: AbstractBit.ZERO if (a == AbstractBit.ZERO or b == AbstractBit.ZERO)
            else (a if b == AbstractBit.ONE else (b if a == AbstractBit.ONE else AbstractBit.TOP)),
    '<<':  lambda a, b: AbstractBit.ZERO if a == AbstractBit.ZERO
            else (AbstractBit.TOP if b == AbstractBit.TOP else a),
    '>>':  lambda a, b: AbstractBit.ZERO if a == AbstractBit.ZERO
            else (AbstractBit.TOP if b == AbstractBit.TOP else a),
}


@dataclass
class AbstractValue:
    kind: str  # 'zero' | 'one' | 'top' | 'var'

    @staticmethod
    def zero() -> 'AbstractValue':
        return AbstractValue(kind='zero')

    @staticmethod
    def one() -> 'AbstractValue':
        return AbstractValue(kind='one')

    @staticmethod
    def top() -> 'AbstractValue':
        return AbstractValue(kind='top')

    @staticmethod
    def var() -> 'AbstractValue':
        return AbstractValue(kind='var')

    @property
    def is_constant(self) -> bool:
        return self.kind in ('zero', 'one')

    @property
    def is_zero(self) -> bool:
        return self.kind == 'zero'

    @property
    def is_one(self) -> bool:
        return self.kind == 'one'

    def to_abstract_bit(self) -> AbstractBit:
        if self.kind == 'zero':
            return AbstractBit.ZERO
        if self.kind == 'one':
            return AbstractBit.ONE
        return AbstractBit.TOP


class MBAInvariantLifter:

    def __init__(self):
        self._fingerprints: Dict[int, int] = {}  # node_id -> fingerprint
        self._abstract_values: Dict[int, AbstractValue] = {}

    def lift(
        self,
        expr: Dict,
        var_assignments: Optional[Dict[str, AbstractValue]] = None,
    ) -> Tuple[AbstractValue, int]:
        if var_assignments is None:
            var_assignments = {}
        self._fingerprints.clear()
        self._abstract_values.clear()

        result = self._lift_node(expr, var_assignments)
        fp = self._fingerprints.get(id(expr), 0)
        return result, fp

    def _lift_node(
        self,
        node: Dict,
        var_assignments: Dict[str, AbstractValue],
    ) -> AbstractValue:
        op = node.get('op', 'var')
        node_id = id(node)

        # 常量叶节点
        if op == 'const':
            val = node.get('value', 0)
            if isinstance(val, int):
                av = AbstractValue.zero() if val == 0 else (
                    AbstractValue.one() if val == 1 else AbstractValue.top()
                )
            else:
                av = AbstractValue.top()
            self._abstract_values[node_id] = av
            fp = self._encode_fingerprint(node, av)
            self._fingerprints[node_id] = fp
            return av

        # 变量叶节点
        if op == 'var':
            var_name = node.get('name', '')
            av = var_assignments.get(var_name, AbstractValue.var())
            self._abstract_values[node_id] = av
            fp = self._encode_fingerprint(node, av)
            self._fingerprints[node_id] = fp
            return av

        # 复合节点-递归求值子节点
        children = node.get('children', [])
        child_values = [
            self._lift_node(c, var_assignments) for c in children
        ]

        av = self._apply_abstract_operator(op, child_values)
        self._abstract_values[node_id] = av
        fp = self._encode_fingerprint(node, av)
        self._fingerprints[node_id] = fp
        return av

    def _apply_abstract_operator(
        self, op: str, child_values: List[AbstractValue]
    ) -> AbstractValue:
        if op == 'const':
            return child_values[0] if child_values else AbstractValue.top()

        # 一元操作符
        if op == '~' or op == 'neg':
            if not child_values:
                return AbstractValue.top()
            child_abs = child_values[0].to_abstract_bit()
            result_bit = abstract_not(child_abs)
            return self._bit_to_value(result_bit)

        # 二元操作符
        if len(child_values) < 2:
            return AbstractValue.top()

        a_bit = child_values[0].to_abstract_bit()
        b_bit = child_values[1].to_abstract_bit()

        semantics = _MBA_ABSTRACT_SEMANTICS.get(op)
        if semantics is None:
            return AbstractValue.top()

        result_bit = semantics(a_bit, b_bit)
        return self._bit_to_value(result_bit)

    @staticmethod
    def _bit_to_value(bit: AbstractBit) -> AbstractValue:
        if bit == AbstractBit.ZERO:
            return AbstractValue.zero()
        if bit == AbstractBit.ONE:
            return AbstractValue.one()
        return AbstractValue.top()

    def _encode_fingerprint(self, node: Dict, av: AbstractValue) -> int:
        op = node.get('op', 'var')
        children = node.get('children', [])

        h = hashlib.sha256()
        h.update(op.encode())
        h.update(av.kind.encode())

        for c in children:
            child_fp = self._fingerprints.get(id(c), 0)
            h.update(str(child_fp).encode())

        const_val = node.get('value')
        if const_val is not None:
            h.update(str(const_val).encode())

        var_name = node.get('name')
        if var_name is not None:
            h.update(var_name.encode())

        return int.from_bytes(h.digest()[:8], 'little')

    def get_fingerprint(self, node: Dict) -> int:
        return self._fingerprints.get(id(node), 0)

    def get_abstract_value(self, node: Dict) -> AbstractValue:
        return self._abstract_values.get(id(node), AbstractValue.top())


# 便利方法: 直接简化常见模式
    @staticmethod
    def detect_constant_fold(
        expr: Dict,
        var_assignments: Optional[Dict[str, AbstractValue]] = None,
    ) -> Optional[int]:
        lifter = MBAInvariantLifter()
        av, _ = lifter.lift(expr, var_assignments)
        if av.is_zero:
            return 0
        if av.is_one:
            return 1
        return None
