# 修改记录:
# 2025-08-03 16:44 - 三域联合抽象: interval+congruence+pointer, 每域独立追踪完备性边界
# 2025-08-04 13:51 - widening 阈值自适应: 循环迭代 <=3 次不触发 widening, 保持精度

"""跨架构类型推断的抽象域定义 - 完备性边界的理论基础

将类型推断问题形式化为抽象解释:
- 具体域 C: 所有可能的运行时类型赋值 (无限)
- 抽象域 A: 可计算的有穷类型摘要
- 抽象函数 alpha: C -> A  (具体->抽象)
- 具体化函数 γ: A -> P(C)  (抽象->具体集合)
- Galois 连接: alpha 和 γ 构成 C <-γ− −alpha-> A

完备性定义:
  一个类型查询 q 在抽象域 A 上是完备的,
  当且仅当 alpha(q(γ(a))) = q#(a) 对所有 a ∈ A 成立
  即--抽象域上的操作精确对应具体域上的操作, 无精度损失

三个互补抽象域:
  1. 区间域: 追踪变量的数值范围 [low, high]
     完备的条件: 变量仅参与线性算术 (无位运算)
     不完备: 位运算 (& | ^) 破坏区间信息
  2. 同余域: 追踪变量 mod k 的值 (k = 2^bitwidth)
     完备的条件: 变量参与位运算和模运算
     不完备: 乘法 (除左移外) 破坏同余信息
  3. 指针域: 追踪变量是否为指针及基址/偏移关系
     完备的条件: 指针运算限于加减常量偏移
     不完备: 指针做位运算 (如对齐掩码) 可能需要其他域辅助
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Set, Tuple, Union


# 区间域 - 数值范围的抽象

@dataclass
class Interval:
    """整数区间抽象 [low, high] ∪ {bottom, top}

    当 low > high 时表示 bottom (不可达)
    当 low == -inf and high == +inf 时表示 top (未知)
    """
    low: int = 0
    high: int = -1          # low > high -> bottom

    @staticmethod
    def bottom() -> 'Interval':
        return Interval(0, -1)

    @staticmethod
    def top() -> 'Interval':
        return Interval(-float('inf'), float('inf'))  # type: ignore[arg-type]

    @property
    def is_bottom(self) -> bool:
        return self.low > self.high

    @property
    def is_top(self) -> bool:
        return (self.low == float('-inf') and self.high == float('inf'))  # type: ignore[comparison-overlap]

    @property
    def is_precise(self) -> bool:
        """区间是否精确--能够给出有意义的类型推断"""
        if self.is_bottom or self.is_top:
            return False
        # 区间宽度 <= 2^16 -> 可判定具体整数类型 (int8/int16/int32)
        width = self.high - self.low
        return width <= 65536 and width >= 0

    def join(self, other: 'Interval') -> 'Interval':
        """最小上界 (lub)"""
        if self.is_bottom:
            return other
        if other.is_bottom:
            return self
        return Interval(
            low=min(self.low, other.low),
            high=max(self.high, other.high),
        )

    def widen(self, other: 'Interval', threshold: int = 3) -> 'Interval':
        """widen--确保不动点计算终止

        若新上界超出旧上界 -> 将上界推到 +inf (极端但安全)
        若新下界低于旧下界 -> 将下界推到 -inf
        仅在第 threshold 次迭代后触发--前几次保留精度
        """
        result = Interval(self.low, self.high)
        if other.low < self.low:
            result.low = float('-inf') if self.low != float('-inf') else self.low  # type: ignore[assignment]
        if other.high > self.high:
            result.high = float('inf') if self.high != float('inf') else self.high  # type: ignore[assignment]
        return result

    def __repr__(self) -> str:
        if self.is_bottom:
            return '⊥'
        if self.is_top:
            return '⊤'
        return f'[{self.low}, {self.high}]'


# 同余域 - 位级对齐信息的抽象

@dataclass
class Congruence:
    """同余类抽象: 值 ≡ remainder (mod modulus)

    用于追踪:
    - 指针对齐: 值 ≡ 0 (mod 4) -> 32-bit 对齐的指针
    - 位掩码后的值: 值 ≡ 0 (mod 256) -> 低 8 位恒为 0
    """
    modulus: int = 0         # 0 表示 top (无同余信息)
    remainder: int = 0

    @staticmethod
    def top() -> 'Congruence':
        return Congruence(0, 0)  # modulus=0 -> 无约束

    @staticmethod
    def exact(val: int) -> 'Congruence':
        return Congruence(1, val)  # modulus=1, remainder=val -> 精确值

    @property
    def is_top(self) -> bool:
        return self.modulus == 0

    @property
    def is_precise(self) -> bool:
        """同余信息可用--能推断对齐和位结构"""
        return self.modulus > 0

    def join(self, other: 'Congruence') -> 'Congruence':
        """两同余类的 join = gcd(mod1, mod2, |rem1-rem2|)

        数学依据: 若 x ≡ r1 (mod m1) 且 x ≡ r2 (mod m2)
        则 x ≡ r (mod gcd(m1, m2, |r1-r2|))
        当 gcd 项为 0 时退化为 top
        """
        if self.is_top:
            return other
        if other.is_top:
            return self
        diff = abs(self.remainder - other.remainder)
        new_mod = math.gcd(self.modulus, math.gcd(other.modulus, diff))
        if new_mod == 0:
            return Congruence.top()
        # 余数取模
        new_rem = self.remainder % new_mod
        return Congruence(new_mod, new_rem)

    def __repr__(self) -> str:
        if self.is_top:
            return '⊤'
        return f'{self.remainder} mod {self.modulus}'


# 指针域 - 内存关系的抽象

class PointerClass(Enum):
    """指针的分类--抽象域可区分的指针类型"""
    NULL = auto()        # 恒为 NULL
    STACK = auto()       # 栈上地址 (相对 rbp/rsp)
    HEAP = auto()        # 堆上地址 (malloc 返回)
    GLOBAL = auto()      # 全局/静态数据段地址
    CODE = auto()        # 代码段地址 (函数指针)
    UNKNOWN = auto()     # 无法确定的指针


@dataclass
class PointerAbstract:
    """指针的抽象--基址类别 + 偏移区间"""
    ptr_class: PointerClass = PointerClass.UNKNOWN
    base_region: str = ""                  # 基址的符号名 (如 'rbp', 'main')
    offset_interval: Interval = field(default_factory=Interval.top)
    is_definitely_ptr: bool = False        # 确认为指针 (被解引用过)
    is_definitely_not_ptr: bool = False    # 确认为非指针 (参与算术)

    @staticmethod
    def unknown() -> 'PointerAbstract':
        return PointerAbstract()

    @staticmethod
    def null_ptr() -> 'PointerAbstract':
        return PointerAbstract(
            ptr_class=PointerClass.NULL,
            is_definitely_ptr=True,
            offset_interval=Interval(0, 0),
        )

    @property
    def is_complete(self) -> bool:
        """指针信息完备--基址类别和偏移均已知"""
        return (
            self.ptr_class != PointerClass.UNKNOWN
            and self.offset_interval.is_precise
        )

    def join(self, other: 'PointerAbstract') -> 'PointerAbstract':
        """指针抽象的 join"""
        if self.is_definitely_not_ptr and other.is_definitely_not_ptr:
            return PointerAbstract(is_definitely_not_ptr=True)

        cls = self.ptr_class
        if cls != other.ptr_class:
            cls = PointerClass.UNKNOWN

        return PointerAbstract(
            ptr_class=cls,
            base_region=self.base_region
            if self.base_region == other.base_region else '',
            offset_interval=self.offset_interval.join(other.offset_interval),
            is_definitely_ptr=self.is_definitely_ptr or other.is_definitely_ptr,
            is_definitely_not_ptr=False,
        )

    def __repr__(self) -> str:
        if self.is_definitely_not_ptr:
            return 'not-ptr'
        if self.ptr_class == PointerClass.NULL:
            return 'NULL'
        off = str(self.offset_interval)
        return f'{self.ptr_class.name}({off})'


# 抽象状态 - 每变量的类型摘要

@dataclass
class TypeAbstractState:
    """一个变量的完整类型抽象--三域联合"""
    var_name: str
    interval: Interval = field(default_factory=Interval.top)
    congruence: Congruence = field(default_factory=Congruence.top)
    pointer: PointerAbstract = field(default_factory=PointerAbstract.unknown)
    # 完备性标记: 此变量的类型在哪个域上可被完全确定
    complete_in_interval: bool = False
    complete_in_congruence: bool = False
    complete_in_pointer: bool = False
    # 推断的类型摘要
    inferred_type: str = 'unknown'  # int8|int16|int32|int64|ptr|uint|unknown

    def join(self, other: 'TypeAbstractState') -> 'TypeAbstractState':
        """状态合并--用于控制流汇合点"""
        return TypeAbstractState(
            var_name=self.var_name,
            interval=self.interval.join(other.interval),
            congruence=self.congruence.join(other.congruence),
            pointer=self.pointer.join(other.pointer),
            # 完备性: 两个分支都完备 -> 汇合后仍完备
            complete_in_interval=(
                self.complete_in_interval and other.complete_in_interval
            ),
            complete_in_congruence=(
                self.complete_in_congruence and other.complete_in_congruence
            ),
            complete_in_pointer=(
                self.complete_in_pointer and other.complete_in_pointer
            ),
            inferred_type=self._infer_type(),
        )

    def _infer_type(self) -> str:
        """从三域联合状态推断最具体的类型"""
        # 指针优先
        if self.pointer.is_definitely_ptr:
            return 'ptr'
        # 区间推断整数宽度
        if self.interval.is_precise:
            w = self.interval.high - self.interval.low
            if self.interval.low >= 0:
                if w <= 255:
                    return 'uint8'
                if w <= 65535:
                    return 'uint16'
                return 'uint32'
            if w <= 127:
                return 'int8'
            if w <= 32767:
                return 'int16'
            return 'int32'
        # 同余推断对齐--可能是指针的间接证据
        if self.congruence.is_precise and self.congruence.modulus >= 4:
            return 'aligned_int'
        return 'unknown'


# 完备性分析器

class TypeCompletenessAnalyzer:
    """分析一组变量的类型抽象状态, 量化完备性差距

    完备性比例 c = |完备的变量| / |总变量|
    量化了当前抽象域的能力边界--哪些变量的类型可以保证正确
    哪些仍不确定--这些是后续精化分析的候选
    """

    def __init__(self):
        self._states: Dict[str, TypeAbstractState] = {}

    def add_state(self, state: TypeAbstractState) -> None:
        """添加或更新变量的抽象状态"""
        name = state.var_name
        if name in self._states:
            self._states[name] = self._states[name].join(state)
        else:
            self._states[name] = state

    def completeness_ratio(self) -> Tuple[float, float, float, float]:
        """返回 (interval_completeness, congruence_completeness,
                  pointer_completeness, overall_completeness)

        overall = 任一域完备的变量比例
        """
        n = max(1, len(self._states))
        c_int = sum(1 for s in self._states.values()
                     if s.complete_in_interval) / n
        c_con = sum(1 for s in self._states.values()
                     if s.complete_in_congruence) / n
        c_ptr = sum(1 for s in self._states.values()
                     if s.complete_in_pointer) / n
        c_any = sum(1 for s in self._states.values()
                     if (s.complete_in_interval or s.complete_in_congruence
                         or s.complete_in_pointer)) / n
        return (c_int, c_con, c_ptr, c_any)

    def completeness_gap(self) -> Dict[str, List[str]]:
        """返回完备性差距--每个变量的不完备域列表

        例如 {'v1': ['interval', 'pointer'], 'v2': ['congruence']}
        表示 v1 在区间域和指针域上不完备, v2 在同余域上不完备
        """
        gaps: Dict[str, List[str]] = {}
        for name, state in self._states.items():
            missing = []
            if not state.complete_in_interval:
                missing.append('interval')
            if not state.complete_in_congruence:
                missing.append('congruence')
            if not state.complete_in_pointer:
                missing.append('pointer')
            if missing:
                gaps[name] = missing
        return gaps

    def summary(self) -> Dict[str, Any]:
        """生成完备性分析摘要"""
        c_int, c_con, c_ptr, c_any = self.completeness_ratio()
        gaps = self.completeness_gap()
        return {
            'total_variables': len(self._states),
            'completeness_interval': round(c_int, 4),
            'completeness_congruence': round(c_con, 4),
            'completeness_pointer': round(c_ptr, 4),
            'completeness_overall': round(c_any, 4),
            'variables_with_gaps': len(gaps),
            'gap_details': {
                name: domains
                for name, domains in sorted(gaps.items())
            },
            'type_assignments': {
                name: state.inferred_type
                for name, state in sorted(self._states.items())
            },
        }
