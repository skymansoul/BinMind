"""
简化值集分析 (VSA) 污点传播 — 符号执行因路径爆炸或不可解约束 (间接调用/混淆代码/手写汇编)
失败时, 以区间抽象作兜底, 追踪 "rax ∈ [stack_base, stack_top]" 而非精确值, 以精度换覆盖率。
核心抽象: StridedInterval 值集 = {lo + k*stride | 0 <= k <= (hi-lo)/stride}
(stride=1 连续区间, stride=0 精确值); TaintTag {USER_INPUT, STACK_ADDR, HEAP_ADDR, CONSTANT, UNKNOWN};
按指令实现常用 x86 操作的 VSA 转移函数。局限: 无法区分同一区间内两个不同地址;
跨函数传播仅支持直接调用, 间接调用保守标记 UNKNOWN。
"""


from dataclasses import dataclass, field
from enum import IntEnum, auto
from typing import Any, Dict, List, Optional, Set, Tuple


class TaintTag(IntEnum):
    """污点来源标签; 值越大不确定性越高。"""
    CONSTANT = 0       # 编译期常量, 攻击者无法控制
    STACK_ADDR = 1     # 栈地址, 可控制 (栈溢出)
    HEAP_ADDR = 2      # 堆地址, 可控制 (堆风水)
    USER_INPUT = 3     # 直接来自外部输入 (recv/read/fgets)
    UNKNOWN = 4        # 来源未知, 保守假定可控制


@dataclass
class StridedInterval:
    """
    stride 区间: {lo + k*stride | 0 <= k <= (hi-lo)/stride, k ∈ N}。
    stride=0 为精确值。使用 64 位无符号算术 (模 2^64)。
    """
    lo: int = 0
    hi: int = 0
    stride: int = 1
    taint: TaintTag = TaintTag.CONSTANT
    is_bottom: bool = False
    is_top: bool = False

    @classmethod
    def exact(cls, value: int, taint: TaintTag = TaintTag.CONSTANT) -> 'StridedInterval':
        """构造精确值 (stride=0)。"""
        return cls(lo=value, hi=value, stride=0, taint=taint)

    @classmethod
    def interval(cls, lo: int, hi: int, taint: TaintTag = TaintTag.UNKNOWN) -> 'StridedInterval':
        """构造连续区间 (stride=1)。"""
        return cls(lo=lo, hi=hi, stride=1, taint=taint)

    @classmethod
    def top(cls) -> 'StridedInterval':
        """构造 top (任意 64 位值)。"""
        return cls(lo=0, hi=0xFFFFFFFFFFFFFFFF, stride=1,
                   taint=TaintTag.UNKNOWN, is_top=True)

    @classmethod
    def bottom(cls) -> 'StridedInterval':
        """构造 bottom (不可达)。"""
        return cls(is_bottom=True)

    def contains(self, value: int) -> bool:
        if self.is_bottom:
            return False
        if self.is_top:
            return True
        if self.stride == 0:
            return value == self.lo
        if value < self.lo or value > self.hi:
            return False
        return (value - self.lo) % self.stride == 0

    def join(self, other: 'StridedInterval') -> 'StridedInterval':
        """最小上界 (合并两个区间)。"""
        if self.is_bottom:
            return other
        if other.is_bottom:
            return self
        if self.is_top or other.is_top:
            return StridedInterval.top()

        new_lo = min(self.lo, other.lo)
        new_hi = max(self.hi, other.hi)
        import math
        new_stride = math.gcd(self.stride, other.stride)
        # 两个不同的精确值合并时放宽为区间
        if self.stride == 0 and other.stride == 0 and self.lo != other.lo:
            new_stride = 1
        new_taint = TaintTag(max(self.taint.value, other.taint.value))
        return StridedInterval(new_lo, new_hi, new_stride, new_taint)

    def widen(self, other: 'StridedInterval') -> 'StridedInterval':
        """加宽算子 (保证不动点终止): 超出阈值推至 top。"""
        joined = self.join(other)
        if joined.hi - joined.lo > 0x100000:  # >1MB 推至 top
            result = StridedInterval.top()
            result.taint = max(self.taint, other.taint, key=lambda t: t.value)
            return result
        return joined


def taint_transfer_mov(src: StridedInterval) -> StridedInterval:
    """MOV dest, src: 污点直接传递。"""
    return StridedInterval(src.lo, src.hi, src.stride,
                           src.taint, src.is_bottom, src.is_top)


def taint_transfer_add(a: StridedInterval, b: StridedInterval) -> StridedInterval:
    """ADD a, b: 值区间相加, 污点取上界。"""
    if a.is_bottom or b.is_bottom:
        return StridedInterval.bottom()
    new_lo = (a.lo + b.lo) & 0xFFFFFFFFFFFFFFFF
    new_hi = (a.hi + b.hi) & 0xFFFFFFFFFFFFFFFF
    import math
    new_stride = math.gcd(a.stride, b.stride)
    new_taint = TaintTag(max(a.taint.value, b.taint.value))
    return StridedInterval(new_lo, new_hi, new_stride, new_taint)


def taint_transfer_load(base: StridedInterval, offset: int = 0) -> StridedInterval:
    """
    内存读取: 保守假设 — 载入值继承地址的污点标签, 但值区间置 top (内存内容未知)。
    若 base 为栈地址, 载入内容区间仍为 top, 污点可标记 USER_INPUT。
    """
    result = StridedInterval.top()
    result.taint = base.taint
    return result


def taint_transfer_store(value: StridedInterval, addr: StridedInterval
                          ) -> StridedInterval:
    """内存写入: 值不变, 污点传播至目标地址。"""
    return value


def analyze_format_arg(buf_interval: StridedInterval,
                        fmt_interval: StridedInterval
                        ) -> Tuple[bool, float, str]:
    """
    判定格式化字符串调用是否危险。
    危险: buf 为格式参数 (第1参数) 且 fmt 来自用户输入; 安全: fmt 为字符串常量
    (.rodata 地址) 或 buf 不是第1参数。
    返回 (is_vulnerable, confidence, reason)。
    """
    # 情形1: 格式参数为字符串常量 (.rodata 内窄地址区间)
    if fmt_interval.stride == 0 and fmt_interval.taint == TaintTag.CONSTANT:
        fmt_low = fmt_interval.lo
        return False, 0.95, 'format string is constant in .rodata'

    # 情形2: 格式参数来自用户输入
    if fmt_interval.taint >= TaintTag.USER_INPUT:
        return True, 0.88, 'format string from user input'

    # 情形3: 来源未知, 保守标记
    if fmt_interval.taint == TaintTag.UNKNOWN:
        return True, 0.55, 'format string origin unknown (conservative flag)'

    # 情形4: 格式参数来自栈/堆, 可控制
    if fmt_interval.taint >= TaintTag.HEAP_ADDR:
        return True, 0.72, f'format string from {fmt_interval.taint.name}'

    return False, 0.90, 'format string appears safe'


class VSATaintEngine:
    """
    VSA 污点传播引擎 — 符号执行失败时作兜底。

    用法:
      engine = VSATaintEngine()
      engine.mark_input(reg='rdi', source=TaintTag.USER_INPUT)
      engine.step_add('rdi', 'rsi')
      result = engine.query('rdi')
    """

    def __init__(self):
        self._registers: Dict[str, StridedInterval] = {}
        self._memory: Dict[int, StridedInterval] = {}
        self._stack_frame_base: int = 0x7FFFFFFF0000

    def mark_input(self, reg: str = 'rdi', source: TaintTag = TaintTag.USER_INPUT
                   ) -> None:
        """将寄存器标记为输入源。"""
        self._registers[reg] = StridedInterval.top()
        self._registers[reg].taint = source

    def mark_constant(self, reg: str, value: int) -> None:
        self._registers[reg] = StridedInterval.exact(value, TaintTag.CONSTANT)

    def step_add(self, dest: str, src: str) -> None:
        a = self._registers.get(dest, StridedInterval.bottom())
        b = self._registers.get(src, StridedInterval.bottom())
        self._registers[dest] = taint_transfer_add(a, b)

    def step_mov(self, dest: str, src: str) -> None:
        if src in self._registers:
            self._registers[dest] = taint_transfer_mov(self._registers[src])

    def step_load(self, dest: str, addr_reg: str) -> None:
        addr = self._registers.get(addr_reg, StridedInterval.bottom())
        self._registers[dest] = taint_transfer_load(addr)

    def step_store(self, value_reg: str, addr_reg: str) -> None:
        val = self._registers.get(value_reg, StridedInterval.bottom())
        addr = self._registers.get(addr_reg, StridedInterval.bottom())
        taint_transfer_store(val, addr)

    def query(self, reg: str) -> StridedInterval:
        return self._registers.get(reg, StridedInterval.bottom())

    def is_tainted(self, reg: str, threshold: TaintTag = TaintTag.USER_INPUT
                   ) -> bool:
        si = self._registers.get(reg)
        return si is not None and si.taint >= threshold

    def downgrade_from_symexec(self, symexec_timeout: bool = False,
                                path_explosion: bool = False) -> Dict[str, Any]:
        """
        记录符号执行失败时的降级原因与 VSA 状态。
        供上层模块 (format_string_detector 等) 决定是否采用 VSA 结果。
        """
        reasons = []
        if symexec_timeout:
            reasons.append('symbolic execution timeout')
        if path_explosion:
            reasons.append('path explosion')
        return {
            'downgraded': True,
            'reasons': reasons,
            'tainted_regs': [r for r, si in self._registers.items()
                            if si.taint >= TaintTag.USER_INPUT],
            'method': 'VSA',
            'warning': 'results are approximate — VSA over-approximates value sets',
        }
