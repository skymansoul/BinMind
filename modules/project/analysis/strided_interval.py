# 跨步区间抽象域 (Strided Interval Domain): 扩展标准区间[lo,hi]为[lo,hi,stride]
# 标准区间在追踪循环变量时丢失同余信息.
#   i=0; while(i<128) i+=4 → 标准区间[0,127], 跨步区间[0,124,4]
#   跨步区间能证明 "i只能是4的倍数", 因此在数组访问buf[i]时,
#   若buf只有4个元素, 跨步区间能精确证明不会越界 (而标准区间会误报)
# 理论来源:
#   G. Balakrishnan "WYSINWYX: What You See Is Not What You eXecute"
#     (PhD thesis, UW-Madison 2007) — Strided Interval在VSA中的应用
#   Reps et al. "Weighted Pushdown Systems" (FSE 2014)
#     — 加权下推系统中的跨步区间传播
# 与现有ValueRange的关系: 互补而非替代 — 标准区间用于快速判断,
#   跨步区间用于需要同余信息的精确判定 (如循环数组写入)
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Union
from enum import Enum, auto
import math

# 64位地址空间常量
_U64_MAX = 0xFFFFFFFFFFFFFFFF
_I64_MIN = -0x8000000000000000
_I64_MAX = 0x7FFFFFFFFFFFFFFF


class StrideType(Enum):
    """跨步区间中的步长类型判定."""
    CONSTANT = auto()      # 固定步长 (stride > 0, 如 i+=4)
    IRREGULAR = auto()     # 不规则 (stride=1, 退化为标准区间)
    UNKNOWN = auto()       # 完全未知 (stride=0, 即TOP)


@dataclass
class StridedInterval:
    """跨步区间: {lo + k*stride | k ∈ N, lo + k*stride ≤ hi}.

    语义: 值只能取 [lo, hi] 内 stride 的倍数.
    stride=1 → 退化为标准区间.
    stride=0 → TOP (无约束).
    """

    lo: int = 0          # 下界
    hi: int = _U64_MAX   # 上界
    stride: int = 1      # 步长 (≥1, 0表示TOP)
    is_top: bool = True
    is_bottom: bool = False

    @staticmethod
    def constant(val: int) -> 'StridedInterval':
        return StridedInterval(lo=val, hi=val, stride=1,
                               is_top=False, is_bottom=False)

    @staticmethod
    def top() -> 'StridedInterval':
        return StridedInterval(lo=0, hi=_U64_MAX, stride=0,
                               is_top=True, is_bottom=False)

    @staticmethod
    def bottom() -> 'StridedInterval':
        return StridedInterval(is_top=False, is_bottom=True)

    @staticmethod
    def interval(lo: int, hi: int) -> 'StridedInterval':
        """从标准区间创建 (stride=1, 即无同余约束)."""
        return StridedInterval(lo=lo, hi=hi, stride=1,
                               is_top=False, is_bottom=False)

    @staticmethod
    def strided(lo: int, hi: int, stride: int) -> 'StridedInterval':
        """创建带步长的跨步区间."""
        if stride <= 0:
            return StridedInterval.top()
        return StridedInterval(lo=lo, hi=hi, stride=stride,
                               is_top=False, is_bottom=False)

# 属性

    @property
    def is_constant(self) -> bool:
        return (not self.is_top and not self.is_bottom
                and self.lo == self.hi and self.stride == 1)

    @property
    def cardinality(self) -> int:
        """区间内可能的取值个数."""
        if self.is_top or self.is_bottom or self.stride == 0:
            return _U64_MAX
        if self.stride == 0:
            return 1
        return max(0, (self.hi - self.lo) // self.stride + 1)

    def contains(self, val: int) -> bool:
        """检查值是否在跨步区间内."""
        if self.is_top:
            return True
        if self.is_bottom:
            return False
        if val < self.lo or val > self.hi:
            return False
        if self.stride <= 1:
            return True
        return (val - self.lo) % self.stride == 0

# 格操作

    def join(self, other: 'StridedInterval') -> 'StridedInterval':
        """最小上界: 取并集的凸包 (stride可能退化为1)."""
        if self.is_bottom:
            return other
        if other.is_bottom:
            return self
        if self.is_top or other.is_top:
            return StridedInterval.top()
        new_lo = min(self.lo, other.lo)
        new_hi = max(self.hi, other.hi)
        # 若步长相同且区间对齐, 保留步长
        # 否则退化为stride=1 (丢失同余信息但保持上界)
        if (self.stride == other.stride
                and (self.lo - other.lo) % self.stride == 0):
            return StridedInterval.strided(new_lo, new_hi, self.stride)
        return StridedInterval.interval(new_lo, new_hi)

    def meet(self, other: 'StridedInterval') -> 'StridedInterval':
        """最大下界: 交集."""
        if self.is_bottom or other.is_bottom:
            return StridedInterval.bottom()
        if self.is_top:
            return other
        if other.is_top:
            return self
        # 计算交集区间
        new_lo = max(self.lo, other.lo)
        new_hi = min(self.hi, other.hi)
        if new_lo > new_hi:
            return StridedInterval.bottom()
        # 步长取最小公倍数
        new_stride = (self.stride * other.stride
                      // math.gcd(self.stride, other.stride))
        # 调整下界到最近的共同步长点
        base = max(self.lo, other.lo)
        if new_stride > 1 and (base - self.lo) % self.stride != 0:
            # 找到满足两个stride的起始点
            found = False
            for candidate in range(base, min(base + new_stride, new_hi + 1)):
                if (candidate - self.lo) % self.stride == 0 and \
                   (candidate - other.lo) % other.stride == 0:
                    base = candidate
                    found = True
                    break
            if not found:
                return StridedInterval.bottom()
        return StridedInterval.strided(base, new_hi, new_stride)

# 算术操作

    def add(self, other: 'StridedInterval') -> 'StridedInterval':
        """跨步区间加法."""
        if self.is_bottom or other.is_bottom:
            return StridedInterval.bottom()
        if self.is_top or other.is_top:
            return StridedInterval.top()
        new_lo = (self.lo + other.lo) & _U64_MAX
        new_hi = (self.hi + other.hi) & _U64_MAX
        # 步长: 取最大公约数 (两个stride组合后约束变弱)
        new_stride = math.gcd(self.stride, other.stride)
        if new_stride == 0:
            new_stride = 1
        return StridedInterval.strided(new_lo, new_hi, max(1, new_stride))

    def add_constant(self, delta: int) -> 'StridedInterval':
        """加常数: 平移区间, 步长不变."""
        if self.is_bottom:
            return StridedInterval.bottom()
        if self.is_top:
            return StridedInterval.top()
        new_lo = (self.lo + delta) & _U64_MAX
        new_hi = (self.hi + delta) & _U64_MAX
        if new_hi < new_lo:  # 溢出回绕
            return StridedInterval.top()
        return StridedInterval.strided(new_lo, new_hi, self.stride)

    def mul_constant(self, factor: int) -> 'StridedInterval':
        """乘常数: 步长乘以因子."""
        if self.is_bottom:
            return StridedInterval.bottom()
        if self.is_top:
            return StridedInterval.top()
        if factor == 0:
            return StridedInterval.constant(0)
        new_lo = self.lo * factor
        new_hi = self.hi * factor
        if factor < 0:
            new_lo, new_hi = self.hi * factor, self.lo * factor
        new_stride = self.stride * abs(factor)
        return StridedInterval.strided(new_lo, new_hi, new_stride)

    def sub(self, other: 'StridedInterval') -> 'StridedInterval':
        if other.is_constant:
            return self.add_constant(-other.lo)
        if self.is_constant:
            neg_other = StridedInterval.strided(-other.hi, -other.lo,
                                                other.stride)
            return neg_other.add_constant(self.lo)
        return StridedInterval.interval(
            (self.lo - other.hi) & _U64_MAX,
            (self.hi - other.lo) & _U64_MAX)

# 谓词 (用于约束验证)

    def max_possible_value(self) -> int:
        """区间内可能的最大值."""
        if self.is_top:
            return _U64_MAX
        if self.is_bottom:
            return 0
        return self.hi

    def min_possible_value(self) -> int:
        """区间内可能的最小值."""
        if self.is_top:
            return 0
        if self.is_bottom:
            return _U64_MAX
        return self.lo

    def definitely_less_equal(self, threshold: int) -> bool:
        """区间内所有值是否确定 ≤ threshold."""
        if self.is_top or self.is_bottom:
            return False
        return self.hi <= threshold

    def may_exceed(self, threshold: int) -> bool:
        """区间内是否存在值 > threshold."""
        if self.is_top:
            return True
        if self.is_bottom:
            return False
        return self.hi > threshold

    def definitely_greater_than(self, threshold: int) -> bool:
        """区间内所有值是否确定 > threshold."""
        if self.is_top or self.is_bottom:
            return False
        return self.lo > threshold

# 降级

    def to_value_range_umin_umax(self) -> Tuple[int, int]:
        """降级为 (umin, umax) 对 (丢失跨步信息)."""
        if self.is_top:
            return (0, _U64_MAX)
        if self.is_bottom:
            return (_U64_MAX, 0)
        return (self.lo, self.hi)

    def stride_type(self) -> StrideType:
        if self.is_top or self.stride == 0:
            return StrideType.UNKNOWN
        if self.stride == 1:
            return StrideType.IRREGULAR
        return StrideType.CONSTANT

    def summarize(self) -> str:
        if self.is_top:
            return "⊤"
        if self.is_bottom:
            return "⊥"
        if self.is_constant:
            return str(self.lo)
        s = f"[{self.lo}, {self.hi}]"
        if self.stride > 1:
            s += f"_{{{stride}}}"
        return s

    def __repr__(self):
        return self.summarize()


class StridedIntervalDomain:
    """跨步区间抽象域管理器.

    维护寄存器/内存的跨步区间映射.
    与ValueRangeDomain并行使用, 值域用于快速判断, 跨步区间用于精确判定.
    """

    def __init__(self):
        self._regs: Dict[str, StridedInterval] = {}
        self._mem: Dict[int, StridedInterval] = {}

    def set(self, reg: str, si: StridedInterval):
        self._regs[reg] = si

    def get(self, reg: str) -> StridedInterval:
        return self._regs.get(reg, StridedInterval.top())

    def set_mem(self, addr: int, si: StridedInterval):
        self._mem[addr] = si

    def get_mem(self, addr: int) -> StridedInterval:
        return self._mem.get(addr, StridedInterval.top())

    def clear_registers(self):
        self._regs.clear()

    def clear_memory(self):
        self._mem.clear()

# 跨步感知的转移函数

    def record_constant(self, reg: str, val: int):
        self.set(reg, StridedInterval.constant(val))

    def record_stride_add(self, dst: str, src: str, delta: int):
        """追踪 src = dst + delta 的跨步传播 (如 i++ → i+=1)."""
        src_si = self.get(src)
        if src_si.is_top:
            return
        if delta != 0:
            self.set(dst, src_si.add_constant(delta))
        else:
            self.set(dst, src_si)

    def record_stride_init(self, reg: str, init_val: int, step: int,
                           bound_hi: int):
        """初始化循环跨步变量: reg = init; reg += step while reg < bound_hi.

        结果: {init, init+step, ..., init + k*step}, k = floor((bound_hi-1-init)/step)
        """
        if step <= 0:
            self.set(reg, StridedInterval.interval(init, bound_hi))
            return
        last = init + ((bound_hi - 1 - init) // step) * step
        if last < init:
            last = bound_hi - 1
        self.set(reg, StridedInterval.strided(init, last, step))

    def record_loop_counter(self, reg: str, start: int, end: int,
                            step: int = 1):
        """记录循环计数器: for(reg=start; reg<end; reg+=step)."""
        if step <= 0:
            step = 1
        last = start + ((end - 1 - start) // step) * step
        if last < start:
            last = end - 1
        self.set(reg, StridedInterval.strided(start, last, step))

    def summary(self) -> Dict:
        return {
            'tracked_regs': len(self._regs),
            'tracked_mem': len(self._mem),
            'strided_regs': sum(
                1 for si in self._regs.values()
                if si.stride_type() == StrideType.CONSTANT),
            'constant_regs': sum(
                1 for si in self._regs.values() if si.is_constant),
        }


# 跨步区间辅助函数

def check_stride_safe_write(write_si: StridedInterval,
                            alloc_lo: int, alloc_hi: int
                            ) -> Tuple[bool, str]:
    """用跨步区间信息增强写入安全检查.

    标准区间可能给出 w_max <= a_max 但无法利用同余信息进一步精确化.
    例: malloc(4) → alloc=[0, 3], 写入 si=[0, 6, 2] → {0, 2, 4, 6}
      标准区间看: w_hi=6 > a_hi=3 → 可能溢出
      跨步区间看: 实际写入地址 = {0, 2, 4, 6}, 只有 {4, 6} 越界
      跨步虽不能证明安全, 但能提供更精确的溢出概率
    """
    if write_si.is_top or write_si.is_bottom:
        return False, "跨步信息不足"

    # 统计越界比例
    total_card = write_si.cardinality
    if total_card == 0:
        return True, "空区间, 无法写入"
    if total_card > 1000000:  # 区间太大, 不做精确统计
        return write_si.hi <= alloc_hi, (
            f"跨步区间过大(card={total_card}), 退化为标准区间比较")

    # 遍历跨步区间内的值 (cardinality小时才有意义)
    overflow_count = 0
    for k in range(total_card):
        addr = write_si.lo + k * write_si.stride
        if addr > alloc_hi:
            overflow_count += 1

    if overflow_count == 0:
        return True, f"跨步验证: {total_card}个访问点全部在[0,{alloc_hi}]内"
    overflow_ratio = overflow_count / total_card
    if overflow_ratio > 0.5:
        return False, f"跨步验证: {overflow_count}/{total_card}点越界(>50%)"
    return False, f"跨步验证: {overflow_count}/{total_card}点越界({overflow_ratio:.0%})"
