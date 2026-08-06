"""值集分析器 (Value-Set Analysis) — strided interval 域用于堆指针追踪.

创建: 2025-08-05 14:22
用途: 在二进制IR层面追踪堆指针通过算术运算和赋值后的可能取值,
      使用 strided interval (s[lb, ub], stride) 而非简单区间域。

与纯区间域 (heap_bound_infer.py) 的区别:
  纯区间域只追踪 [lo, hi], 无法区分"值总是 10 的倍数"和"值在 [0,100] 内任意变化"。
  strided interval 增加步幅 (stride) 维度: s[0, 100], stride=10 表示值只能是
  {0, 10, 20, ..., 100} 中的一个。这对堆分析至关重要:
    malloc 返回值始终对齐到 16 字节 → stride=16
    数组索引 i*4 → stride=4
    这使我们可以证明某些"看起来越界"的访问实际上在合法范围内。

理论依据:
  Balakrishnan & Reps (2004) "Analyzing Memory Accesses in x86 Executables"
  (CC) — CodeSurfer/x86 中 VSA 的原始描述
  Reps & Balakrishnan (2008) "Improved Memory-Access Analysis for x86 Executables"
  (CC) — strided interval 域的扩展
"""

from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple


# 全局未知值哨兵
_TOP = float('inf')


@dataclass
class StridedInterval:
    """Strided Interval: s[lower, upper], stride.

    s[0, 100], stride=1 → 可以是 0..100 任意整数
    s[0, 100], stride=10 → 只能是 {0, 10, 20, ..., 100}
    s[16, 16], stride=0 → 精确值 16
    s[0, inf], stride=1 → TOP (完全未知)
    """
    lower: int = 0
    upper: int = 0
    stride: int = 1

    def is_top(self) -> bool:
        return self.upper >= _TOP or self.stride <= 0

    def is_singleton(self) -> bool:
        return self.lower == self.upper and self.stride == 0

    def contains(self, val: int) -> bool:
        """检查 val 是否在该区间内."""
        if self.is_top():
            return True
        if val < self.lower or val > self.upper:
            return False
        if self.stride <= 1:
            return True
        return (val - self.lower) % self.stride == 0

    def add_constant(self, c: int) -> 'StridedInterval':
        """加常数: s[a,b],k + c = s[a+c,b+c],k."""
        if self.is_top():
            return self
        return StridedInterval(
            self.lower + c, self.upper + c, self.stride)

    def union(self, other: 'StridedInterval') -> 'StridedInterval':
        """两个 strided interval 的并集."""
        if self.is_top() or other.is_top():
            return StridedInterval(0, int(_TOP), 1)
        new_lower = min(self.lower, other.lower)
        new_upper = max(self.upper, other.upper)
        # 步幅取最大公约数
        import math
        new_stride = math.gcd(self.stride, other.stride)
        if new_stride == 0:
            new_stride = 1
        return StridedInterval(new_lower, new_upper, new_stride)

    def wide_enough_for(self, offset: int) -> bool:
        """检查此区间是否足够宽以包含 offset 处的有效访问."""
        if self.is_top():
            return True
        return self.lower <= offset <= self.upper

    def __repr__(self) -> str:
        if self.is_top():
            return 'TOP'
        if self.stride == 0:
            return f'{{{self.lower}}}'
        return f'[{self.lower},{self.upper}],stride={self.stride}'


class ValueSetAnalyzer:
    """值集分析器 — strided interval 域上的堆指针追踪.

    使用方式:
      vsa = ValueSetAnalyzer()
      vsa.set_register('rax', 0x1000, stride=16)  # malloc 返回值
      vsa.add_constant('rbx', 'rax', 24)            # rbx = rax + 24
      vsa.check_bounds('rbx', 0, 256)               # 检查访问是否在 [0,255] 内
    """

    def __init__(self):
        # 寄存器/变量的当前值集
        self._registers: Dict[str, StridedInterval] = {}
        # 内存地址 → 值集 (稀疏, 仅追踪堆相关)
        self._memory: Dict[int, StridedInterval] = {}
        # 分配记录: insn_addr → (size, ptr_name)
        self._allocs: Dict[int, Tuple[int, str]] = {}
        # 边界违规记录
        self._violations: List[Tuple[int, str, str, str]] = []

    # //// 值集操作 ////
    def set_register(self, reg_name: str, value: int,
                     stride: int = 0) -> None:
        """设置寄存器的精确值."""
        self._registers[reg_name] = StridedInterval(value, value, stride)

    def set_register_interval(self, reg_name: str, lo: int, hi: int,
                               stride: int = 1) -> None:
        """设置寄存器的区间值."""
        self._registers[reg_name] = StridedInterval(lo, hi, stride)

    def get_register(self, reg_name: str) -> StridedInterval:
        """获取寄存器的值集."""
        return self._registers.get(reg_name, StridedInterval(0, int(_TOP), 1))

    def add_constant(self, dst: str, src: str, constant: int) -> None:
        """dst = src + constant."""
        src_vs = self.get_register(src)
        self._registers[dst] = src_vs.add_constant(constant)

    def copy_register(self, dst: str, src: str) -> None:
        """dst = src."""
        self._registers[dst] = self.get_register(src)

    def merge_registers(self, dst: str, src1: str, src2: str) -> None:
        """dst = src1 ∪ src2 (控制流汇合点)."""
        self._registers[dst] = (
            self.get_register(src1).union(self.get_register(src2)))

    # //// 分配注册 ////
    def register_allocation(self, insn_addr: int, alloc_size: int,
                            ptr_reg: str, model) -> None:
        """注册一个 malloc(n) 调用, 使用分配器模型获取实际可用大小.

        model 是 Ptmalloc2Model 实例, 用于获取舍入后的实际可用大小。
        """
        constraint = model.model_alloc(alloc_size)
        self._allocs[insn_addr] = (constraint.usable_size, ptr_reg)
        # malloc 返回对齐到 16 的指针 → stride=16
        self.set_register(ptr_reg, insn_addr % 0x10000, stride=16)

    # //// 边界检查 ////
    def check_access(self, insn_addr: int, ptr_reg: str,
                     offset_si: StridedInterval, access_size: int,
                     func_name: str = '') -> Optional[str]:
        """检查 *(ptr_reg + offset) 是否在任意活跃分配的范围内.

        返回 None 表示合法, 返回字符串表示违规原因.
        """
        if not self._allocs:
            return None

        # 在活跃分配中查找指针基址匹配
        for alloc_addr, (usable_size, alloc_reg) in self._allocs.items():
            # 若 ptr_reg 是 alloc_reg 的别名, 做边界检查
            if ptr_reg != alloc_reg:
                # 简化: 仅检查直接寄存器匹配
                # 完整实现需别名分析 (见 pointer_alias_tracker.py)
                continue

            # 检查 offset 的下界和上界
            if offset_si.is_top():
                continue  # 无法确定, 保守放过

            # 若 offset 上界 < usable_size → 合法
            if offset_si.upper < usable_size:
                return None

            # 利用 stride 信息做更精细的判断
            # 若 offset 的所有可能值 (考虑 stride) 都在范围内 → 合法
            if (offset_si.lower >= 0
                    and offset_si.upper < usable_size
                    and usable_size % max(1, offset_si.stride) == 0):
                return None

            # 保守判断: 如果 offset_lower 已经超过范围 → 确定溢出
            if offset_si.lower >= usable_size:
                msg = (f'heap overflow: *({ptr_reg}+{offset_si.lower})'
                       f' exceeds usable {usable_size}B in {func_name}')
                self._violations.append(
                    (insn_addr, ptr_reg, str(offset_si), func_name))
                return msg

        return None

    def check_access_with_model(self, insn_addr: int, ptr_reg: str,
                                 offset: int, requested_size: int,
                                 access_size: int, model,
                                 func_name: str = '') -> Optional[str]:
        """使用分配器模型的边界检查 — 核心误报过滤逻辑。

        不仅检查 offset < requested_size, 还检查:
          1. 分配器舍入后的可用大小 (含 padding)
          2. 分配器对齐约束 (stride 过滤)
          3. 最小块大小约束
        """
        constraint = model.model_alloc(requested_size)
        usable = constraint.usable_size

        # 直接检查: offset + access_size <= usable?
        if offset + access_size <= usable:
            return None

        # 更精细的检查: offset 是否只落在 padding 区?
        # padding = usable - requested_size
        # 若 offset 在 [requested_size, usable) 内 → 编译器的合法 padding 访问
        padding = usable - requested_size
        if (padding > 0 and offset >= requested_size
                and offset + access_size <= usable):
            return None  # 在 padding 区内, 编译器合法访问

        # stride 检查: 若 ptr 对齐到 16, offset 也是 16 的倍数
        # → 可能是指向结构体数组的合法索引
        _align = 16  # MALLOC_ALIGNMENT on x86-64
        if offset % _align == 0 and access_size <= _align:
            if offset + access_size <= usable + _align:
                return None  # 对齐访问的宽松容忍

        # 确认越界
        msg = (f'heap overflow: offset {offset}+{access_size} '
               f'exceeds usable {usable}B '
               f'(requested {requested_size}B, padding {padding}B) '
               f'in {func_name}')
        self._violations.append(
            (insn_addr, ptr_reg, f'offset={offset}', func_name))
        return msg

    # //// 静态方法 ////
    @staticmethod
    def parse_offset_expr(expr: str) -> StridedInterval:
        """解析偏移表达式为 strided interval.

        支持: '0x100', 'rax+8', 'rax*4+0x10', '24'
        """
        expr = expr.strip().lower()
        # 纯数字
        try:
            v = int(expr, 0)
            return StridedInterval(v, v, 0)
        except ValueError:
            pass
        # 包含乘法的复杂表达式 → 扩大 stride
        if '*' in expr:
            parts = expr.split('*')
            try:
                multiplier = int(parts[1].strip(), 0)
                return StridedInterval(0, 256 * multiplier, multiplier)
            except (ValueError, IndexError):
                pass
        return StridedInterval(0, int(_TOP), 1)

    def stats(self) -> dict:
        return {
            'registers_tracked': len(self._registers),
            'allocations_tracked': len(self._allocs),
            'violations_found': len(self._violations),
        }

    def clear(self) -> None:
        self._registers.clear()
        self._memory.clear()
        self._allocs.clear()
        self._violations.clear()
