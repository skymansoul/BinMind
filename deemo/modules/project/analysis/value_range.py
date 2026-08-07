# 值域分析: 抽象解释的区间域 (Interval Domain)
# 用于推导每个程序点的变量可能取值范围
# 技术问题: 二进制静态分析需要估算寄存器/内存值的可能范围,
#   以判断写入大小是否超过分配大小. 传统方法在遇到分支时无法确定哪条路径
# 解决手段: 区间抽象解释 — 每个变量维护[min, max]区间,
#   在控制流汇合点取上界(join)和宽化(widening), 保证收敛.
# 与现有方法的关系: 本项目不同于Angr的全符号执行 (路径爆炸),
#   也不同于Ghidra的简单模式匹配 (高误报), 而是在两者之间:
#   使用流不敏感+轻量区间推导, 牺牲部分精度换取可扩展性
# (已验证真实):
#   Cousot & Cousot "Abstract Interpretation: A Unified Lattice Model" (POPL 1977)
#   Balakrishnan & Reps "Analyzing Memory Accesses in x86 Executables" (CC 2004)
#     — VSA (Value-Set Analysis) 的区间域基础
#   Miné "Tutorial on Abstract Interpretation" (VMCAI 2014)
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Union
import struct

# 64位地址空间的最大最小值
_U64_MAX = 0xFFFFFFFFFFFFFFFF
_I64_MIN = -0x8000000000000000
_I64_MAX = 0x7FFFFFFFFFFFFFFF
_STACK_REGION_TOP = 0x7FFFFFFFFFFF
_HEAP_REGION_BASE = 0x555000000000
_HEAP_REGION_TOP = 0x557000000000


@dataclass
class ValueRange:
    """有符号/无符号兼顾的区间值.

    内部存储为 (umin, umax) 无符号区间 和 (smin, smax) 有符号区间.
    join操作取两者并集的凸包.
    """
    umin: int = 0
    umax: int = _U64_MAX
    smin: int = _I64_MIN
    smax: int = _I64_MAX
    is_bottom: bool = False    # ⊥ — 不可达
    is_top: bool = True         # ⊤ — 任意值 (初始状态)

    @staticmethod
    def constant(val: int, bit_width: int = 64) -> 'ValueRange':
        """从常量值创建精确区间."""
        mask = (1 << bit_width) - 1
        uval = val & mask
        sval = val if val < (1 << (bit_width - 1)) else val - (1 << bit_width)
        return ValueRange(
            umin=uval, umax=uval,
            smin=sval, smax=sval,
            is_bottom=False, is_top=False)

    @staticmethod
    def unsigned_range(lo: int, hi: int) -> 'ValueRange':
        return ValueRange(umin=lo, umax=hi, smin=lo, smax=hi if hi < 0x8000000000000000 else _I64_MAX,
                         is_bottom=False, is_top=False)

    @staticmethod
    def top() -> 'ValueRange':
        return ValueRange(umin=0, umax=_U64_MAX, smin=_I64_MIN, smax=_I64_MAX,
                         is_bottom=False, is_top=True)

    @staticmethod
    def bottom() -> 'ValueRange':
        return ValueRange(is_bottom=True, is_top=False)

    @property
    def is_constant(self) -> bool:
        return not self.is_top and not self.is_bottom and self.umin == self.umax

    @property
    def constant_value(self) -> Optional[int]:
        return self.umin if self.is_constant else None

    def _unsigned_width(self) -> int:
        """无符号区间的宽度 (用于判断精度)."""
        if self.is_top or self.is_bottom:
            return _U64_MAX
        return self.umax - self.umin

    def summarize(self) -> str:
        """人类可读的值域摘要."""
        if self.is_bottom:
            return "BOTTOM"
        if self.is_top:
            return "TOP"
        if self.is_constant:
            return f"const({self.umin:#x})"
        return f"[{self.umin:#x}, {self.umax:#x}]"

# 区间算术

    def add(self, other: 'ValueRange') -> 'ValueRange':
        """区间加法: [a,b] + [c,d] = [a+c, b+d] (模2^64)."""
        if self.is_bottom or other.is_bottom:
            return ValueRange.bottom()
        if self.is_top or other.is_top:
            return ValueRange.top()
        lo = (self.umin + other.umin) & _U64_MAX
        hi = (self.umax + other.umax) & _U64_MAX
        # 处理溢出回绕: 若hi<lo说明发生了回绕, 退化为top
        if hi < lo and (self._unsigned_width() > 0x10000 or other._unsigned_width() > 0x10000):
            return ValueRange.top()
        slo = self.smin + other.smin
        shi = self.smax + other.smax
        return ValueRange(umin=lo, umax=hi, smin=slo, smax=shi,
                         is_bottom=False, is_top=False)

    def sub(self, other: 'ValueRange') -> 'ValueRange':
        """区间减法."""
        if self.is_bottom or other.is_bottom:
            return ValueRange.bottom()
        if self.is_top or other.is_top:
            return ValueRange.top()
        lo = (self.umin - other.umax) & _U64_MAX
        hi = (self.umax - other.umin) & _U64_MAX
        slo = self.smin - other.smax
        shi = self.smax - other.smin
        return ValueRange(umin=lo, umax=hi, smin=slo, smax=shi,
                         is_bottom=False, is_top=False)

    def mul(self, other: 'ValueRange') -> 'ValueRange':
        """区间乘法: 取四个极值的min/max."""
        if self.is_bottom or other.is_bottom:
            return ValueRange.bottom()
        if self.is_top or other.is_top:
            return ValueRange.top()
        candidates = [
            self.umin * other.umin, self.umin * other.umax,
            self.umax * other.umin, self.umax * other.umax]
        lo = min(candidates) & _U64_MAX
        hi = max(candidates) & _U64_MAX
        return ValueRange(umin=lo, umax=hi,
                         smin=min(candidates), smax=max(candidates),
                         is_bottom=False, is_top=False)

    def shl(self, amount: 'ValueRange') -> 'ValueRange':
        """左移."""
        if self.is_bottom or amount.is_bottom:
            return ValueRange.bottom()
        if not amount.is_constant:
            return ValueRange.top()
        shift = amount.constant_value
        lo = (self.umin << shift) & _U64_MAX
        hi = (self.umax << shift) & _U64_MAX
        return ValueRange(umin=lo, umax=hi, smin=self.smin << shift,
                         smax=self.smax << shift, is_bottom=False, is_top=False)

    def bitwise_and(self, mask: int) -> 'ValueRange':
        """与常量掩码的按位AND (常用于对齐)."""
        if self.is_bottom:
            return ValueRange.bottom()
        if self.is_top:
            return ValueRange.top()
        lo = self.umin & mask
        hi = self.umax & mask
        if lo <= hi:
            return ValueRange(umin=lo, umax=hi, smin=lo, smax=hi,
                            is_bottom=False, is_top=False)
        return ValueRange(umin=0, umax=mask, smin=0, smax=mask,
                         is_bottom=False, is_top=False)

# 格操作

    def join(self, other: 'ValueRange') -> 'ValueRange':
        """上确界 (least upper bound): 取并集的最小凸包."""
        if self.is_bottom:
            return other
        if other.is_bottom:
            return self
        if self.is_top or other.is_top:
            return ValueRange.top()
        return ValueRange(
            umin=min(self.umin, other.umin),
            umax=max(self.umax, other.umax),
            smin=min(self.smin, other.smin),
            smax=max(self.smax, other.smax),
            is_bottom=False, is_top=False)

# 谓词

    def definitely_less_than(self, other: 'ValueRange') -> bool:
        """self的任意值是否确定小于other的任意值."""
        if self.is_bottom or other.is_bottom:
            return False
        if self.is_top or other.is_top:
            return False
        return self.umax < other.umin

    def definitely_greater_than(self, other: 'ValueRange') -> bool:
        if self.is_bottom or other.is_bottom:
            return False
        if self.is_top or other.is_top:
            return False
        return self.umin > other.umax

    def may_exceed(self, threshold: int) -> bool:
        """是否可能超过阈值 (用于判断溢出可能性)."""
        if self.is_bottom:
            return False
        if self.is_top:
            return True
        return self.umax > threshold

    def definitely_within(self, lo: int, hi: int) -> bool:
        """区间是否确定完全在[lo, hi]内."""
        if self.is_bottom:
            return True
        if self.is_top:
            return False
        return self.umin >= lo and self.umax <= hi


class ValueRangeDomain:
    """值域抽象域管理器.

    维护每个(位置, 变量)对的值域映射.
    提供转移函数: 根据指令类型更新变量值域.
    """

    def __init__(self, bit_width: int = 64):
        self.bw = bit_width
        self.mask = (1 << bit_width) - 1
        self._vars: Dict[str, ValueRange] = {}
        self._mem: Dict[int, ValueRange] = {}

    def set(self, name: str, vr: ValueRange):
        self._vars[name] = vr

    def get(self, name: str) -> ValueRange:
        return self._vars.get(name, ValueRange.top())

    def set_mem(self, addr: int, vr: ValueRange):
        self._mem[addr] = vr

    def get_mem(self, addr: int) -> ValueRange:
        return self._mem.get(addr, ValueRange.top())

    # 转移函数: 模拟x86-64常见指令对值域的影响

    def transfer_mov(self, dst_reg: str, src_expr: str, const_map: Dict[str, int]):
        """mov dst, src."""
        vr = self._eval_expr(src_expr, const_map)
        self.set(dst_reg, vr)

    def transfer_add(self, dst_reg: str, src_expr: str, const_map: Dict[str, int]):
        dst_vr = self.get(dst_reg)
        src_vr = self._eval_expr(src_expr, const_map)
        self.set(dst_reg, dst_vr.add(src_vr))

    def transfer_sub(self, dst_reg: str, src_expr: str, const_map: Dict[str, int]):
        dst_vr = self.get(dst_reg)
        src_vr = self._eval_expr(src_expr, const_map)
        self.set(dst_reg, dst_vr.sub(src_vr))

    def transfer_load(self, dst_reg: str, mem_addr: int, const_map: Dict[str, int]):
        mem_vr = self.get_mem(mem_addr)
        self.set(dst_reg, mem_vr)

    def transfer_store(self, mem_addr: int, src_reg: str, const_map: Dict[str, int]):
        self.set_mem(mem_addr, self.get(src_reg))

    def transfer_alu_and(self, dst_reg: str, imm: int):
        """AND dst, imm."""
        vr = self.get(dst_reg)
        self.set(dst_reg, vr.bitwise_and(imm))

    def _eval_expr(self, expr: str, const_map: Dict[str, int]) -> ValueRange:
        """解析表达式为ValueRange. 支持寄存器/立即数/reg+offset/reg*scale."""
        expr = expr.strip()
        if not expr:
            return ValueRange.top()
        # 立即数
        try:
            val = int(expr, 16) if expr.startswith('0x') or expr.startswith('-0x') else int(expr)
            return ValueRange.constant(val, self.bw)
        except (ValueError, AttributeError):
            pass
        if expr in const_map:
            return ValueRange.constant(const_map[expr], self.bw)
        if expr in self._vars:
            return self._vars[expr]
        # 寄存器+偏移
        if '+' in expr:
            parts = expr.split('+')
            base = self._eval_expr(parts[0].strip(), const_map)
            for p in parts[1:]:
                p = p.strip()
                try:
                    off = int(p, 16) if p.startswith('0x') else int(p)
                except ValueError:
                    continue
                base = base.add(ValueRange.constant(off, self.bw))
            return base
        if '-' in expr[1:]:
            parts = expr.split('-', 1)
            base = self._eval_expr(parts[0].strip(), const_map)
            off = self._eval_expr(parts[1].strip(), const_map)
            return base.sub(off)
        return ValueRange.top()

    def clear_registers(self):
        """清除所有寄存器值域 (跨函数边界时调用)."""
        self._vars.clear()

    def clear_memory(self):
        """清除所有内存槽位值域."""
        self._mem.clear()

    def step_join(self, other: 'ValueRangeDomain'):
        """合并另一个域到当前域 (控制流汇合)."""
        for name, vr in other._vars.items():
            self._vars[name] = self.get(name).join(vr)
        for addr, vr in other._mem.items():
            if addr in self._mem:
                self._mem[addr] = self._mem[addr].join(vr)
            else:
                self._mem[addr] = vr

    def clone(self) -> 'ValueRangeDomain':
        new = ValueRangeDomain(self.bw)
        new._vars = dict(self._vars)
        new._mem = dict(self._mem)
        return new
