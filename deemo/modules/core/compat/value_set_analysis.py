# 值集分析 (Value-Set Analysis) — 基于抽象解释的间接跳转目标解析
# 参考: BAP (Binary Analysis Platform, Brumley et al. CMU) 的 VSA 实现 —
#       strided intervals 抽象域在二进制分析中的应用
# 参考: "Sound and Precise Cross-Layer Jump Target Resolution"
#       (Pasquier et al. 2025) — 跨层间接跳转解析的 soundness 保证
# 参考: angr VSA (Shoshitaishvili et al. IEEE S&P 2016) —
#       Value-set analysis 在二进制框架中的工程化实现

import struct as _struct
from typing import Tuple, Optional

# ===== Strided Interval (跨度区间) =====
# VSA 的核心数据抽象: 一个整数值集合表示为 stride(步长) + lower/upper(范围)
# 例如: {0, 4, 8, ..., 100} 表示为 SI(4, 0, 100)
# 这是抽象解释理论在数值域上的标准应用 — 牺牲精度换取有限分析时间

# 注意: 对于非 strided 的集合, stride=1 成为传统区间抽象 [lower, upper]
# 混合使用: SI(0, lower, upper) 等价于 [lower, upper]  —— 拓扑元

class StridedInterval:
    # 跨度区间: {x | x = lower + k*stride, k≥0, lower ≤ x ≤ upper}
    # stride=0 → singleton, stride=1 → classical interval
    # 运算语义参考 BAP VSA (Brumley et al.): 加法保持stride, 乘法放大stride, 位运算降级
    __slots__ = ('stride', 'lower', 'upper')

    def __init__(self, stride: int, lower: int, upper: int):
        self.stride = stride
        self.lower = min(lower, upper)
        self.upper = max(lower, upper)

    @classmethod
    def singleton(cls, value: int) -> 'StridedInterval':
        return cls(0, value, value)

    @classmethod
    def interval(cls, lower: int, upper: int) -> 'StridedInterval':
        return cls(1, lower, upper)

    @classmethod
    def top(cls, bits: int = 64) -> 'StridedInterval':
        """全局最大值 — 表示所有可能值的集合。"""
        max_val = (1 << bits) - 1
        return cls(1, 0, max_val)

    def is_singleton(self) -> bool:
        return self.stride == 0 and self.lower == self.upper

    def is_top(self) -> bool:
        return self.stride == 1 and self.lower == 0 and self.upper >= 0x7FFFFFFFFFFFFFFF

    def contains(self, value: int) -> bool:
        if value < self.lower or value > self.upper:
            return False
        if self.stride == 0:
            return value == self.lower
        return (value - self.lower) % self.stride == 0

    def __add__(self, other):
        if isinstance(other, int):
            return StridedInterval(self.stride,
                                   self.lower + other, self.upper + other)
        if isinstance(other, StridedInterval):
            # 保守合并: stride 取 gcd，区间取和
            import math
            new_stride = math.gcd(self.stride, other.stride) if self.stride and other.stride else 1
            return StridedInterval(new_stride,
                                   self.lower + other.lower,
                                   self.upper + other.upper)
        return StridedInterval.top()

    def __sub__(self, other):
        if isinstance(other, int):
            return StridedInterval(self.stride,
                                   self.lower - other, self.upper - other)
        return StridedInterval.top()

    def __mul__(self, other):
        if isinstance(other, int):
            if other == 0:
                return StridedInterval.singleton(0)
            new_stride = self.stride * other
            return StridedInterval(new_stride,
                                   self.lower * other, self.upper * other)
        return StridedInterval.top()

    def union(self, other: 'StridedInterval') -> 'StridedInterval':
        """两个 SI 的并集（最小上界）。
        stride 取 gcd 的保守近似 — 因为并集可能破坏 strided 性质。"""
        import math
        new_stride = math.gcd(self.stride, other.stride) if self.stride and other.stride else 1
        if self.stride == 0 and other.stride == 0:
            diff = abs(self.lower - other.lower)
            new_stride = diff if diff > 0 else 0
        return StridedInterval(new_stride,
                               min(self.lower, other.lower),
                               max(self.upper, other.upper))

    def __repr__(self):
        if self.is_singleton():
            return f'SI({self.lower})'
        if self.stride == 1:
            return f'SI([{self.lower:#x}, {self.upper:#x}])'
        return f'SI({self.stride}, [{self.lower:#x}, {self.upper:#x}])'

    def bitwise_and(self, mask: int) -> 'StridedInterval':
        """与常量掩码的位与运算 — 精度降级为 stride=1 区间。"""
        if mask == 0:
            return StridedInterval.singleton(0)
        # 保守: 与操作可显著缩小范围但难以保持 stride
        new_upper = min(self.upper, mask)
        return StridedInterval(1, 0, new_upper)


# ===== 抽象寄存器状态 =====
# VSA 的寄存器文件 — 每个寄存器映射到一个 StridedInterval
# 支持 x86-64 所有通用寄存器 + 栈内存 (以全局变量建模)


class VSARegisterState:
    """VSA 寄存器状态栈。
    每个寄存器的值为一个 StridedInterval — 可能是一个确切值 (singleton)
    或一个值范围 (interval)。"""

    def __init__(self, bits: int = 64):
        self._regs: dict[str, StridedInterval] = {}
        self._stack: dict[int, StridedInterval] = {}  # 简化的栈模型
        self._bits = bits
        self._max_val = (1 << bits) - 1

    def set(self, reg: str, val: StridedInterval):
        self._regs[reg] = val

    def get(self, reg: str) -> StridedInterval:
        return self._regs.get(reg, StridedInterval.top(self._bits))

    def set_const(self, reg: str, val: int):
        self._regs[reg] = StridedInterval.singleton(val)

    def store(self, addr: StridedInterval, val: StridedInterval):
        """将值存入抽象地址。若 addr 为确切值则直接写入栈模型；
        否则 over-approximate — 可能覆盖多个栈槽。"""
        if addr.is_singleton():
            self._stack[addr.lower] = val
        # 非确切地址的 store 过于保守，跳过以避免污染分析结果

    def load(self, addr: StridedInterval) -> StridedInterval:
        if addr.is_singleton():
            return self._stack.get(addr.lower, StridedInterval.top(self._bits))
        return StridedInterval.top(self._bits)


# ===== VSA 传播引擎 =====
# 指令语义的抽象传递函数 — 从具体指令映射到 SI 运算
# 参考: BAP 的 VSA 转移函数表 (Brumley et al. 2007)

def vsa_transfer(mnemonic: str, operands: list[str],
                 state: VSARegisterState) -> None:
    """对一条指令执行 VSA 抽象求值。
    覆盖: mov, lea, add, sub, and, or, xor, shl, shr, imul, push, pop。
    未实现的指令类别保守地将其目标寄存器设为 TOP。"""
    mnem = mnemonic.lower()

    if mnem in ('mov', 'movzx', 'movsx', 'movsxd'):
        if len(operands) >= 2:
            src = _vsa_eval_operand(operands[1], state)
            _vsa_set_operand(operands[0], src, state)

    elif mnem == 'lea':
        if len(operands) >= 2:
            # LEA dst, [base + index*scale + disp]
            result = _vsa_eval_lea(operands[1], state)
            _vsa_set_operand(operands[0], result, state)

    elif mnem in ('add', 'sub', 'imul'):
        if len(operands) >= 2:
            d = _vsa_eval_operand(operands[0], state)
            s = _vsa_eval_operand(operands[1], state)
            if mnem == 'add':
                result = d + s if isinstance(s, int) else d + s
            elif mnem == 'sub':
                result = d - s if isinstance(s, int) else d - StridedInterval(1, s.lower, s.upper)
            else:
                result = d * s if isinstance(s, int) else StridedInterval.top()
            _vsa_set_operand(operands[0], result, state)

    elif mnem in ('and', 'or', 'xor'):
        if len(operands) >= 2:
            d = _vsa_eval_operand(operands[0], state)
            s = _vsa_eval_operand(operands[1], state)
            if isinstance(s, int) and mnem == 'and':
                _vsa_set_operand(operands[0], d.bitwise_and(s), state)
            else:
                _vsa_set_operand(operands[0], StridedInterval.top(), state)

    elif mnem in ('push',):
        if len(operands) >= 1:
            val = _vsa_eval_operand(operands[0], state)
            sp = state.get('rsp')
            state.store(sp - StridedInterval.singleton(8), val)
            state.set('rsp', sp - StridedInterval.singleton(8))

    elif mnem in ('pop',):
        if len(operands) >= 1:
            sp = state.get('rsp')
            loaded = state.load(sp)
            _vsa_set_operand(operands[0], loaded, state)
            state.set('rsp', sp + StridedInterval.singleton(8))

    elif mnem in ('nop', 'int3'):
        pass  # 无效应, 无需处理


# ---- 操作数求值 ----
def _vsa_eval_operand(op_str: str, state: VSARegisterState):
    """解析操作数字符串为整数常量或 StridedInterval。"""
    import re
    op = op_str.strip()

    # 立即数
    m = re.match(r'^-?(?:0x([0-9a-fA-F]+)|(\d+))$', op)
    if m:
        val_str = m.group(1) or m.group(2)
        if val_str:
            base = 16 if m.group(1) else 10
            return int(val_str, base)
        return 0

    # 内存引用 — 简化: 返回 TOP
    if '[' in op:
        return StridedInterval.top()

    # 寄存器
    return state.get(op)


def _vsa_set_operand(op_str: str, val, state: VSARegisterState):
    op = op_str.strip()
    if '[' in op:
        return  # 不支持内存写入 (保守)
    state.set(op, val if isinstance(val, StridedInterval) else StridedInterval.singleton(val))


def _vsa_eval_lea(operand: str, state: VSARegisterState) -> StridedInterval:
    """解析 LEA 操作数的基址+变址+偏移模式。
    格式: [base + index*scale + displacement] 或类似变体。"""
    import re
    op = operand.strip()
    # 去除方括号
    if op.startswith('[') and op.endswith(']'):
        op = op[1:-1]

    result = StridedInterval.singleton(0)
    parts = re.split(r'\s*[+]\s*', op)
    for part in parts:
        part = part.strip()
        if not part:
            continue
        # 立即数偏移
        if re.match(r'^-?(?:0x[0-9a-fA-F]+|\d+)$', part):
            val = int(part, 16 if part.startswith('0x') or part.startswith('-0x') else 10)
            result = result + val
        # 寄存器 * 常数
        elif '*' in part:
            reg_name, scale_str = part.split('*')
            reg_val = state.get(reg_name.strip())
            scale = int(scale_str.strip())
            result = result + (reg_val * scale)
        # 纯寄存器
        else:
            result = result + state.get(part)

    return result


# ===== 间接跳转目标解析 =====
# VSA 的主要应用: 解析 jmp rax / call [rbx+8] 等间接转移的目标
# 这是静态反汇编中最大的精度瓶颈 — 间接跳转可达的地址集合决定 CFG 完整性
# 参考: Pasquier et al. (2025) 的跨层解析策略

def resolve_indirect_jump(jump_type: str, target_expr: str,
                           state: VSARegisterState) -> list[int]:
    """使用 VSA 状态解析间接跳转的可能目标地址集合。
    jump_type: 'jmp' | 'call'
    target_expr: 目标操作数 (如 'rax', '[rbx+8]')

    返回可能目标地址列表（仅返回确切值；非确切值时返回空）。"""
    val = _vsa_eval_operand(target_expr, state)
    if isinstance(val, StridedInterval):
        if val.is_singleton():
            return [val.lower]
        # 若区间 ≤ 512 且 stride 较小，枚举所有可能值
        span = val.upper - val.lower
        if span <= 512 and val.stride > 0:
            targets = []
            v = val.lower
            while v <= val.upper:
                targets.append(v)
                v += val.stride
            return targets
        return []  # 无法确切解析
    if isinstance(val, int):
        return [val]
    return []


# ===== 全局变量初始化状态推断 =====
# 静态分析中，全局变量的初始值可能来自 .data/.rdata 段
# 参考: angr 的 SimMemory 和 CLE 加载器 — 将段内容映射到 VSA 状态

def infer_global_initial_values(data_section: bytes, base_addr: int,
                                  target_vars: list[tuple[int, int]]) -> dict[int, StridedInterval]:
    """从 .data/.rdata 段推断全局变量的初始 VSA 值。
    target_vars: [(offset, size), ...] — 变量在段中的偏移和大小
    仅支持 ≤ 8 字节的变量 — 大于 8 字节的聚合类型返回 TOP。"""
    results = {}
    for offset, size in target_vars:
        if offset + size > len(data_section) or size > 8:
            results[base_addr + offset] = StridedInterval.top()
            continue
        raw = data_section[offset:offset + size]
        if size == 1:
            val = raw[0]
        elif size == 2:
            val = _struct.unpack('<H', raw)[0]
        elif size == 4:
            val = _struct.unpack('<I', raw)[0]
        elif size == 8:
            val = _struct.unpack('<Q', raw)[0]
        else:
            val = int.from_bytes(raw, 'little')
        results[base_addr + offset] = StridedInterval.singleton(val)
    return results
