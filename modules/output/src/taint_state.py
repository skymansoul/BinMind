"""
字节级寄存器污点状态 — x86/x64 寄存器名解析 + 位掩码存储。

x86 寄存器重叠模型:
  RAX[63:0] ⊃ EAX[31:0] ⊃ AX[15:0] ⊃ {AL[7:0], AH[15:8]}
  32-bit 操作有 zero-extend 语义: mov eax, 0 → RAX[63:32] = 0
  16/8-bit 操作仅影响对应字节，高位保留。

修改记录:
  2025-07-30 16:03 - 增加 SIMD 寄存器 (XMM0-15) 的 16 字节状态支持
2025-08-01 08:45 - 独立模块
"""

from typing import Tuple


class TaintState:
    """
    单寄存器的字节级污点状态 — 位掩码存储。

    bit[i] = 1 → byte i 被污染。
    64-bit GP 寄存器: 8 bytes (64 bit mask)
    128-bit SIMD 寄存器 (XMM): 16 bytes
    """

    def __init__(self, byte_count: int = 8):
        self.byte_count = byte_count
        self.mask: int = 0
        self._max_mask = (1 << byte_count) - 1

    def set_byte(self, index: int):
        if 0 <= index < self.byte_count:
            self.mask |= (1 << index)

    def set_range(self, start: int, count: int):
        for i in range(max(start, 0), min(start + count, self.byte_count)):
            self.mask |= (1 << i)

    def clear(self):
        self.mask = 0

    def clear_range(self, start: int, count: int):
        for i in range(max(start, 0), min(start + count, self.byte_count)):
            self.mask &= ~(1 << i)

    def is_tainted_any(self) -> bool:
        return self.mask != 0

    def is_tainted_byte(self, index: int) -> bool:
        if 0 <= index < self.byte_count:
            return bool(self.mask & (1 << index))
        return False

    def tainted_byte_count(self) -> int:
        return self.mask.bit_count()

    def copy_from(self, other: 'TaintState', src_offset: int = 0,
                  dst_offset: int = 0, count: int = -1):
        """从另一个 TaintState 复制指定范围的污点位。count=-1 → 全部可用。"""
        if count < 0:
            count = min(self.byte_count - dst_offset, other.byte_count - src_offset)
        for i in range(count):
            src_i = src_offset + i
            dst_i = dst_offset + i
            if (0 <= src_i < other.byte_count and
                0 <= dst_i < self.byte_count and
                other.is_tainted_byte(src_i)):
                self.set_byte(dst_i)

    def __repr__(self) -> str:
        return f"TaintState(mask=0x{self.mask:0{self.byte_count*2}x})"


# x86/x64 寄存器名 → 父寄存器 + 字节偏移映射

_GP64_NAMES = frozenset({
    'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp',
    'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15'
})

_GP8L_TO_PARENT = {
    'al': 'rax', 'bl': 'rbx', 'cl': 'rcx', 'dl': 'rdx',
    'sil': 'rsi', 'dil': 'rdi', 'bpl': 'rbp', 'spl': 'rsp',
}

_GP8H_TO_PARENT = {'ah': 'rax', 'bh': 'rbx', 'ch': 'rcx', 'dh': 'rdx'}

_GP16_TO_PARENT = {
    'ax': 'rax', 'bx': 'rbx', 'cx': 'rcx', 'dx': 'rdx',
    'si': 'rsi', 'di': 'rdi', 'bp': 'rbp', 'sp': 'rsp',
}

_GP32_TO_PARENT = {
    'eax': 'rax', 'ebx': 'rbx', 'ecx': 'rcx', 'edx': 'rdx',
    'esi': 'rsi', 'edi': 'rdi', 'ebp': 'rbp', 'esp': 'rsp',
}


def resolve_register(reg: str) -> Tuple[str, int, int]:
    """
    解析 x86 子寄存器 → (父寄存器名, 起始字节偏移, 字节数)。

    偏移从低字节起算: AL = bytes[0], AH = bytes[1], AX = bytes[0:2],
    EAX = bytes[0:4] (且 zero-extend 清除 bytes[4:8])。

    SIMD: xmm0 → ('xmm0', 0, 16)
    未识别寄存器按 8 字节 GP64 处理。
    """
    reg_lower = reg.lower().strip()

    if reg_lower in _GP64_NAMES:
        return reg_lower, 0, 8

    if reg_lower.startswith('r') and reg_lower[1:].isdigit():
        return reg_lower, 0, 8

    if reg_lower in _GP8H_TO_PARENT:
        return _GP8H_TO_PARENT[reg_lower], 1, 1

    if reg_lower in _GP8L_TO_PARENT:
        return _GP8L_TO_PARENT[reg_lower], 0, 1

    if reg_lower in _GP16_TO_PARENT:
        return _GP16_TO_PARENT[reg_lower], 0, 2

    # 32-bit: zero-extend 由调用者处理
    if reg_lower in _GP32_TO_PARENT:
        return _GP32_TO_PARENT[reg_lower], 0, 4

    if reg_lower.startswith('xmm'):
        return reg_lower, 0, 16

    return reg_lower, 0, 8
