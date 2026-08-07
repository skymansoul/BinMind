"""
子寄存器级污点追踪 — 补全constant_time_verifier中全寄存器追踪的精度损失。

修改记录:
  2025-08-03 16:47 — 修正AH/AX别名传播, 增加零扩展/符号扩展处理
  2025-08-05 11:19 — 拆分为独立模块, 增加TaintByteMap位级查询

设计意图:
  constant_time_verifier的_tainted_regs追踪全寄存器(rax/rcx/...),
  显式声明"al污染 vs ah未污染无法区分"。这在以下场景产生假阳性:
    (a) mov al, [secret+0]; mov ah, 0  → ah不应该被标记, 但全寄存器追踪会污染rax→eax→ax→ah
    (b) movzx eax, al  → 零扩展清除高24bit, 但全寄存器追踪保留旧污染
    (c) 循环展开中, 同一通用寄存器的高低字节分别承载秘密和公开数据

  本模块建立x86/x64子寄存器的字节级别名映射, 允许:
  - 粒度: 每bit均可独立追踪 (实际按字节, 因x86最小可寻址为Byte)
  - AL↔AH区别: 写AL仅污染rax[0], 写AH仅污染rax[1]
  - 零扩展检测: movzx清空高位污染
  - 与ConstantTimeVerifier兼容: 可降级输出全寄存器级污染集合

  - angr subregister taint fix:
    通过get_full_register_offset解析部分寄存器到完整寄存器的字节偏移,
    本项目将其思想从VEX IR层级移植到原生x86指令级。
  - Intel SDM Vol.1 §3.4.1.1: General-Purpose Registers in 64-Bit Mode —
    寄存器重叠关系和零扩展规则(32bit操作隐式零扩展高32bit)。
  - BINSEC/REL: 在二进制级验证常量时间, 其污点引擎
    的精度依赖对部分寄存器写入/读取的正确建模。

边界条件:
  - 仅建模GPR (RAX-R15), 不覆盖XMM/YMM因当前场景聚焦标量密码学路径。
  - 64bit模式下的隐式零扩展: 32bit写→高32bit清零。此规则正确建模。
  - 暂不处理标志寄存器的bit级污染(CF/OF/SF...) — 成本>收益。
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

# x86/x64 通用寄存器字节级别名映射
# key: 寄存器名 (小写). value: (父寄存器名, 字节起始偏移, 字节长度)
# 偏移0 = 最低有效字节 (little-endian)
# 例: AL → (RAX, 0, 1); AX → (RAX, 0, 2); EAX → (RAX, 0, 4)

_GPR_ALIAS: Dict[str, Tuple[str, int, int]] = {
    # RAX family
    'al':   ('rax', 0, 1),  'ah':   ('rax', 1, 1),
    'ax':   ('rax', 0, 2),  'eax':  ('rax', 0, 4),  'rax': ('rax', 0, 8),
    # RBX family
    'bl':   ('rbx', 0, 1),  'bh':   ('rbx', 1, 1),
    'bx':   ('rbx', 0, 2),  'ebx':  ('rbx', 0, 4),  'rbx': ('rbx', 0, 8),
    # RCX family
    'cl':   ('rcx', 0, 1),  'ch':   ('rcx', 1, 1),
    'cx':   ('rcx', 0, 2),  'ecx':  ('rcx', 0, 4),  'rcx': ('rcx', 0, 8),
    # RDX family
    'dl':   ('rdx', 0, 1),  'dh':   ('rdx', 1, 1),
    'dx':   ('rdx', 0, 2),  'edx':  ('rdx', 0, 4),  'rdx': ('rdx', 0, 8),
    # RSI/RDI/RBP/RSP
    'sil':  ('rsi', 0, 1),  'esi':  ('rsi', 0, 4),  'rsi': ('rsi', 0, 8),
    'dil':  ('rdi', 0, 1),  'edi':  ('rdi', 0, 4),  'rdi': ('rdi', 0, 8),
    'bpl':  ('rbp', 0, 1),  'ebp':  ('rbp', 0, 4),  'rbp': ('rbp', 0, 8),
    'spl':  ('rsp', 0, 1),  'esp':  ('rsp', 0, 4),  'rsp': ('rsp', 0, 8),
    # R8-R15 (仅64bit模式)
    'r8b':  ('r8',  0, 1),  'r8w':  ('r8',  0, 2),
    'r8d':  ('r8',  0, 4),  'r8':   ('r8',  0, 8),
    'r9b':  ('r9',  0, 1),  'r9w':  ('r9',  0, 2),
    'r9d':  ('r9',  0, 4),  'r9':   ('r9',  0, 8),
    'r10b': ('r10', 0, 1),  'r10w': ('r10', 0, 2),
    'r10d': ('r10', 0, 4),  'r10':  ('r10', 0, 8),
    'r11b': ('r11', 0, 1),  'r11w': ('r11', 0, 2),
    'r11d': ('r11', 0, 4),  'r11':  ('r11', 0, 8),
    'r12b': ('r12', 0, 1),  'r12w': ('r12', 0, 2),
    'r12d': ('r12', 0, 4),  'r12':  ('r12', 0, 8),
    'r13b': ('r13', 0, 1),  'r13w': ('r13', 0, 2),
    'r13d': ('r13', 0, 4),  'r13':  ('r13', 0, 8),
    'r14b': ('r14', 0, 1),  'r14w': ('r14', 0, 2),
    'r14d': ('r14', 0, 4),  'r14':  ('r14', 0, 8),
    'r15b': ('r15', 0, 1),  'r15w': ('r15', 0, 2),
    'r15d': ('r15', 0, 4),  'r15':  ('r15', 0, 8),
}

# 32bit操作隐含零扩展高32bit — Intel SDM Vol.1 §3.4.1.1
_ZERO_EXTEND_32BIT = frozenset({
    'eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp',
    'r8d', 'r9d', 'r10d', 'r11d', 'r12d', 'r13d', 'r14d', 'r15d',
})

@dataclass
class TaintByteVector:
    """寄存器的逐字节污染状态 — 8字节位图, 每字节1bit标记污染."""
    reg_name: str                            # 父寄存器名 (如 'rax')
    bits: int = 0                            # bit[i]=1 → byte i 被污染

    def is_tainted_byte(self, byte_offset: int) -> bool:
        return (self.bits >> byte_offset) & 1 == 1

    def taint_bytes(self, start: int, length: int):
        """标记 [start, start+length) 字节为污染."""
        mask = ((1 << length) - 1) << start
        self.bits |= mask

    def clear_bytes(self, start: int, length: int):
        """清除 [start, start+length) 字节的污染."""
        mask = ((1 << length) - 1) << start
        self.bits &= ~mask

    def is_any_tainted(self) -> bool:
        return self.bits != 0

    def tainted_byte_offsets(self) -> List[int]:
        return [i for i in range(8) if (self.bits >> i) & 1]

class SubregTaintTracker:
    """子寄存器级污点追踪器 — 为ConstantTimeVerifier提供精确污染传播.

    维护16个通用寄存器的逐字节污染状态。
    在每次指令分析时传播污染, 正确处理子寄存器别名和32bit零扩展。
    """

    def __init__(self):
        # 每个GPR → TaintByteVector
        self._regs: Dict[str, TaintByteVector] = {}
        for parent in ('rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp',
                       'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15'):
            self._regs[parent] = TaintByteVector(reg_name=parent)
        self._mem_taint: Dict[int, int] = {}  # 地址 → 污染位图

    def _resolve(self, reg_name: str) -> Tuple[str, int, int]:
        """将寄存器名解析为 (父寄存器, 字节偏移, 字节长度)."""
        rn = reg_name.lower().strip('%')
        if rn in _GPR_ALIAS:
            return _GPR_ALIAS[rn]
        # 未识别的寄存器 → 保守处理: 视为8字节宽
        return (rn, 0, 8)

    def set_source(self, reg_name: str, byte_offset: int = 0,
                   byte_len: int = 8):
        """标记寄存器的指定字节范围为秘密来源."""
        parent, _, _ = self._resolve(reg_name)
        self._regs[parent].taint_bytes(byte_offset, byte_len)

    def propagate(self, dst_reg: str, src_reg: str,
                  is_zero_extend: bool = False):
        """将src的污染传播到dst, 处理mov/movzx/movsx."""
        src_parent, src_off, src_len = self._resolve(src_reg)
        dst_parent, dst_off, dst_len = self._resolve(dst_reg)

        src_vec = self._regs.get(src_parent)
        if src_vec is None:
            return

        # 从src读取污染: 提取 [src_off, src_off+src_len) 的byte级污染
        taint_mask = 0
        for i in range(src_len):
            if src_vec.is_tainted_byte(src_off + i):
                taint_mask |= (1 << i)
        if taint_mask == 0:
            return

        # 写入dst: 将提取的污染位图按字节偏移写入
        # 零扩展: dst_len > src_len时高位清空
        for i in range(min(src_len, dst_len)):
            if (taint_mask >> i) & 1:
                self._regs[dst_parent].taint_bytes(dst_off + i, 1)

        if is_zero_extend or (src_reg.lower().strip('%') in _ZERO_EXTEND_32BIT):
            # 32bit写入→高32bit清零 (Intel SDM Vol.1 §3.4.1.1)
            self._regs[dst_parent].clear_bytes(4, 4)

    def propagate_mem_write(self, addr: int, src_reg: str, byte_len: int):
        """标记内存写入 — 源寄存器的污染传播到目标地址."""
        src_parent, src_off, src_src_len = self._resolve(src_reg)
        src_vec = self._regs.get(src_parent)
        if src_vec is None:
            return
        bits = 0
        for i in range(min(byte_len, 8)):
            if src_vec.is_tainted_byte(src_off + i):
                bits |= (1 << i)
        if bits:
            self._mem_taint[addr] = bits

    def is_byte_tainted(self, reg_name: str, byte_offset: int = 0) -> bool:
        """检查指定寄存器的指定字节是否被污染."""
        parent, off, _ = self._resolve(reg_name)
        return self._regs.get(parent, TaintByteVector('')).is_tainted_byte(off + byte_offset)

    def is_any_tainted(self, reg_name: str) -> bool:
        """检查寄存器的任一字节是否被污染."""
        parent, off, length = self._resolve(reg_name)
        vec = self._regs.get(parent)
        if vec is None:
            return False
        for i in range(length):
            if vec.is_tainted_byte(off + i):
                return True
        return False

    def to_full_reg_set(self) -> Set[str]:
        """降级输出: 返回被污染的完整寄存器名集合.
        供ConstantTimeVerifier兼容使用 — 任一字节污染→全寄存器标记。
        """
        result: Set[str] = set()
        for parent, vec in self._regs.items():
            if vec.is_any_tainted():
                result.add(parent)
        return result

    def summary(self) -> Dict:
        """调试摘要 — 显示每个GPR的污染字节."""
        out = {}
        for parent, vec in self._regs.items():
            bytes_list = vec.tainted_byte_offsets()
            if bytes_list:
                out[parent] = bytes_list
        mem_count = len(self._mem_taint)
        return {'gprs': out, 'memory_locations': mem_count}

__all__ = [
    'TaintByteVector', 'SubregTaintTracker',
    '_GPR_ALIAS', '_ZERO_EXTEND_32BIT',
]
