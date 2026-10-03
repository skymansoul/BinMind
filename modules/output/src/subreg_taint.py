"""
x86/x64 子寄存器级污点追踪器 — 字节粒度状态机。

基于 taint_state.py 的 TaintState + 寄存器名解析，
在 GP64 和 SIMD 寄存器集合上维护逐字节污点状态。

核心操作:
  taint('al')       → 仅污染 RAX byte[0]
  taint('eax')      → 污染 RAX byte[0:4]
  propagate('rax', 'rbx')  → 将 RBX 的全部污点传播到 RAX
  untaint('eax', zero_extend_32=True) → 清除 EAX 并 zero-extend

  angr sub-register taint fixes (github.com/borzacchiello/angr, c4f6892)
    — 使用完整寄存器偏移量检查子寄存器污点
  TaintInduce — 学习 x86/ARM64/MIPS 的污点传播规则
  Clang Static Analyzer Taint.cpp — TaintedSubRegions 模式

修改记录:
  2025-07-28 10:17 - 增加 zero-extend 语义
  2025-08-01 08:45 - 拆分 TaintState + resolve_register 至 taint_state.py
"""

from typing import Dict

from modules.output.src.taint_state import TaintState, resolve_register

_GP64_NAMES = frozenset({
    'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp',
    'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15'
})

class SubRegTaintTracker:
    """
    x86/x64 子寄存器级污点追踪器。

    维护所有 GP64 寄存器的字节级污点状态 (每个 8 bytes)。
    SIMD 寄存器按需惰性初始化以减少内存开销。

    典型用法:
      tracker = SubRegTaintTracker()
      tracker.taint('al')                          # 用户输入污染 AL
      tracker.propagate('rbx', 'rax')              # mov rbx, rax
      tracker.untaint('eax', zero_extend_32=True)  # xor eax, eax
      tracker.query_byte('rax', 0)                 # → False
    """

    def __init__(self):
        self._gp: Dict[str, TaintState] = {
            name: TaintState(8) for name in _GP64_NAMES
        }
        self._simd: Dict[str, TaintState] = {}

    def _get_state(self, reg: str) -> TaintState:
        parent, offset, size = resolve_register(reg)
        if parent.startswith('xmm'):
            if parent not in self._simd:
                self._simd[parent] = TaintState(16)
            return self._simd[parent]
        if parent not in self._gp:
            self._gp[parent] = TaintState(8)
        return self._gp[parent]

# 基本操作

    def taint(self, reg: str, byte_offset: int = 0, byte_count: int = -1):
        """
        标记寄存器指定字节范围为污染。
        taint('al') → RAX byte[0]; taint('eax') → RAX byte[0:4]
        """
        parent, parent_offset, parent_size = resolve_register(reg)
        state = self._get_state(reg)
        if byte_count < 0:
            byte_count = parent_size
        state.set_range(parent_offset + byte_offset, byte_count)

    def untaint(self, reg: str, zero_extend_32: bool = False):
        """
        清除寄存器污点。
        zero_extend_32: 模拟 32-bit 操作清除高 32 位 (mov eax, 0 → RAX[63:32]=0)。
        """
        parent, parent_offset, parent_size = resolve_register(reg)
        state = self._get_state(reg)
        state.clear_range(parent_offset, parent_size)
        if zero_extend_32 and parent_size == 4 and parent in self._gp:
            state.clear_range(4, 4)

    def propagate(self, dst_reg: str, src_reg: str,
                  src_offset: int = 0, dst_offset: int = 0,
                  count: int = -1, zero_extend_32: bool = False):
        """
        污点传播: src → dst。
        zero_extend_32: 目标是 32-bit 时清除高位。
        """
        dst_state = self._get_state(dst_reg)
        src_state = self._get_state(src_reg)
        _, dst_p_offset, dst_p_size = resolve_register(dst_reg)
        _, src_p_offset, src_p_size = resolve_register(src_reg)

        if count < 0:
            count = min(dst_p_size - dst_offset, src_p_size - src_offset)

        dst_state.copy_from(
            src_state,
            src_offset=src_p_offset + src_offset,
            dst_offset=dst_p_offset + dst_offset,
            count=count,
        )
        if zero_extend_32 and dst_p_size == 4:
            dst_state.clear_range(4, 4)

# 查询

    def query(self, reg: str) -> TaintState:
        """返回寄存器的 TaintState 引用 (修改会影响内部状态)。"""
        return self._get_state(reg)

    def query_byte(self, reg: str, byte_index: int = 0) -> bool:
        """查询指定字节是否被污染。"""
        parent, offset, size = resolve_register(reg)
        state = self._get_state(reg)
        actual = offset + byte_index
        if actual >= state.byte_count:
            return False
        return state.is_tainted_byte(actual)

    def is_tainted(self, reg: str) -> bool:
        """寄存器任意字节被污染? """
        return self._get_state(reg).is_tainted_any()

    def summary(self) -> Dict[str, int]:
        """
        返回当前所有被污染寄存器的摘要: {reg_name: tainted_byte_count}。
        仅包含非零污染的寄存器。
        """
        result = {}
        for name, state in self._gp.items():
            if state.is_tainted_any():
                result[name.upper()] = state.tainted_byte_count()
        for name, state in self._simd.items():
            if state.is_tainted_any():
                result[name.upper()] = state.tainted_byte_count()
        return result
