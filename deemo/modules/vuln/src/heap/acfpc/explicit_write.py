"""显式偏移写检查器 — 非 call 型 store 指令的几何判定.

检测器对显式 store (mov [reg+off], val) 报出的 finding 无 size 参数,
无法走调用级证据链. 对这类写直接以偏移+宽度与契约可用大小比较:
目标寄存器身份 == 契约返回值身份, 且 off+width ≤ usable → 安全压制.
在线状态判定: 逐条 step 更新定义后再检查, 保证 def 查询位置敏感.
"""

import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from .def_chain import DefChainTracker
from .alloc_contract import AllocContract
from .allocator_geometry import write_fits, usable_size

_WIDTH = {'qword': 8, 'dword': 4, 'word': 2, 'byte': 1}
_PAT = re.compile(
    r'mov\s+(?:(qword|dword|word|byte)\s+ptr\s+)?'
    r'\[([a-z0-9]+)([+-])(0x[0-9a-fA-F]+|\d+)\]\s*,',
    re.IGNORECASE)
_PAT0 = re.compile(
    r'mov\s+(?:(qword|dword|word|byte)\s+ptr\s+)?'
    r'\[([a-z0-9]+)\]\s*,',
    re.IGNORECASE)
@dataclass
class ExplicitWrite:
    insn_idx: int
    offset: int
    width: int
    base_reg: str
    reason: str = ''


class ExplicitWriteChecker:
    """显式 store 的几何安全检查 (在线状态判定)."""

    def __init__(self, tracker: DefChainTracker, mode: str = 'strict'):
        self._tracker = tracker
        self._mode = mode

    def scan(self, instructions: List[str],
             contracts: List[AllocContract]) -> Dict[int, ExplicitWrite]:
        """返回 {insn_idx: ExplicitWrite}, 仅含可证明安全的写.

        逐条 step 更新定义状态后再判定, 保证 def 查询位置敏感."""
        safe: Dict[int, ExplicitWrite] = {}
        for i, line in enumerate(instructions):
            self._tracker.step(line, i)
            m = _PAT.search(line)
            if m:
                width = _WIDTH[m.group(1).lower()] if m.group(1) else 4
                reg, sign, num = m.group(2), m.group(3), m.group(4)
            else:
                m0 = _PAT0.search(line)
                if not m0:
                    continue
                width = _WIDTH[m0.group(1).lower()] if m0.group(1) else 4
                reg, sign, num = m0.group(2), '+', '0'
            try:
                off = int(num, 0)
            except ValueError:
                continue
            if sign == '-':
                off = -off
            if off < 0:
                continue
            node = self._tracker.def_of_reg(reg)
            reg_id = self._tracker.identity(node)
            if not reg_id:
                continue
            for c in contracts:
                if c.size_kind != 'IMM':
                    continue
                if c.result_identity != reg_id:
                    continue
                if write_fits(c.size_imm, off, width, self._mode):
                    usable = usable_size(c.size_imm, self._mode)
                    safe[i] = ExplicitWrite(
                        insn_idx=i, offset=off, width=width,
                        base_reg=reg,
                        reason=(f'显式写 [{reg}+{off}] 宽 {width}B ≤ '
                                f'可用 {usable}B ({c.func}({c.size_imm}))'))
                    break
        return safe
DST_REGS = {'win64': 'rcx', 'sysv': 'rdi'}
_SIZE_REGS = {'win64': 'r8', 'sysv': 'rdx'}


