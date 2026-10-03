"""判决合成 — 将耦合/守卫/几何证据合成三值结论.

SUPPRESS 仅由确定性证据触发; CONFIRM 仅由双常量数值比较触发;
UNCHANGED 保留原 finding. 证据优先级: 几何数值 > 守卫支配 >
参数耦合. 双模式几何 (strict/glibc) 由构造参数决定.
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional

from .def_chain import DefKind
from .alloc_contract import AllocContract
from .write_coupling import Coupling, CouplingVerdict
from .allocator_geometry import usable_size, write_fits, overflow_bytes


class ACFPCVerdictKind(Enum):
    SUPPRESS = auto()
    CONFIRM = auto()
    UNCHANGED = auto()


@dataclass
class ACFPCVerdict:
    kind: ACFPCVerdictKind
    reason: str = ''
    evidence: List[str] = field(default_factory=list)
    confidence_delta: float = 0.0


class VerdictSynthesizer:
    """综合证据, 输出每个写点的判决."""

    def __init__(self, mode: str = 'strict'):
        self._mode = mode

    def synthesize_imm_write(self, contract: AllocContract,
                             write_imm: int) -> ACFPCVerdict:
        """双常量数值判定: 写 size 与分配大小直接比较."""
        req = contract.size_imm
        if write_imm <= 0 or req <= 0:
            return ACFPCVerdict(ACFPCVerdictKind.UNCHANGED,
                                '常量缺失, 无法数值判定')
        usable = usable_size(req, self._mode)
        if write_fits(req, 0, write_imm, self._mode):
            return ACFPCVerdict(
                ACFPCVerdictKind.SUPPRESS,
                f'{contract.func}({req}) 可用 {usable}B ≥ 写 {write_imm}B',
                [f'usable_size({req})={usable}',
                 f'write={write_imm} fits'])
        ob = overflow_bytes(req, 0, write_imm, self._mode)
        return ACFPCVerdict(
            ACFPCVerdictKind.CONFIRM,
            f'{contract.func}({req}) 可用 {usable}B < 写 {write_imm}B'
            f' (溢出 {ob}B)',
            [f'write_end={write_imm}', f'usable={usable}',
             f'overflow={ob}'],
            confidence_delta=0.15)

    def synthesize_guarded_write(self, usable: int, guarded: bool,
                                 guard_reason: str) -> ACFPCVerdict:
        if guarded:
            return ACFPCVerdict(
                ACFPCVerdictKind.SUPPRESS,
                f'守卫支配: {guard_reason}',
                ['guard_dominance'])
        return ACFPCVerdict(ACFPCVerdictKind.UNCHANGED,
                            f'守卫不成立: {guard_reason}')

    def synthesize_coupled_write(self, cv: CouplingVerdict) -> ACFPCVerdict:
        if cv.verdict == Coupling.COUPLED:
            return ACFPCVerdict(
                ACFPCVerdictKind.SUPPRESS,
                f'参数耦合: {cv.reason}',
                ['write_alloc_coupling'])
        return ACFPCVerdict(ACFPCVerdictKind.UNCHANGED, cv.reason)

    def synthesize_strncpy_same_size(self, contract: AllocContract) -> ACFPCVerdict:
        """strncpy 语义特例: 写入量为 n+1 (含终止符).

        strict 模式下 usable(n) = n, n+1 > n 恒成立 → 语言语义越界
        1 字节. 仅当分配 size 与写入 n 相同 (同源或等值) 时触发,
        该条件表明缓冲区恰无终止符空间."""
        return ACFPCVerdict(
            ACFPCVerdictKind.CONFIRM,
            f'strncpy(dst, src, {contract.size_imm}) 写入含终止符 '
            f'{contract.size_imm + 1}B > 分配 {contract.size_imm}B',
            ['strncpy_nul_overflow'],
            confidence_delta=0.15)
