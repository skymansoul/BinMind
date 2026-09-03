"""UAF 对象代际状态 — 槽级 generation 计数.

每个指针槽 (寄存器/栈槽) 维护 (gen, source): alloc 返回推进新代际,
free 推进到无效态, mov 拷贝继承源代际, 清零置 NULL 代际. 全局指针
族以 ripabs 身份承载, 无代际语义. 同代际且来源为有效对象即同一对象.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
@dataclass
class SlotGen:
    """一个指针槽的代际状态."""
    gen: int = 0            # 代际号: 0=初始, 正数=有效对象, -1=NULL, -2=未知
    source: str = ''        # 来源描述: alloc / freed / null / unknown / ripabs
    def_idx: int = -1       # 最后定义指令索引

    def clone(self) -> 'SlotGen':
        return SlotGen(gen=self.gen, source=self.source,
                       def_idx=self.def_idx)


GEN_UNKNOWN = -2
GEN_NULL = -1
GEN_GLOBAL = -3   # 全局指针族: source 承载 ripabs 身份, 不参与代际推进


class GenState:
    """代际状态容器: 寄存器 + 栈槽."""

    def __init__(self):
        self._regs: Dict[str, SlotGen] = {}
        self._slots: Dict[str, SlotGen] = {}
        self._next_gen: int = 1

    def reg(self, name: str) -> SlotGen:
        return self._regs.get(name, SlotGen(GEN_UNKNOWN, 'unknown'))

    def slot(self, name: str) -> SlotGen:
        return self._slots.get(name, SlotGen(GEN_UNKNOWN, 'unknown'))

    def set_reg(self, name: str, sg: SlotGen) -> None:
        self._regs[name] = sg

    def set_slot(self, name: str, sg: SlotGen) -> None:
        self._slots[name] = sg

    def fresh_alloc(self, source: str = 'alloc') -> SlotGen:
        """新对象代际: gen 单调递增, 来源标注分配函数."""
        g = self._next_gen
        self._next_gen += 1
        return SlotGen(g, source, -1)

    def freed(self) -> SlotGen:
        """free 后的无效代际: gen 推进到下一个代际, 来源 freed."""
        g = self._next_gen
        self._next_gen += 1
        return SlotGen(g, 'freed', -1)

    def null(self) -> SlotGen:
        return SlotGen(GEN_NULL, 'null', -1)

    def unknown(self) -> SlotGen:
        return SlotGen(GEN_UNKNOWN, 'unknown', -1)

    def same_object(self, a: SlotGen, b: SlotGen) -> bool:
        """同代际且同来源类型 → 同一对象."""
        return a.gen == b.gen and a.gen > 0

    def clobber_volatile(self) -> None:
        """call 后易失寄存器代际置未知 (编译器约定破坏)."""
        # TODO: 按 ABI 参数化易失寄存器集, 现为 win64/sysv 并集
        for reg in ('rax', 'rcx', 'rdx', 'r8', 'r9', 'r10', 'r11'):
            cur = self._regs.get(reg)
            if cur is not None and cur.gen > 0 and \
                    cur.source != 'freed':
                self._regs[reg] = SlotGen(GEN_UNKNOWN, 'unknown', -1)

    def snapshot(self) -> dict:
        return {
            'regs': {k: (v.gen, v.source) for k, v in self._regs.items()},
            'slots': {k: (v.gen, v.source) for k, v in self._slots.items()},
        }

REG_BITS = ('rax', 'eax', 'rcx', 'ecx', 'rdx', 'edx', 'r8', 'r8d',
            'r9', 'r9d', 'rsi', 'esi', 'rdi', 'edi', 'rbx', 'ebx',
            'r10', 'r10d', 'r11', 'r11d', 'r12', 'r12d', 'r13',
            'r13d', 'r14', 'r14d', 'r15', 'r15d', 'rbp', 'rsp')
_BASE_OF = {'eax': 'rax', 'ecx': 'rcx', 'edx': 'rdx', 'esi': 'rsi',
            'edi': 'rdi', 'ebx': 'rbx', 'r8d': 'r8', 'r9d': 'r9'}
_ALLOC = ('malloc', 'calloc', 'realloc')
_FREE = ('free',)
_PARAM_REGS = ('rcx', 'rdx', 'r8', 'r9', 'rdi', 'rsi')


@dataclass
class GenEvent:
    """单指令的代际事件记录."""
    idx: int
    mnem: str = ''
    kind: str = ''          # alloc / free / copy / zero / slot_store /
                            # slot_load / call / other
    args: Dict = None
    addr: int = 0


def slot_name(op: str) -> Optional[str]:
    """规范栈槽名: [rbp-0x8] → rbp-8."""
    s = op.strip().strip('[]')
    if '+' in s:
        base, num = s.split('+', 1)
        sign = 1
    elif '-' in s:
        base, num = s.split('-', 1)
        sign = -1
    else:
        return None
    base = base.strip()
    if base not in ('rbp', 'rsp'):
        return None
    try:
        return f'{base}{"+" if sign == 1 else "-"}{abs(int(num.strip(), 0))}'
    except ValueError:
        return None


def parse_int(t: str) -> Optional[int]:
    try:
        return int(t.strip(), 0)
    except ValueError:
        return None


def _strip_ptr(op: str) -> str:
    s = op.strip()
    for p in ('QWORD PTR ', 'DWORD PTR ', 'BYTE PTR ', 'WORD PTR '):
        if s.upper().startswith(p):
            return s[len(p):].strip()
    return s


