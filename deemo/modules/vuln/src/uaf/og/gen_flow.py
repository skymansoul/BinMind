"""UAF 对象代际转移 — 槽级代际状态与指令流映射.

每个指针槽 (寄存器/栈槽) 维护 (gen, source): alloc 返回推进新代际,
free 推进到无效态, mov 拷贝继承源代际, 清零置 NULL 代际, 任意重赋值
改变槽代际. call 返回值隐式更新 rax. 线性扫描将指令映射为代际
事件, 调用点参数快照供跨函数绑定.
"""
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

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

    def fresh_alloc(self) -> SlotGen:
        """新对象代际: gen 单调递增, 来源 alloc."""
        g = self._next_gen
        self._next_gen += 1
        return SlotGen(g, 'alloc', -1)

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

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


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


class GenFlowTracker:
    """线性指令流的代际转移执行器."""

    def __init__(self, state: Optional[GenState] = None,
                 abi: str = 'win64'):
        self._state = state or GenState()
        self._abi = abi
        self._calls: List[GenEvent] = []
        self._free_events: List[GenEvent] = []
        self._last_call: str = ''

    @property
    def state(self) -> GenState:
        return self._state

    def run(self, instructions: List[str],
            addrs: Optional[List[int]] = None) -> None:
        for idx, text in enumerate(instructions):
            addr = addrs[idx] if addrs and idx < len(addrs) else 0
            self.step(text, idx, addr)

    def step(self, text: str, idx: int,
             addr: int = 0) -> Optional[GenEvent]:
        line = text.strip()
        if not line:
            return None
        parts = line.split(None, 1)
        if len(parts) < 2:
            return None
        mnem = parts[0].lower()
        ops = parts[1].strip()
        ev = GenEvent(idx=idx, mnem=mnem, addr=addr, args={})

        if mnem.startswith('call'):
            self._handle_call(ev, ops)
            return ev
        if mnem in ('mov', 'movzx', 'movsx', 'movsxd', 'movq', 'movabs'):
            self._handle_mov(ev, ops)
        elif mnem == 'xor':
            self._handle_xor(ev, ops)
        elif mnem == 'lea':
            self._handle_lea(ev, ops)
        elif mnem == 'ret':
            self._state = GenState()
        return ev

    def _handle_call(self, ev: GenEvent, ops: str) -> None:
        raw = ops.strip()
        m = re.search(r'<([^>]+)>', raw)
        callee = m.group(1).split('+')[0].split('@')[0].strip() if m \
            else raw.split()[0].strip('*')
        ev.args['callee'] = callee
        args = {}
        for reg in _PARAM_REGS:
            sg = self._state.reg(reg)
            if sg.gen != GEN_UNKNOWN:
                args[reg] = (sg.gen, sg.source)
        ev.args['params'] = args
        self._calls.append(ev)
        self._last_call = callee

        if callee in _ALLOC:
            ret = self._state.fresh_alloc()
            self._state.set_reg('rax', ret)
            self._state.set_reg('eax', ret)
            ev.kind = 'alloc'
            ev.args['gen'] = ret.gen
            return
        if callee in _FREE:
            reg = 'rcx' if self._abi == 'win64' else 'rdi'
            ev.kind = 'free'
            ev.args['free_reg'] = reg
            freed = self._state.freed()
            self._state.set_reg(reg, freed)
            self._state.set_reg(_BASE_OF.get(reg, reg), freed)
            self._free_events.append(ev)
            return
        # 普通调用: 参数槽代际快照已记录; 易失寄存器 clobber
        ev.kind = 'call'
        self._state.clobber_volatile()

    def _handle_mov(self, ev: GenEvent, ops: str) -> None:
        if ',' not in ops:
            return
        dst, src = (x.strip() for x in ops.split(',', 1))
        dst = _strip_ptr(dst)
        src = _strip_ptr(src)
        if dst.startswith('[') and dst.endswith(']'):
            sl = slot_name(dst)
            if sl:
                sg = self._src_gen(src)
                self._state.set_slot(sl, sg)
                ev.kind = 'slot_store'
                ev.args = {'slot': sl, 'src': sg.source, 'gen': sg.gen}
            return
        dst_reg = dst.split()[0]
        if dst_reg in REG_BITS:
            sg = self._src_gen(src)
            self._state.set_reg(dst_reg, sg)
            if dst_reg in _BASE_OF:
                self._state.set_reg(_BASE_OF[dst_reg], sg)
            ev.kind = 'copy'
            ev.args = {'dst': dst_reg, 'src': sg.source, 'gen': sg.gen}

    def _src_gen(self, src: str) -> SlotGen:
        s = src.strip()
        for reg in REG_BITS:
            if s == reg or s.startswith(reg + ' ') or s.startswith(reg + ','):
                sg = self._state.reg(reg)
                if sg.gen == GEN_UNKNOWN:
                    return self._state.unknown()
                return SlotGen(sg.gen, sg.source, sg.def_idx)
        if s.startswith('[') and s.endswith(']'):
            sl = slot_name(s)
            if sl:
                return self._state.slot(sl)
            rm = re.search(r'\[rip\+0x([0-9a-fA-F]+)\]', s)
            am = re.search(r'#\s+(?:0x)?([0-9a-fA-F]{6,16})\b', s)
            if am:
                return SlotGen(GEN_GLOBAL, f'ripabs:{am.group(1).lower()}', -1)
            if rm:
                return SlotGen(GEN_GLOBAL, f'rip:{rm.group(1).lower()}', -1)
            return self._state.unknown()
        v = parse_int(s)
        if v is not None:
            return self._state.null() if v == 0 else self._state.unknown()
        return self._state.unknown()

    def _handle_xor(self, ev: GenEvent, ops: str) -> None:
        if ',' not in ops:
            return
        a, b = (x.strip() for x in ops.split(','))
        if a == b and a.split()[0] in REG_BITS:
            reg = a.split()[0]
            sg = self._state.null()
            self._state.set_reg(reg, sg)
            if reg in _BASE_OF:
                self._state.set_reg(_BASE_OF[reg], sg)
            ev.kind = 'zero'
            ev.args = {'reg': reg}

    def _handle_lea(self, ev: GenEvent, ops: str) -> None:
        if ',' not in ops:
            return
        dst = ops.split(',', 1)[0].strip().split()[0]
        if dst not in REG_BITS:
            return
        src = _strip_ptr(ops.split(',', 1)[1].strip())
        if src.startswith('[') and src.endswith(']'):
            inner = src[1:-1]
            base = re.match(r'^([a-z0-9]+)', inner, re.I)
            if base:
                sg = self._state.reg(base.group(1))
                if sg.gen > 0:
                    self._state.set_reg(dst, SlotGen(sg.gen, sg.source, -1))
                    ev.kind = 'copy'
                    ev.args = {'dst': dst, 'gen': sg.gen}
                    return
        self._state.set_reg(dst, self._state.unknown())
        ev.kind = 'other'

    def free_events(self) -> List[GenEvent]:
        return self._free_events

    def calls(self) -> List[GenEvent]:
        return self._calls

    def gen_at(self, reg: str) -> SlotGen:
        return self._state.reg(reg)
