"""定义链追踪 — 寄存器/栈槽最近定义点线性近似.

  - 输入仅指令文本, 无 CFG. 定义链按线性顺序近似, 写覆盖旧定义.
  - 直通: mov/lea/movzx 保持数据源; add/sub/shl 等标记 DERIVED,
    同源性断裂, 耦合判定保守.
  - 栈槽别名: [rbp-N]/[rsp+N] 与寄存器 mov 建立绑定 (spill 模拟).
  - call: 快照参数寄存器定义; rax 隐式更新为 RETURN 身份.
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

class DefKind:
    IMM = 'IMM'          # 立即数
    REG = 'REG'          # 寄存器拷贝 (直通)
    SLOT = 'SLOT'        # 栈槽 (spill 读取)
    MEM = 'MEM'          # 全局/间接内存读取
    DERIVED = 'DERIVED'  # 经算术变换, 同源性断裂
    ARG = 'ARG'          # 函数入参寄存器 (无法跟踪来源)
    RETURN = 'RETURN'    # call 返回值 (身份=目标函数)
    UNKNOWN = 'UNKNOWN'


@dataclass
class DefNode:
    """一个数据定义点."""
    kind: str = DefKind.UNKNOWN
    imm: int = 0              # IMM 时的立即数值
    reg: str = ''             # REG 时的源寄存器
    slot: str = ''            # SLOT 时的栈槽名
    insn_idx: int = -1        # 定义指令位置
    derived_op: str = ''      # DERIVED 时的操作描述
    derived_base: str = ''    # DERIVED 时的基身份键
    derived_delta: int = 0    # DERIVED 时的立即数增量
    ret_name: str = ''        # RETURN 时的目标函数名

    def is_concrete(self) -> bool:
        return self.kind == DefKind.IMM

    def describe(self) -> str:
        if self.kind == DefKind.IMM:
            return f'imm({self.imm:#x})'
        if self.kind == DefKind.REG:
            return f'reg({self.reg})'
        if self.kind == DefKind.SLOT:
            return f'slot({self.slot})'
        if self.kind == DefKind.DERIVED:
            return f'derived({self.derived_op})'
        if self.kind == DefKind.RETURN:
            return f'ret({self.ret_name})'
        return self.kind


@dataclass
class CallSnapshot:
    """call 指令处的参数寄存器定义快照."""
    insn_idx: int
    callee: str = ''
    args: Dict[str, DefNode] = field(default_factory=dict)


REG_BITS = {
    'rax': 64, 'eax': 32, 'ax': 16, 'al': 8, 'ah': 8,
    'rbx': 64, 'ebx': 32, 'bx': 16, 'bl': 8, 'bh': 8,
    'rcx': 64, 'ecx': 32, 'cx': 16, 'cl': 8, 'ch': 8,
    'rdx': 64, 'edx': 32, 'dx': 16, 'dl': 8, 'dh': 8,
    'rsi': 64, 'esi': 32, 'si': 16, 'sil': 8,
    'rdi': 64, 'edi': 32, 'di': 16, 'dil': 8,
    'r8': 64, 'r8d': 32, 'r8w': 16, 'r8b': 8,
    'r9': 64, 'r9d': 32, 'r9w': 16, 'r9b': 8,
    'r10': 64, 'r10d': 32, 'r11': 64, 'r11d': 32,
    'r12': 64, 'r12d': 32, 'r13': 64, 'r13d': 32,
    'r14': 64, 'r14d': 32, 'r15': 64, 'r15d': 32,
    'rbp': 64, 'rsp': 64, 'rip': 64,
}
_BASE_OF = {'eax': 'rax', 'ax': 'rax', 'al': 'rax', 'ah': 'rax',
            'ebx': 'rbx', 'bx': 'rbx', 'bl': 'rbx', 'bh': 'rbx',
            'ecx': 'rcx', 'cx': 'rcx', 'cl': 'rcx', 'ch': 'rcx',
            'edx': 'rdx', 'dx': 'rdx', 'dl': 'rdx', 'dh': 'rdx',
            'esi': 'rsi', 'si': 'rsi', 'sil': 'rsi',
            'edi': 'rdi', 'di': 'rdi', 'dil': 'rdi',
            'r8d': 'r8', 'r8w': 'r8', 'r8b': 'r8',
            'r9d': 'r9', 'r9w': 'r9', 'r9b': 'r9'}
_D32_OF = {'rax': 'eax', 'rbx': 'ebx', 'rcx': 'ecx', 'rdx': 'edx',
           'rsi': 'esi', 'rdi': 'edi', 'r8': 'r8d', 'r9': 'r9d'}


def slot_name(operand: str) -> Optional[str]:
    """规范栈槽名: [rbp-0x8] → rbp-8, [rsp+0x10] → rsp+16."""
    op = operand.strip().strip('[]')
    parts = op.split('+') if '+' in op else op.split('-')
    if len(parts) != 2:
        return None
    base = parts[0].strip()
    if base not in ('rbp', 'rsp'):
        return None
    try:
        val = int(parts[1].strip(), 0)
    except ValueError:
        return None
    sign = '+' if '+' in op else '-'
    return f'{base}{sign}{val}'


def parse_int(text: str) -> Optional[int]:
    try:
        return int(text.strip(), 0)
    except ValueError:
        return None

class DefChainTracker:
    """线性指令流的定义链追踪器.

    仅追踪影响同源性判定的数据依赖, 不构建完整 SSA.
    """

    def __init__(self):
        self._regs: Dict[str, DefNode] = {}
        self._slots: Dict[str, DefNode] = {}
        self._mem: Dict[str, DefNode] = {}
        self._calls: List[CallSnapshot] = []
        self._param_regs = ('rcx', 'rdx', 'r8', 'r9', 'rdi', 'rsi')
        self._import_map: Dict[int, str] = {}
        self._last_call: str = ''
        self._last_call_idx: int = -1

    def set_import_map(self, import_map: Dict[int, str]) -> None:
        """注入 thunk 地址→名字映射, 支撑无符号二进制的调用识别."""
        self._import_map = import_map

    def scan(self, instructions: List[str],
             addrs: Optional[List[int]] = None) -> None:
        """线性扫描全部指令, 建立定义链."""
        for idx, text in enumerate(instructions):
            addr = addrs[idx] if addrs and idx < len(addrs) else None
            self.step(text, idx, addr)

    def step(self, text: str, idx: int = -1,
             addr: Optional[int] = None) -> None:
        """单步处理一条指令, 供位置敏感查询在线判定."""
        line = text.strip()
        if not line:
            return
        parts = line.split(None, 1)
        if len(parts) < 2:
            return
        mnem = parts[0].lower()
        ops = parts[1].strip() if len(parts) > 1 else ''
        if mnem.startswith('call'):
            self._record_call(idx, mnem, ops, addr)
            return
        if mnem in ('mov', 'movzx', 'movsx', 'movsxd', 'lea',
                    'movq', 'movabs', 'cmovne', 'cmove', 'cmovb'):
            self._apply_move(idx, mnem, ops)
        elif mnem.startswith('mov') and ',' in ops:
            self._apply_move(idx, mnem, ops)
        elif mnem in ('add', 'sub', 'imul', 'mul', 'shl', 'shr',
                      'sar', 'and', 'or', 'xor', 'neg', 'inc', 'dec'):
            self._apply_arith(idx, mnem, ops)
        elif mnem in ('xchg', 'bswap', 'pop', 'push'):
            self._apply_misc(idx, mnem, ops)

    def _record_call(self, idx: int, mnem: str, ops: str,
                     addr: Optional[int] = None) -> None:
        callee = self._callee_name(ops, addr)
        snap = CallSnapshot(insn_idx=idx, callee=callee)
        for reg in self._param_regs:
            node = self._regs.get(reg)
            if node is None and reg in _D32_OF:
                node = self._regs.get(_D32_OF[reg])
            if node is not None:
                snap.args[reg] = node
        self._calls.append(snap)
        self._last_call = callee
        self._last_call_idx = idx
        # call 返回值约定: rax 隐式定义为 RETURN(callee), 支撑
        # 后续 mov reg, rax 的返回值身份传播
        self._regs['rax'] = DefNode(DefKind.RETURN, reg='rax',
                                    insn_idx=idx, ret_name=callee)
        self._regs['eax'] = self._regs['rax']

    def _callee_name(self, ops: str,
                     addr: Optional[int] = None) -> str:
        """call 目标名: <符号> → IAT thunk → 裸地址."""
        raw = ops.strip()
        if not raw:
            return 'indirect'
        m = re.search(r'<([^>]+)>', raw)
        if m:
            name = m.group(1)
            return name.split('+')[0].split('@')[0].strip()
        try:
            target = int(raw.split()[0].strip('*'), 16)
            if target in self._import_map:
                return self._import_map[target]
        except (ValueError, IndexError):
            pass
        return raw.split()[0].strip('*')

    def _apply_move(self, idx: int, mnem: str, ops: str) -> None:
        if ',' not in ops:
            return
        dst, src = ops.split(',', 1)
        dst, src = dst.strip(), src.strip()
        node = self._resolve_src(src, idx)
        if dst.startswith('[') and dst.endswith(']'):
            sl = slot_name(dst)
            if sl:
                self._slots[sl] = node
            else:
                self._mem[dst] = node
            return
        dst_reg = dst.strip().split()[0] if dst.strip() else ''
        if dst_reg in REG_BITS:
            if mnem == 'lea':
                base_id, delta = self._parse_lea(src)
                old = self._regs.get(dst_reg)
                if not base_id and old is not None:
                    base_id = self.identity(old)
                self._regs[dst_reg] = DefNode(
                    DefKind.DERIVED, reg=dst_reg, insn_idx=idx,
                    derived_op=f'lea {src}',
                    derived_base=base_id, derived_delta=delta)
            else:
                self._regs[dst_reg] = self._maybe_return(node, idx)
            if dst_reg in _BASE_OF:
                # 32 位写零扩展高 32 位, 基寄存器值同步
                self._regs[_BASE_OF[dst_reg]] = self._regs[dst_reg]

    def _maybe_return(self, node: DefNode, idx: int) -> DefNode:
        """call 后 'mov reg, rax' 标记为返回值身份."""
        if node.kind == DefKind.RETURN:
            return node
        if self._last_call and idx - self._last_call_idx <= 3:
            if node.kind in (DefKind.UNKNOWN, DefKind.REG):
                return DefNode(DefKind.RETURN, reg=node.reg, insn_idx=idx,
                               ret_name=self._last_call)
        return node

    def _parse_lea(self, src: str):
        """lea 操作数 → (基身份, 增量). lea rax,[rbp-8] 基为槽;
        lea r8,[rax+0x1] 基为 rax 身份, 增量为 1."""
        s = src.strip()
        if not (s.startswith('[') and s.endswith(']')):
            return '', 0
        inner = s[1:-1]
        m = re.match(r'^([a-z0-9]+)([+-])(0x[0-9a-fA-F]+|\d+)$', inner,
                     re.IGNORECASE)
        if m:
            reg = m.group(1)
            sign = -1 if m.group(2) == '-' else 1
            try:
                delta = sign * int(m.group(3), 0)
            except ValueError:
                delta = 0
            dn = self.def_of_reg(reg)
            base_id = self.identity(dn)
            return base_id, delta
        if re.fullmatch(r'[a-z0-9]+', inner, re.IGNORECASE):
            dn = self.def_of_reg(inner)
            return self.identity(dn), 0
        return '', 0

    def _apply_arith(self, idx: int, mnem: str, ops: str) -> None:
        if ',' not in ops:
            dst = ops.strip().split()[0]
            if dst in REG_BITS:
                self._regs[dst] = DefNode(DefKind.DERIVED, reg=dst,
                                          insn_idx=idx, derived_op=mnem)
                if dst in _BASE_OF:
                    self._regs[_BASE_OF[dst]] = self._regs[dst]
            return
        dst = ops.split(',', 1)[0].strip()
        dst_reg = dst.split()[0] if dst else ''
        if dst_reg not in REG_BITS:
            return
        rest = ops.split(',', 1)[1].strip()
        delta = 0
        m = re.search(r'(?:0x[0-9a-fA-F]+|\d+)$', rest)
        if m:
            try:
                delta = int(m.group(0), 0)
            except ValueError:
                delta = 0
        old = self._regs.get(dst_reg)
        base_id = self.identity(old) if old is not None else ''
        self._regs[dst_reg] = DefNode(
            DefKind.DERIVED, reg=dst_reg, insn_idx=idx,
            derived_op=mnem, derived_base=base_id, derived_delta=delta)
        if dst_reg in _BASE_OF:
            self._regs[_BASE_OF[dst_reg]] = self._regs[dst_reg]

    def _apply_misc(self, idx: int, mnem: str, ops: str) -> None:
        if mnem == 'xchg' and ',' in ops:
            a, b = (x.strip().split()[0] for x in ops.split(','))
            if a in REG_BITS and b in REG_BITS:
                na, nb = self._regs.get(a), self._regs.get(b)
                self._regs[a] = nb or DefNode(DefKind.UNKNOWN, insn_idx=idx)
                self._regs[b] = na or DefNode(DefKind.UNKNOWN, insn_idx=idx)

    def _resolve_src(self, src: str, idx: int) -> DefNode:
        """源操作数 → DefNode. 栈槽读取返回 SLOT 身份节点 (同源判定基础)."""
        s = src.strip()
        for _p in ('QWORD PTR ', 'DWORD PTR ', 'BYTE PTR ',
                   'WORD PTR ', 'XMMWORD PTR ', 'OWORD PTR '):
            if s.upper().startswith(_p):
                s = s[len(_p):].strip()
                break
        if s.startswith('[') and s.endswith(']'):
            sl = slot_name(s)
            if sl:
                return DefNode(DefKind.SLOT, slot=sl, insn_idx=idx)
            return DefNode(DefKind.MEM, insn_idx=idx)
        for reg in sorted(REG_BITS, key=len, reverse=True):
            if s == reg or s.startswith(reg + ' ') or s.startswith(reg + ','):
                node = self._regs.get(reg)
                if node is None:
                    base = _D32_OF.get(reg) or _BASE_OF.get(reg)
                    node = self._regs.get(base) if base else None
                return node or DefNode(DefKind.REG, reg=reg, insn_idx=idx)
        imm = parse_int(s)
        if imm is not None:
            return DefNode(DefKind.IMM, imm=imm, insn_idx=idx)
        if s.startswith('QWORD PTR') or s.startswith('DWORD PTR'):
            return DefNode(DefKind.MEM, insn_idx=idx)
        return DefNode(DefKind.UNKNOWN, insn_idx=idx)


    def def_of_reg(self, reg: str) -> DefNode:
        if reg not in REG_BITS:
            return DefNode(DefKind.UNKNOWN)
        return self._regs.get(reg) or DefNode(DefKind.UNKNOWN)

    def def_of_slot(self, slot: str) -> DefNode:
        return self._slots.get(slot) or DefNode(DefKind.UNKNOWN)

    def calls(self) -> List[CallSnapshot]:
        return self._calls

    def calls_named(self, names: Tuple[str, ...]) -> List[CallSnapshot]:
        return [c for c in self._calls if c.callee in names]

    def call_args(self, insn_idx: int) -> Dict[str, DefNode]:
        for c in self._calls:
            if c.insn_idx == insn_idx:
                return c.args
        return {}

    def resolve(self, node: DefNode) -> DefNode:
        """沿直通链展开到根 (数值提取); identity 停在身份锚点."""
        cur = node
        for _ in range(10):
            if cur.kind == DefKind.REG and cur.reg:
                nxt = self._regs.get(cur.reg)
                if nxt is None:
                    nxt = self._regs.get(_D32_OF.get(cur.reg, '')) or \
                        self._regs.get(_BASE_OF.get(cur.reg, ''))
                if nxt and nxt is not cur:
                    cur = nxt
                    continue
            if cur.kind == DefKind.SLOT and cur.slot:
                nxt = self._slots.get(cur.slot)
                if nxt and nxt is not cur:
                    cur = nxt
                    continue
            break
        return cur

    def identity(self, node: DefNode) -> str:
        """身份键: SLOT/MEM/ARG/RETURN 为锚点, REG 沿链展开."""
        cur = node
        for _ in range(10):
            if cur.kind == DefKind.SLOT and cur.slot:
                return f'slot:{cur.slot}'
            if cur.kind == DefKind.MEM:
                return 'mem'
            if cur.kind == DefKind.ARG:
                return f'arg:{cur.reg}'
            if cur.kind == DefKind.RETURN:
                return f'ret:{cur.ret_name}'
            if cur.kind == DefKind.REG and cur.reg:
                nxt = self._regs.get(cur.reg)
                if nxt is None:
                    nxt = self._regs.get(_D32_OF.get(cur.reg, '')) or \
                        self._regs.get(_BASE_OF.get(cur.reg, ''))
                if nxt and nxt is not cur:
                    cur = nxt
                    continue
                return f'arg:{cur.reg}'
            return ''
        return ''
