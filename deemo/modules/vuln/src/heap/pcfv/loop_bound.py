"""循环归纳变量解析 — 计算循环累积写入的上限迭代次数.

创建: 2023-09-21
设计决策:
  - 识别反向边(back-edge)jcc 构成的最内层循环: 边界条件通常形如
    cmp ind_var, bound; jl/jle target(回跳). 归纳变量在该循环体内
    单调增减, 迭代次数 = (bound - init) / stride.
  - 只处理常量 bound/init/stride 的简单循环, 其它情形返回 None
    (保守: 不做无根据的循环展开判定).
  - loop_store 访问点需在循环体内且地址与归纳变量相关.
"""
import re
from typing import Dict, List, Optional, Tuple

from .cfg import IntraCFG
from .value_flow import ValueFlowTracer, norm_reg

_JCC_BACK = {'jl', 'jle', 'jb', 'jbe', 'jg', 'jge', 'ja', 'jae',
             'jne', 'jnz', 'je', 'jz'}
_IMM_RE = re.compile(r'0x[0-9a-fA-F]+|\b\d+\b')


class LoopBoundExtractor:
    """从函数指令流提取循环归纳变量与迭代上界."""

    def __init__(self, insns: list, tracer: ValueFlowTracer):
        self._insns = insns
        self._tracer = tracer
        self._cfg = IntraCFG(insns)
        self._addr_to_idx: Dict[int, int] = {i.addr: n for n, i in enumerate(insns)}
        self._loops: List[dict] = []
        self._detect()

    def _detect(self) -> None:
        for i, insn in enumerate(self._insns):
            if insn.mnemonic not in _JCC_BACK:
                continue
            tgt = _parse_target(insn.operands)
            if tgt is None or tgt not in self._addr_to_idx:
                continue
            back_idx = self._addr_to_idx[tgt]
            if back_idx > i:
                continue  # 后向边
            loop = self._summarize_loop(back_idx, i)
            if loop is not None:
                self._loops.append(loop)

    def _summarize_loop(self, head_idx: int, back_jcc_idx: int) -> Optional[dict]:
        """解析循环: 归纳变量(寄存器或栈槽), 初始值, 步长, 上界."""
        jcc = self._insns[back_jcc_idx]
        cmp_insn = self._find_cmp_before(back_jcc_idx)
        if cmp_insn is None:
            return None
        left, right = _split_pair(cmp_insn.operands)
        bound = _parse_imm(right)
        if bound is None:
            bound_m = re.search(r'\b(r[0-9a-d]+[bwd]?)\b', right,
                                re.IGNORECASE)
            if bound_m:
                bv = self._tracer.trace(norm_reg(bound_m.group(1)),
                                        jcc.addr)
                bound = bv.interval_hi
            if bound is None:
                return None

        # 归纳变量: 寄存器 或 栈槽 ([rbp-0x4] 形式, -O0 计数器)
        ind_slot = None
        ind_reg = None
        reg_m = re.search(r'\b(r[0-9a-d]+[bwd]?|[er]?[abcd]x)\b', left,
                          re.IGNORECASE)
        if reg_m and '[' not in left:
            ind_reg = norm_reg(reg_m.group(1))
        else:
            slot_m = re.search(r'\[([^\]]+)\]', left)
            if slot_m:
                ind_slot = _slot_key(slot_m.group(0))

        if ind_reg is None and ind_slot is None:
            return None

        if ind_reg is not None:
            init = self._find_induction_init(ind_reg, head_idx, jcc.addr)
        else:
            init = self._find_slot_init(ind_slot, head_idx, jcc.addr)
        if ind_reg is not None:
            stride = self._find_stride(ind_reg, head_idx, back_jcc_idx)
        else:
            stride = self._find_slot_stride(ind_slot, head_idx,
                                            back_jcc_idx)
        if init is None or stride is None or stride == 0:
            return None

        op = jcc.mnemonic
        if op in ('jl', 'jb'):        # ind < bound
            iters = _ceil_div(bound - init, stride)
        elif op in ('jle', 'jbe'):    # ind <= bound
            iters = _ceil_div(bound - init, stride) + 1
        elif op in ('jne', 'jnz'):
            iters = _ceil_div(bound - init, stride)
        elif op in ('jg', 'ja'):
            iters = _ceil_div(init - bound, stride)
        elif op in ('jge', 'jae'):
            iters = _ceil_div(init - bound, stride) + 1
        else:
            return None

        if iters <= 0 or iters > 1_000_000:
            return None

        return {'head_idx': head_idx, 'back_idx': back_jcc_idx,
                'ind_reg': ind_reg, 'ind_slot': ind_slot,
                'init': init, 'stride': stride,
                'bound': bound, 'iters': iters, 'jcc': jcc.addr}

    def _find_slot_init(self, slot: str, head_idx: int,
                        jcc_addr: int) -> Optional[int]:
        """栈槽计数器初始化: mov DWORD PTR [rbp-4], imm 或 xor+mov.
        注意: 循环守卫 jmp 会插在初始化与循环头之间, 不能因 jmp 中断扫描."""
        for j in range(head_idx - 1, max(-1, head_idx - 20) - 1, -1):
            insn = self._insns[j]
            if insn.addr >= jcc_addr:
                continue
            mn = insn.mnemonic
            if mn in ('mov', 'movabs'):
                dst, src = _split_pair(insn.operands)
                if _slot_key(dst) == slot:
                    imm = _parse_imm(src)
                    if imm is not None:
                        return imm
                    src_reg_m = re.search(
                        r'\b(r[0-9a-d]+[bwd]?|[er]?[abcd]x)\b', src,
                        re.IGNORECASE)
                    if src_reg_m:
                        v = self._tracer.trace(
                            norm_reg(src_reg_m.group(1)), insn.addr)
                        return v.constant_value
            elif mn in ('xor', 'pxor'):
                dst, src = _split_pair(insn.operands)
                if _slot_key(dst) == slot and dst.rstrip() == src.rstrip():
                    return 0
            elif mn in ('call', 'callq'):
                break
        return None

    def _find_slot_stride(self, slot: str, head_idx: int,
                          back_idx: int) -> Optional[int]:
        for j in range(head_idx, back_idx):
            insn = self._insns[j]
            if insn.mnemonic in ('add', 'sub', 'inc', 'dec'):
                dst, src = _split_pair(insn.operands)
                if _slot_key(dst) == slot:
                    if insn.mnemonic == 'inc':
                        return 1
                    if insn.mnemonic == 'dec':
                        return -1
                    imm = _parse_imm(src)
                    if imm is not None:
                        return imm if insn.mnemonic == 'add' else -imm
        return None

    def _find_cmp_before(self, idx: int):
        for j in range(idx - 1, max(0, idx - 4) - 1, -1):
            insn = self._insns[j]
            if insn.mnemonic in ('cmp', 'cmpq', 'cmpb', 'cmpw',
                                 'test', 'testq'):
                return insn
            if insn.mnemonic.startswith(('mov', 'lea', 'call', 'jmp')):
                return None
        return None

    def _find_induction_init(self, reg: str, head_idx: int,
                             jcc_addr: int) -> Optional[int]:
        for j in range(head_idx - 1, max(-1, head_idx - 15) - 1, -1):
            insn = self._insns[j]
            if insn.addr >= jcc_addr:
                continue
            if insn.mnemonic in ('mov', 'movabs'):
                dst, src = _split_pair(insn.operands)
                if norm_reg(dst) == reg:
                    v = self._tracer.trace(reg, insn.addr)
                    return v.constant_value if v.is_constant else None
            if insn.mnemonic == 'xor':
                dst, src = _split_pair(insn.operands)
                if norm_reg(dst) == reg and dst.rstrip() == src.rstrip():
                    return 0
            if insn.mnemonic.startswith(('call', 'jmp', 'j')):
                break
        return None

    def _find_stride(self, reg: str, head_idx: int, back_idx: int) -> Optional[int]:
        for j in range(head_idx, back_idx):
            insn = self._insns[j]
            if insn.mnemonic in ('add', 'sub', 'inc', 'dec'):
                dst, src = _split_pair(insn.operands)
                if norm_reg(dst) == reg:
                    if insn.mnemonic == 'inc':
                        return 1
                    if insn.mnemonic == 'dec':
                        return -1
                    imm = _parse_imm(src)
                    if imm is not None:
                        return imm if insn.mnemonic == 'add' else -imm
        return None

    def is_in_loop(self, addr: int) -> Optional[dict]:
        """addr 若在最内层循环体内 → 返回该循环摘要."""
        idx = self._addr_to_idx.get(addr)
        if idx is None:
            return None
        best = None
        for loop in self._loops:
            if loop['head_idx'] <= idx <= loop['back_idx']:
                if best is None or (loop['back_idx'] - loop['head_idx']
                                    < best['back_idx'] - best['head_idx']):
                    best = loop
        return best


def _parse_target(operands: str) -> Optional[int]:
    """解析跳转目标: '140001792 <main+0x32>' / '0x140001792'.
    objdump 无0x前缀的地址是十六进制, 按16进制优先解析."""
    t = operands.strip()
    token = t.split()[0] if t else ''
    if not token:
        return None
    try:
        return int(token, 16)
    except ValueError:
        pass
    try:
        return int(token, 10)
    except ValueError:
        return None


def _parse_imm(op: str) -> Optional[int]:
    if not op:
        return None
    m = re.search(r'0x[0-9a-fA-F]+', op)
    if m:
        try:
            return int(m.group(0), 16)
        except ValueError:
            return None
    m = re.search(r'\b\d+\b', op)
    if m:
        v = int(m.group(0))
        return v if v < 0x1000000 else None
    return None


def _split_pair(operands: str) -> Tuple[str, str]:
    parts = [p.strip() for p in operands.split(',')]
    while len(parts) < 2:
        parts.append('')
    return parts[0], parts[1]


def _ceil_div(a: int, b: int) -> int:
    if a <= 0:
        return 0
    return (a + b - 1) // b


def _slot_key(mem_operand: str) -> str:
    """栈槽规范化键: 'DWORD PTR [rbp-0x4]' → '[rbp-4]'."""
    m = re.search(r'\[([^\]]+)\]', mem_operand)
    if not m:
        return mem_operand
    inner = m.group(1).strip()
    reg_m = re.search(r'\b(r[0-9a-d]+[bwd]?|[er]?[abcd]x|[er]?[sb]p)\b',
                      inner, re.IGNORECASE)
    if reg_m is None:
        return inner
    reg = norm_reg(reg_m.group(1))
    disp_m = re.search(r'([+-])\s*(0x[0-9a-fA-F]+|\d+)', inner)
    disp = 0
    if disp_m:
        try:
            val = int(disp_m.group(2), 0)
        except ValueError:
            val = 0
        disp = val if disp_m.group(1) == '+' else -val
    return f'[{reg}{disp:+d}]'
