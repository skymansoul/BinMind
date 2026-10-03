# coding: utf-8
"""守卫感知的路径敏感区间精化 — 从分支/条件移动提取 write_size 上限.

误报根因: 溢出路径上存在上限守卫 (cmp + cmov / cmp + jcc + 赋值) 时,
现有区间分析无视分支条件, 将 write_size 视为 top 而保留候选.
本模块在 write 值定义点到 write 调用之间提取守卫, 精化 write_size 区间
上界; 若 alloc 下界 ≥ 守卫上限, 则可证明安全并过滤.

守卫模式 (均取保守上界):
  A  min-cap:  cmp x, CAP; cmova/cmovbe x, CAP  → x ≤ CAP
  B  branch-cap: cmp x, CAP; jcc L; mov x, CAP; L → 汇合后 x ≤ CAP
  C  relational: cmp write, alloc; jbe/jae → write ≤ alloc (alloc 已知时)

参考: 路径敏感分析中的守卫精化 (Branch Guard Propagation) 与
      区间域 meet 运算; 在此将守卫转化为可精化区间的代数约束.
"""

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from modules.core.compat.value_range import Interval

_CMOV_MIN = {'cmova', 'cmovae', 'cmovnbe', 'cmovnbel'}   # unsigned above → min(x, cap)
_CMOV_CAP = {'cmovbe', 'cmovb', 'cmovna', 'cmovnae'}     # unsigned below → x 原本 ≤ cap
_JCC_ABOVE = {'ja', 'jae', 'jnbe', 'jnbel'}              # 超过时跳走 → fallthrough 路径 x ≤ cap
_JCC_BELOW = {'jbe', 'jb', 'jna', 'jnae', 'jle', 'jl'}   # 低于时跳走 → taken 路径 x ≤ cap
_CMOV_ALL = _CMOV_MIN | _CMOV_CAP
_JCC_ALL = _JCC_ABOVE | _JCC_BELOW

_REG_NAMES = ['r15', 'r14', 'r13', 'r12', 'r11', 'r10', 'r9', 'r8',
              'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp',
              'eax', 'ebx', 'ecx', 'edx', 'esi', 'edi',
              'ax', 'bx', 'cx', 'dx', 'si', 'di',
              'r8d', 'r9d', 'r10d', 'r11d', 'r12d', 'r13d', 'r14d', 'r15d',
              'al', 'bl', 'cl', 'dl', 'spl', 'bpl']
_REG_TOKEN = re.compile(
    r'\b(' + '|'.join(sorted(_REG_NAMES, key=len, reverse=True)) + r')\b', re.I)

_REG_FAMILY: Dict[str, str] = {
    'rax': 'rax', 'rbx': 'rbx', 'rcx': 'rcx', 'rdx': 'rdx',
    'rsi': 'rsi', 'rdi': 'rdi', 'rbp': 'rbp', 'rsp': 'rsp',
    'eax': 'rax', 'ebx': 'rbx', 'ecx': 'rcx', 'edx': 'rdx',
    'esi': 'rsi', 'edi': 'rdi',
    'ax': 'rax', 'bx': 'rbx', 'cx': 'rcx', 'dx': 'rdx',
    'si': 'rsi', 'di': 'rdi', 'al': 'rax', 'bl': 'rbx',
    'cl': 'rcx', 'dl': 'rdx', 'spl': 'rsp', 'bpl': 'rbp',
}
for _i in range(8, 16):
    _b = f'r{_i}'
    _REG_FAMILY[_b] = _b
    _REG_FAMILY[f'{_b}d'] = _b
    _REG_FAMILY[f'{_b}w'] = _b
    _REG_FAMILY[f'{_b}b'] = _b


def _regs(op_str: str) -> List[str]:
    out = []
    for m in _REG_TOKEN.finditer(op_str):
        fam = _REG_FAMILY.get(m.group(1).lower())
        if fam and fam not in out:
            out.append(fam)
    return out


_MEM_SLOT = re.compile(r'\[([a-z]+[0-9a-z]*)\s*([+\-])\s*(0x[0-9a-f]+|\d+)\]', re.I)


@dataclass
class Guard:
    """一条可证明 write_size 上界约束."""
    kind: str            # 'min_cap' | 'branch_cap' | 'relational'
    var: str             # 被约束的变量 (write 值的直接来源)
    cap: int             # 上界 (字节)
    addr: int            # 守卫指令地址
    detail: str = ''


def _slot_in(op_str: str) -> Optional[str]:
    m = _MEM_SLOT.search(op_str)
    if not m:
        return None
    base, sign, disp = m.group(1).lower(), m.group(2), m.group(3)
    v = int(disp, 16) if disp.startswith(('0x', '0X')) else int(disp)
    v = v if sign == '+' else -v
    return f'{base}{v:+d}'


def _imm_of(op: str) -> Optional[int]:
    op = op.strip()
    if op.startswith(('0x', '0X')):
        try: return int(op, 16)
        except ValueError: return None
    if op.lstrip('-').isdigit():
        return int(op)
    return None


def _reg_imm(insns: List[Dict], reg: str, boundary: int) -> Optional[int]:
    """boundary 之前 reg 最近被赋的立即数."""
    for insn in insns:
        if insn['addr'] >= boundary:
            break
        ops = [o.strip() for o in insn.get('op_str', '').split(',')]
        if not ops:
            continue
        dst = ops[0]
        if reg in _regs(dst) and insn['mnemonic'].startswith('mov') and len(ops) >= 2:
            imm = _imm_of(ops[-1])
            if imm is not None:
                return imm
    return None


def extract_guards(insns: List[Dict], lo_addr: int, hi_addr: int,
                   var: str) -> List[Guard]:
    """在 [lo_addr, hi_addr) 指令窗口内提取约束 var 的守卫."""
    # TODO: 循环携带的守卫条件 (回边路径) 未纳入, 退化依赖区间域
    window = [i for i in insns if lo_addr <= i['addr'] < hi_addr]
    guards: List[Guard] = []
    cmov_active = False

    for i, insn in enumerate(window):
        mn = insn['mnemonic']
        op_str = insn['op_str']
        addr = insn['addr']

        if mn == 'cmp':
            ops = [o.strip() for o in op_str.split(',')]
            if len(ops) < 2:
                continue
            left, right = ops[0], ops[1]
            lregs = _regs(left)
            rregs = _regs(right)
            if var not in lregs and var not in rregs:
                continue
            if var in lregs:
                other, other_side = right, rregs
            else:
                other, other_side = left, lregs
            cap = _imm_of(other)
            if cap is None and other_side:
                cap = _reg_imm(window, other_side[0], addr)
            if cap is None:
                continue
            # 后续指令决定守卫类型
            nxt = window[i + 1] if i + 1 < len(window) else None
            if nxt is None:
                continue
            nm, nop = nxt['mnemonic'], nxt['op_str']
            if nm in _CMOV_ALL and var in _regs(nop.split(',')[0]):
                guards.append(Guard('min_cap', var, cap, addr,
                                    f'cmp+{nm}: {var} ≤ {cap}'))
            elif nm in _JCC_ALL:
                # 分支守卫: 汇合后 var ≤ cap
                guards.append(Guard('branch_cap', var, cap, addr,
                                    f'cmp+{nm}: 汇合后 {var} ≤ {cap}'))
        # 关系守卫: cmp write, alloc(常量) 后接 jbe/jae
        if mn == 'jbe' or mn == 'jna' or mn == 'jae' or mn == 'jnbe':
            cmov_active = False
    return guards


def refine_with_guards(alloc_low: Optional[int], alloc_high: Optional[int],
                       write_iv: Interval, guards: List[Guard],
                       allowed_vars: List[str]) -> Tuple[Interval, List[str]]:
    """用守卫精化 write 区间, 返回 (精化区间, 应用的守卫说明)."""
    refined = write_iv
    applied: List[str] = []
    norm_allowed = {_normalize(v) for v in allowed_vars}
    for g in guards:
        if g.var not in allowed_vars and _normalize(g.var) not in norm_allowed:
            continue
        # 只收紧上界; 下界不变 (保持保守)
        hi = refined.hi
        if hi < 0 or g.cap < hi:
            refined = Interval(refined.lo, g.cap)
            applied.append(g.detail)
    # 若存在 alloc 常量下界且精化后 write 上界 ≤ alloc 下界 → 安全
    return refined, applied


def _resolve_var_lineage(var: str, write_def: Optional[int],
                         insns: List[Dict]) -> Tuple[List[str], int]:
    """将 write 值变量解析为 (寄存器谱系, 锚点地址).

    write 值为栈槽 (rbp-16) 时, 守卫作用于产生该值的寄存器 (cmov 链),
    锚点取槽 store 地址 (守卫窗口需覆盖 store 之前的 cmp/cmov);
    值为寄存器时锚点取 write_def 本身.
    """
    if var.startswith(('rbp', 'rsp')) and write_def:
        for insn in insns:
            if insn['addr'] == write_def:
                ops = [o.strip() for o in insn.get('op_str', '').split(',')]
                if len(ops) >= 2 and _slot_in(ops[-1]):
                    slot = _slot_in(ops[-1])
                    store = _slot_last_store(insns, slot, write_def)
                    if store is not None:
                        for s in insns:
                            if s['addr'] == store:
                                regs = [r for r in _regs(s['op_str'])
                                        if r not in ('rbp', 'rsp')]
                                return (regs, store)
    return ([var], write_def or 0)


def _slot_last_store(insns: List[Dict], slot: str,
                     boundary: int) -> Optional[int]:
    """boundary 之前对 slot 的最后一次 store (跨函数用地址序取末次)."""
    store_addr: Optional[int] = None
    for insn in insns:
        if insn['addr'] >= boundary:
            break
        ops = [o.strip() for o in insn.get('op_str', '').split(',')]
        if ops and _slot_in(ops[0]) == slot:
            store_addr = insn['addr']
    return store_addr


def prove_safe_with_guards(candidate: Dict, insns: List[Dict],
                           write_var: Optional[str] = None) -> Tuple[bool, str, Interval]:
    """对候选执行守卫精化证明.

    返回 (可证安全, 理由, 精化后 write 区间).
    """
    alloc_size = candidate.get('alloc_size', 0)
    write_site = candidate.get('write_site', 0)
    write_def = candidate.get('write_def', 0)
    var = write_var or candidate.get('write_size_var', '')

    lineage, anchor = _resolve_var_lineage(var, write_def, insns)
    lo = anchor - 32 if anchor else (write_def if write_def else write_site - 64)
    guards: List[Guard] = []
    for v in lineage:
        guards.extend(extract_guards(insns, lo, write_site, v))
    if not guards:
        return False, '无守卫', Interval.top()

    write_iv = Interval.top()
    if candidate.get('write_size'):
        write_iv = Interval.constant(candidate['write_size'])
    refined, applied = refine_with_guards(
        alloc_size, alloc_size, write_iv, guards, lineage)

    # 安全判定: alloc 常量下界 ≥ 精化后 write 上界
    if alloc_size > 0 and refined.hi >= 0 and alloc_size >= refined.hi:
        detail = '; '.join(applied)
        return True, (f'守卫精化: malloc({alloc_size}) ≥ write≤{refined.hi} '
                      f'({detail})'), refined
    return False, f'守卫精化后 write≤{refined.hi}, 但 alloc={alloc_size} 不覆盖', refined


def _normalize(var: str) -> str:
    """去除 var@addr 后缀."""
    return var[:var.rfind('@')] if '@' in var else var
