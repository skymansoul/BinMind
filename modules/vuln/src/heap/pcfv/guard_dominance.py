"""守卫提取与支配性验证 — 从 cmp/test+jcc 提取候选约束, 过滤非支配守卫.

创建: 2023-06-02
设计决策:
  - 只采信"支配访问点且极性一致"的守卫: 非支配守卫(兄弟分支)对访问点的
    值域无约束力, 采信它们会误过滤真阳性, 这是基线 path_value_narrowing
    的主要漏报来源之一.
  - cmp/test 指令与 jcc 的配对: 一条 jcc 立即前驱(线性顺序)的 cmp/test
    即为其条件来源, 复杂度 O(N).
"""
import re
from typing import Dict, List, Optional, Tuple

from .cfg import IntraCFG
from .types import GuardConstraint

_COND_OPS = {
    'je': ('eq', True), 'jne': ('ne', True),
    'jz': ('eq', True), 'jnz': ('ne', True),
    'jg': ('gt', True), 'jnle': ('gt', True),
    'jge': ('ge', True), 'jnl': ('ge', True),
    'jl': ('lt', True), 'jnge': ('lt', True),
    'jle': ('le', True), 'jng': ('le', True),
    'ja': ('gt', True), 'jnbe': ('gt', True),
    'jae': ('ge', True), 'jnb': ('ge', True),
    'jb': ('lt', True), 'jnae': ('lt', True),
    'jbe': ('le', True), 'jna': ('le', True),
    'js': ('lt', True), 'jns': ('ge', True),
}

_REG_RE = re.compile(r'\b(r[0-9a-d]+[bwd]?|[er]?[abcd]x|[er]?[sd]i|[er]?[sb]p)\b',
                     re.IGNORECASE)
_IMM_RE = re.compile(r'0x[0-9a-fA-F]+|\b\d+\b')


def _norm_reg(reg: str) -> str:
    return {'rax': 'rax', 'eax': 'rax', 'ax': 'rax', 'al': 'rax',
            'rbx': 'rbx', 'ebx': 'rbx', 'rcx': 'rcx', 'ecx': 'rcx',
            'rdx': 'rdx', 'edx': 'rdx', 'rsi': 'rsi', 'esi': 'rsi',
            'rdi': 'rdi', 'edi': 'rdi', 'r8': 'r8', 'r8d': 'r8',
            'r9': 'r9', 'r9d': 'r9', 'r10': 'r10', 'r10d': 'r10',
            'r11': 'r11', 'r11d': 'r11', 'r12': 'r12', 'r12d': 'r12',
            'r13': 'r13', 'r13d': 'r13', 'r14': 'r14', 'r14d': 'r14',
            'r15': 'r15', 'r15d': 'r15', 'rbp': 'rbp', 'rsp': 'rsp',
            }.get(reg.lower(), reg.lower())


class GuardExtractor:
    """从指令流提取守卫约束并做支配性验证."""

    def __init__(self, insns: list):
        self._insns = insns
        self._cfg = IntraCFG(insns)
        self._insn_at: Dict[int, object] = {i.addr: i for i in insns}
        # jcc 指令地址集合: 支配遍历时跳过非分支节点
        self._jcc_addrs = {i.addr for i in insns
                           if i.mnemonic in _COND_OPS}

    def collect_for_access(self, access_addr: int,
                           related_regs: Tuple[str, ...],
                           max_guards: int = 12) -> List[GuardConstraint]:
        """收集支配 access_addr 且作用于 related_regs 的守卫."""
        if access_addr not in self._insn_at:
            return []
        # 无分支函数: 不存在守卫, 直接返回 (大线性函数快速路径)
        if not self._jcc_addrs:
            return []
        doms = self._cfg.dominators(access_addr)
        related = {r.lower() for r in related_regs if r}
        guards: List[GuardConstraint] = []

        for baddr in sorted(doms):
            if baddr == access_addr:
                continue
            if baddr not in self._jcc_addrs:
                continue
            branch = self._insn_at.get(baddr)
            if branch is None:
                continue
            cond = self._constraint_of(baddr, branch)
            if cond is None:
                continue
            cmp_reg, cmp_op, bound = cond
            # 槽守卫: cmp [rbp-4], bound → 关联键 slot:[rbp-4]
            if cmp_reg.startswith('slot:'):
                if cmp_reg not in related:
                    continue
            elif cmp_reg.lower() not in related:
                continue
            polarity = self._cfg.branch_polarity_for_access(
                baddr, access_addr)
            if polarity == 0:
                continue
            # polarity: 1=taken边, 2=fallthrough边.
# COND_OPS 记录的是"跳转发生时"的条件含义.
            op_on_path = cmp_op
            if polarity == 2:
                op_on_path = _negate(cmp_op)
            guards.append(GuardConstraint(
                branch_addr=baddr, reg=cmp_reg, op=op_on_path,
                bound_value=bound, polarity_taken=(polarity == 1),
                dominates=True))
            if len(guards) >= max_guards:
                break
        return guards

    def _constraint_of(self, baddr: int, branch) -> Optional[Tuple[str, str, int]]:
        """找到 jcc 之前最近的 cmp/test 指令, 解析约束."""
        idx = self._insn_idx(baddr)
        if idx is None:
            return None
        for j in range(idx - 1, max(0, idx - 4) - 1, -1):
            insn = self._insns[j]
            mn = insn.mnemonic
            if mn in ('cmp', 'cmpq', 'cmpb', 'cmpw', 'test', 'testq'):
                left, right = _split_operands(insn.operands)
                # 栈槽守卫: cmp DWORD PTR [rbp-4], 64
                if '[' in left:
                    slot = _slot_key_of(left)
                    if slot is not None:
                        imm = _parse_imm(right)
                        if imm is not None:
                            return slot, _COND_OPS.get(
                                branch.mnemonic, ('eq', True))[0], imm
                        continue
                reg = _norm_reg(_REG_RE.search(left).group(1)) \
                    if _REG_RE.search(left) else None
                imm = _parse_imm(right)
                if reg is None or imm is None:
                    imm = _parse_imm(left) if imm is None and left else None
                    if reg is None:
                        m = _REG_RE.search(right)
                        reg = _norm_reg(m.group(1)) if m else None
                    if imm is None:
                        continue
                # 寄存器守卫的槽解析: cmp eax,64 而 eax 由 mov eax,[rbp-4] 载入
                # → 约束实际作用于槽 [rbp-4], 访问索引也来自该槽时守卫成立
                if reg is not None:
                    slot = self._reg_slot_source(reg, j)
                    if slot is not None:
                        op, _ = _COND_OPS.get(branch.mnemonic, ('eq', True))
                        return slot, op, imm
                # test reg, reg → reg == 0 语义
                if mn.startswith('test') and reg and right.rstrip() == left.rstrip():
                    return reg, 'eq', 0
                op, _ = _COND_OPS.get(branch.mnemonic, ('eq', True))
                if mn.startswith('test'):
                    return reg, 'eq', imm
                return reg, op, imm
            if mn.startswith(('mov', 'lea', 'xor', 'add', 'sub')):
                # 中间夹了赋值 → cmp 不再相邻, 保守放弃
                return None
        return None

    def _reg_slot_source(self, reg: str, upto_idx: int) -> Optional[str]:
        """reg 在 upto_idx 之前是否由槽加载定义 → 返回 slot 键.
        FIXME: 回溯窗口 4 条指令对长寄存器链不足, 需与值流追踪对齐."""
        for j in range(upto_idx - 1, max(0, upto_idx - 4) - 1, -1):
            insn = self._insns[j]
            mn = insn.mnemonic
            if mn.startswith(('call', 'j')):
                return None
            if mn in ('mov', 'movabs', 'movzx', 'movsx', 'movsxd'):
                dst, src = _split_operands(insn.operands)
                m = _REG_RE.search(dst)
                if m and _norm_reg(m.group(1)) == reg and '[' in src:
                    return _slot_key_of(src)
                return None
            if mn.startswith(('lea', 'xor', 'add', 'sub', 'imul')):
                return None
        return None

    def _insn_idx(self, addr: int) -> Optional[int]:
        for i, insn in enumerate(self._insns):
            if insn.addr == addr:
                return i
        return None


def _split_operands(operands: str) -> Tuple[str, str]:
    parts = [p.strip() for p in operands.split(',')]
    while len(parts) < 2:
        parts.append('')
    return parts[0], parts[1]


def _slot_key_of(operand: str) -> Optional[str]:
    """'DWORD PTR [rbp-0x4]' → 'slot:[rbp-4]'."""
    import re as _re
    m = _re.search(r'\[([^\]]+)\]', operand)
    if not m:
        return None
    inner = m.group(1).strip()
    reg_m = _REG_RE.search(inner)
    if reg_m is None:
        return None
    reg = _norm_reg(reg_m.group(1))
    disp = 0
    dm = _re.search(r'([+-])\s*(0x[0-9a-fA-F]+|\d+)', inner)
    if dm:
        try:
            v = int(dm.group(2), 0)
        except ValueError:
            v = 0
        disp = v if dm.group(1) == '+' else -v
    return f'slot:[{reg}{disp:+d}]'


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
        val = int(m.group(0))
        return val if val < 0x1000000 else None
    return None


def _negate(op: str) -> str:
    return {'lt': 'ge', 'le': 'gt', 'gt': 'le', 'ge': 'lt',
            'eq': 'ne', 'ne': 'eq'}.get(op, 'ge')
