"""守卫支配判定 — 写点前路径守卫对 size/索引上界的证明.

  - 误报主根因之二: 写入看似无界, 实际受前置边界检查约束
    (if (n <= cap) memcpy(p, q, n)). 无 CFG 前提下, 只要守卫对写
    size 的身份 (寄存器或栈槽) 给出上界, 且该上界不超过可用大小,
    则写不可能越界, 与分支去向无关.
  - 支持 cmp reg, imm 与 cmp [slot], imm 两种形式.
  - JCC 语义: 到达写点时寄存器满足约束的补集. 对任意条件跳转,
    守卫上界按 跳走方向 取逆: ja/jbe 族给出 ≤, jae/jb 族给出 <.
  - 循环型: cmp reg, N; jl loop 给出索引上界 N, 供循环累积写.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .def_chain import DefChainTracker, DefKind, DefNode, slot_name

WINDOW = 16

_BOUNDED_JCC = ('jbe', 'jb', 'jle', 'jl', 'jnae', 'jna', 'jng',
                'ja', 'jae', 'jg', 'jge', 'jnbe', 'jnb')


@dataclass
class Guard:
    """一条 cmp+jcc 约束."""
    cmp_idx: int
    jcc_idx: int
    identity: str               # 被约束值的身份键 (slot:rbp-8 / arg:edx)
    upper: int                  # 约束上界
    inclusive: bool             # True: 值 ≤ upper; False: 值 < upper
    jump_target: str = ''

    def bound_value(self) -> int:
        return self.upper if self.inclusive else self.upper - 1


def _extract_imm(text: str) -> Optional[int]:
    import re
    m = re.search(r'(?:0x[0-9a-fA-F]+|\d+)$', text.strip())
    if not m:
        return None
    try:
        return int(m.group(0), 0)
    except ValueError:
        return None


def _jcc_bound_inclusive(jcc: str) -> bool:
    """jcc 到达写点时的约束: True 表示 bound=upper, False 表示 upper-1."""
    if jcc in ('jbe', 'jle', 'jna', 'jg', 'jnbe'):
        return True
    if jcc in ('jb', 'jl', 'jnae', 'jng', 'jae', 'jnb'):
        return False
    return True


def _constraint_identity(op: str) -> Optional[str]:
    """cmp 第一操作数的身份键: 寄存器或栈槽."""
    op = op.strip()
    for _p in ('QWORD PTR ', 'DWORD PTR ', 'BYTE PTR ', 'WORD PTR '):
        if op.upper().startswith(_p):
            op = op[len(_p):].strip()
            break
    if op.startswith('[') and op.endswith(']'):
        sl = slot_name(op)
        if sl:
            return f'slot:{sl}'
        return None
    reg = op.split()[0]
    if reg in ('rax', 'eax', 'rcx', 'ecx', 'rdx', 'edx', 'r8', 'r8d',
               'rsi', 'esi', 'rdi', 'edi', 'rbx', 'ebx', 'r9', 'r9d'):
        return f'arg:{reg}'
    return None


class GuardDominanceChecker:
    """窗口守卫收集与支配证明."""

    def __init__(self, tracker: DefChainTracker):
        self._tracker = tracker

    def collect(self, instructions: List[str],
                write_idx: int) -> List[Guard]:
        guards: List[Guard] = []
        start = max(0, write_idx - WINDOW)
        pending: Dict[str, Tuple[int, int, bool, str]] = {}
        for i in range(start, write_idx):
            line = instructions[i].strip()
            if not line:
                continue
            parts = line.split(None, 1)
            if len(parts) < 2:
                continue
            mnem, ops = parts[0].lower(), parts[1].strip()
            if mnem == 'cmp' and ',' in ops:
                a, b = (x.strip() for x in ops.split(',', 1))
                cid = _constraint_identity(a)
                if cid is None:
                    continue
                upper = _extract_imm(b)
                if upper is not None and upper >= 0:
                    pending[cid] = (i, upper, False, '')
                continue
            if mnem in _BOUNDED_JCC:
                target = ops.strip().split()[0] if ops.strip() else ''
                for cid, (ci, upper, _incl, _t) in list(pending.items()):
                    guards.append(Guard(
                        cmp_idx=ci, jcc_idx=i, identity=cid, upper=upper,
                        inclusive=_jcc_bound_inclusive(mnem),
                        jump_target=target))
                    del pending[cid]
        return guards

    def size_guard_bound(self, guards: List[Guard],
                         size_node: DefNode) -> Optional[int]:
        """若守卫约束了写 size 参数 → 返回可证明上界.

        守卫身份与写 size 参数身份双向解析到根后比较:
        守卫约束寄存器时, 经定义链落到槽身份再比对."""
        root_id = self._tracker.identity(size_node)
        for g in guards:
            gid = g.identity
            if gid.startswith('arg:'):
                dn = self._tracker.def_of_reg(gid[4:])
                gid = self._tracker.identity(dn) or gid
            if gid == root_id:
                return g.bound_value()
        root = self._tracker.resolve(size_node)
        if root.kind == DefKind.IMM:
            return root.imm
        return None

    def prove_write_within(self, guards: List[Guard], size_node: DefNode,
                           usable: int) -> Tuple[bool, str]:
        """证明写 size 上界 ≤ usable."""
        bound = self.size_guard_bound(guards, size_node)
        if bound is not None and bound <= usable:
            return True, f'守卫上界 {bound} ≤ 可用 {usable}'
        if bound is not None:
            return False, f'守卫上界 {bound} > 可用 {usable}, 不压制'
        return False, '无守卫约束'
