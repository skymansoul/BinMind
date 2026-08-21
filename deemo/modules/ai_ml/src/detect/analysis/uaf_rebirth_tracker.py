# UAF指针重生追踪-free后指针被重新赋有效值则悬垂状态清除
# 误报根源: realloc(p,n)结果写回p被当作free→p是旧指针释放,但写回后p已是新分配;
#   后续使用新指针p是合法用法, 却被别名追踪标记为UAF
#   例: p=realloc(p,n); memcpy(p,src,n) → 误报UAF
# 方法: 对每个freed别名集合, 在最后一次free到use之间扫描重生赋值:
#   (1) realloc/malloc/calloc结果写回成员寄存器或栈槽 → 成员/槽获得新有效分配
#   (2) xor m,m / mov m,imm → 成员被重写 → 重生
#   (3) 从重生槽重新加载的成员(use窗口内 mov m,[slot]) → 该成员新鲜
# use时仅当使用仍未重生的(悬垂)成员才成立; 全部重生则use为误报
# 安全性: 仅过滤(清除误报use), 不新增检测-召回只增不减

import re
import logging
from typing import Dict, List, Optional, Set, Tuple

from .uaf_alias_tracker import AliasSet, UafAliasTracker

logger = logging.getLogger(__name__)

_ALLOC_FUNCS = {'malloc', 'calloc', 'realloc', 'alloca'}
_ARG_REGS = {'rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9'}
_NON_REG = {'qword', 'dword', 'word', 'byte', 'ptr', 'xmmword'}

_SLOT_RE = re.compile(r'\[(rbp|rsp)([+\-]0x[0-9a-f]+)\]')
_RELOAD_RE = re.compile(
    r'mov\s+%?(\w+),\s*(?:\w+\s+ptr\s+)?\[(rbp|rsp)([+\-]0x[0-9a-f]+)\]')


class RebirthTracker:
    """指针重生追踪器-成员+槽粒度识别free后的重生赋值, 过滤误报use。

    独立于别名追踪器运行: 输入其输出的AliasSet列表, 就地剪除已重生成员的use_sites。
    """

    def __init__(self, max_scan: int = 60):
        self._max_scan = max_scan

    def apply(self, instructions: List[str],
              alias_sets: List[AliasSet]) -> List[AliasSet]:
        """过滤use_sites——只保留对仍悬垂成员的use"""
        for aset in alias_sets:
            if not aset.is_freed or not aset.use_sites:
                continue
            kept = []
            for use_idx in aset.use_sites:
                if self._is_dangling_use(instructions, aset, use_idx):
                    kept.append(use_idx)
            aset.use_sites = kept
            aset.is_vulnerable = bool(kept)
        return alias_sets

    def _is_dangling_use(self, instructions: List[str],
                         aset: AliasSet, use_idx: int) -> bool:
        """use是否命中仍未重生的悬垂成员-成员/槽两级重生判定"""
        last_free = max((f for f in aset.free_sites if f < use_idx), default=-1)
        if last_free < 0:
            return True
        reborn_mem: Set[str] = set()
        reborn_slots: Set[str] = set()
        end = min(use_idx, len(instructions))
        # 从last_free起扫: realloc调用自身是free点, 其结果写回紧随其后(last_free处即重生)
        for j in range(last_free, end):
            if j < 0 or j >= len(instructions):
                continue
            ms, sl = self._reborn_members(instructions, j, aset.members)
            reborn_mem |= ms
            reborn_slots |= sl

        dead = aset.members - reborn_mem
        if not dead:
            return False
        # use窗口内: 死成员从重生槽重新加载 → 该成员新鲜
        active_dead = set(dead)
        lo = max(0, use_idx - 4)
        for j in range(lo, use_idx):
            il = instructions[j].strip().lower()
            m = _RELOAD_RE.match(il)
            if m and reborn_slots:
                slot = f"[{m.group(2)}{m.group(3)}]"
                if slot in reborn_slots and m.group(1) in active_dead:
                    active_dead.discard(m.group(1))
        if not active_dead:
            return False
        return self._uses_dead_member(instructions, use_idx, active_dead)

    @staticmethod
    def _reborn_members(instructions: List[str], j: int,
                        members: Set[str]) -> Tuple[Set[str], Set[str]]:
        """指令j是否使成员/槽重生——返回(重生成员, 重生槽)"""
        if j < 0 or j >= len(instructions):
            return set(), set()
        il = instructions[j].strip().lower()
        if not il or il.startswith((';', '.')):
            return set(), set()
        reborn: Set[str] = set()
        slots: Set[str] = set()

        # (1) alloc/realloc调用→结果写回成员寄存器或栈槽
        if 'call' in il and any(a in il for a in _ALLOC_FUNCS):
            for k in range(j + 1, min(j + 3, len(instructions))):
                ni = instructions[k].strip().lower()
                m = re.match(r'mov\s+%?(?:rax|eax),\s*%?(\w+)', ni)
                if m and m.group(1) in members:
                    reborn.add(m.group(1))
                m2 = re.match(r'mov\s+(\w+),\s*(?:rax|eax)\b', ni)
                if m2 and m2.group(1) in members:
                    reborn.add(m2.group(1))
                # 结果存栈槽: mov [rbp-X], rax → 槽持有新指针
                sm = re.match(r'mov\s+(?:\w+\s+ptr\s+)?\[(rbp|rsp)([+\-]0x[0-9a-f]+)\]\s*,\s*%?(?:rax|eax)', ni)
                if sm:
                    slots.add(f"[{sm.group(1)}{sm.group(2)}]")
            return reborn, slots

        # (2) xor m,m → 置零重生
        m = re.match(r'xor\s+%?(\w+),\s*%?\1\b', il)
        if m and m.group(1) in members:
            return {m.group(1)}, set()

        # (3) mov m, imm → 重写重生(含置0)
        m = re.match(r'mov\s+\$?(0x[0-9a-f]+|\d+),\s*%?(\w+)', il)
        if m and m.group(2) in members:
            return {m.group(2)}, set()
        m = re.match(r'mov\s+%?(\w+),\s*(0x[0-9a-f]+|\d+)', il)
        if m and m.group(1) in members:
            return {m.group(1)}, set()
        return reborn, slots

    @staticmethod
    def _uses_dead_member(instructions: List[str], use_idx: int,
                          dead: Set[str]) -> bool:
        """use窗口内是否存在对悬垂成员的危险使用(解引用/调用参数)。
        与别名追踪器一致: 参数污染发生在call前的mov member→arg_reg, 需扫描窗口
        """
        lo = max(0, use_idx - 6)
        hi = min(len(instructions), use_idx + 1)
        for j in range(lo, hi):
            il = instructions[j].strip().lower()
            if not il or il.startswith(';'):
                continue
            for m in dead:
                # 内存解引用: [m+off] / [m] / (m)
                if re.search(rf'\[{re.escape(m)}([+\-]|])', il):
                    return True
                if re.search(rf'\(%?{re.escape(m)}(?:,|\))', il):
                    return True
                # 调用参数: mov m → arg_reg 或 mov arg_reg → m
                for arg in _ARG_REGS:
                    if re.search(rf'mov\s+%?{re.escape(m)},\s*%?{arg}\b', il):
                        return True
                    if re.search(rf'mov\s+%?{arg},\s*%?{re.escape(m)}\b', il):
                        return True
        return False
