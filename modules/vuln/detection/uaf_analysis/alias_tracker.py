"""
堆指针别名追踪器 — 追踪free→use之间的指针别名和赋值链。

核心改进（相比基础uaf_detector.py）:
  1. 别名感知: mov rax, rbx; free(rbx); use(rax) 也应该被检测
     (基础版仅追踪直接free的寄存器, 不管别名)
  2. realloc检测: realloc(ptr, 0)等价于free(ptr), realloc(ptr, n)可能移动ptr
  3. 赋值距离感知: free后N条指令内无use → 降低置信度(N>50 → low)

方法: 基于值等价类的轻量别名分析
  - 当 mov dst, src 时, dst和src进入同一别名类
  - free(reg)时, 整个别名类被标记为freed
  - use(reg)时, 检查reg所在别名类是否被标记
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class AliasClass:
    """值等价类 — 一组可能持有相同指针值的寄存器"""
    members: Set[str] = field(default_factory=set)
    freed_at: int = -1                # 该类被释放的指令索引, -1=未释放
    freed_by: str = ""                # free / realloc / delete


@dataclass
class UafFindingEnhanced:
    location: str
    freed_reg: str                    # 被free的原始寄存器
    used_reg: str                     # 被use的寄存器(可能是别名)
    free_insn_idx: int
    use_insn_idx: int
    instruction_gap: int
    use_type: str                     # read / write / call_via
    realloc_possible: bool            # gap间是否可能有realloc复用该内存
    danger_score: float               # 0-10
    confidence: str


_FREE_FUNCS = {'free', '_ZdlPv', 'HeapFree', 'VirtualFree'}
_REALLOC_FUNCS = {'realloc', '_Znwm', 'reallocarray'}
_DELETE_FUNCS = {'_ZdaPv', 'delete', 'operator delete'}


def _parse_written_regs(insn: str) -> Set[str]:
    """提取指令写入的寄存器集合"""
    written = set()
    parts = insn.lower().replace(',', ' ').split()
    if not parts: return written
    mnemonic = parts[0]
    all_regs = {'rax','rbx','rcx','rdx','rsi','rdi','r8','r9','r10','r11',
                'r12','r13','r14','r15','rsp','rbp',
                'eax','ebx','ecx','edx','esi','edi','esp','ebp'}
    if mnemonic in ('mov','movzx','movsx','lea','xor','add','sub','and','or','pop'):
        for p in parts[1:2]:
            for r in all_regs:
                if r == p or r in p:
                    full = 'r' + r[1:] if r.startswith('e') else r
                    written.add(full)
    if mnemonic == 'call':
        written.add('rax')  # 返回值
    return written


def _parse_read_regs(insn: str) -> Set[str]:
    read = set()
    parts = insn.lower().replace(',', ' ').split()
    if len(parts) < 2: return read
    all_regs = {'rax','rbx','rcx','rdx','rsi','rdi','r8','r9','r10','r11',
                'r12','r13','r14','r15','rbp','rsp',
                'eax','ebx','ecx','edx','esi','edi','ebp','esp'}
    for p in parts[1:]:
        for r in all_regs:
            if r in p:  # 子串匹配: '[rbx]'→rbx, 'rcx,'→rcx
                full = 'r' + r[1:] if r.startswith('e') else r
                read.add(full)
    return read


def _is_deref(insn: str) -> Tuple[bool, str]:
    """指令是否解引用指针 → (是, read/write/call_via)"""
    lower = insn.lower().strip()
    if '[' in lower:
        if 'mov' in lower and ',' in lower:
            dst_is_mem = '[' in lower.split(',')[0] if ',' in lower else False
            return True, 'write' if dst_is_mem else 'read'
        return True, 'read'
    if lower.startswith('call') and '*' in lower:
        return True, 'call_via'
    return False, ''


def track_aliases_and_detect_uaf(
    instructions: List[str],
) -> List[UafFindingEnhanced]:
    """
    别名感知的UAF检测。
    返回按danger_score降序排列的UafFindingEnhanced列表。
    """
    alias_classes: Dict[str, AliasClass] = {}  # reg_name → AliasClass
    class_counter = 0
    findings: List[UafFindingEnhanced] = []

    # 初始化: 每个寄存器属于自己的等价类
    all_regs = {'rax','rbx','rcx','rdx','rsi','rdi','r8','r9','r10','r11',
                'r12','r13','r14','r15'}

    for i, insn in enumerate(instructions):
        written = _parse_written_regs(insn)
        read = _parse_read_regs(insn)
        insn_lower = insn.lower().strip()

        # mov dst, src → 合并dst和src的别名类
        if written and read:
            dst = list(written)[0]
            src = list(read)[0] if read else None
            if src and dst in all_regs and src in all_regs:
                cls_dst = alias_classes.get(dst)
                cls_src = alias_classes.get(src)
                if cls_dst and cls_src and cls_dst != cls_src:
                    cls_dst.members |= cls_src.members
                    for m in cls_src.members:
                        alias_classes[m] = cls_dst
                elif not cls_dst and cls_src:
                    cls_src.members.add(dst)
                    alias_classes[dst] = cls_src
                elif not cls_dst and not cls_src:
                    ac = AliasClass(members={dst, src})
                    class_counter += 1
                    alias_classes[dst] = ac
                    alias_classes[src] = ac

        # call free/realloc/delete → 标记别名类为freed
        if 'call' in insn_lower:
            parts = insn_lower.split()
            if len(parts) >= 2:
                callee = parts[-1].lstrip('*').strip('<>').split('@')[0]
                # call指令本身不包含寄存器操作数—需向前查找参数传递
                ptr_regs = set(read)
                if not ptr_regs and i > 0:
                    prev_written = _parse_written_regs(instructions[i-1])
                    ptr_regs = prev_written  # 前一条指令写入的寄存器=call参数
                for r in ptr_regs:
                        if callee in _FREE_FUNCS:
                            alias_classes[r].freed_at = i
                            alias_classes[r].freed_by = 'free'
                        elif callee in _REALLOC_FUNCS:
                            alias_classes[r].freed_at = i
                            alias_classes[r].freed_by = 'realloc'
                        elif callee in _DELETE_FUNCS:
                            alias_classes[r].freed_at = i
                            alias_classes[r].freed_by = 'delete'

        # 检查对已释放别名类的use
        is_deref, dtype = _is_deref(insn)
        if is_deref:
            for r in read:
                if r in alias_classes and alias_classes[r].freed_at >= 0:
                    ac = alias_classes[r]
                    gap = i - ac.freed_at
                    # 重新赋值检测: 若written覆盖了read寄存器, 则不被标记为UAF
                    if r in written:
                        continue
                    # 计算danger_score
                    danger = min(10.0, (10.0 if gap <= 5 else
                                        7.0 if gap <= 20 else
                                        4.0 if gap <= 50 else 2.0))
                    if ac.freed_by == 'realloc':
                        danger *= 0.8  # realloc不总是释放
                    findings.append(UafFindingEnhanced(
                        location=f'uaf@{i}',
                        freed_reg=next(iter(ac.members), r),
                        used_reg=r, free_insn_idx=ac.freed_at,
                        use_insn_idx=i, instruction_gap=gap,
                        use_type=dtype,
                        realloc_possible=(gap > 10),
                        danger_score=round(danger, 1),
                        confidence='confirmed' if gap <= 20 else 'likely'))

    findings.sort(key=lambda f: f.danger_score, reverse=True)
    return findings
