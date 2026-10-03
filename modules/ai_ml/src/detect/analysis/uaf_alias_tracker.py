# UAF别名追踪器-寄存器拷贝链感知的指针生命周期追踪
# 核心: 指令索引化别名图+按alloc-site作用域计算闭包→隔离跨alloc的寄存器复用污染
# 别名传播free/use: free(rbx)且rbx∈alias_set(ptr)→标记FREED, 后续use→UAF
# 理论: Andersen式别名分析的轻量寄存器版

from __future__ import annotations

import re
import logging
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from collections import defaultdict

from .alias_graph import (
    build_alias_graph, transitive_closure, build_stack_alias_map, _NON_REG)

logger = logging.getLogger(__name__)


@dataclass
class AliasSet:
    """一个指针的别名集合-包含所有持有相同指针值的寄存器/内存位置"""
    canonical: str               # 规范名称(alloc时的寄存器)
    members: Set[str]            # 所有别名成员(寄存器名)
    alloc_site: int
    free_sites: List[int] = field(default_factory=list)
    use_sites: List[int] = field(default_factory=list)
    is_freed: bool = False
    is_vulnerable: bool = False


class UafAliasTracker:
    """别名感知UAF追踪器-指令索引化别名图+按alloc作用域闭包→隔离跨alloc寄存器复用
    5阶段: 别名图→alloc/free→闭包→free传播→危险使用(含killed_members追踪)"""

    _ALLOC_FUNCS = {'malloc', 'calloc', 'realloc', 'alloca'}
    _FREE_FUNCS = {'free', 'kfree', 'delete', 'realloc'}
    _COPY_INSTRS = {'mov', 'lea'}

    def __init__(self, max_trace_dist: int = 40):
        self._max_dist = max_trace_dist

    def analyze(self,
                instructions: List[str],
                bb_boundaries: Optional[List[Tuple[int, int]]] = None
                ) -> List[AliasSet]:
        """别名感知UAF分析-主入口"""
        n = len(instructions)
        if n < 5:
            return []

        # 阶段1: 构建指令索引化别名图
        alias_graph = self._build_alias_graph(instructions)

        # 阶段2: 识别alloc/free站点
        alloc_sites = self._find_alloc_sites(instructions)
        free_sites = self._find_free_sites(instructions)

        # 阶段3: 为每个alloc创建别名集合(作用域: 仅alloc之后的边)
        # rax/rdi等规范寄存器在多次alloc间共享, BFS经过它们会造成跨alloc桥接
        # stop_nodes: BFS到达这些节点后不继续扩展, 阻断桥接但保留直接别名
        _STOP_NODES = {'rax', 'eax', 'rdi', 'edi', 'rsi', 'esi',
                       'rdx', 'edx', 'rcx', 'ecx', 'r8', 'r8d', 'r9', 'r9d'}
        alias_sets: Dict[str, AliasSet] = {}

        for ptr_reg, alloc_idx in alloc_sites:
            closure = self._transitive_closure(
                ptr_reg, alias_graph, min_idx=alloc_idx + 1,
                stop_nodes=_STOP_NODES)
            canonical = f"{ptr_reg}@{alloc_idx}"
            aset = AliasSet(
                canonical=canonical, members=closure,
                alloc_site=alloc_idx)
            alias_sets[canonical] = aset

        # 阶段4: 传播free-若free的寄存器在别名集合中，标记整个集合
        for free_idx, freed_reg in free_sites:
            matched = self._find_matching_alias_set(freed_reg, alias_sets)
            if matched:
                matched.free_sites.append(free_idx)
                matched.is_freed = True

        # 阶段5: 检测每个free之后的危险使用(解引用、作为参数)
        # 逐free扫描而非仅扫描last_free之后-多free场景下使用可能在free之间
        _ARG_REGS = {'rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9'}
        for aset in alias_sets.values():
            if not aset.is_freed:
                continue
            for free_idx in sorted(aset.free_sites):
                arg_reg_tainted = set()
                killed_members: Set[str] = set()  # 被后续分配重新赋值的成员
                for j in range(free_idx + 1, min(free_idx + self._max_dist, n)):
                    instr = instructions[j].strip().lower()
                    if not instr or instr.startswith(';'):
                        continue
                    # 检测新分配→成员被重新赋有效值→该成员不再是悬垂指针
                    if 'call' in instr and any(
                        af in instr for af in self._ALLOC_FUNCS):
                        # 下一条指令通常是 mov %rax, %reg → 该reg被"复活"
                        for k in range(j + 1, min(j + 3, n)):
                            next_instr = instructions[k].strip().lower()
                            # AT&T: mov %rax, %reg
                            m = re.match(r'mov\s+%?(?:rax|eax),\s*%?(\w+)', next_instr)
                            if m:
                                killed_members.add(m.group(1))
                            # Intel: mov reg, rax
                            m_i = re.match(r'mov\s+(\w+),\s*(?:rax|eax)\b', next_instr)
                            if m_i:
                                killed_members.add(m_i.group(1))
                    # 检查: 别名寄存器→调用约定寄存器的mov
                    # AT&T: mov %src, %dst → 源第一, 目标第二
                    for m in aset.members:
                        if m in killed_members:
                            continue  # 已被新分配覆盖, 安全
                        for arg_reg in _ARG_REGS:
                            # AT&T: mov %src, %dst → 源第一, 目标第二
                            if re.search(rf'mov\s+%?{re.escape(m)},\s*%?{arg_reg}\b', instr):
                                arg_reg_tainted.add(arg_reg)
                            # Intel: mov dst, src → 目标在前
                            elif re.search(rf'mov\s+%?{arg_reg},\s*%?{re.escape(m)}\b', instr):
                                arg_reg_tainted.add(arg_reg)
                    # 检查: 调用约定寄存器被用作call参数(排除free类函数)
                    if 'call' in instr and not any(
                        ff in instr for ff in self._FREE_FUNCS):
                        for arg_reg in _ARG_REGS:
                            if arg_reg in arg_reg_tainted:
                                aset.use_sites.append(j)
                                aset.is_vulnerable = True
                                break
                    # 检查: 直接解引用(跳过已杀死的成员)
                    active_members = aset.members - killed_members
                    if self._is_dangerous_use(instr, active_members):
                        if j not in aset.use_sites:
                            aset.use_sites.append(j)
                            aset.is_vulnerable = True

        return [a for a in alias_sets.values()
                if a.is_vulnerable or a.is_freed]

    # ── 指令索引化别名图(闭包仅考虑[alloc_idx, ∞)边→隔离跨alloc作用域) ──

    def _build_alias_graph(self,
                           instructions: List[str]
                           ) -> Dict[str, Set[Tuple[str, int]]]:
        """构建指令索引化的寄存器别名图-委托alias_graph"""
        return build_alias_graph(instructions)  # type: ignore[return-value]

    def _transitive_closure(self,
                            start: str,
                            graph: Dict[str, Set[Tuple[str, int]]],
                            min_idx: int = 0,
                            max_idx: int = 999999,
                            stop_nodes: Optional[Set[str]] = None
                            ) -> Set[str]:
        """BFS计算别名传递闭包-委托alias_graph"""
        return transitive_closure(start, graph, min_idx, max_idx, stop_nodes)

    # alloc/free 站点识别

    def _find_alloc_sites(self,
                          instructions: List[str]
                          ) -> List[Tuple[str, int]]:
        """查找alloc调用并确定结果寄存器"""
        sites = []
        for i, instr in enumerate(instructions):
            instr_l = instr.strip().lower()
            if 'call' not in instr_l:
                continue
            for af in self._ALLOC_FUNCS:
                if af in instr_l:
                    ptr = self._resolve_result_reg(instructions, i)
                    if ptr:
                        sites.append((ptr, i))
                    break
        return sites

    def _find_free_sites(self,
                         instructions: List[str]
                         ) -> List[Tuple[int, str]]:
        """查找free调用并解析被释放的寄存器-双ABI"""
        sites = []
        for i, instr in enumerate(instructions):
            instr_l = instr.strip().lower()
            if 'call' not in instr_l:
                continue
            for ff in self._FREE_FUNCS:
                if ff in instr_l:
                    freed = self._resolve_free_param(instructions, i)
                    if freed:
                        sites.append((i, freed))
                    break
        return sites

    def _resolve_result_reg(self, instructions: List[str],
                            call_idx: int) -> Optional[str]:
        """alloc后结果寄存器——mov %rax,%reg(AT&T)或mov reg,rax(Intel)"""
        for j in range(call_idx + 1, min(call_idx + 3, len(instructions))):
            instr = instructions[j].strip().lower()
            m = re.match(r'mov\s+%?(?:rax|eax),\s*%?(\w+)', instr)
            if m and m.group(1) not in _NON_REG:
                return m.group(1)
            mi = re.match(r'mov\s+(\w+),\s*(?:rax|eax)\b', instr)
            if mi and mi.group(1) not in _NON_REG:
                return mi.group(1)
        return 'rax'

    def _resolve_free_param(self,
                            instructions: List[str],
                            free_idx: int) -> Optional[str]:
        """free()参数来源——rdi优先(Win用rcx), 仅追踪到非自身时返回"""
        for param_reg in ('rdi', 'rcx'):
            r = self._trace_reg_source(instructions, free_idx - 1, param_reg)
            if r and r != param_reg:
                return r
        return None

    def _trace_reg_source(self,
                          instructions: List[str],
                          from_idx: int,
                          target_reg: str,
                          depth: int = 0) -> Optional[str]:
        """反向追踪寄存器来源(≤5步, rax穿透停止)—双ABI"""
        if depth > 5 or from_idx < 0:
            return target_reg
        current = target_reg.lower()
        # ABI检测: 有%→AT&T, 无%→Intel
        _intel = not any('%' in instructions[j].strip().lower()
                         for j in range(max(0, from_idx - 5),
                                        min(len(instructions), from_idx + 2))
                         if instructions[j].strip() and not instructions[j].strip().startswith(';'))
        for j in range(from_idx, max(-1, from_idx - 6), -1):
            if j < 0:
                break
            instr = instructions[j].strip().lower()
            m = re.match(rf'mov\s+%?(\w+),\s*%?{re.escape(current)}', instr)
            src = None
            if m:
                src = m.group(1)
            elif _intel:
                mm = re.match(rf'mov\s+%?{re.escape(current)},\s*(?:\w+\s+ptr\s+)?\[(\w+)\]', instr)
                if mm:
                    src = mm.group(1)
                elif re.match(rf'mov\s+%?{re.escape(current)},\s*(?:\w+\s+ptr\s+)?\[(rbp|rsp)', instr):
                    return current  # Intel栈加载→停止
                else:
                    mi = re.match(rf'mov\s+%?{re.escape(current)},\s*%?(\w+)', instr)
                    if mi: src = mi.group(1)
            if src:
                if src in ('rax', 'eax') and depth > 0:
                    return current
                if (not src.startswith(('0x', '[')) and not src[0].isdigit()
                        and src not in _NON_REG):
                    return self._trace_reg_source(instructions, j - 1, src, depth + 1)
            m = re.match(rf'lea\s+[^(]*\(%?(\w+)\)\s*,\s*%?{re.escape(current)}', instr)
            if m:
                return self._trace_reg_source(instructions, j - 1, m.group(1), depth + 1)
            if _intel:
                ml = re.match(rf'lea\s+%?{re.escape(current)},\s*\[(\w+)(?:[+\-]\w+)?\]', instr)
                if ml:
                    return self._trace_reg_source(instructions, j - 1, ml.group(1), depth + 1)
            m = re.match(rf'mov\s*\(%?(\w+)\)\s*,\s*%?{re.escape(current)}', instr)
            if m:
                return self._trace_reg_source(instructions, j - 1, m.group(1), depth + 1)
            if re.match(rf'xor\s+%?({re.escape(current)}),\s*%?\1\b', instr):
                return None
            if re.match(rf'mov\s+\$?(0x[0-9a-f]+|\d+),\s*%?{re.escape(current)}', instr):
                return None
            if _intel and re.match(rf'mov\s+%?{re.escape(current)},\s*(0x[0-9a-f]+|\d+)', instr):
                return None
        return current

    # 辅助方法

    def _find_matching_alias_set(self, reg: str,
                                  alias_sets: Dict[str, AliasSet]) -> Optional[AliasSet]:
        """查找包含指定寄存器的别名集合-优先最近alloc"""
        r = reg.lower()
        best = None; best_alloc = -1
        for a in alias_sets.values():
            if r in a.members and a.alloc_site > best_alloc:
                best = a; best_alloc = a.alloc_site
        return best

    def _is_dangerous_use(self, instr: str, members: Set[str]) -> bool:
        """指令是否对别名集合中的指针有危险使用"""
        for m in members:
            if f'({m})' in instr or f'({m},' in instr:
                return True
            if 'call' in instr and re.search(rf'\b{m}\b', instr) and not any(
                ff in instr for ff in self._FREE_FUNCS):
                return True
        return False
